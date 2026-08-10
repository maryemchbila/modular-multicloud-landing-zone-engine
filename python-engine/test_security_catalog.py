"""Tests CIS-2 du catalogue avec des regles synthetiques non officielles."""

import json
import subprocess
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

import security_catalog
from security_catalog import (
    DuplicateSecurityRuleError,
    SecurityRuleCatalog,
    SecurityRuleNotFoundError,
)
from security_models import (
    RuleStatus,
    SecurityFinding,
    SecurityResource,
    SecurityRuleMetadata,
    SecuritySeverity,
    UnknownSecurityCloudError,
)
from security_rule import SecurityRule
from security_scanner import SecurityComplianceScanner
from terraform_runner import TerraformRunner


class _CatalogTestRule(SecurityRule):
    """Fixture INTERNAL_TEST; elle ne represente aucun controle CIS officiel."""

    runtime_secret = "fake-runtime-secret-not-for-inventory"

    def evaluate(self, resource: SecurityResource) -> SecurityFinding:
        return SecurityFinding(
            rule_id=self.metadata.rule_id,
            cloud=resource.cloud,
            resource_type=resource.resource_type,
            resource_name=resource.resource_name,
            resource_address=resource.resource_address,
            status=RuleStatus.PASS,
            severity=self.metadata.severity,
            title=self.metadata.title,
            message="Synthetic catalog fixture passed.",
            recommendation=self.metadata.recommendation,
        )


class SecurityRuleCatalogTests(unittest.TestCase):
    @staticmethod
    def _metadata(
        *,
        rule_id: str = "TEST_GCP_COMPUTE_001",
        cloud: str = "gcp",
        service: str = "compute",
        resource_type: str = "google_compute_instance",
        enabled: bool = True,
        tags: tuple[str, ...] = ("compute",),
        profiles: tuple[str, ...] = ("baseline",),
        framework: str | None = "INTERNAL_TEST",
        framework_version: str | None = "1.0-test",
        reference_id: str | None = "TEST-REF-001",
        reference_url: str | None = "https://example.invalid/test-ref-001",
        control_family: str | None = "compute-security",
        rationale: str | None = "Synthetic rationale for tests only.",
    ) -> SecurityRuleMetadata:
        return SecurityRuleMetadata(
            rule_id=rule_id,
            cloud=cloud,
            service=service,
            resource_type=resource_type,
            title=f"Synthetic rule {rule_id}",
            description="INTERNAL_TEST fixture; not an official CIS control.",
            severity=SecuritySeverity.MEDIUM,
            recommendation="Use a synthetic safe configuration.",
            enabled=enabled,
            tags=tags,
            profiles=profiles,
            framework=framework,
            framework_version=framework_version,
            reference_id=reference_id,
            reference_url=reference_url,
            control_family=control_family,
            rationale=rationale,
        )

    @classmethod
    def _rule(cls, **metadata_overrides) -> _CatalogTestRule:
        return _CatalogTestRule(cls._metadata(**metadata_overrides))

    def _mixed_catalog(self) -> SecurityRuleCatalog:
        catalog = SecurityRuleCatalog(description="Synthetic catalog only.")
        catalog.register_many(
            (
                self._rule(
                    rule_id="TEST_GCP_COMPUTE_001",
                    tags=("compute", "logging"),
                    profiles=("baseline",),
                ),
                self._rule(
                    rule_id="TEST_GCP_NETWORK_001",
                    service="network",
                    resource_type="google_compute_firewall",
                    tags=("network", "ssh", "ingress"),
                    profiles=("baseline", "strict"),
                ),
                self._rule(
                    rule_id="TEST_OCI_NETWORK_001",
                    cloud="oci",
                    service="network",
                    resource_type="oci_core_security_list",
                    tags=("network", "ssh"),
                    profiles=("strict",),
                    reference_id="TEST-REF-OCI-001",
                ),
                self._rule(
                    rule_id="TEST_OCI_IAM_001",
                    cloud="oci",
                    service="iam",
                    resource_type="oci_identity_policy",
                    enabled=False,
                    tags=("iam",),
                    profiles=("custom",),
                    reference_id="TEST-REF-OCI-002",
                ),
            )
        )
        return catalog

    def test_empty_catalog_is_created(self) -> None:
        catalog = SecurityRuleCatalog()

        self.assertEqual(catalog.rules, ())
        self.assertEqual(catalog.to_dict()["rules_total"], 0)

    def test_register_adds_one_rule(self) -> None:
        catalog = SecurityRuleCatalog()
        rule = self._rule()

        catalog.register(rule)

        self.assertEqual(catalog.rules, (rule,))

    def test_register_many_adds_multiple_rules(self) -> None:
        catalog = SecurityRuleCatalog()
        rules = (
            self._rule(),
            self._rule(
                rule_id="TEST_OCI_COMPUTE_001",
                cloud="oci",
                resource_type="oci_core_instance",
            ),
        )

        catalog.register_many(rules)

        self.assertEqual(len(catalog.rules), 2)

    def test_duplicate_rule_id_is_rejected(self) -> None:
        catalog = SecurityRuleCatalog()
        catalog.register(self._rule())

        with self.assertRaises(DuplicateSecurityRuleError):
            catalog.register(self._rule())

    def test_duplicate_inside_batch_is_rejected_atomically(self) -> None:
        catalog = SecurityRuleCatalog()
        duplicate_rules = (self._rule(), self._rule())

        with self.assertRaises(DuplicateSecurityRuleError):
            catalog.register_many(duplicate_rules)

        self.assertEqual(catalog.rules, ())

    def test_get_returns_existing_rule(self) -> None:
        catalog = SecurityRuleCatalog()
        rule = self._rule()
        catalog.register(rule)

        self.assertIs(catalog.get("TEST_GCP_COMPUTE_001"), rule)

    def test_get_missing_rule_raises_business_error(self) -> None:
        with self.assertRaises(SecurityRuleNotFoundError):
            SecurityRuleCatalog().get("TEST_MISSING_001")

    def test_enabled_is_true_by_default_for_cis1_constructor(self) -> None:
        metadata = SecurityRuleMetadata(
            rule_id="TEST_GCP_COMPUTE_LEGACY",
            cloud="gcp",
            service="compute",
            resource_type="google_compute_instance",
            title="Synthetic legacy fixture",
            description="Uses only the eight CIS-1 fields.",
            severity=SecuritySeverity.INFO,
            recommendation="No real recommendation.",
        )

        self.assertTrue(metadata.enabled)
        self.assertEqual(metadata.tags, ())
        self.assertEqual(metadata.profiles, ())

    def test_disabled_rule_remains_in_inventory(self) -> None:
        catalog = SecurityRuleCatalog()
        disabled_rule = self._rule(enabled=False)
        catalog.register(disabled_rule)

        self.assertIs(catalog.get(disabled_rule.metadata.rule_id), disabled_rule)
        self.assertEqual(catalog.to_dict()["rules_disabled"], 1)

    def test_enabled_only_excludes_disabled_rule(self) -> None:
        catalog = self._mixed_catalog()

        selected = catalog.select(cloud="oci", enabled_only=True)

        self.assertEqual(
            [rule.metadata.rule_id for rule in selected],
            ["TEST_OCI_NETWORK_001"],
        )

    def test_enabled_only_false_includes_disabled_rule(self) -> None:
        catalog = self._mixed_catalog()

        selected = catalog.select(cloud="oci", enabled_only=False)

        self.assertEqual(len(selected), 2)

    def test_select_gcp_normalises_cloud(self) -> None:
        selected = self._mixed_catalog().select(cloud=" GCP ")

        self.assertEqual({rule.metadata.cloud for rule in selected}, {"gcp"})
        self.assertEqual(len(selected), 2)

    def test_select_oci(self) -> None:
        selected = self._mixed_catalog().select(cloud="oci")

        self.assertEqual({rule.metadata.cloud for rule in selected}, {"oci"})

    def test_select_compute_service(self) -> None:
        selected = self._mixed_catalog().select(service=" COMPUTE ")

        self.assertEqual(
            [rule.metadata.rule_id for rule in selected],
            ["TEST_GCP_COMPUTE_001"],
        )

    def test_select_network_service(self) -> None:
        selected = self._mixed_catalog().select(service="network")

        self.assertEqual(len(selected), 2)
        self.assertTrue(all(rule.metadata.service == "network" for rule in selected))

    def test_select_resource_type(self) -> None:
        selected = self._mixed_catalog().select(
            resource_type="google_compute_firewall"
        )

        self.assertEqual(
            [rule.metadata.rule_id for rule in selected],
            ["TEST_GCP_NETWORK_001"],
        )

    def test_select_baseline_profile(self) -> None:
        selected = self._mixed_catalog().select(profile=" BASELINE ")

        self.assertEqual(len(selected), 2)

    def test_select_strict_profile(self) -> None:
        selected = self._mixed_catalog().select(profile="strict")

        self.assertEqual(len(selected), 2)

    def test_select_single_tag(self) -> None:
        selected = self._mixed_catalog().select(tags={"ssh"})

        self.assertEqual(len(selected), 2)

    def test_multiple_tags_default_to_all(self) -> None:
        selected = self._mixed_catalog().select(tags={"network", "ingress"})

        self.assertEqual(
            [rule.metadata.rule_id for rule in selected],
            ["TEST_GCP_NETWORK_001"],
        )

    def test_multiple_tags_can_match_any(self) -> None:
        selected = self._mixed_catalog().select(
            tags={"compute", "ssh"},
            tag_match="ANY",
        )

        self.assertEqual(len(selected), 3)

    def test_invalid_tag_match_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "all.*any"):
            self._mixed_catalog().select(tags={"ssh"}, tag_match="some")

    def test_tags_are_normalised_sorted_and_deduplicated(self) -> None:
        metadata = self._metadata(tags=(" SSH ", "network", "ssh", "Ingress"))

        self.assertEqual(metadata.tags, ("ingress", "network", "ssh"))

    def test_profiles_are_normalised_sorted_and_deduplicated(self) -> None:
        metadata = self._metadata(
            profiles=(" STRICT ", "baseline", "strict", "Custom")
        )

        self.assertEqual(metadata.profiles, ("baseline", "custom", "strict"))

    def test_framework_is_preserved(self) -> None:
        self.assertEqual(self._metadata().framework, "INTERNAL_TEST")

    def test_framework_version_is_preserved(self) -> None:
        self.assertEqual(self._metadata().framework_version, "1.0-test")

    def test_reference_id_is_preserved(self) -> None:
        self.assertEqual(self._metadata().reference_id, "TEST-REF-001")

    def test_reference_url_is_preserved(self) -> None:
        self.assertEqual(
            self._metadata().reference_url,
            "https://example.invalid/test-ref-001",
        )

    def test_reference_url_with_secret_query_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "secret"):
            self._metadata(
                reference_url="https://example.invalid/ref?token=fake-sensitive"
            )

    def test_control_family_is_preserved(self) -> None:
        self.assertEqual(self._metadata().control_family, "compute-security")

    def test_rationale_is_preserved(self) -> None:
        self.assertEqual(
            self._metadata().rationale,
            "Synthetic rationale for tests only.",
        )

    def test_catalog_to_dict_has_stable_inventory_counts(self) -> None:
        payload = self._mixed_catalog().to_dict()

        self.assertEqual(payload["catalog_version"], "1.0")
        self.assertEqual(payload["rules_total"], 4)
        self.assertEqual(payload["rules_enabled"], 3)
        self.assertEqual(payload["rules_disabled"], 1)
        self.assertEqual(payload["clouds"], {"gcp": 2, "oci": 2})

    def test_catalog_to_json_is_valid(self) -> None:
        payload = json.loads(self._mixed_catalog().to_json())

        self.assertEqual(len(payload["rules"]), 4)

    def test_metadata_enums_are_serialised_as_text(self) -> None:
        catalog = SecurityRuleCatalog()
        catalog.register(self._rule())

        self.assertEqual(
            catalog.to_dict()["rules"][0]["severity"],
            "MEDIUM",
        )

    def test_catalog_order_is_deterministic(self) -> None:
        rules = list(self._mixed_catalog().rules)
        reversed_catalog = SecurityRuleCatalog(description="Synthetic catalog only.")
        reversed_catalog.register_many(reversed(rules))

        self.assertEqual(
            [rule.metadata.rule_id for rule in self._mixed_catalog().rules],
            [rule.metadata.rule_id for rule in reversed_catalog.rules],
        )
        self.assertEqual(
            self._mixed_catalog().to_json(),
            reversed_catalog.to_json(),
        )

    def test_selection_order_is_deterministic(self) -> None:
        catalog = self._mixed_catalog()

        first = catalog.select(tags={"network", "ssh"}, tag_match="any")
        second = catalog.select(tags=("ssh", "network"), tag_match="any")

        self.assertEqual(first, second)

    def test_scanner_accepts_catalog_selection_directly(self) -> None:
        catalog = SecurityRuleCatalog()
        catalog.register(self._rule())
        scanner = SecurityComplianceScanner(catalog.select(cloud="gcp"))
        resource = SecurityResource(
            cloud="gcp",
            service="compute",
            resource_type="google_compute_instance",
            resource_name="vm_test_01",
            resource_address="google_compute_instance.vm_test_01",
            attributes={"synthetic": True},
        )

        result = scanner.scan("gcp", [resource])

        self.assertEqual(result.passed, 1)

    def test_catalog_never_calls_terraform(self) -> None:
        with patch.object(TerraformRunner, "run") as terraform_run:
            catalog = SecurityRuleCatalog()
            catalog.register(self._rule())
            catalog.select(cloud="gcp")
            catalog.to_json()

        terraform_run.assert_not_called()

    def test_catalog_never_starts_a_subprocess_or_cloud_cli(self) -> None:
        with patch.object(subprocess, "run") as process_run:
            catalog = SecurityRuleCatalog()
            catalog.register(self._rule(cloud="oci"))
            catalog.select(cloud="oci")

        process_run.assert_not_called()

    def test_catalog_module_has_no_cloud_sdk_import(self) -> None:
        module_names = set(security_catalog.__dict__)

        self.assertTrue(
            {"google", "oci", "googleapiclient", "subprocess"}.isdisjoint(
                module_names
            )
        )

    def test_cis1_rule_fixture_remains_scanner_compatible(self) -> None:
        legacy_rule = _CatalogTestRule(
            SecurityRuleMetadata(
                "TEST_GCP_COMPUTE_LEGACY",
                "gcp",
                "compute",
                "google_compute_instance",
                "Synthetic legacy fixture",
                "Uses positional CIS-1 fields.",
                SecuritySeverity.LOW,
                "No real recommendation.",
            )
        )

        self.assertTrue(legacy_rule.metadata.enabled)
        self.assertEqual(legacy_rule.metadata.tags, ())

    def test_unknown_cloud_filter_is_rejected_centrally(self) -> None:
        with self.assertRaises(UnknownSecurityCloudError):
            self._mixed_catalog().select(cloud="azure")

    def test_empty_rule_id_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "rule_id"):
            self._metadata(rule_id="  ")

    def test_empty_title_is_rejected(self) -> None:
        values = self._metadata().to_dict()

        with self.assertRaisesRegex(ValueError, "title"):
            SecurityRuleMetadata(
                rule_id=values["rule_id"],
                cloud=values["cloud"],
                service=values["service"],
                resource_type=values["resource_type"],
                title=" ",
                description=values["description"],
                severity=SecuritySeverity.MEDIUM,
                recommendation=values["recommendation"],
            )

    def test_catalog_serialisation_excludes_runtime_rule_data(self) -> None:
        catalog = SecurityRuleCatalog()
        catalog.register(self._rule())

        payload = catalog.to_json()

        self.assertNotIn(_CatalogTestRule.runtime_secret, payload)
        self.assertNotIn("evaluate", payload)

    def test_registered_metadata_is_immutable(self) -> None:
        catalog = SecurityRuleCatalog()
        rule = self._rule()
        catalog.register(rule)

        with self.assertRaises(FrozenInstanceError):
            rule.metadata.rule_id = "TEST_CHANGED"

        self.assertIs(catalog.get("TEST_GCP_COMPUTE_001"), rule)


if __name__ == "__main__":
    unittest.main()
