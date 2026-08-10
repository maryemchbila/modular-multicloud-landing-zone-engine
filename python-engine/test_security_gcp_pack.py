"""Tests du pack, du catalogue et du scan synthetique GCP CIS-3."""

import subprocess
import unittest
from unittest.mock import patch

import security_gcp_rules
from security_catalog import SecurityRuleCatalog
from security_gcp_pack import build_gcp_security_rule_pack
from security_gcp_rules import (
    GCP_COMPUTE_RESOURCE_TYPE,
    GCP_IAM_RESOURCE_TYPE,
    GCP_INTERNAL_FRAMEWORK,
    GCP_INTERNAL_FRAMEWORK_VERSION,
    GCP_NETWORK_RESOURCE_TYPE,
    GCP_STORAGE_RESOURCE_TYPE,
)
from security_models import SecurityResource, SecurityScanStatus, SecuritySeverity
from security_scanner import SecurityComplianceScanner
from terraform_runner import TerraformRunner


class GcpSecurityRulePackTests(unittest.TestCase):
    @staticmethod
    def _resource(
        *,
        service: str,
        resource_type: str,
        resource_name: str,
        attributes: dict,
        cloud: str = "gcp",
    ) -> SecurityResource:
        return SecurityResource(
            cloud=cloud,
            service=service,
            resource_type=resource_type,
            resource_name=resource_name,
            resource_address=f"{resource_type}.{resource_name}",
            attributes=attributes,
        )

    def _synthetic_resources(self) -> list[SecurityResource]:
        return [
            self._resource(
                service="compute",
                resource_type=GCP_COMPUTE_RESOURCE_TYPE,
                resource_name="vm_private_secure",
                attributes={
                    "public_ip": False,
                    "shielded_vm": True,
                    "deletion_protection": True,
                },
            ),
            self._resource(
                service="compute",
                resource_type=GCP_COMPUTE_RESOURCE_TYPE,
                resource_name="vm_public_incomplete",
                attributes={
                    "public_ip": True,
                    "shielded_vm": False,
                },
            ),
            self._resource(
                service="network",
                resource_type=GCP_NETWORK_RESOURCE_TYPE,
                resource_name="firewall_open_ssh",
                attributes={
                    "direction": "INGRESS",
                    "source_ranges": ["0.0.0.0/0"],
                    "allowed_ports": [22],
                    "protocol": "tcp",
                    "all_ports": False,
                },
            ),
            self._resource(
                service="network",
                resource_type=GCP_NETWORK_RESOURCE_TYPE,
                resource_name="firewall_restricted",
                attributes={
                    "direction": "INGRESS",
                    "source_ranges": ["10.0.0.0/8"],
                    "allowed_ports": [22, 3389],
                    "protocol": "tcp",
                    "all_ports": True,
                },
            ),
            self._resource(
                service="storage",
                resource_type=GCP_STORAGE_RESOURCE_TYPE,
                resource_name="bucket_private",
                attributes={
                    "public_access": False,
                    "uniform_bucket_level_access": True,
                    "versioning_enabled": True,
                },
            ),
            self._resource(
                service="storage",
                resource_type=GCP_STORAGE_RESOURCE_TYPE,
                resource_name="bucket_public",
                attributes={
                    "public_access": True,
                    "uniform_bucket_level_access": False,
                    "versioning_enabled": False,
                },
            ),
            self._resource(
                service="iam",
                resource_type=GCP_IAM_RESOURCE_TYPE,
                resource_name="binding_owner",
                attributes={
                    "roles": ["roles/owner"],
                    "permissions": ["storage.objects.get"],
                    "members": ["serviceAccount:synthetic@example.invalid"],
                },
            ),
        ]

    @staticmethod
    def _catalog() -> SecurityRuleCatalog:
        catalog = SecurityRuleCatalog(
            catalog_name="gcp-internal-security-baseline",
            catalog_version="gcp-v1",
            description="Internal GCP security rules; not an official CIS catalog.",
        )
        catalog.register_many(build_gcp_security_rule_pack())
        return catalog

    def test_factory_returns_all_rules(self) -> None:
        self.assertTrue(build_gcp_security_rule_pack())

    def test_pack_contains_exactly_twelve_rules(self) -> None:
        self.assertEqual(len(build_gcp_security_rule_pack()), 12)

    def test_all_rule_ids_are_unique(self) -> None:
        rule_ids = [rule.metadata.rule_id for rule in build_gcp_security_rule_pack()]

        self.assertEqual(len(rule_ids), len(set(rule_ids)))

    def test_all_rules_are_gcp(self) -> None:
        self.assertTrue(
            all(
                rule.metadata.cloud == "gcp"
                for rule in build_gcp_security_rule_pack()
            )
        )

    def test_all_rules_use_internal_framework(self) -> None:
        self.assertEqual(
            {rule.metadata.framework for rule in build_gcp_security_rule_pack()},
            {GCP_INTERNAL_FRAMEWORK},
        )

    def test_all_rules_use_gcp_v1_framework_version(self) -> None:
        self.assertEqual(
            {
                rule.metadata.framework_version
                for rule in build_gcp_security_rule_pack()
            },
            {GCP_INTERNAL_FRAMEWORK_VERSION},
        )

    def test_no_official_cis_id_reference_or_text_is_serialised(self) -> None:
        for rule in build_gcp_security_rule_pack():
            with self.subTest(rule_id=rule.metadata.rule_id):
                self.assertTrue(rule.metadata.rule_id.startswith("GCP_INTERNAL_"))
                self.assertIsNone(rule.metadata.reference_id)
                self.assertIsNone(rule.metadata.reference_url)
                self.assertNotIn("cis", rule.metadata.to_json().casefold())

    def test_pack_order_is_rule_id_ascending(self) -> None:
        rule_ids = [rule.metadata.rule_id for rule in build_gcp_security_rule_pack()]

        self.assertEqual(rule_ids, sorted(rule_ids))

    def test_repeated_pack_builds_have_identical_metadata(self) -> None:
        first = [rule.metadata.to_dict() for rule in build_gcp_security_rule_pack()]
        second = [rule.metadata.to_dict() for rule in build_gcp_security_rule_pack()]

        self.assertEqual(first, second)

    def test_catalog_register_many_accepts_pack(self) -> None:
        self.assertEqual(len(self._catalog().rules), 12)

    def test_catalog_select_gcp_returns_twelve_enabled_rules(self) -> None:
        selected = self._catalog().select(cloud="gcp")

        self.assertEqual(len(selected), 12)
        self.assertTrue(all(rule.metadata.enabled for rule in selected))

    def test_catalog_select_network_returns_three_rules(self) -> None:
        selected = self._catalog().select(cloud="gcp", service="network")

        self.assertEqual(len(selected), 3)
        self.assertTrue(all(rule.metadata.service == "network" for rule in selected))

    def test_catalog_select_baseline_returns_all_rules(self) -> None:
        selected = self._catalog().select(cloud="gcp", profile="baseline")

        self.assertEqual(len(selected), 12)

    def test_scanner_executes_only_three_rules_per_resource_type(self) -> None:
        resources = [
            self._synthetic_resources()[0],
            self._synthetic_resources()[2],
            self._synthetic_resources()[4],
            self._synthetic_resources()[6],
        ]
        scanner = SecurityComplianceScanner(self._catalog().select(cloud="gcp"))

        result = scanner.scan("gcp", resources)

        self.assertEqual(result.total_rules_evaluated, 12)

    def test_gcp_pack_is_not_executed_on_oci(self) -> None:
        oci_resource = self._resource(
            cloud="oci",
            service="compute",
            resource_type="oci_core_instance",
            resource_name="oci_vm_test",
            attributes={"public_ip": True},
        )
        scanner = SecurityComplianceScanner(build_gcp_security_rule_pack())

        result = scanner.scan("oci", [oci_resource])

        self.assertEqual(result.total_rules_evaluated, 0)

    def test_synthetic_e2e_has_expected_mixed_result(self) -> None:
        selected = self._catalog().select(cloud="gcp", profile="baseline")
        scanner = SecurityComplianceScanner(selected)

        result = scanner.scan("gcp", self._synthetic_resources())

        self.assertEqual(result.total_rules_evaluated, 21)
        self.assertEqual(result.passed, 13)
        self.assertEqual(result.failed, 4)
        self.assertEqual(result.warnings, 3)
        self.assertEqual(result.skipped, 1)
        self.assertEqual(result.not_applicable, 0)
        self.assertEqual(result.severity_counts[SecuritySeverity.HIGH], 4)
        self.assertEqual(result.severity_counts[SecuritySeverity.MEDIUM], 3)
        self.assertIs(result.scan_status, SecurityScanStatus.FAIL)

    def test_synthetic_e2e_findings_are_deterministic(self) -> None:
        resources = self._synthetic_resources()
        first_scanner = SecurityComplianceScanner(build_gcp_security_rule_pack())
        second_scanner = SecurityComplianceScanner(build_gcp_security_rule_pack())

        first = first_scanner.scan("gcp", resources)
        second = second_scanner.scan("gcp", reversed(resources))

        self.assertEqual(first.to_json(), second.to_json())

    def test_sensitive_resource_values_never_reach_result(self) -> None:
        fake_secrets = ("FAKE_SECRET", "FAKE_TOKEN", "FAKE_KEY")
        resource = self._resource(
            service="compute",
            resource_type=GCP_COMPUTE_RESOURCE_TYPE,
            resource_name="vm_with_fake_secrets",
            attributes={
                "public_ip": False,
                "shielded_vm": True,
                "deletion_protection": True,
                "password": fake_secrets[0],
                "token": fake_secrets[1],
                "private_key": fake_secrets[2],
            },
        )
        result = SecurityComplianceScanner(build_gcp_security_rule_pack()).scan(
            "gcp",
            [resource],
        )
        payload = result.to_json()

        for fake_secret in fake_secrets:
            self.assertNotIn(fake_secret, payload)
        for finding in result.findings:
            for fake_secret in fake_secrets:
                self.assertNotIn(fake_secret, finding.message)
                self.assertNotIn(fake_secret, finding.recommendation)

    def test_pack_never_calls_terraform_or_subprocess(self) -> None:
        with (
            patch.object(TerraformRunner, "run") as terraform_run,
            patch.object(subprocess, "run") as process_run,
        ):
            rules = build_gcp_security_rule_pack()
            catalog = SecurityRuleCatalog()
            catalog.register_many(rules)
            catalog.select(cloud="gcp")

        terraform_run.assert_not_called()
        process_run.assert_not_called()

    def test_rule_module_has_no_gcp_sdk_or_environment_dependency(self) -> None:
        module_names = set(security_gcp_rules.__dict__)

        self.assertTrue(
            {
                "google",
                "google.auth",
                "google.cloud",
                "os",
                "subprocess",
            }.isdisjoint(module_names)
        )


if __name__ == "__main__":
    unittest.main()
