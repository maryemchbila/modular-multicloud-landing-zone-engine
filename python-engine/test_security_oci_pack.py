"""Tests du pack, du catalogue et du scan synthetique OCI CIS-4."""

import subprocess
import unittest
from unittest.mock import patch

import security_oci_rules
from security_catalog import SecurityRuleCatalog
from security_gcp_pack import build_gcp_security_rule_pack
from security_gcp_rules import GCP_COMPUTE_RESOURCE_TYPE
from security_models import SecurityResource, SecurityScanStatus, SecuritySeverity
from security_oci_pack import build_oci_security_rule_pack
from security_oci_rules import (
    OCI_COMPUTE_RESOURCE_TYPE,
    OCI_IAM_RESOURCE_TYPE,
    OCI_INTERNAL_FRAMEWORK,
    OCI_INTERNAL_FRAMEWORK_VERSION,
    OCI_NETWORK_RESOURCE_TYPE,
    OCI_STORAGE_RESOURCE_TYPE,
)
from security_scanner import SecurityComplianceScanner
from terraform_runner import TerraformRunner


class OciSecurityRulePackTests(unittest.TestCase):
    @staticmethod
    def _resource(
        *,
        service: str,
        resource_type: str,
        resource_name: str,
        attributes: dict,
        cloud: str = "oci",
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
                resource_type=OCI_COMPUTE_RESOURCE_TYPE,
                resource_name="oci_vm_private_secure",
                attributes={
                    "public_ip": False,
                    "secure_boot": True,
                    "in_transit_encryption": True,
                },
            ),
            self._resource(
                service="compute",
                resource_type=OCI_COMPUTE_RESOURCE_TYPE,
                resource_name="oci_vm_public_incomplete",
                attributes={
                    "public_ip": True,
                    "secure_boot": False,
                },
            ),
            self._resource(
                service="network",
                resource_type=OCI_NETWORK_RESOURCE_TYPE,
                resource_name="security_list_open_ssh",
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
                resource_type=OCI_NETWORK_RESOURCE_TYPE,
                resource_name="security_list_restricted",
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
                resource_type=OCI_STORAGE_RESOURCE_TYPE,
                resource_name="oci_bucket_private",
                attributes={
                    "public_access": False,
                    "versioning_enabled": True,
                    "customer_managed_key": True,
                },
            ),
            self._resource(
                service="storage",
                resource_type=OCI_STORAGE_RESOURCE_TYPE,
                resource_name="oci_bucket_public",
                attributes={
                    "public_access": True,
                    "versioning_enabled": False,
                    "customer_managed_key": False,
                },
            ),
            self._resource(
                service="iam",
                resource_type=OCI_IAM_RESOURCE_TYPE,
                resource_name="oci_policy_manage_all",
                attributes={
                    "statements": ["manage all-resources"],
                    "permissions": ["objectstorage-namespaces-read"],
                    "subjects": ["group:synthetic-admins"],
                    "broad_subject": False,
                },
            ),
        ]

    @staticmethod
    def _oci_catalog() -> SecurityRuleCatalog:
        catalog = SecurityRuleCatalog(
            catalog_name="oci-internal-security-baseline",
            catalog_version="oci-v1",
            description="Internal OCI security rules; not an official CIS catalog.",
        )
        catalog.register_many(build_oci_security_rule_pack())
        return catalog

    @staticmethod
    def _combined_catalog() -> SecurityRuleCatalog:
        catalog = SecurityRuleCatalog(
            catalog_name="multi-cloud-internal-security-baseline",
            catalog_version="1.0",
        )
        catalog.register_many(
            build_gcp_security_rule_pack() + build_oci_security_rule_pack()
        )
        return catalog

    def test_factory_returns_all_rules(self) -> None:
        self.assertTrue(build_oci_security_rule_pack())

    def test_pack_contains_exactly_twelve_rules(self) -> None:
        self.assertEqual(len(build_oci_security_rule_pack()), 12)

    def test_all_rule_ids_are_unique(self) -> None:
        rule_ids = [rule.metadata.rule_id for rule in build_oci_security_rule_pack()]

        self.assertEqual(len(rule_ids), len(set(rule_ids)))

    def test_all_rules_are_oci(self) -> None:
        self.assertTrue(
            all(
                rule.metadata.cloud == "oci"
                for rule in build_oci_security_rule_pack()
            )
        )

    def test_all_rules_use_internal_framework(self) -> None:
        self.assertEqual(
            {rule.metadata.framework for rule in build_oci_security_rule_pack()},
            {OCI_INTERNAL_FRAMEWORK},
        )

    def test_all_rules_use_oci_v1_framework_version(self) -> None:
        self.assertEqual(
            {
                rule.metadata.framework_version
                for rule in build_oci_security_rule_pack()
            },
            {OCI_INTERNAL_FRAMEWORK_VERSION},
        )

    def test_no_official_cis_id_reference_or_text_is_serialised(self) -> None:
        for rule in build_oci_security_rule_pack():
            with self.subTest(rule_id=rule.metadata.rule_id):
                self.assertTrue(rule.metadata.rule_id.startswith("OCI_INTERNAL_"))
                self.assertIsNone(rule.metadata.reference_id)
                self.assertIsNone(rule.metadata.reference_url)
                self.assertNotIn("cis", rule.metadata.to_json().casefold())

    def test_pack_order_is_rule_id_ascending(self) -> None:
        rule_ids = [rule.metadata.rule_id for rule in build_oci_security_rule_pack()]

        self.assertEqual(rule_ids, sorted(rule_ids))

    def test_repeated_pack_builds_have_identical_metadata(self) -> None:
        first = [rule.metadata.to_dict() for rule in build_oci_security_rule_pack()]
        second = [rule.metadata.to_dict() for rule in build_oci_security_rule_pack()]

        self.assertEqual(first, second)

    def test_catalog_register_many_accepts_pack(self) -> None:
        self.assertEqual(len(self._oci_catalog().rules), 12)

    def test_catalog_select_oci_returns_twelve_enabled_rules(self) -> None:
        selected = self._oci_catalog().select(cloud="oci")

        self.assertEqual(len(selected), 12)
        self.assertTrue(all(rule.metadata.enabled for rule in selected))

    def test_catalog_select_network_returns_three_rules(self) -> None:
        selected = self._oci_catalog().select(cloud="oci", service="network")

        self.assertEqual(len(selected), 3)

    def test_catalog_select_compute_returns_three_rules(self) -> None:
        selected = self._oci_catalog().select(cloud="oci", service="compute")

        self.assertEqual(len(selected), 3)

    def test_catalog_select_storage_returns_three_rules(self) -> None:
        selected = self._oci_catalog().select(cloud="oci", service="storage")

        self.assertEqual(len(selected), 3)

    def test_catalog_select_iam_returns_three_rules(self) -> None:
        selected = self._oci_catalog().select(cloud="oci", service="iam")

        self.assertEqual(len(selected), 3)

    def test_catalog_select_baseline_returns_all_rules(self) -> None:
        selected = self._oci_catalog().select(cloud="oci", profile="baseline")

        self.assertEqual(len(selected), 12)

    def test_scanner_executes_only_three_rules_per_resource_type(self) -> None:
        resources = [
            self._synthetic_resources()[0],
            self._synthetic_resources()[2],
            self._synthetic_resources()[4],
            self._synthetic_resources()[6],
        ]
        scanner = SecurityComplianceScanner(self._oci_catalog().select(cloud="oci"))

        result = scanner.scan("oci", resources)

        self.assertEqual(result.total_rules_evaluated, 12)

    def test_oci_pack_is_not_executed_on_gcp(self) -> None:
        gcp_resource = self._resource(
            cloud="gcp",
            service="compute",
            resource_type=GCP_COMPUTE_RESOURCE_TYPE,
            resource_name="gcp_vm_test",
            attributes={"public_ip": True},
        )
        scanner = SecurityComplianceScanner(build_oci_security_rule_pack())

        result = scanner.scan("gcp", [gcp_resource])

        self.assertEqual(result.total_rules_evaluated, 0)

    def test_synthetic_oci_e2e_has_expected_mixed_result(self) -> None:
        selected = self._oci_catalog().select(cloud="oci", profile="baseline")
        scanner = SecurityComplianceScanner(selected)

        result = scanner.scan("oci", self._synthetic_resources())

        self.assertEqual(result.total_rules_evaluated, 21)
        self.assertEqual(result.passed, 13)
        self.assertEqual(result.failed, 4)
        self.assertEqual(result.warnings, 3)
        self.assertEqual(result.skipped, 1)
        self.assertEqual(result.not_applicable, 0)
        self.assertEqual(result.severity_counts[SecuritySeverity.HIGH], 4)
        self.assertEqual(result.severity_counts[SecuritySeverity.MEDIUM], 3)
        self.assertIs(result.scan_status, SecurityScanStatus.FAIL)

    def test_synthetic_oci_e2e_findings_are_deterministic(self) -> None:
        resources = self._synthetic_resources()
        first_scanner = SecurityComplianceScanner(build_oci_security_rule_pack())
        second_scanner = SecurityComplianceScanner(build_oci_security_rule_pack())

        first = first_scanner.scan("oci", resources)
        second = second_scanner.scan("oci", reversed(resources))

        self.assertEqual(first.to_json(), second.to_json())

    def test_combined_catalog_contains_both_packs(self) -> None:
        catalog = self._combined_catalog()

        self.assertEqual(len(catalog.rules), 24)
        self.assertEqual(len(catalog.select(cloud="gcp")), 12)
        self.assertEqual(len(catalog.select(cloud="oci")), 12)

    def test_combined_catalog_cloud_separation_reaches_scanners(self) -> None:
        catalog = self._combined_catalog()
        gcp_resource = self._resource(
            cloud="gcp",
            service="compute",
            resource_type=GCP_COMPUTE_RESOURCE_TYPE,
            resource_name="gcp_vm_private",
            attributes={
                "public_ip": False,
                "shielded_vm": True,
                "deletion_protection": True,
            },
        )
        oci_resource = self._synthetic_resources()[0]

        gcp_result = SecurityComplianceScanner(
            catalog.select(cloud="gcp")
        ).scan("gcp", [gcp_resource, oci_resource])
        oci_result = SecurityComplianceScanner(
            catalog.select(cloud="oci")
        ).scan("oci", [gcp_resource, oci_resource])

        self.assertEqual(gcp_result.total_rules_evaluated, 3)
        self.assertTrue(
            all(finding.rule_id.startswith("GCP_INTERNAL_") for finding in gcp_result.findings)
        )
        self.assertEqual(oci_result.total_rules_evaluated, 3)
        self.assertTrue(
            all(finding.rule_id.startswith("OCI_INTERNAL_") for finding in oci_result.findings)
        )

    def test_sensitive_resource_values_never_reach_result(self) -> None:
        fake_secrets = ("FAKE_PASSWORD", "FAKE_TOKEN", "FAKE_PRIVATE_KEY")
        resource = self._resource(
            service="compute",
            resource_type=OCI_COMPUTE_RESOURCE_TYPE,
            resource_name="oci_vm_with_fake_secrets",
            attributes={
                "public_ip": False,
                "secure_boot": True,
                "in_transit_encryption": True,
                "password": fake_secrets[0],
                "token": fake_secrets[1],
                "private_key": fake_secrets[2],
            },
        )
        result = SecurityComplianceScanner(build_oci_security_rule_pack()).scan(
            "oci",
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
            rules = build_oci_security_rule_pack()
            catalog = SecurityRuleCatalog()
            catalog.register_many(rules)
            catalog.select(cloud="oci")

        terraform_run.assert_not_called()
        process_run.assert_not_called()

    def test_rule_module_has_no_oci_sdk_or_environment_dependency(self) -> None:
        module_names = set(security_oci_rules.__dict__)

        self.assertTrue(
            {"oci", "os", "subprocess"}.isdisjoint(module_names)
        )


if __name__ == "__main__":
    unittest.main()
