"""Tests unitaires des modeles generiques du scanner CIS-1."""

import json
import unittest

from security_models import (
    RuleStatus,
    SecurityFinding,
    SecurityResource,
    SecurityRuleMetadata,
    SecurityScanResult,
    SecurityScanStatus,
    SecuritySeverity,
    UnknownSecurityCloudError,
)


class SecurityModelsTests(unittest.TestCase):
    @staticmethod
    def _finding(
        *,
        status: RuleStatus = RuleStatus.PASS,
        severity: SecuritySeverity = SecuritySeverity.LOW,
    ) -> SecurityFinding:
        return SecurityFinding(
            rule_id="TEST_GCP_COMPUTE_001",
            cloud="gcp",
            resource_type="google_compute_instance",
            resource_name="vm_web_01",
            resource_address="google_compute_instance.vm_web_01",
            status=status,
            severity=severity,
            title="Synthetic test rule",
            message="Synthetic test result.",
            recommendation="Use a synthetic safe value.",
        )

    def test_security_severity_contains_the_five_levels(self) -> None:
        self.assertEqual(
            [severity.value for severity in SecuritySeverity],
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        )

    def test_security_severity_priority_is_stable(self) -> None:
        self.assertEqual(
            [severity.priority for severity in SecuritySeverity],
            [5, 4, 3, 2, 1],
        )

    def test_rule_status_pass_is_stable(self) -> None:
        self.assertEqual(RuleStatus.PASS.value, "PASS")

    def test_rule_status_fail_is_stable(self) -> None:
        self.assertEqual(RuleStatus.FAIL.value, "FAIL")

    def test_rule_status_warning_is_stable(self) -> None:
        self.assertEqual(RuleStatus.WARNING.value, "WARNING")

    def test_rule_status_not_applicable_is_stable(self) -> None:
        self.assertEqual(RuleStatus.NOT_APPLICABLE.value, "NOT_APPLICABLE")

    def test_gcp_security_resource_is_valid_and_normalised(self) -> None:
        resource = SecurityResource(
            cloud=" GCP ",
            service="COMPUTE",
            resource_type="google_compute_instance",
            resource_name="vm_web_01",
            resource_address="google_compute_instance.vm_web_01",
            attributes={"name": "vm-web-01"},
        )

        self.assertEqual(resource.cloud, "gcp")
        self.assertEqual(resource.service, "compute")
        self.assertEqual(resource.attributes["name"], "vm-web-01")

    def test_oci_security_resource_is_valid(self) -> None:
        resource = SecurityResource(
            cloud="oci",
            service="network",
            resource_type="oci_core_security_list",
            resource_name="web_security_list",
            resource_address="oci_core_security_list.web_security_list",
            attributes={"source": "10.0.0.0/8"},
        )

        self.assertEqual(resource.cloud, "oci")

    def test_unknown_cloud_is_rejected(self) -> None:
        with self.assertRaisesRegex(UnknownSecurityCloudError, "inconnu"):
            SecurityResource(
                cloud="azure",
                resource_type="virtual_machine",
                resource_name="vm",
                resource_address="virtual_machine.vm",
                attributes={},
            )

    def test_rule_metadata_is_serialisable_with_text_enum(self) -> None:
        metadata = SecurityRuleMetadata(
            rule_id="TEST_OCI_NETWORK_001",
            cloud="OCI",
            service="NETWORK",
            resource_type="oci_core_security_list",
            title="Synthetic OCI rule",
            description="Fixture only.",
            severity=SecuritySeverity.HIGH,
            recommendation="Restrict the synthetic source.",
        )

        payload = metadata.to_dict()
        self.assertEqual(payload["cloud"], "oci")
        self.assertEqual(payload["service"], "network")
        self.assertEqual(payload["severity"], "HIGH")

    def test_security_finding_is_serialisable(self) -> None:
        finding = self._finding(
            status=RuleStatus.FAIL,
            severity=SecuritySeverity.HIGH,
        )

        payload = json.loads(finding.to_json())
        self.assertEqual(payload["rule_id"], "TEST_GCP_COMPUTE_001")
        self.assertEqual(payload["status"], "FAIL")
        self.assertEqual(payload["severity"], "HIGH")

    def test_security_scan_result_is_serialisable(self) -> None:
        result = SecurityScanResult.build("gcp", [self._finding()])

        payload = json.loads(result.to_json())
        self.assertEqual(payload["total_rules_evaluated"], 1)
        self.assertEqual(payload["findings"][0]["status"], "PASS")
        self.assertEqual(payload["scan_status"], "PASS")

    def test_scan_result_to_dict_uses_text_enums(self) -> None:
        result = SecurityScanResult.build(
            "gcp",
            [
                self._finding(
                    status=RuleStatus.WARNING,
                    severity=SecuritySeverity.MEDIUM,
                )
            ],
        )

        payload = result.to_dict()
        self.assertEqual(payload["findings"][0]["status"], "WARNING")
        self.assertEqual(payload["findings"][0]["severity"], "MEDIUM")
        self.assertEqual(payload["severity_counts"]["MEDIUM"], 1)
        self.assertEqual(payload["scan_status"], "PASS_WITH_WARNINGS")
        self.assertIs(result.scan_status, SecurityScanStatus.PASS_WITH_WARNINGS)


if __name__ == "__main__":
    unittest.main()

