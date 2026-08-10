"""Tests du moteur CIS-1 avec des regles synthetiques non officielles."""

import json
import unittest
from unittest.mock import patch

from security_models import (
    RuleStatus,
    SecurityFinding,
    SecurityResource,
    SecurityRuleMetadata,
    SecurityScanStatus,
    SecuritySeverity,
    UnknownSecurityCloudError,
)
from security_rule import SecurityRule
from security_scanner import SecurityComplianceScanner
from terraform_runner import TerraformRunner


class _SyntheticRule(SecurityRule):
    """Fixture d'architecture; ce n'est pas une regle CIS officielle."""

    def __init__(
        self,
        metadata: SecurityRuleMetadata,
        status: RuleStatus,
        *,
        message: str = "Synthetic evaluation result.",
        failure: Exception | None = None,
    ) -> None:
        super().__init__(metadata)
        self.status = status
        self.message = message
        self.failure = failure
        self.evaluation_count = 0

    def evaluate(self, resource: SecurityResource) -> SecurityFinding:
        self.evaluation_count += 1
        if self.failure is not None:
            raise self.failure
        return SecurityFinding(
            rule_id=self.metadata.rule_id,
            cloud=resource.cloud,
            resource_type=resource.resource_type,
            resource_name=resource.resource_name,
            resource_address=resource.resource_address,
            status=self.status,
            severity=self.metadata.severity,
            title=self.metadata.title,
            message=self.message,
            recommendation=self.metadata.recommendation,
        )


class SecurityComplianceScannerTests(unittest.TestCase):
    @staticmethod
    def _metadata(
        *,
        rule_id: str = "TEST_GCP_COMPUTE_001",
        cloud: str = "gcp",
        service: str = "compute",
        resource_type: str = "google_compute_instance",
        severity: SecuritySeverity = SecuritySeverity.LOW,
        recommendation: str = "Use a safe synthetic configuration.",
    ) -> SecurityRuleMetadata:
        return SecurityRuleMetadata(
            rule_id=rule_id,
            cloud=cloud,
            service=service,
            resource_type=resource_type,
            title=f"Synthetic rule {rule_id}",
            description="Test fixture only; not an official CIS control.",
            severity=severity,
            recommendation=recommendation,
        )

    @staticmethod
    def _resource(
        *,
        cloud: str = "gcp",
        service: str = "compute",
        resource_type: str = "google_compute_instance",
        resource_name: str = "vm_web_01",
        resource_address: str = "google_compute_instance.vm_web_01",
        attributes: dict | None = None,
    ) -> SecurityResource:
        return SecurityResource(
            cloud=cloud,
            service=service,
            resource_type=resource_type,
            resource_name=resource_name,
            resource_address=resource_address,
            attributes=attributes or {"synthetic": True},
        )

    def _scan_one(
        self,
        status: RuleStatus,
        severity: SecuritySeverity = SecuritySeverity.LOW,
    ):
        rule = _SyntheticRule(
            self._metadata(severity=severity),
            status,
        )
        return SecurityComplianceScanner([rule]).scan(
            "gcp",
            [self._resource()],
        )

    def test_scanner_without_rules_returns_stable_pass(self) -> None:
        result = SecurityComplianceScanner([]).scan(
            "gcp",
            [self._resource()],
        )

        self.assertEqual(result.total_rules_evaluated, 0)
        self.assertEqual(result.findings, ())
        self.assertEqual(
            result.to_dict()["severity_counts"],
            {severity.value: 0 for severity in SecuritySeverity},
        )
        self.assertIs(result.scan_status, SecurityScanStatus.PASS)

    def test_pass_rule_increments_passed(self) -> None:
        result = self._scan_one(RuleStatus.PASS)

        self.assertEqual(result.passed, 1)
        self.assertEqual(result.failed, 0)

    def test_fail_high_increments_failure_and_severity(self) -> None:
        result = self._scan_one(RuleStatus.FAIL, SecuritySeverity.HIGH)

        self.assertEqual(result.failed, 1)
        self.assertEqual(result.severity_counts[SecuritySeverity.HIGH], 1)

    def test_warning_medium_increments_warning_and_severity(self) -> None:
        result = self._scan_one(RuleStatus.WARNING, SecuritySeverity.MEDIUM)

        self.assertEqual(result.warnings, 1)
        self.assertEqual(result.severity_counts[SecuritySeverity.MEDIUM], 1)

    def test_not_applicable_is_counted_without_failure(self) -> None:
        result = self._scan_one(RuleStatus.NOT_APPLICABLE)

        self.assertEqual(result.not_applicable, 1)
        self.assertEqual(result.failed, 0)
        self.assertIs(result.scan_status, SecurityScanStatus.PASS)

    def test_gcp_rule_is_not_executed_on_oci(self) -> None:
        rule = _SyntheticRule(self._metadata(), RuleStatus.FAIL)
        oci_resource = self._resource(
            cloud="oci",
            resource_type="oci_core_instance",
            resource_address="oci_core_instance.vm_web_01",
        )

        result = SecurityComplianceScanner([rule]).scan("oci", [oci_resource])

        self.assertEqual(result.total_rules_evaluated, 0)
        self.assertEqual(rule.evaluation_count, 0)

    def test_network_rule_is_not_executed_on_compute_resource(self) -> None:
        rule = _SyntheticRule(
            self._metadata(
                rule_id="TEST_GCP_NETWORK_001",
                service="network",
                resource_type="google_compute_firewall",
            ),
            RuleStatus.FAIL,
        )

        result = SecurityComplianceScanner([rule]).scan(
            "gcp",
            [self._resource()],
        )

        self.assertEqual(result.total_rules_evaluated, 0)
        self.assertEqual(rule.evaluation_count, 0)

    def test_service_scope_is_filtered_when_resource_exposes_service(self) -> None:
        rule = _SyntheticRule(
            self._metadata(service="network"),
            RuleStatus.FAIL,
        )

        result = SecurityComplianceScanner([rule]).scan(
            "gcp",
            [self._resource(service="compute")],
        )

        self.assertEqual(result.total_rules_evaluated, 0)

    def test_multiple_resources_are_evaluated(self) -> None:
        rule = _SyntheticRule(self._metadata(), RuleStatus.PASS)
        resources = [
            self._resource(),
            self._resource(
                resource_name="vm_batch_01",
                resource_address="google_compute_instance.vm_batch_01",
            ),
        ]

        result = SecurityComplianceScanner([rule]).scan("gcp", resources)

        self.assertEqual(result.total_rules_evaluated, 2)
        self.assertEqual(result.passed, 2)
        self.assertEqual(rule.evaluation_count, 2)

    def test_multiple_rules_are_evaluated(self) -> None:
        rules = [
            _SyntheticRule(
                self._metadata(rule_id="TEST_GCP_COMPUTE_002"),
                RuleStatus.PASS,
            ),
            _SyntheticRule(
                self._metadata(rule_id="TEST_GCP_COMPUTE_001"),
                RuleStatus.WARNING,
            ),
        ]

        result = SecurityComplianceScanner(rules).scan(
            "gcp",
            [self._resource()],
        )

        self.assertEqual(result.total_rules_evaluated, 2)
        self.assertEqual(result.passed, 1)
        self.assertEqual(result.warnings, 1)

    def test_findings_use_stable_severity_rule_and_address_sort(self) -> None:
        high_rule = _SyntheticRule(
            self._metadata(
                rule_id="TEST_GCP_COMPUTE_020",
                severity=SecuritySeverity.HIGH,
            ),
            RuleStatus.FAIL,
        )
        low_rule = _SyntheticRule(
            self._metadata(
                rule_id="TEST_GCP_COMPUTE_010",
                severity=SecuritySeverity.LOW,
            ),
            RuleStatus.FAIL,
        )
        resources = [
            self._resource(
                resource_name="zeta",
                resource_address="google_compute_instance.zeta",
            ),
            self._resource(
                resource_name="alpha",
                resource_address="google_compute_instance.alpha",
            ),
        ]

        result = SecurityComplianceScanner([low_rule, high_rule]).scan(
            "gcp",
            resources,
        )

        self.assertEqual(
            [
                (finding.severity, finding.rule_id, finding.resource_address)
                for finding in result.findings
            ],
            [
                (
                    SecuritySeverity.HIGH,
                    "TEST_GCP_COMPUTE_020",
                    "google_compute_instance.alpha",
                ),
                (
                    SecuritySeverity.HIGH,
                    "TEST_GCP_COMPUTE_020",
                    "google_compute_instance.zeta",
                ),
                (
                    SecuritySeverity.LOW,
                    "TEST_GCP_COMPUTE_010",
                    "google_compute_instance.alpha",
                ),
                (
                    SecuritySeverity.LOW,
                    "TEST_GCP_COMPUTE_010",
                    "google_compute_instance.zeta",
                ),
            ],
        )

    def test_reversed_inputs_produce_identical_serialisation(self) -> None:
        rules = [
            _SyntheticRule(
                self._metadata(rule_id="TEST_GCP_COMPUTE_002"),
                RuleStatus.PASS,
            ),
            _SyntheticRule(
                self._metadata(rule_id="TEST_GCP_COMPUTE_001"),
                RuleStatus.FAIL,
            ),
        ]
        resources = [
            self._resource(),
            self._resource(
                resource_name="vm_batch_01",
                resource_address="google_compute_instance.vm_batch_01",
            ),
        ]

        first = SecurityComplianceScanner(rules).scan("gcp", resources)
        second = SecurityComplianceScanner(reversed(rules)).scan(
            "gcp", reversed(resources)
        )

        self.assertEqual(first.to_json(), second.to_json())

    def test_rule_exception_is_sanitised_and_skipped(self) -> None:
        rule = _SyntheticRule(
            self._metadata(),
            RuleStatus.FAIL,
            failure=RuntimeError("sensitive stack detail"),
        )

        with self.assertLogs("security_scanner", level="WARNING"):
            result = SecurityComplianceScanner([rule]).scan(
                "gcp",
                [self._resource()],
            )

        self.assertEqual(result.skipped, 1)
        self.assertEqual(result.findings[0].status, RuleStatus.SKIPPED)
        self.assertEqual(result.findings[0].message, "Rule evaluation failed.")
        self.assertNotIn("sensitive stack detail", result.to_json())

    def test_fake_secrets_are_not_propagated_to_scan_result(self) -> None:
        fake_password = "fake-password-sensitive-value"
        fake_token = "fake-token-sensitive-value"
        rule = _SyntheticRule(
            self._metadata(),
            RuleStatus.FAIL,
            failure=RuntimeError(fake_token),
        )
        resource = self._resource(attributes={"password": fake_password})

        with self.assertLogs("security_scanner", level="WARNING"):
            payload = SecurityComplianceScanner([rule]).scan(
                "gcp",
                [resource],
            ).to_json()

        self.assertNotIn(fake_password, payload)
        self.assertNotIn(fake_token, payload)

    def test_rule_cannot_copy_sensitive_attribute_into_finding(self) -> None:
        fake_secret = "fake-private-key-sensitive-value"
        rule = _SyntheticRule(
            self._metadata(),
            RuleStatus.FAIL,
            message=f"Leaked value: {fake_secret}",
        )
        resource = self._resource(
            attributes={"connection": {"private_key": fake_secret}}
        )

        with self.assertLogs("security_scanner", level="WARNING"):
            result = SecurityComplianceScanner([rule]).scan("gcp", [resource])

        self.assertEqual(result.skipped, 1)
        self.assertNotIn(fake_secret, result.to_json())

    def test_scan_status_is_pass(self) -> None:
        self.assertIs(
            self._scan_one(RuleStatus.PASS).scan_status,
            SecurityScanStatus.PASS,
        )

    def test_scan_status_is_pass_with_warnings(self) -> None:
        self.assertIs(
            self._scan_one(RuleStatus.WARNING).scan_status,
            SecurityScanStatus.PASS_WITH_WARNINGS,
        )

    def test_scan_status_is_fail(self) -> None:
        self.assertIs(
            self._scan_one(RuleStatus.FAIL).scan_status,
            SecurityScanStatus.FAIL,
        )

    def test_rule_id_is_preserved(self) -> None:
        result = self._scan_one(RuleStatus.PASS)

        self.assertEqual(result.findings[0].rule_id, "TEST_GCP_COMPUTE_001")

    def test_recommendation_is_preserved(self) -> None:
        recommendation = "Restrict the synthetic configuration."
        rule = _SyntheticRule(
            self._metadata(recommendation=recommendation),
            RuleStatus.FAIL,
        )

        result = SecurityComplianceScanner([rule]).scan(
            "gcp", [self._resource()]
        )

        self.assertEqual(result.findings[0].recommendation, recommendation)

    def test_resource_address_is_preserved(self) -> None:
        result = self._scan_one(RuleStatus.PASS)

        self.assertEqual(
            result.findings[0].resource_address,
            "google_compute_instance.vm_web_01",
        )

    def test_unknown_scan_cloud_is_rejected_before_evaluation(self) -> None:
        rule = _SyntheticRule(self._metadata(), RuleStatus.PASS)

        with self.assertRaises(UnknownSecurityCloudError):
            SecurityComplianceScanner([rule]).scan(
                "azure",
                [self._resource()],
            )

        self.assertEqual(rule.evaluation_count, 0)

    def test_scanner_never_calls_terraform_runner(self) -> None:
        with patch.object(TerraformRunner, "run") as terraform_run:
            result = self._scan_one(RuleStatus.PASS)

        terraform_run.assert_not_called()
        self.assertEqual(result.passed, 1)

    def test_output_is_json_serialisable(self) -> None:
        payload = json.loads(self._scan_one(RuleStatus.PASS).to_json())

        self.assertEqual(payload["cloud"], "gcp")


if __name__ == "__main__":
    unittest.main()
