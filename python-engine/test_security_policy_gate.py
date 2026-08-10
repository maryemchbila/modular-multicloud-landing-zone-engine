"""Tests de decision pure du Security Policy Gate POLICY-1."""

import json
import subprocess
import unittest
from dataclasses import replace
from unittest.mock import patch

from security_evaluation import MultiCloudSecurityEvaluationResult
from security_models import (
    RuleStatus,
    SecurityFinding,
    SecurityScanResult,
    SecuritySeverity,
)
from security_policy_gate import (
    SecurityPolicyGate,
    build_default_security_policy_gate,
)
from security_policy_models import (
    PolicyDecisionStatus,
    PolicyReasonCode,
    SecurityPolicyDisabledError,
    build_default_security_policy,
)
from terraform_runner import TerraformRunner


class SecurityPolicyGateTests(unittest.TestCase):
    @staticmethod
    def _finding(
        *,
        rule_id: str = "GCP_INTERNAL_NETWORK_001",
        cloud: str = "gcp",
        status: RuleStatus = RuleStatus.PASS,
        severity: SecuritySeverity = SecuritySeverity.LOW,
        address: str | None = None,
        message: str = "Synthetic policy fixture.",
        recommendation: str = "Use safe synthetic configuration.",
    ) -> SecurityFinding:
        return SecurityFinding(
            rule_id=rule_id,
            cloud=cloud,
            resource_type=(
                "google_compute_firewall"
                if cloud == "gcp"
                else "oci_core_security_list"
            ),
            resource_name="policy_fixture",
            resource_address=address or f"{cloud}_resource.policy_fixture",
            status=status,
            severity=severity,
            title="Synthetic internal policy finding",
            message=message,
            recommendation=recommendation,
        )

    @classmethod
    def _result(
        cls,
        *findings: SecurityFinding,
        resources_total: int = 1,
    ) -> MultiCloudSecurityEvaluationResult:
        cloud_results = {}
        for cloud in ("gcp", "oci"):
            cloud_findings = tuple(
                finding for finding in findings if finding.cloud == cloud
            )
            if cloud_findings:
                cloud_results[cloud] = SecurityScanResult.build(
                    cloud, cloud_findings
                )
        return MultiCloudSecurityEvaluationResult(
            cloud_results=cloud_results,
            resources_total=resources_total,
        )

    @staticmethod
    def _evaluate(result: MultiCloudSecurityEvaluationResult):
        return build_default_security_policy_gate().evaluate(result)

    def test_pass_findings_allow(self) -> None:
        decision = self._evaluate(self._result(self._finding()))
        self.assertIs(decision.decision, PolicyDecisionStatus.ALLOW)
        self.assertIs(decision.reason_code, PolicyReasonCode.ALLOW_BASELINE_MET)
        self.assertTrue(decision.deployment_allowed)
        self.assertFalse(decision.requires_human_approval)

    def test_medium_warning_allows_with_default_baseline(self) -> None:
        decision = self._evaluate(
            self._result(
                self._finding(
                    status=RuleStatus.WARNING,
                    severity=SecuritySeverity.MEDIUM,
                )
            )
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.ALLOW)
        self.assertEqual(decision.severity_summary["MEDIUM"], 1)

    def test_low_and_info_issues_allow(self) -> None:
        decision = self._evaluate(
            self._result(
                self._finding(
                    rule_id="GCP_INTERNAL_STORAGE_001",
                    status=RuleStatus.FAIL,
                    severity=SecuritySeverity.LOW,
                ),
                self._finding(
                    rule_id="GCP_INTERNAL_IAM_001",
                    status=RuleStatus.WARNING,
                    severity=SecuritySeverity.INFO,
                ),
            )
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.ALLOW)

    def test_high_failure_requires_approval(self) -> None:
        decision = self._evaluate(
            self._result(
                self._finding(
                    status=RuleStatus.FAIL,
                    severity=SecuritySeverity.HIGH,
                )
            )
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)
        self.assertIs(decision.reason_code, PolicyReasonCode.APPROVAL_REQUIRED)
        self.assertTrue(decision.requires_human_approval)
        self.assertFalse(decision.deployment_allowed)

    def test_medium_failure_reaching_threshold_requires_approval(self) -> None:
        decision = self._evaluate(
            self._result(
                self._finding(
                    status=RuleStatus.FAIL,
                    severity=SecuritySeverity.MEDIUM,
                )
            )
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)

    def test_critical_failure_blocks(self) -> None:
        decision = self._evaluate(
            self._result(
                self._finding(
                    status=RuleStatus.FAIL,
                    severity=SecuritySeverity.CRITICAL,
                )
            )
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.BLOCK)
        self.assertIs(
            decision.reason_code,
            PolicyReasonCode.BLOCK_CRITICAL_FINDING,
        )
        self.assertFalse(decision.requires_human_approval)
        self.assertFalse(decision.deployment_allowed)

    def test_multiple_critical_failures_block(self) -> None:
        decision = self._evaluate(
            self._result(
                self._finding(
                    rule_id="GCP_INTERNAL_COMPUTE_001",
                    status=RuleStatus.FAIL,
                    severity=SecuritySeverity.CRITICAL,
                ),
                self._finding(
                    rule_id="GCP_INTERNAL_NETWORK_001",
                    status=RuleStatus.FAIL,
                    severity=SecuritySeverity.CRITICAL,
                ),
            )
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.BLOCK)
        self.assertEqual(len(decision.triggered_findings), 2)

    def test_critical_wins_over_high_and_only_critical_rule_triggers(self) -> None:
        decision = self._evaluate(
            self._result(
                self._finding(
                    rule_id="GCP_INTERNAL_NETWORK_001",
                    status=RuleStatus.FAIL,
                    severity=SecuritySeverity.HIGH,
                ),
                self._finding(
                    rule_id="OCI_INTERNAL_COMPUTE_001",
                    cloud="oci",
                    status=RuleStatus.FAIL,
                    severity=SecuritySeverity.CRITICAL,
                ),
            )
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.BLOCK)
        self.assertEqual(decision.triggered_rules, ("OCI_INTERNAL_COMPUTE_001",))
        self.assertEqual(decision.severity_summary["CRITICAL"], 1)
        self.assertEqual(decision.severity_summary["HIGH"], 1)

    def test_zero_resources_requires_approval(self) -> None:
        decision = self._evaluate(self._result(resources_total=0))
        self.assertIs(decision.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)
        self.assertIs(
            decision.reason_code,
            PolicyReasonCode.INSUFFICIENT_SECURITY_DATA,
        )

    def test_zero_findings_requires_approval(self) -> None:
        decision = self._evaluate(self._result(resources_total=2))
        self.assertIs(decision.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)

    def test_all_skipped_requires_approval_without_treating_it_as_failure(self) -> None:
        decision = self._evaluate(
            self._result(
                self._finding(
                    status=RuleStatus.SKIPPED,
                    severity=SecuritySeverity.CRITICAL,
                )
            )
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)
        self.assertIs(
            decision.reason_code,
            PolicyReasonCode.INSUFFICIENT_SECURITY_DATA,
        )
        self.assertEqual(decision.severity_summary["CRITICAL"], 0)

    def test_pass_plus_skipped_can_allow_for_default_policy(self) -> None:
        decision = self._evaluate(
            self._result(
                self._finding(),
                self._finding(
                    rule_id="GCP_INTERNAL_NETWORK_002",
                    status=RuleStatus.SKIPPED,
                    severity=SecuritySeverity.CRITICAL,
                ),
            )
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.ALLOW)

    def test_complete_evaluation_policy_rejects_any_skipped_finding(self) -> None:
        policy = replace(
            build_default_security_policy(),
            require_complete_security_evaluation=True,
        )
        result = self._result(
            self._finding(),
            self._finding(
                rule_id="GCP_INTERNAL_NETWORK_002",
                status=RuleStatus.SKIPPED,
            ),
        )
        decision = SecurityPolicyGate(policy).evaluate(result)
        self.assertIs(decision.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)
        self.assertIs(
            decision.reason_code,
            PolicyReasonCode.INSUFFICIENT_SECURITY_DATA,
        )

    def test_known_critical_block_wins_when_evaluation_is_incomplete(self) -> None:
        policy = replace(
            build_default_security_policy(),
            require_complete_security_evaluation=True,
        )
        result = self._result(
            self._finding(
                rule_id="GCP_INTERNAL_COMPUTE_001",
                status=RuleStatus.FAIL,
                severity=SecuritySeverity.CRITICAL,
            ),
            self._finding(
                rule_id="GCP_INTERNAL_NETWORK_002",
                status=RuleStatus.SKIPPED,
            ),
        )
        decision = SecurityPolicyGate(policy).evaluate(result)
        self.assertIs(decision.decision, PolicyDecisionStatus.BLOCK)
        self.assertIs(
            decision.reason_code,
            PolicyReasonCode.BLOCK_CRITICAL_FINDING,
        )

    def test_high_threshold_is_configurable(self) -> None:
        policy = replace(build_default_security_policy(), high_fail_threshold=2)
        decision = SecurityPolicyGate(policy).evaluate(
            self._result(
                self._finding(
                    status=RuleStatus.FAIL,
                    severity=SecuritySeverity.HIGH,
                )
            )
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.ALLOW)

    def test_high_threshold_can_block_by_policy_configuration(self) -> None:
        policy = replace(build_default_security_policy(), approval_on_high=False)
        decision = SecurityPolicyGate(policy).evaluate(
            self._result(
                self._finding(
                    status=RuleStatus.FAIL,
                    severity=SecuritySeverity.HIGH,
                )
            )
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.BLOCK)
        self.assertIs(
            decision.reason_code,
            PolicyReasonCode.BLOCK_THRESHOLD_EXCEEDED,
        )

    def test_critical_can_require_approval_by_policy_configuration(self) -> None:
        policy = replace(build_default_security_policy(), block_on_critical=False)
        decision = SecurityPolicyGate(policy).evaluate(
            self._result(
                self._finding(
                    status=RuleStatus.FAIL,
                    severity=SecuritySeverity.CRITICAL,
                )
            )
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)

    def test_disabled_policy_fails_closed_with_business_error(self) -> None:
        policy = replace(build_default_security_policy(), enabled=False)
        with self.assertRaises(SecurityPolicyDisabledError):
            SecurityPolicyGate(policy).evaluate(self._result(self._finding()))

    def test_gate_requires_existing_multicloud_result(self) -> None:
        with self.assertRaisesRegex(TypeError, "MultiCloudSecurityEvaluationResult"):
            build_default_security_policy_gate().evaluate(object())

    def test_secure_gcp_and_oci_allow(self) -> None:
        decision = self._evaluate(
            self._result(
                self._finding(),
                self._finding(
                    rule_id="OCI_INTERNAL_NETWORK_001",
                    cloud="oci",
                ),
                resources_total=2,
            )
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.ALLOW)

    def test_gcp_high_and_secure_oci_require_approval(self) -> None:
        decision = self._evaluate(
            self._result(
                self._finding(
                    status=RuleStatus.FAIL,
                    severity=SecuritySeverity.HIGH,
                ),
                self._finding(
                    rule_id="OCI_INTERNAL_NETWORK_001",
                    cloud="oci",
                ),
                resources_total=2,
            )
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)

    def test_secure_gcp_and_oci_critical_block(self) -> None:
        decision = self._evaluate(
            self._result(
                self._finding(),
                self._finding(
                    rule_id="OCI_INTERNAL_NETWORK_001",
                    cloud="oci",
                    status=RuleStatus.FAIL,
                    severity=SecuritySeverity.CRITICAL,
                ),
                resources_total=2,
            )
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.BLOCK)

    def test_triggered_findings_are_sorted_by_severity_rule_and_address(self) -> None:
        decision = self._evaluate(
            self._result(
                self._finding(
                    rule_id="GCP_INTERNAL_NETWORK_002",
                    status=RuleStatus.WARNING,
                    severity=SecuritySeverity.LOW,
                    address="gcp_resource.z",
                ),
                self._finding(
                    rule_id="GCP_INTERNAL_NETWORK_001",
                    status=RuleStatus.WARNING,
                    severity=SecuritySeverity.MEDIUM,
                    address="gcp_resource.b",
                ),
                self._finding(
                    rule_id="GCP_INTERNAL_NETWORK_001",
                    status=RuleStatus.WARNING,
                    severity=SecuritySeverity.MEDIUM,
                    address="gcp_resource.a",
                ),
            )
        )
        self.assertEqual(
            [item.resource_address for item in decision.triggered_findings],
            ["gcp_resource.a", "gcp_resource.b", "gcp_resource.z"],
        )
        self.assertEqual(
            decision.triggered_rules,
            ("GCP_INTERNAL_NETWORK_001", "GCP_INTERNAL_NETWORK_002"),
        )

    def test_severity_summary_counts_only_failures_and_warnings(self) -> None:
        decision = self._evaluate(
            self._result(
                self._finding(
                    rule_id="GCP_INTERNAL_NETWORK_001",
                    status=RuleStatus.PASS,
                    severity=SecuritySeverity.CRITICAL,
                ),
                self._finding(
                    rule_id="GCP_INTERNAL_NETWORK_002",
                    status=RuleStatus.WARNING,
                    severity=SecuritySeverity.MEDIUM,
                ),
                self._finding(
                    rule_id="GCP_INTERNAL_NETWORK_003",
                    status=RuleStatus.FAIL,
                    severity=SecuritySeverity.LOW,
                ),
            )
        )
        self.assertEqual(
            dict(decision.severity_summary),
            {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 1, "INFO": 0},
        )

    def test_secret_values_in_excluded_fields_are_never_serialised(self) -> None:
        secrets = (
            "FAKE_PASSWORD_POLICY1",
            "FAKE_TOKEN_POLICY1",
            "FAKE_PRIVATE_KEY_POLICY1",
            "FAKE_SECRET_POLICY1",
        )
        result = self._result(
            self._finding(
                status=RuleStatus.FAIL,
                severity=SecuritySeverity.HIGH,
                message=f"Details: {secrets[0]} {secrets[1]}",
                recommendation=f"Hidden: {secrets[2]} {secrets[3]}",
            )
        )
        decision = self._evaluate(result)
        payloads = (
            json.dumps(decision.to_dict()),
            decision.to_json(),
            decision.message,
            json.dumps([item.to_dict() for item in decision.triggered_findings]),
        )
        for payload in payloads:
            for secret in secrets:
                self.assertNotIn(secret, payload)

    def test_reversed_findings_produce_identical_serialisation(self) -> None:
        findings = (
            self._finding(
                rule_id="GCP_INTERNAL_NETWORK_002",
                status=RuleStatus.WARNING,
                severity=SecuritySeverity.LOW,
            ),
            self._finding(
                rule_id="GCP_INTERNAL_NETWORK_001",
                status=RuleStatus.WARNING,
                severity=SecuritySeverity.MEDIUM,
            ),
        )
        first = self._evaluate(self._result(*findings)).to_json()
        second = self._evaluate(self._result(*reversed(findings))).to_json()
        self.assertEqual(first, second)

    def test_gate_does_not_rerun_scanner_terraform_or_subprocess(self) -> None:
        result = self._result(self._finding())
        with (
            patch("security_scanner.SecurityComplianceScanner.scan") as scan,
            patch.object(TerraformRunner, "run") as terraform_run,
            patch.object(subprocess, "run") as process_run,
        ):
            decision = self._evaluate(result)
        self.assertIs(decision.decision, PolicyDecisionStatus.ALLOW)
        scan.assert_not_called()
        terraform_run.assert_not_called()
        process_run.assert_not_called()

    def test_gate_does_not_modify_input_result(self) -> None:
        result = self._result(
            self._finding(
                status=RuleStatus.WARNING,
                severity=SecuritySeverity.MEDIUM,
            )
        )
        before = result.to_json()
        self._evaluate(result)
        self.assertEqual(result.to_json(), before)


if __name__ == "__main__":
    unittest.main()
