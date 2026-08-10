"""Tests POLICY-3 du reporting et de la trace d'audit des decisions."""

import json
import subprocess
import tempfile
import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

from security_evaluation import MultiCloudSecurityEvaluationResult
from security_models import (
    RuleStatus,
    SecurityFinding,
    SecurityScanResult,
    SecuritySeverity,
)
from security_policy_gate import SecurityPolicyGate
from security_policy_models import (
    PolicyDecisionStatus,
    PolicyReasonCode,
    SecurityPolicyException,
    SecurityPolicyProfile,
    SecurityPolicyThresholds,
    build_baseline_security_policy,
    build_custom_security_policy,
    build_strict_security_policy,
)
from security_policy_report import (
    InvalidPolicyReportInputError,
    PolicyDecisionReport,
    PolicyDecisionReportBuilder,
)
from security_report import SecurityComplianceReport, SecurityTerraformContext
from terraform_report import TerraformExecutionReport
from terraform_runner import TerraformRunner


FIXED_DECISION_TIME = datetime(2026, 8, 10, 20, 59, tzinfo=timezone.utc)
FIXED_REPORT_TIME = datetime(2026, 8, 10, 21, 0, tzinfo=timezone.utc)
FIXED_UUID = UUID("12345678-1234-5678-1234-567812345678")


class SecurityPolicyReportTests(unittest.TestCase):
    @staticmethod
    def _finding(
        *,
        rule_id: str = "GCP_INTERNAL_NETWORK_001",
        cloud: str = "gcp",
        status: RuleStatus = RuleStatus.PASS,
        severity: SecuritySeverity = SecuritySeverity.LOW,
        address: str | None = None,
        message: str = "Synthetic POLICY-3 fixture.",
        recommendation: str = "Use safe synthetic configuration.",
    ) -> SecurityFinding:
        return SecurityFinding(
            rule_id=rule_id,
            cloud=cloud,
            resource_type="synthetic_resource",
            resource_name="policy3_fixture",
            resource_address=address or f"{cloud}_resource.policy3_fixture",
            status=status,
            severity=severity,
            title="Synthetic POLICY-3 finding",
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
            selected = tuple(item for item in findings if item.cloud == cloud)
            if selected:
                cloud_results[cloud] = SecurityScanResult.build(cloud, selected)
        return MultiCloudSecurityEvaluationResult(
            cloud_results=cloud_results,
            resources_total=resources_total,
        )

    @staticmethod
    def _builder(repository_root: Path | None = None):
        return PolicyDecisionReportBuilder(
            repository_root=repository_root,
            now_factory=lambda: FIXED_REPORT_TIME,
            uuid_factory=lambda: FIXED_UUID,
        )

    @classmethod
    def _decision(cls, policy, result):
        return SecurityPolicyGate(policy).evaluate(
            result,
            evaluated_at=FIXED_DECISION_TIME,
        )

    @classmethod
    def _build(cls, policy, result, **contexts):
        decision = cls._decision(policy, result)
        return cls._builder().build(
            policy=policy,
            decision=decision,
            evaluation_result=result,
            **contexts,
        )

    @staticmethod
    def _terraform_report(
        *,
        run_id: str = "tfplan_gcp_20260810T205800Z_abcdef12",
        secret: str | None = None,
    ) -> TerraformExecutionReport:
        return TerraformExecutionReport(
            schema_version="1.0",
            run_id=run_id,
            generated_at="2026-08-10T20:58:00Z",
            cloud="gcp",
            working_directory=(
                f"C:/Users/LENOVO/{secret}" if secret else "hcl-generator/generated/gcp"
            ),
            fmt_status="PASS",
            init_status="PASS",
            validate_status="PASS",
            plan_status="CHANGES_DETECTED",
            final_status="PASS",
            failed_step=None,
            total_duration_seconds=1.5,
            fmt_exit_code=0,
            init_exit_code=0,
            validate_exit_code=0,
            plan_exit_code=2,
            fmt_duration_seconds=0.1,
            init_duration_seconds=0.2,
            validate_duration_seconds=0.3,
            plan_duration_seconds=0.9,
            fmt_timed_out=False,
            init_timed_out=False,
            validate_timed_out=False,
            plan_timed_out=False,
            error_category=None,
            reason_code=None,
            error_message=secret,
            add_count=1,
            change_count=0,
            destroy_count=0,
        )

    @classmethod
    def _security_report(
        cls,
        result: MultiCloudSecurityEvaluationResult,
        *,
        terraform_report: TerraformExecutionReport | None = None,
        diagnostic: str = "Synthetic safe diagnostic",
    ) -> SecurityComplianceReport:
        terraform_context = None
        if terraform_report is not None:
            terraform_context = SecurityTerraformContext(
                terraform_run_id=terraform_report.run_id,
                cloud=terraform_report.cloud,
                terraform_final_status=terraform_report.final_status,
                failed_step=terraform_report.failed_step,
                plan_status=terraform_report.plan_status,
                plan_exit_code=terraform_report.plan_exit_code,
                add_count=terraform_report.add_count,
                change_count=terraform_report.change_count,
                destroy_count=terraform_report.destroy_count,
            )
        findings = tuple(
            finding
            for cloud in result.clouds_evaluated
            for finding in result.cloud_results[cloud].findings
        )
        return SecurityComplianceReport(
            schema_version="1.0",
            run_id="security_multicloud_20260810T205900Z_deadbeef",
            generated_at="2026-08-10T20:59:00Z",
            framework="INTERNAL_SECURITY_BASELINE",
            framework_versions={cloud: "internal-v1" for cloud in result.clouds_evaluated},
            evaluation_status=result.evaluation_status,
            clouds_evaluated=result.clouds_evaluated,
            resources_seen=result.resources_total,
            resources_adapted=result.resources_total,
            resources_skipped=0,
            unsupported_resource_types=(),
            adaptation_warnings=(diagnostic,),
            resources_total=result.resources_total,
            findings_total=result.findings_total,
            passed=result.passed,
            failed=result.failed,
            warnings=result.warnings,
            skipped=result.skipped,
            not_applicable=result.not_applicable,
            severity_counts=result.severity_counts,
            cloud_results=result.cloud_results,
            resources_by_cloud={cloud: 1 for cloud in result.clouds_evaluated},
            findings=findings,
            rules_available_by_cloud={cloud: 12 for cloud in result.clouds_evaluated},
            rules_evaluated_by_cloud={
                cloud: len(result.cloud_results[cloud].findings)
                for cloud in result.clouds_evaluated
            },
            terraform_context=terraform_context,
        )

    @staticmethod
    def _custom_policy():
        return build_custom_security_policy(
            policy_id="INTERNAL_SECURITY_POLICY_CUSTOM_AUDIT",
            policy_version="2.3",
            name="Custom audit fixture",
            description="Internal custom policy for POLICY-3 tests.",
            thresholds=SecurityPolicyThresholds(
                block_fail_critical=1,
                block_fail_high=3,
                approval_fail_high=2,
                approval_fail_medium=4,
                approval_warning_high=1,
                approval_warning_medium=5,
            ),
        )

    def test_report_model_and_builder_exist_with_schema_and_injected_ids(self) -> None:
        result = self._result(self._finding())
        report = self._build(build_baseline_security_policy(), result)
        self.assertIsInstance(report, PolicyDecisionReport)
        self.assertEqual(report.schema_version, "1.0")
        self.assertEqual(report.run_id, "policy_20260810T210000Z_12345678")
        self.assertEqual(report.generated_at, "2026-08-10T21:00:00Z")

    def test_policy_snapshot_contains_required_safe_fields(self) -> None:
        policy = build_strict_security_policy()
        report = self._build(policy, self._result(self._finding()))
        self.assertEqual(
            tuple(report.policy),
            (
                "policy_id",
                "policy_version",
                "profile",
                "enabled",
                "name",
                "description",
            ),
        )
        self.assertEqual(report.policy["policy_id"], policy.policy_id)
        self.assertEqual(report.policy["policy_version"], "1.0")
        self.assertEqual(report.policy["profile"], "STRICT")

    def test_all_profiles_are_serialized(self) -> None:
        policies = (
            build_baseline_security_policy(),
            build_strict_security_policy(),
            self._custom_policy(),
        )
        for policy, expected in zip(
            policies,
            ("BASELINE", "STRICT", "CUSTOM"),
        ):
            with self.subTest(profile=expected):
                report = self._build(policy, self._result(self._finding()))
                self.assertEqual(report.to_dict()["policy"]["profile"], expected)

    def test_allow_report_preserves_decision_flags(self) -> None:
        report = self._build(
            build_baseline_security_policy(),
            self._result(self._finding()),
        )
        self.assertEqual(report.decision["status"], "ALLOW")
        self.assertFalse(report.decision["requires_human_approval"])
        self.assertTrue(report.decision["deployment_allowed"])

    def test_require_approval_report_preserves_decision_flags(self) -> None:
        finding = self._finding(
            status=RuleStatus.FAIL,
            severity=SecuritySeverity.HIGH,
        )
        report = self._build(
            build_baseline_security_policy(),
            self._result(finding),
        )
        self.assertEqual(report.decision["status"], "REQUIRE_APPROVAL")
        self.assertTrue(report.decision["requires_human_approval"])
        self.assertFalse(report.decision["deployment_allowed"])

    def test_block_report_preserves_reason_and_flags(self) -> None:
        finding = self._finding(
            status=RuleStatus.FAIL,
            severity=SecuritySeverity.CRITICAL,
        )
        report = self._build(
            build_strict_security_policy(),
            self._result(finding),
        )
        self.assertEqual(report.decision["status"], "BLOCK")
        self.assertEqual(
            report.decision["reason_code"],
            "POLICY_BLOCK_CRITICAL_FINDING",
        )
        self.assertFalse(report.decision["requires_human_approval"])
        self.assertFalse(report.decision["deployment_allowed"])

    def test_threshold_snapshots_are_exact_for_each_profile(self) -> None:
        baseline = self._build(
            build_baseline_security_policy(),
            self._result(self._finding()),
        )
        strict = self._build(
            build_strict_security_policy(),
            self._result(self._finding()),
        )
        custom = self._build(
            self._custom_policy(),
            self._result(self._finding()),
        )
        self.assertEqual(baseline.thresholds["block_fail_high"], 0)
        self.assertEqual(strict.thresholds["block_fail_high"], 1)
        self.assertEqual(custom.thresholds["block_fail_high"], 3)
        self.assertEqual(custom.thresholds["approval_warning_medium"], 5)

    def test_triggered_rules_and_findings_reuse_safe_decision_projection(self) -> None:
        finding = self._finding(
            status=RuleStatus.FAIL,
            severity=SecuritySeverity.CRITICAL,
        )
        report = self._build(
            build_baseline_security_policy(),
            self._result(finding),
        )
        payload = report.to_dict()
        self.assertEqual(
            payload["decision"]["triggered_rules"],
            ["GCP_INTERNAL_NETWORK_001"],
        )
        self.assertEqual(payload["triggered_findings"][0]["status"], "FAIL")
        self.assertEqual(
            tuple(payload["triggered_findings"][0]),
            ("rule_id", "cloud", "resource_address", "severity", "status", "title"),
        )

    def test_finding_order_is_deterministic(self) -> None:
        findings = (
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
                address="gcp_resource.a",
            ),
        )
        first = self._build(
            build_baseline_security_policy(),
            self._result(*findings),
        )
        second = self._build(
            build_baseline_security_policy(),
            self._result(*reversed(findings)),
        )
        self.assertEqual(first.to_json(), second.to_json())

    def test_applied_exception_snapshot_contains_reason_scope_and_expiration(self) -> None:
        exception = SecurityPolicyException(
            exception_id="EXC-CHANGE-001",
            reason="Temporary approved migration exception",
            rule_ids=("GCP_INTERNAL_NETWORK_001",),
            clouds=("gcp",),
            expires_at=FIXED_DECISION_TIME + timedelta(days=1),
            reference="CHG-001",
            metadata={"internal": "excluded"},
        )
        policy = build_strict_security_policy(exceptions=(exception,))
        finding = self._finding(
            status=RuleStatus.FAIL,
            severity=SecuritySeverity.HIGH,
        )
        report = self._build(policy, self._result(finding))
        payload = report.to_dict()["exceptions"]
        self.assertEqual(payload["applied_exception_ids"], ["EXC-CHANGE-001"])
        self.assertEqual(payload["applied"][0]["reason"], exception.reason)
        self.assertEqual(payload["applied"][0]["scope"]["clouds"], ["gcp"])
        self.assertEqual(payload["applied"][0]["expires_at"], "2026-08-11T20:59:00Z")
        self.assertNotIn("metadata", payload["applied"][0])
        self.assertEqual(payload["excepted_findings"][0]["severity"], "HIGH")

    def test_disabled_and_non_applied_exceptions_are_absent(self) -> None:
        active = SecurityPolicyException(
            exception_id="EXC-ACTIVE-001",
            reason="Temporary approved migration exception",
            rule_ids=("GCP_INTERNAL_NETWORK_001",),
        )
        disabled = SecurityPolicyException(
            exception_id="EXC-DISABLED-002",
            reason="Disabled migration exception",
            enabled=False,
            rule_ids=("GCP_INTERNAL_NETWORK_001",),
        )
        policy = build_strict_security_policy(exceptions=(disabled, active))
        finding = self._finding(
            status=RuleStatus.FAIL,
            severity=SecuritySeverity.HIGH,
        )
        report = self._build(policy, self._result(finding))
        ids = report.to_dict()["exceptions"]["applied_exception_ids"]
        snapshots = report.to_dict()["exceptions"]["applied"]
        self.assertEqual(ids, ["EXC-ACTIVE-001"])
        self.assertEqual([item["exception_id"] for item in snapshots], ids)

    def test_critical_matching_exception_is_not_reported_as_applied(self) -> None:
        exception = SecurityPolicyException(
            exception_id="EXC-CRITICAL-001",
            reason="Temporary migration exception",
            rule_ids=("GCP_INTERNAL_NETWORK_001",),
        )
        policy = build_strict_security_policy(exceptions=(exception,))
        critical = self._finding(
            status=RuleStatus.FAIL,
            severity=SecuritySeverity.CRITICAL,
        )
        report = self._build(policy, self._result(critical))
        self.assertEqual(report.decision["status"], "BLOCK")
        self.assertEqual(report.applied_exception_ids, ())
        self.assertEqual(report.excepted_findings, ())
        self.assertEqual(report.triggered_findings[0].severity, SecuritySeverity.CRITICAL)

    def test_security_context_without_security_report(self) -> None:
        result = self._result(
            self._finding(
                status=RuleStatus.WARNING,
                severity=SecuritySeverity.MEDIUM,
            )
        )
        report = self._build(build_baseline_security_policy(), result)
        context = report.to_dict()["security_context"]
        self.assertIsNone(context["security_run_id"])
        self.assertEqual(context["resources_total"], 1)
        self.assertEqual(context["findings_total"], 1)
        self.assertEqual(context["medium_count"], 1)

    def test_gcp_oci_and_multicloud_contexts(self) -> None:
        cases = (
            (self._result(self._finding()), ["gcp"]),
            (
                self._result(
                    self._finding(rule_id="OCI_INTERNAL_NETWORK_001", cloud="oci")
                ),
                ["oci"],
            ),
            (
                self._result(
                    self._finding(),
                    self._finding(rule_id="OCI_INTERNAL_NETWORK_001", cloud="oci"),
                    resources_total=2,
                ),
                ["gcp", "oci"],
            ),
        )
        for result, expected in cases:
            with self.subTest(clouds=expected):
                report = self._build(build_baseline_security_policy(), result)
                self.assertEqual(
                    report.to_dict()["security_context"]["clouds_evaluated"],
                    expected,
                )

    def test_security_run_correlation(self) -> None:
        result = self._result(self._finding())
        security_report = self._security_report(result)
        report = self._build(
            build_baseline_security_policy(),
            result,
            security_report=security_report,
        )
        self.assertEqual(
            report.security_context.security_run_id,
            security_report.run_id,
        )

    def test_terraform_context_is_optional(self) -> None:
        report = self._build(
            build_baseline_security_policy(),
            self._result(self._finding()),
        )
        self.assertIsNone(report.terraform_context)
        self.assertIsNone(report.to_dict()["terraform_context"])

    def test_terraform_context_and_run_correlation(self) -> None:
        result = self._result(self._finding())
        terraform_report = self._terraform_report()
        security_report = self._security_report(
            result,
            terraform_report=terraform_report,
        )
        report = self._build(
            build_baseline_security_policy(),
            result,
            security_report=security_report,
            terraform_report=terraform_report,
        )
        context = report.to_dict()["terraform_context"]
        self.assertEqual(context["terraform_run_id"], terraform_report.run_id)
        self.assertEqual(context["terraform_final_status"], "PASS")
        self.assertEqual(context["plan_status"], "CHANGES_DETECTED")
        self.assertEqual(context["plan_exit_code"], 2)

    def test_terraform_context_can_come_from_security_report(self) -> None:
        result = self._result(self._finding())
        terraform_report = self._terraform_report()
        security_report = self._security_report(
            result,
            terraform_report=terraform_report,
        )
        report = self._build(
            build_baseline_security_policy(),
            result,
            security_report=security_report,
        )
        self.assertEqual(
            report.terraform_context.terraform_run_id,
            terraform_report.run_id,
        )

    def test_audit_section_has_injected_dates_source_and_counts(self) -> None:
        finding = self._finding(
            status=RuleStatus.FAIL,
            severity=SecuritySeverity.CRITICAL,
        )
        report = self._build(
            build_strict_security_policy(),
            self._result(finding),
        )
        audit = report.to_dict()["audit"]
        self.assertEqual(audit["decision_evaluated_at"], "2026-08-10T20:59:00Z")
        self.assertEqual(audit["policy_report_generated_at"], "2026-08-10T21:00:00Z")
        self.assertEqual(audit["decision_source"], "SecurityPolicyGate")
        self.assertEqual(audit["profile"], "STRICT")
        self.assertEqual(audit["triggered_findings_count"], 1)

    def test_safety_section_is_explicitly_false(self) -> None:
        report = self._build(
            build_baseline_security_policy(),
            self._result(self._finding()),
        )
        self.assertEqual(
            report.to_dict()["safety"],
            {
                "terraform_apply_executed": False,
                "terraform_destroy_executed": False,
                "cloud_write_operation_executed": False,
                "auto_approval_executed": False,
                "credentials_included": False,
                "raw_security_attributes_included": False,
                "raw_terraform_values_included": False,
            },
        )

    def test_to_dict_to_json_and_text_are_complete(self) -> None:
        finding = self._finding(
            status=RuleStatus.FAIL,
            severity=SecuritySeverity.CRITICAL,
        )
        report = self._build(
            build_strict_security_policy(),
            self._result(finding),
        )
        payload = report.to_dict()
        self.assertEqual(json.loads(report.to_json()), payload)
        self.assertEqual(
            tuple(payload),
            (
                "schema_version",
                "run_id",
                "generated_at",
                "policy",
                "decision",
                "thresholds",
                "security_context",
                "terraform_context",
                "triggered_findings",
                "exceptions",
                "audit",
                "safety",
            ),
        )
        text = report.render_text()
        self.assertIn("POLICY DECISION REPORT", text)
        self.assertIn(policy_id := report.policy["policy_id"], text)
        self.assertEqual(policy_id, "INTERNAL_SECURITY_POLICY_STRICT")
        self.assertIn("BLOCK", text)
        self.assertIn("GCP_INTERNAL_NETWORK_001", text)
        self.assertNotIn("\x1b", text)

    def test_text_contains_applied_exception(self) -> None:
        exception = SecurityPolicyException(
            exception_id="EXC-TEXT-001",
            reason="Temporary text audit exception",
            rule_ids=("GCP_INTERNAL_NETWORK_001",),
        )
        policy = build_strict_security_policy(exceptions=(exception,))
        finding = self._finding(
            status=RuleStatus.FAIL,
            severity=SecuritySeverity.HIGH,
        )
        text = self._build(policy, self._result(finding)).render_text()
        self.assertIn("EXC-TEXT-001", text)
        self.assertIn(exception.reason, text)
        self.assertIn("EXCEPTED FINDINGS", text)

    def test_write_report_creates_same_base_json_and_txt_atomically(self) -> None:
        report = self._build(
            build_baseline_security_policy(),
            self._result(self._finding()),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            builder = self._builder(root)
            json_path, text_path = builder.write_report(report)
            self.assertEqual(json_path.parent, root / "artifacts/policy/reports")
            self.assertEqual(json_path.stem, text_path.stem)
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8")), report.to_dict())
            self.assertEqual(text_path.read_text(encoding="utf-8").rstrip(), report.render_text())
            self.assertEqual(tuple(json_path.parent.glob("*.tmp")), ())

    def test_serialization_is_deterministic_with_injected_sources(self) -> None:
        result = self._result(self._finding())
        policy = build_baseline_security_policy()
        decision = self._decision(policy, result)
        first = self._builder().build(
            policy=policy,
            decision=decision,
            evaluation_result=result,
        )
        second = self._builder().build(
            policy=policy,
            decision=decision,
            evaluation_result=result,
        )
        self.assertEqual(first.to_json(), second.to_json())
        self.assertEqual(first.render_text(), second.render_text())

    def test_builder_does_not_mutate_inputs(self) -> None:
        result = self._result(self._finding())
        policy = build_baseline_security_policy()
        decision = self._decision(policy, result)
        before = (policy.to_json(), decision.to_json(), result.to_json())
        self._builder().build(
            policy=policy,
            decision=decision,
            evaluation_result=result,
        )
        self.assertEqual(
            (policy.to_json(), decision.to_json(), result.to_json()),
            before,
        )

    def test_optional_context_reports_are_not_mutated(self) -> None:
        result = self._result(self._finding())
        terraform_report = self._terraform_report()
        security_report = self._security_report(
            result,
            terraform_report=terraform_report,
        )
        policy = build_baseline_security_policy()
        before = (security_report.to_json(), terraform_report.to_json())
        self._builder().build(
            policy=policy,
            decision=self._decision(policy, result),
            evaluation_result=result,
            security_report=security_report,
            terraform_report=terraform_report,
        )
        self.assertEqual(
            (security_report.to_json(), terraform_report.to_json()),
            before,
        )

    def test_report_is_immutable(self) -> None:
        report = self._build(
            build_baseline_security_policy(),
            self._result(self._finding()),
        )
        with self.assertRaises(FrozenInstanceError):
            report.run_id = "changed"
        with self.assertRaises(TypeError):
            report.thresholds["block_fail_high"] = 9

    def test_policy_id_version_and_profile_mismatches_are_rejected(self) -> None:
        result = self._result(self._finding())
        policy = build_baseline_security_policy()
        decision = self._decision(policy, result)
        mismatches = (
            replace(decision, policy_id="OTHER_POLICY"),
            replace(decision, policy_version="9.9"),
            replace(decision, profile=SecurityPolicyProfile.STRICT),
        )
        for mismatch in mismatches:
            with self.subTest(decision=mismatch):
                with self.assertRaises(InvalidPolicyReportInputError):
                    self._builder().build(
                        policy=policy,
                        decision=mismatch,
                        evaluation_result=result,
                    )

    def test_security_report_mismatch_is_rejected(self) -> None:
        result = self._result(self._finding())
        other_result = self._result(
            self._finding(),
            self._finding(rule_id="OCI_INTERNAL_NETWORK_001", cloud="oci"),
            resources_total=2,
        )
        security_report = self._security_report(other_result)
        policy = build_baseline_security_policy()
        with self.assertRaises(InvalidPolicyReportInputError):
            self._builder().build(
                policy=policy,
                decision=self._decision(policy, result),
                evaluation_result=result,
                security_report=security_report,
            )

    def test_terraform_run_mismatch_is_rejected(self) -> None:
        result = self._result(self._finding())
        terraform_report = self._terraform_report()
        security_report = self._security_report(
            result,
            terraform_report=terraform_report,
        )
        other_terraform_report = replace(
            terraform_report,
            run_id="tfplan_gcp_20260810T205800Z_feedface",
        )
        policy = build_baseline_security_policy()
        with self.assertRaisesRegex(InvalidPolicyReportInputError, "terraform"):
            self._builder().build(
                policy=policy,
                decision=self._decision(policy, result),
                evaluation_result=result,
                security_report=security_report,
                terraform_report=other_terraform_report,
            )

    def test_applied_exception_missing_from_policy_is_rejected(self) -> None:
        exception = SecurityPolicyException(
            exception_id="EXC-MISSING-001",
            reason="Temporary approved migration exception",
            rule_ids=("GCP_INTERNAL_NETWORK_001",),
        )
        source_policy = build_strict_security_policy(exceptions=(exception,))
        report_policy = build_strict_security_policy()
        result = self._result(
            self._finding(
                status=RuleStatus.FAIL,
                severity=SecuritySeverity.HIGH,
            )
        )
        with self.assertRaisesRegex(InvalidPolicyReportInputError, "exception"):
            self._builder().build(
                policy=report_policy,
                decision=self._decision(source_policy, result),
                evaluation_result=result,
            )

    def test_naive_report_clock_is_rejected(self) -> None:
        result = self._result(self._finding())
        policy = build_baseline_security_policy()
        builder = PolicyDecisionReportBuilder(
            now_factory=lambda: datetime(2026, 8, 10, 21, 0),
            uuid_factory=lambda: FIXED_UUID,
        )
        with self.assertRaisesRegex(InvalidPolicyReportInputError, "fuseau"):
            builder.build(
                policy=policy,
                decision=self._decision(policy, result),
                evaluation_result=result,
            )

    def test_insufficient_data_is_auditable_and_never_allow(self) -> None:
        result = self._result(resources_total=0)
        report = self._build(build_baseline_security_policy(), result)
        self.assertEqual(report.decision["status"], "REQUIRE_APPROVAL")
        self.assertEqual(
            report.decision["reason_code"],
            "POLICY_INSUFFICIENT_SECURITY_DATA",
        )
        self.assertIn("insufficient", report.decision["message"].casefold())

    def test_all_skipped_is_auditable_and_never_allow(self) -> None:
        skipped = self._finding(
            status=RuleStatus.SKIPPED,
            severity=SecuritySeverity.HIGH,
        )
        report = self._build(
            build_baseline_security_policy(),
            self._result(skipped),
        )
        self.assertEqual(report.decision["status"], "REQUIRE_APPROVAL")
        self.assertIs(
            PolicyReasonCode(report.decision["reason_code"]),
            PolicyReasonCode.INSUFFICIENT_SECURITY_DATA,
        )
        self.assertEqual(report.triggered_findings[0].status, RuleStatus.SKIPPED)

    def test_secret_and_raw_source_values_never_propagate(self) -> None:
        secrets = (
            "FAKE_PASSWORD_POLICY3",
            "FAKE_TOKEN_POLICY3",
            "FAKE_PRIVATE_KEY_POLICY3",
            "FAKE_SECRET_POLICY3",
        )
        exception = SecurityPolicyException(
            exception_id="EXC-SAFE-001",
            reason="Temporary approved migration exception",
            rule_ids=("GCP_INTERNAL_NETWORK_001",),
            metadata={
                "password": secrets[0],
                "token": secrets[1],
                "private_key": secrets[2],
                "secret": secrets[3],
            },
        )
        finding = self._finding(
            status=RuleStatus.FAIL,
            severity=SecuritySeverity.HIGH,
            message=f"raw stdout {secrets[0]} {secrets[1]}",
            recommendation=f"raw stderr {secrets[2]} {secrets[3]}",
        )
        result = self._result(finding)
        terraform_report = self._terraform_report(secret=secrets[0])
        security_report = self._security_report(
            result,
            terraform_report=terraform_report,
            diagnostic=f"raw attributes {secrets[1]} tfstate tfvars",
        )
        policy = build_strict_security_policy(exceptions=(exception,))
        decision = self._decision(policy, result)
        report = self._builder().build(
            policy=policy,
            decision=decision,
            evaluation_result=result,
            security_report=security_report,
            terraform_report=terraform_report,
        )
        payloads = (
            json.dumps(report.to_dict()),
            report.to_json(),
            report.render_text(),
        )
        with tempfile.TemporaryDirectory() as directory:
            paths = self._builder(Path(directory)).write_report(report)
            payloads += tuple(path.read_text(encoding="utf-8") for path in paths)
        for payload in payloads:
            for secret in secrets:
                self.assertNotIn(secret, payload)
            self.assertNotIn("C:/Users/LENOVO", payload)
            self.assertNotIn("tfstate", payload)
            self.assertNotIn("tfvars", payload)
            self.assertNotIn("raw stdout", payload)
            self.assertNotIn("raw stderr", payload)

    def test_builder_never_recalculates_or_executes_any_pipeline(self) -> None:
        result = self._result(self._finding())
        policy = build_baseline_security_policy()
        decision = self._decision(policy, result)
        with (
            patch.object(SecurityPolicyGate, "evaluate") as evaluate,
            patch.object(TerraformRunner, "run") as terraform_run,
            patch.object(subprocess, "run") as process_run,
        ):
            report = self._builder().build(
                policy=policy,
                decision=decision,
                evaluation_result=result,
            )
        self.assertEqual(report.decision["status"], "ALLOW")
        evaluate.assert_not_called()
        terraform_run.assert_not_called()
        process_run.assert_not_called()

    def test_synthetic_multicloud_strict_exception_end_to_end(self) -> None:
        exception = SecurityPolicyException(
            exception_id="EXC-FIREWALL-001",
            reason="Temporary approved firewall migration exception",
            rule_ids=("GCP_INTERNAL_NETWORK_001",),
            resource_addresses=("google_compute_firewall.legacy_admin",),
        )
        policy = build_strict_security_policy(exceptions=(exception,))
        gcp_high = self._finding(
            status=RuleStatus.FAIL,
            severity=SecuritySeverity.HIGH,
            address="google_compute_firewall.legacy_admin",
        )
        oci_clean = self._finding(
            rule_id="OCI_INTERNAL_NETWORK_001",
            cloud="oci",
        )
        result = self._result(gcp_high, oci_clean, resources_total=2)
        report = self._build(policy, result)
        payload = report.to_dict()
        self.assertEqual(payload["policy"]["profile"], "STRICT")
        self.assertEqual(payload["decision"]["status"], "REQUIRE_APPROVAL")
        self.assertTrue(payload["decision"]["requires_human_approval"])
        self.assertFalse(payload["decision"]["deployment_allowed"])
        self.assertEqual(
            payload["exceptions"]["applied_exception_ids"],
            ["EXC-FIREWALL-001"],
        )
        self.assertEqual(payload["exceptions"]["excepted_findings"][0]["status"], "FAIL")
        self.assertEqual(payload["security_context"]["clouds_evaluated"], ["gcp", "oci"])


if __name__ == "__main__":
    unittest.main()
