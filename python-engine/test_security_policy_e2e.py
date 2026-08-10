"""Tests POLICY-4 de la composition CIS-8 -> gate -> rapport policy."""

import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import UUID

from security_evaluation import MultiCloudSecurityEvaluationResult
from security_models import RuleStatus, SecurityFinding, SecurityScanResult, SecuritySeverity
from security_policy_e2e import (
    PolicyPipelineStageStatus,
    TerraformSecurityPolicyEndToEndPipeline,
    TerraformSecurityPolicyEndToEndResult,
    _print_safe_summary,
    build_default_terraform_security_policy_engine,
    main,
)
from security_policy_gate import SecurityPolicyGate
from security_policy_models import (
    PolicyDecisionStatus,
    SecurityPolicyException,
    SecurityPolicyProfile,
    SecurityPolicyThresholds,
    build_baseline_security_policy,
    build_custom_security_policy,
    build_strict_security_policy,
)
from security_policy_report import PolicyDecisionReportBuilder
from security_gcp_pack import build_gcp_security_rule_pack
from security_oci_pack import build_oci_security_rule_pack
from security_report import SecurityComplianceReport, SecurityTerraformContext
from security_terraform_e2e import (
    TerraformSecurityEndToEndResult,
    TerraformSecurityStageStatus,
)
from terraform_e2e import TerraformEndToEndResult, TerraformEngineStatus
from terraform_report import TerraformExecutionReport


FIXED_DECISION_TIME = datetime(2026, 8, 10, 20, 59, tzinfo=timezone.utc)
FIXED_REPORT_TIME = datetime(2026, 8, 10, 21, 0, tzinfo=timezone.utc)
FIXED_UUID = UUID("12345678-1234-5678-1234-567812345678")


class FakeSecurityPipeline:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = []

    def run(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.result


class TerraformSecurityPolicyEndToEndTests(unittest.TestCase):
    @staticmethod
    def _finding(
        status=RuleStatus.PASS,
        severity=SecuritySeverity.LOW,
        *,
        cloud="gcp",
        rule_id="GCP_INTERNAL_NETWORK_001",
    ):
        return SecurityFinding(
            rule_id=rule_id,
            cloud=cloud,
            resource_type="synthetic_resource",
            resource_name="policy4_fixture",
            resource_address=f"{cloud}_resource.policy4_fixture",
            status=status,
            severity=severity,
            title="Synthetic POLICY-4 finding",
            message="Synthetic safe diagnostic.",
            recommendation="Use synthetic safe configuration.",
        )

    @classmethod
    def _evaluation(cls, *findings, resources_total=1):
        by_cloud = {}
        for cloud in ("gcp", "oci"):
            selected = tuple(item for item in findings if item.cloud == cloud)
            if selected:
                by_cloud[cloud] = SecurityScanResult.build(cloud, selected)
        return MultiCloudSecurityEvaluationResult(
            cloud_results=by_cloud,
            resources_total=resources_total,
        )

    @staticmethod
    def _terraform_report():
        return TerraformExecutionReport(
            schema_version="1.0",
            run_id="tfplan_gcp_20260810T205800Z_abcdef12",
            generated_at="2026-08-10T20:58:00Z",
            cloud="gcp",
            working_directory="hcl-generator/generated/gcp",
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
            error_message=None,
            add_count=1,
            change_count=0,
            destroy_count=0,
        )

    @classmethod
    def _security_report(cls, evaluation, terraform_report):
        findings = tuple(
            finding
            for cloud in evaluation.clouds_evaluated
            for finding in evaluation.cloud_results[cloud].findings
        )
        return SecurityComplianceReport(
            schema_version="1.0",
            run_id="security_multicloud_20260810T205900Z_deadbeef",
            generated_at="2026-08-10T20:59:00Z",
            framework="INTERNAL_SECURITY_BASELINE",
            framework_versions={cloud: "internal-v1" for cloud in evaluation.clouds_evaluated},
            evaluation_status=evaluation.evaluation_status,
            clouds_evaluated=evaluation.clouds_evaluated,
            resources_seen=evaluation.resources_total,
            resources_adapted=evaluation.resources_total,
            resources_skipped=0,
            unsupported_resource_types=(),
            adaptation_warnings=(),
            resources_total=evaluation.resources_total,
            findings_total=evaluation.findings_total,
            passed=evaluation.passed,
            failed=evaluation.failed,
            warnings=evaluation.warnings,
            skipped=evaluation.skipped,
            not_applicable=evaluation.not_applicable,
            severity_counts=evaluation.severity_counts,
            cloud_results=evaluation.cloud_results,
            resources_by_cloud={cloud: 1 for cloud in evaluation.clouds_evaluated},
            findings=findings,
            rules_available_by_cloud={cloud: 12 for cloud in evaluation.clouds_evaluated},
            rules_evaluated_by_cloud={cloud: len(evaluation.cloud_results[cloud].findings) for cloud in evaluation.clouds_evaluated},
            terraform_context=SecurityTerraformContext(
                terraform_run_id=terraform_report.run_id,
                cloud=terraform_report.cloud,
                terraform_final_status=terraform_report.final_status,
                failed_step=terraform_report.failed_step,
                plan_status=terraform_report.plan_status,
                plan_exit_code=terraform_report.plan_exit_code,
                add_count=terraform_report.add_count,
                change_count=terraform_report.change_count,
                destroy_count=terraform_report.destroy_count,
            ),
        )

    @classmethod
    def _cis_result(cls, evaluation=None, *, engine_status=TerraformEngineStatus.PASS):
        terraform_report = cls._terraform_report()
        terraform_result = TerraformEndToEndResult(
            cloud="gcp",
            engine_status=engine_status,
            plan_pipeline_result=None,
            report=terraform_report,
            report_written=False,
            json_path=None,
            text_path=None,
            duration_seconds=0.1,
        )
        security_report = (
            cls._security_report(evaluation, terraform_report)
            if evaluation is not None
            else None
        )
        return TerraformSecurityEndToEndResult(
            engine_status=engine_status,
            cloud="gcp",
            terraform_result=terraform_result,
            show_status=(TerraformSecurityStageStatus.PASS if evaluation is not None else TerraformSecurityStageStatus.FAIL),
            show_error_classification=None,
            adaptation_status=(TerraformSecurityStageStatus.PASS if evaluation is not None else TerraformSecurityStageStatus.SKIPPED),
            adaptation_result=None,
            security_evaluation_status=(TerraformSecurityStageStatus.PASS if evaluation is not None else TerraformSecurityStageStatus.SKIPPED),
            security_evaluation_result=evaluation,
            security_report=security_report,
            security_report_written=False,
            security_json_path=None,
            security_text_path=None,
            duration_seconds=0.2,
            temporary_plan_created=False,
            temporary_plan_cleaned=False,
        )

    @staticmethod
    def _builder(root=None):
        return PolicyDecisionReportBuilder(
            repository_root=root,
            now_factory=lambda: FIXED_REPORT_TIME,
            uuid_factory=lambda: FIXED_UUID,
        )

    @classmethod
    def _pipeline(cls, cis_result, *, policy=None, builder=None):
        security_pipeline = FakeSecurityPipeline(cis_result)
        gate = MagicMock(wraps=SecurityPolicyGate(policy or build_baseline_security_policy()))
        gate.policy = policy or build_baseline_security_policy()
        report_builder = MagicMock(wraps=builder or cls._builder())
        pipeline = TerraformSecurityPolicyEndToEndPipeline(
            security_pipeline, gate, report_builder
        )
        return pipeline, security_pipeline, gate, report_builder

    def test_happy_path_reuses_cis_objects_and_calls_each_stage_once(self):
        evaluation = self._evaluation(self._finding())
        cis_result = self._cis_result(evaluation)
        pipeline, security_pipeline, gate, builder = self._pipeline(cis_result)

        result = pipeline.run(" GCP ", evaluated_at=FIXED_DECISION_TIME)

        self.assertIs(result.security_pipeline_result, cis_result)
        self.assertEqual(security_pipeline.calls, [{"cloud": "gcp", "write_report": False}])
        gate.evaluate.assert_called_once_with(evaluation, evaluated_at=FIXED_DECISION_TIME)
        builder.build.assert_called_once()
        builder.write_report.assert_not_called()
        self.assertEqual(result.engine_status, TerraformEngineStatus.PASS)
        self.assertEqual(result.policy_gate_status, PolicyPipelineStageStatus.PASS)
        self.assertEqual(result.policy_report_status, PolicyPipelineStageStatus.PASS)
        self.assertEqual(result.policy_decision.decision, PolicyDecisionStatus.ALLOW)
        self.assertEqual(
            result.policy_report.decision["status"],
            result.policy_decision.decision.value,
        )
        self.assertFalse(result.apply_executed)

    def test_security_pipeline_exception_is_sanitized_and_fails_engine(self):
        pipeline = TerraformSecurityPolicyEndToEndPipeline(
            FakeSecurityPipeline(error=RuntimeError("SECRET_TOKEN")),
            SecurityPolicyGate(build_baseline_security_policy()),
            self._builder(),
        )
        result = pipeline.run("gcp")
        self.assertEqual(result.engine_status, TerraformEngineStatus.FAIL)
        self.assertEqual(result.policy_gate_status, PolicyPipelineStageStatus.SKIPPED)
        self.assertNotIn("SECRET_TOKEN", result.to_json())

    def test_missing_evaluation_skips_policy_without_changing_cis_engine_status(self):
        for status in (TerraformEngineStatus.PASS, TerraformEngineStatus.FAIL):
            with self.subTest(status=status):
                cis_result = self._cis_result(None, engine_status=status)
                pipeline, _, gate, builder = self._pipeline(cis_result)
                result = pipeline.run("gcp")
                self.assertEqual(result.engine_status, status)
                self.assertEqual(result.policy_gate_status, PolicyPipelineStageStatus.SKIPPED)
                self.assertEqual(result.policy_report_status, PolicyPipelineStageStatus.SKIPPED)
                self.assertIsNone(result.policy_decision)
                gate.evaluate.assert_not_called()
                builder.build.assert_not_called()

    def test_failed_cis_engine_skips_policy_even_if_result_is_inconsistent(self):
        evaluation = self._evaluation(self._finding())
        pipeline, _, gate, builder = self._pipeline(
            self._cis_result(evaluation, engine_status=TerraformEngineStatus.FAIL)
        )
        result = pipeline.run("gcp")
        self.assertEqual(result.engine_status, TerraformEngineStatus.FAIL)
        self.assertEqual(result.policy_gate_status, PolicyPipelineStageStatus.SKIPPED)
        gate.evaluate.assert_not_called()
        builder.build.assert_not_called()

    def test_baseline_high_requires_approval_and_critical_blocks(self):
        cases = (
            (SecuritySeverity.HIGH, PolicyDecisionStatus.REQUIRE_APPROVAL),
            (SecuritySeverity.CRITICAL, PolicyDecisionStatus.BLOCK),
        )
        for severity, expected in cases:
            with self.subTest(severity=severity):
                evaluation = self._evaluation(self._finding(RuleStatus.FAIL, severity))
                pipeline, *_ = self._pipeline(self._cis_result(evaluation))
                result = pipeline.run("gcp", evaluated_at=FIXED_DECISION_TIME)
                self.assertEqual(result.policy_decision.decision, expected)
                self.assertEqual(result.engine_status, TerraformEngineStatus.PASS)

    def test_strict_high_blocks_without_turning_block_into_engine_failure(self):
        evaluation = self._evaluation(self._finding(RuleStatus.FAIL, SecuritySeverity.HIGH))
        strict = build_strict_security_policy()
        pipeline, *_ = self._pipeline(self._cis_result(evaluation), policy=strict)
        result = pipeline.run("gcp", evaluated_at=FIXED_DECISION_TIME)
        self.assertEqual(result.policy_decision.decision, PolicyDecisionStatus.BLOCK)
        self.assertEqual(result.engine_status, TerraformEngineStatus.PASS)

    def test_insufficient_evaluation_requires_human_approval(self):
        evaluation = self._evaluation(resources_total=0)
        pipeline, *_ = self._pipeline(self._cis_result(evaluation))
        result = pipeline.run("gcp", evaluated_at=FIXED_DECISION_TIME)
        self.assertEqual(result.policy_decision.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)
        self.assertTrue(result.policy_decision.requires_human_approval)

    def test_all_skipped_evaluation_requires_human_approval(self):
        evaluation = self._evaluation(
            self._finding(RuleStatus.SKIPPED, SecuritySeverity.HIGH)
        )
        pipeline, *_ = self._pipeline(self._cis_result(evaluation))
        result = pipeline.run("gcp", evaluated_at=FIXED_DECISION_TIME)
        self.assertEqual(result.policy_decision.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)

    def test_policy2_exceptions_are_reused_for_high_but_never_for_critical(self):
        exception = SecurityPolicyException(
            exception_id="EXC-POLICY4-001",
            reason="Synthetic approved migration exception",
            rule_ids=("GCP_INTERNAL_NETWORK_001",),
        )
        strict = build_strict_security_policy(exceptions=(exception,))
        for severity, expected, applied in (
            (SecuritySeverity.HIGH, PolicyDecisionStatus.REQUIRE_APPROVAL, True),
            (SecuritySeverity.CRITICAL, PolicyDecisionStatus.BLOCK, False),
        ):
            with self.subTest(severity=severity):
                evaluation = self._evaluation(self._finding(RuleStatus.FAIL, severity))
                pipeline, *_ = self._pipeline(self._cis_result(evaluation), policy=strict)
                result = pipeline.run("gcp", evaluated_at=FIXED_DECISION_TIME)
                self.assertEqual(result.policy_decision.decision, expected)
                self.assertEqual(
                    "EXC-POLICY4-001" in result.policy_report.applied_exception_ids,
                    applied,
                )
                reported_findings = (
                    result.policy_report.triggered_findings
                    + result.policy_report.excepted_findings
                )
                self.assertIn(
                    "GCP_INTERNAL_NETWORK_001",
                    {finding.rule_id for finding in reported_findings},
                )

    def test_security_and_policy_report_write_switches_are_independent(self):
        for security_write in (False, True):
            for policy_write in (False, True):
                with self.subTest(security_write=security_write, policy_write=policy_write):
                    evaluation = self._evaluation(self._finding())
                    with tempfile.TemporaryDirectory() as temporary:
                        pipeline, security_pipeline, _, builder = self._pipeline(
                            self._cis_result(evaluation), builder=self._builder(Path(temporary))
                        )
                        result = pipeline.run(
                            "gcp",
                            write_security_report=security_write,
                            write_policy_report=policy_write,
                            evaluated_at=FIXED_DECISION_TIME,
                        )
                        self.assertEqual(security_pipeline.calls[0]["write_report"], security_write)
                        self.assertEqual(result.policy_report_written, policy_write)
                        self.assertEqual(builder.write_report.call_count, int(policy_write))
                        self.assertEqual(result.policy_json_path is not None, policy_write)

    def test_report_correlates_existing_security_and_terraform_run_ids(self):
        evaluation = self._evaluation(self._finding())
        cis_result = self._cis_result(evaluation)
        pipeline, *_ = self._pipeline(cis_result)
        result = pipeline.run("gcp", evaluated_at=FIXED_DECISION_TIME)
        report = result.policy_report.to_dict()
        self.assertEqual(report["security_context"]["security_run_id"], cis_result.security_report.run_id)
        self.assertEqual(report["terraform_context"]["terraform_run_id"], cis_result.terraform_result.report.run_id)

    def test_gate_exception_retains_cis_result_and_stops_reporting(self):
        evaluation = self._evaluation(self._finding())
        pipeline, _, gate, builder = self._pipeline(self._cis_result(evaluation))
        gate.evaluate.side_effect = RuntimeError("credential=SECRET")
        result = pipeline.run("gcp")
        self.assertEqual(result.engine_status, TerraformEngineStatus.FAIL)
        self.assertEqual(result.policy_gate_status, PolicyPipelineStageStatus.ERROR)
        self.assertEqual(result.policy_report_status, PolicyPipelineStageStatus.SKIPPED)
        self.assertIsNone(result.policy_decision)
        builder.build.assert_not_called()
        self.assertNotIn("SECRET", result.to_json())

    def test_report_build_exception_retains_decision(self):
        evaluation = self._evaluation(self._finding())
        pipeline, _, _, builder = self._pipeline(self._cis_result(evaluation))
        builder.build.side_effect = RuntimeError("SECRET")
        result = pipeline.run("gcp")
        self.assertEqual(result.engine_status, TerraformEngineStatus.FAIL)
        self.assertEqual(result.policy_gate_status, PolicyPipelineStageStatus.PASS)
        self.assertEqual(result.policy_report_status, PolicyPipelineStageStatus.ERROR)
        self.assertIsNotNone(result.policy_decision)
        self.assertIsNone(result.policy_report)

    def test_report_write_exception_retains_in_memory_report(self):
        evaluation = self._evaluation(self._finding())
        pipeline, _, _, builder = self._pipeline(self._cis_result(evaluation))
        builder.write_report.side_effect = OSError("SECRET_PATH")
        result = pipeline.run("gcp", write_policy_report=True)
        self.assertEqual(result.engine_status, TerraformEngineStatus.FAIL)
        self.assertEqual(result.policy_report_status, PolicyPipelineStageStatus.ERROR)
        self.assertIsNotNone(result.policy_decision)
        self.assertIsNotNone(result.policy_report)
        self.assertFalse(result.policy_report_written)
        self.assertNotIn("SECRET_PATH", result.to_json())

    def test_result_serialization_and_summary_expose_only_safe_fields(self):
        evaluation = self._evaluation(self._finding())
        pipeline, *_ = self._pipeline(self._cis_result(evaluation))
        result = pipeline.run("gcp", evaluated_at=FIXED_DECISION_TIME)
        serialized = result.to_json()
        parsed = json.loads(serialized)
        self.assertFalse(any(parsed["safety"].values()))
        for forbidden in ("raw_stdout", "raw_stderr", "planned_values", "SECRET_TOKEN"):
            self.assertNotIn(forbidden, serialized)
        output = io.StringIO()
        with patch("sys.stdout", output):
            _print_safe_summary(result)
        self.assertIn("policy_decision=ALLOW", output.getvalue())
        self.assertNotIn("planned_values", output.getvalue())

    def test_source_secrets_are_absent_from_decision_and_written_policy_reports(self):
        secrets = (
            "FAKE_PASSWORD_POLICY4",
            "FAKE_TOKEN_POLICY4",
            "FAKE_PRIVATE_KEY_POLICY4",
            "FAKE_SECRET_POLICY4",
        )
        finding = SecurityFinding(
            rule_id="GCP_INTERNAL_NETWORK_001",
            cloud="gcp",
            resource_type="synthetic_resource",
            resource_name=secrets[0],
            resource_address="gcp_resource.policy4_fixture",
            status=RuleStatus.FAIL,
            severity=SecuritySeverity.HIGH,
            title="Synthetic POLICY-4 finding",
            message=" ".join(secrets[1:]),
            recommendation="Use synthetic safe configuration.",
        )
        evaluation = self._evaluation(finding)
        with tempfile.TemporaryDirectory() as temporary:
            pipeline, *_ = self._pipeline(
                self._cis_result(evaluation), builder=self._builder(Path(temporary))
            )
            result = pipeline.run(
                "gcp", write_policy_report=True, evaluated_at=FIXED_DECISION_TIME
            )
            outputs = "\n".join(
                (
                    result.policy_decision.to_json(),
                    result.policy_report.to_json(),
                    result.policy_json_path.read_text(encoding="utf-8"),
                    result.policy_text_path.read_text(encoding="utf-8"),
                    result.to_json(),
                )
            )
        for secret in secrets:
            self.assertNotIn(secret, outputs)

    def test_fixed_clock_and_uuid_make_policy_report_deterministic(self):
        evaluation = self._evaluation(self._finding())
        cis_result = self._cis_result(evaluation)
        first, *_ = self._pipeline(cis_result)
        second, *_ = self._pipeline(cis_result)
        first_result = first.run("gcp", evaluated_at=FIXED_DECISION_TIME)
        second_result = second.run("gcp", evaluated_at=FIXED_DECISION_TIME)
        self.assertEqual(first_result.policy_decision, second_result.policy_decision)
        self.assertEqual(first_result.policy_report.to_json(), second_result.policy_report.to_json())

    def test_invalid_cloud_and_write_flags_fail_before_cis_execution(self):
        cis = FakeSecurityPipeline(self._cis_result(None))
        pipeline = TerraformSecurityPolicyEndToEndPipeline(
            cis, SecurityPolicyGate(build_baseline_security_policy()), self._builder()
        )
        for cloud in ("aws", "", None):
            with self.subTest(cloud=cloud), self.assertRaises(ValueError):
                pipeline.run(cloud)
        with self.assertRaises(TypeError):
            pipeline.run("gcp", write_policy_report="yes")
        self.assertEqual(cis.calls, [])

    def test_default_factory_supports_baseline_strict_and_explicit_policy(self):
        custom_policy = build_custom_security_policy(
            policy_id="INTERNAL_SECURITY_POLICY_CUSTOM_POLICY4",
            policy_version="1.0",
            name="POLICY-4 custom fixture",
            description="Synthetic custom policy injected through the Python API.",
            thresholds=SecurityPolicyThresholds(
                block_fail_critical=1,
                block_fail_high=2,
                approval_fail_high=1,
                approval_fail_medium=2,
                approval_warning_high=1,
                approval_warning_medium=2,
            ),
        )
        with patch("security_policy_e2e.build_default_terraform_security_engine", return_value=FakeSecurityPipeline()):
            baseline = build_default_terraform_security_policy_engine(profile="baseline")
            strict = build_default_terraform_security_policy_engine(profile=SecurityPolicyProfile.STRICT)
            explicit = build_default_terraform_security_policy_engine(policy=custom_policy)
        self.assertEqual(baseline.policy.profile, SecurityPolicyProfile.BASELINE)
        self.assertEqual(strict.policy.profile, SecurityPolicyProfile.STRICT)
        self.assertEqual(explicit.policy.profile, SecurityPolicyProfile.CUSTOM)
        self.assertIs(explicit.policy, custom_policy)

    def test_cli_passes_only_safe_options_and_returns_engine_status(self):
        result = MagicMock(spec=TerraformSecurityPolicyEndToEndResult)
        result.engine_status = TerraformEngineStatus.PASS
        engine = MagicMock()
        engine.run.return_value = result
        with patch("security_policy_e2e.build_default_terraform_security_policy_engine", return_value=engine) as factory, patch("security_policy_e2e._print_safe_summary"):
            exit_code = main(["--cloud", "oci", "--profile", "strict", "--write-policy-report"])
        self.assertEqual(exit_code, 0)
        factory.assert_called_once_with(profile="strict")
        engine.run.assert_called_once_with(
            cloud="oci", write_security_report=False, write_policy_report=True
        )

    def test_cli_rejects_apply_destroy_and_auto_approval_flags(self):
        for option in ("--apply", "--destroy", "--auto-approve"):
            with self.subTest(option=option), self.assertRaises(SystemExit):
                main(["--cloud", "gcp", option])

    def test_cli_rejects_invalid_profile_before_factory_call(self):
        with patch("security_policy_e2e.build_default_terraform_security_policy_engine") as factory:
            with self.assertRaises(SystemExit):
                main(["--cloud", "gcp", "--profile", "custom"])
        factory.assert_not_called()

    def test_rule_inventory_remains_twelve_per_cloud(self):
        gcp_rules = build_gcp_security_rule_pack()
        oci_rules = build_oci_security_rule_pack()
        self.assertEqual(len(gcp_rules), 12)
        self.assertEqual(len(oci_rules), 12)
        self.assertEqual(len(gcp_rules) + len(oci_rules), 24)

    def test_source_has_no_direct_execution_or_security_reimplementation(self):
        source = Path(__file__).with_name("security_policy_e2e.py").read_text(encoding="utf-8")
        for forbidden in (
            "subprocess", "TerraformRunner(", "TerraformSecurityResourceAdapter(",
            "SecurityComplianceScanner(", "--apply", "--destroy", "--auto-approve",
            "input(", "gcloud create", "gcloud update", "gcloud delete",
            "oci create", "oci update", "oci delete",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
