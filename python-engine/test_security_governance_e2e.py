"""Tests POLICY-6 du pipeline final de gouvernance."""

import io
import tempfile
import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import UUID

from security_approval_models import ApprovalStatus, AuthorizationStatus
from security_approval_workflow import HumanApprovalWorkflow
from security_governance_e2e import (
    FinalGovernanceResult,
    GovernanceStageStatus,
    TerraformSecurityGovernanceEndToEndPipeline,
    _print_safe_summary,
    build_default_terraform_security_governance_engine,
    main,
)
from security_governance_report import GovernanceAuditReportBuilder
from security_gcp_pack import build_gcp_security_rule_pack
from security_oci_pack import build_oci_security_rule_pack
from security_policy_e2e import PolicyPipelineStageStatus
from security_policy_models import (
    PolicyDecisionStatus,
    PolicyReasonCode,
    SecurityPolicyProfile,
    SecurityPolicyThresholds,
    build_custom_security_policy,
)
from security_terraform_e2e import TerraformSecurityStageStatus
from terraform_e2e import TerraformEngineStatus
from test_security_governance_report import (
    build_policy_decision,
    build_policy_result,
)


CREATED_AT = datetime(2026, 8, 10, 21, 0, tzinfo=timezone.utc)
REPORT_AT = datetime(2026, 8, 10, 21, 10, tzinfo=timezone.utc)


class FakePolicyPipeline:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = []

    def run(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.result


class TerraformSecurityGovernanceEndToEndTests(unittest.TestCase):
    @staticmethod
    def _workflow_mock():
        workflow = HumanApprovalWorkflow(
            now_factory=lambda: CREATED_AT,
            uuid_factory=lambda: UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        )
        return MagicMock(wraps=workflow)

    @staticmethod
    def _builder_mock(root=None):
        builder = GovernanceAuditReportBuilder(
            repository_root=root,
            now_factory=lambda: REPORT_AT,
            uuid_factory=lambda: UUID("12345678-1234-5678-1234-567812345678"),
        )
        return MagicMock(wraps=builder)

    @classmethod
    def _pipeline(cls, policy_result, *, root=None):
        policy_pipeline = FakePolicyPipeline(policy_result)
        workflow = cls._workflow_mock()
        builder = cls._builder_mock(root)
        pipeline = TerraformSecurityGovernanceEndToEndPipeline(
            policy_pipeline,
            workflow,
            builder,
        )
        return pipeline, policy_pipeline, workflow, builder

    @staticmethod
    def _with_synthetic_runtime_context(policy_result, security_status):
        runtime = SimpleNamespace(
            terraform_final_status="PASS",
            security_evaluation_status=security_status,
        )
        return replace(policy_result, security_pipeline_result=runtime)

    def test_allow_final_flow_is_authorized_without_apply(self):
        decision = build_policy_decision(PolicyDecisionStatus.ALLOW)
        policy_result = self._with_synthetic_runtime_context(
            build_policy_result(decision), TerraformSecurityStageStatus.PASS
        )
        pipeline, *_ = self._pipeline(policy_result)
        result = pipeline.run(" GCP ")
        self.assertEqual(result.engine_status, TerraformEngineStatus.PASS)
        self.assertEqual(result.approval_status, "NOT_REQUIRED")
        self.assertEqual(result.authorization_status, "AUTHORIZED")
        self.assertEqual(result.governance_status, "AUTHORIZED")
        self.assertEqual(result.terraform_final_status, "PASS")
        self.assertFalse(result.apply_executed)
        self.assertFalse(result.authorization.execution_performed)

    def test_baseline_high_stops_at_pending_approval_without_human_action(self):
        decision = build_policy_decision()
        pipeline, _, workflow, _ = self._pipeline(build_policy_result(decision))
        result = pipeline.run("gcp")
        self.assertEqual(result.engine_status, TerraformEngineStatus.PASS)
        self.assertEqual(result.approval_status, "PENDING")
        self.assertEqual(result.authorization_status, "PENDING_APPROVAL")
        self.assertEqual(result.governance_status, "PENDING_APPROVAL")
        workflow.approve.assert_not_called()
        workflow.reject.assert_not_called()
        self.assertFalse(result.auto_approval_executed)

    def test_critical_block_is_business_block_with_engine_pass(self):
        decision = build_policy_decision(PolicyDecisionStatus.BLOCK)
        pipeline, _, workflow, _ = self._pipeline(build_policy_result(decision))
        result = pipeline.run("gcp")
        self.assertEqual(result.engine_status, TerraformEngineStatus.PASS)
        self.assertEqual(result.approval_status, "NOT_ALLOWED")
        self.assertEqual(result.authorization_status, "BLOCKED")
        workflow.approve.assert_not_called()

    def test_strict_high_policy_outcome_is_preserved_as_blocked(self):
        decision = build_policy_decision(
            PolicyDecisionStatus.BLOCK,
            profile=SecurityPolicyProfile.STRICT,
            reason_code=PolicyReasonCode.BLOCK_THRESHOLD_EXCEEDED,
        )
        pipeline, *_ = self._pipeline(build_policy_result(decision))
        result = pipeline.run("gcp")
        self.assertEqual(result.policy_pipeline_result.policy_decision.profile, SecurityPolicyProfile.STRICT)
        self.assertEqual(result.authorization_status, "BLOCKED")

    def test_policy_exception_remains_pending_not_human_approved(self):
        base = build_policy_decision()
        finding = base.triggered_findings[0]
        decision = replace(
            base,
            profile=SecurityPolicyProfile.STRICT,
            reason_code=PolicyReasonCode.APPROVAL_EXCEPTION_APPLIED,
            triggered_rules=(),
            triggered_findings=(),
            applied_exception_ids=("EXC-POLICY6-001",),
            excepted_findings=(finding,),
        )
        pipeline, _, workflow, _ = self._pipeline(build_policy_result(decision))
        result = pipeline.run("gcp")
        self.assertEqual(result.approval_status, "PENDING")
        self.assertEqual(result.authorization_status, "PENDING_APPROVAL")
        workflow.approve.assert_not_called()

    def test_policy4_pipeline_gate_workflow_and_report_are_called_only_as_expected(self):
        policy_result = build_policy_result(build_policy_decision())
        pipeline, policy_pipeline, workflow, builder = self._pipeline(policy_result)
        result = pipeline.run("oci", evaluated_at=CREATED_AT)
        self.assertEqual(
            policy_pipeline.calls,
            [{
                "cloud": "oci",
                "write_security_report": False,
                "write_policy_report": False,
                "evaluated_at": CREATED_AT,
            }],
        )
        workflow.create_request.assert_called_once()
        workflow.build_authorization.assert_called_once()
        workflow.approve.assert_not_called()
        workflow.reject.assert_not_called()
        builder.build.assert_called_once()
        builder.write_report.assert_not_called()
        self.assertIs(result.policy_pipeline_result, policy_result)

    def test_all_report_write_options_are_independent(self):
        for security_write in (False, True):
            for policy_write in (False, True):
                for governance_write in (False, True):
                    with self.subTest(
                        security=security_write,
                        policy=policy_write,
                        governance=governance_write,
                    ), tempfile.TemporaryDirectory() as temporary:
                        pipeline, policy_pipeline, _, builder = self._pipeline(
                            build_policy_result(build_policy_decision()),
                            root=Path(temporary),
                        )
                        result = pipeline.run(
                            "gcp",
                            write_security_report=security_write,
                            write_policy_report=policy_write,
                            write_governance_report=governance_write,
                        )
                        call = policy_pipeline.calls[0]
                        self.assertEqual(call["write_security_report"], security_write)
                        self.assertEqual(call["write_policy_report"], policy_write)
                        self.assertEqual(builder.write_report.call_count, int(governance_write))
                        self.assertEqual(result.governance_report_written, governance_write)
                        self.assertEqual(result.governance_json_path is not None, governance_write)
                        self.assertEqual(result.authorization_status, "PENDING_APPROVAL")

    def test_no_policy_decision_skips_approval_authorization_and_report(self):
        policy_result = replace(
            build_policy_result(build_policy_decision()),
            policy_gate_status=PolicyPipelineStageStatus.SKIPPED,
            policy_report_status=PolicyPipelineStageStatus.SKIPPED,
            policy_decision=None,
            policy_report=None,
        )
        pipeline, _, workflow, builder = self._pipeline(policy_result)
        result = pipeline.run("gcp")
        self.assertEqual(result.engine_status, TerraformEngineStatus.PASS)
        self.assertEqual(result.approval_stage_status, GovernanceStageStatus.SKIPPED)
        self.assertIsNone(result.approval_request)
        self.assertIsNone(result.authorization)
        self.assertEqual(result.governance_status, "SKIPPED")
        workflow.create_request.assert_not_called()
        builder.build.assert_not_called()

    def test_policy_engine_failure_skips_approval_and_remains_fail(self):
        policy_result = replace(
            build_policy_result(build_policy_decision()),
            engine_status=TerraformEngineStatus.FAIL,
        )
        pipeline, _, workflow, builder = self._pipeline(policy_result)
        result = pipeline.run("gcp")
        self.assertEqual(result.engine_status, TerraformEngineStatus.FAIL)
        self.assertEqual(result.approval_stage_status, GovernanceStageStatus.SKIPPED)
        workflow.create_request.assert_not_called()
        builder.build.assert_not_called()

    def test_policy_stage_error_forces_final_fail_without_approval(self):
        policy_result = replace(
            build_policy_result(build_policy_decision()),
            engine_status=TerraformEngineStatus.PASS,
            policy_gate_status=PolicyPipelineStageStatus.ERROR,
        )
        pipeline, _, workflow, builder = self._pipeline(policy_result)
        result = pipeline.run("gcp")
        self.assertEqual(result.engine_status, TerraformEngineStatus.FAIL)
        self.assertEqual(result.approval_stage_status, GovernanceStageStatus.SKIPPED)
        workflow.create_request.assert_not_called()
        builder.build.assert_not_called()

    def test_policy_pipeline_exception_and_invalid_result_are_sanitized(self):
        for source in (
            FakePolicyPipeline(error=RuntimeError("FAKE_SECRET_POLICY6")),
            FakePolicyPipeline(result="invalid"),
        ):
            with self.subTest(source=source):
                pipeline = TerraformSecurityGovernanceEndToEndPipeline(
                    source,
                    self._workflow_mock(),
                    self._builder_mock(),
                )
                result = pipeline.run("gcp")
                self.assertEqual(result.engine_status, TerraformEngineStatus.FAIL)
                self.assertEqual(result.approval_stage_status, GovernanceStageStatus.SKIPPED)
                self.assertNotIn("FAKE_SECRET_POLICY6", result.to_json())

    def test_approval_workflow_error_is_technical_not_business_status(self):
        pipeline, _, workflow, builder = self._pipeline(
            build_policy_result(build_policy_decision())
        )
        workflow.create_request.side_effect = RuntimeError("FAKE_TOKEN_POLICY6")
        result = pipeline.run("gcp")
        self.assertEqual(result.engine_status, TerraformEngineStatus.FAIL)
        self.assertEqual(result.approval_stage_status, GovernanceStageStatus.ERROR)
        self.assertIsNone(result.authorization)
        self.assertEqual(result.governance_status, "ERROR")
        builder.build.assert_not_called()
        self.assertNotIn("FAKE_TOKEN_POLICY6", result.to_json())

    def test_authorization_error_retains_no_partial_request_in_public_result(self):
        pipeline, _, workflow, builder = self._pipeline(
            build_policy_result(build_policy_decision())
        )
        workflow.build_authorization.side_effect = RuntimeError("internal")
        result = pipeline.run("gcp")
        self.assertEqual(result.engine_status, TerraformEngineStatus.FAIL)
        self.assertEqual(result.approval_stage_status, GovernanceStageStatus.ERROR)
        self.assertIsNone(result.authorization)
        builder.build.assert_not_called()

    def test_report_builder_error_retains_policy_approval_and_authorization(self):
        pipeline, _, _, builder = self._pipeline(
            build_policy_result(build_policy_decision())
        )
        builder.build.side_effect = RuntimeError("FAKE_PRIVATE_KEY_POLICY6")
        result = pipeline.run("gcp")
        self.assertEqual(result.engine_status, TerraformEngineStatus.FAIL)
        self.assertEqual(result.approval_stage_status, GovernanceStageStatus.PASS)
        self.assertEqual(result.governance_report_status, GovernanceStageStatus.ERROR)
        self.assertIsNotNone(result.approval_request)
        self.assertIsNotNone(result.authorization)
        self.assertIsNone(result.governance_report)
        self.assertNotIn("FAKE_PRIVATE_KEY_POLICY6", result.to_json())

    def test_report_write_error_retains_in_memory_report_and_authorization(self):
        pipeline, _, _, builder = self._pipeline(
            build_policy_result(build_policy_decision())
        )
        builder.write_report.side_effect = OSError("FAKE_PASSWORD_POLICY6")
        result = pipeline.run("gcp", write_governance_report=True)
        self.assertEqual(result.engine_status, TerraformEngineStatus.FAIL)
        self.assertEqual(result.governance_report_status, GovernanceStageStatus.ERROR)
        self.assertIsNotNone(result.authorization)
        self.assertIsNotNone(result.governance_report)
        self.assertFalse(result.governance_report_written)
        self.assertNotIn("FAKE_PASSWORD_POLICY6", result.to_json())

    def test_final_result_serialization_is_safe_and_immutable(self):
        decision = build_policy_decision(message="FAKE_SECRET_POLICY6")
        pipeline, *_ = self._pipeline(build_policy_result(decision))
        result = pipeline.run("gcp")
        payload = result.to_dict()
        self.assertFalse(any(payload["safety"].values()))
        output = result.to_json()
        for forbidden in (
            "FAKE_SECRET_POLICY6", "raw_stdout", "raw_stderr", "tfstate",
            "tfvars", "planned_values", "attributes", "credentials",
        ):
            self.assertNotIn(forbidden, output)
        with self.assertRaises(FrozenInstanceError):
            result.engine_status = TerraformEngineStatus.FAIL

    def test_safe_summary_contains_only_statuses_ids_and_report_paths(self):
        pipeline, *_ = self._pipeline(build_policy_result(build_policy_decision()))
        result = pipeline.run("gcp")
        output = io.StringIO()
        with patch("sys.stdout", output):
            _print_safe_summary(result)
        text = output.getvalue()
        self.assertIn("authorization_status=PENDING_APPROVAL", text)
        self.assertIn("approval_request_id=approval_", text)
        for forbidden in ("raw_stdout", "tfstate", "attributes", "credentials"):
            self.assertNotIn(forbidden, text)

    def test_invalid_cloud_and_write_flags_fail_before_policy_pipeline(self):
        source = FakePolicyPipeline(build_policy_result(build_policy_decision()))
        pipeline = TerraformSecurityGovernanceEndToEndPipeline(
            source, self._workflow_mock(), self._builder_mock()
        )
        for cloud in ("aws", "", None):
            with self.subTest(cloud=cloud), self.assertRaises(ValueError):
                pipeline.run(cloud)
        for field_name in (
            "write_security_report", "write_policy_report", "write_governance_report"
        ):
            with self.subTest(field=field_name), self.assertRaises(TypeError):
                pipeline.run("gcp", **{field_name: "yes"})
        self.assertEqual(source.calls, [])

    def test_default_factory_supports_baseline_strict_and_custom_policy(self):
        fake_policy_pipeline = FakePolicyPipeline()
        custom = build_custom_security_policy(
            policy_id="INTERNAL_SECURITY_POLICY_CUSTOM_GOVERNANCE",
            policy_version="2.0",
            name="Custom governance policy",
            description="Synthetic custom policy for POLICY-6.",
            thresholds=SecurityPolicyThresholds(
                block_fail_critical=1,
                block_fail_high=2,
                approval_fail_high=1,
                approval_fail_medium=2,
                approval_warning_high=1,
                approval_warning_medium=2,
            ),
        )
        with patch(
            "security_governance_e2e.build_default_terraform_security_policy_engine",
            return_value=fake_policy_pipeline,
        ) as factory:
            baseline = build_default_terraform_security_governance_engine(profile="baseline")
            strict = build_default_terraform_security_governance_engine(profile="strict")
            explicit = build_default_terraform_security_governance_engine(policy=custom)
        self.assertIsInstance(baseline, TerraformSecurityGovernanceEndToEndPipeline)
        self.assertIsInstance(strict.approval_workflow, HumanApprovalWorkflow)
        self.assertIsInstance(explicit.governance_report_builder, GovernanceAuditReportBuilder)
        self.assertEqual(factory.call_args_list[0].kwargs["profile"], "baseline")
        self.assertEqual(factory.call_args_list[1].kwargs["profile"], "strict")
        self.assertIs(factory.call_args_list[2].kwargs["policy"], custom)

    def test_default_factory_auxiliary_components_run_with_system_clocks(self):
        policy_result = build_policy_result(build_policy_decision())
        with patch(
            "security_governance_e2e.build_default_terraform_security_policy_engine",
            return_value=FakePolicyPipeline(policy_result),
        ):
            engine = build_default_terraform_security_governance_engine()
        result = engine.run("gcp")
        self.assertEqual(result.engine_status, TerraformEngineStatus.PASS)
        self.assertEqual(result.authorization_status, "PENDING_APPROVAL")
        self.assertIsNotNone(result.governance_report)

    def test_cli_passes_safe_options_and_returns_engine_status(self):
        result = MagicMock(spec=FinalGovernanceResult)
        result.engine_status = TerraformEngineStatus.PASS
        engine = MagicMock()
        engine.run.return_value = result
        with patch(
            "security_governance_e2e.build_default_terraform_security_governance_engine",
            return_value=engine,
        ) as factory, patch("security_governance_e2e._print_safe_summary"):
            exit_code = main([
                "--cloud", "oci", "--profile", "strict",
                "--write-security-report", "--write-policy-report",
                "--write-governance-report",
            ])
        self.assertEqual(exit_code, 0)
        factory.assert_called_once_with(profile="strict")
        engine.run.assert_called_once_with(
            cloud="oci",
            write_security_report=True,
            write_policy_report=True,
            write_governance_report=True,
        )

    def test_cli_rejects_approval_apply_destroy_force_and_bypass_options(self):
        for option in (
            "--approve", "--auto-approve", "--apply", "--destroy", "--force", "--bypass"
        ):
            with self.subTest(option=option), self.assertRaises(SystemExit):
                main(["--cloud", "gcp", option])

    def test_source_has_no_direct_execution_scan_gate_approval_or_cloud_api(self):
        source = Path(__file__).with_name("security_governance_e2e.py").read_text(encoding="utf-8")
        for forbidden in (
            "subprocess", "TerraformRunner(", "SecurityComplianceScanner(",
            "MultiCloudSecurityEvaluationEngine(", "SecurityPolicyGate(",
            ".approve(", ".reject(", "terraform apply", "terraform destroy",
            "input(", "requests.", "gcloud ", "oci ",
        ):
            self.assertNotIn(forbidden, source)

    def test_rule_inventory_and_gitignore_scope_are_correct(self):
        gcp_rules = build_gcp_security_rule_pack()
        oci_rules = build_oci_security_rule_pack()
        self.assertEqual(len(gcp_rules), 12)
        self.assertEqual(len(oci_rules), 12)
        self.assertEqual(len(gcp_rules) + len(oci_rules), 24)
        gitignore = Path(__file__).parent.parent.joinpath(".gitignore").read_text(encoding="utf-8")
        self.assertIn("/artifacts/governance/reports/", gitignore.splitlines())


if __name__ == "__main__":
    unittest.main()
