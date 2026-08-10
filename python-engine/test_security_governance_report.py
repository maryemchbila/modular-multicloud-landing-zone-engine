"""Tests POLICY-6 du rapport d'audit final de gouvernance."""

import json
import tempfile
import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from security_approval_models import ApprovalStatus, AuthorizationStatus
from security_approval_workflow import HumanApprovalWorkflow
from security_governance_report import (
    GovernanceAuditReport,
    GovernanceAuditReportBuilder,
    InvalidGovernanceReportInputError,
)
from security_models import RuleStatus, SecuritySeverity
from security_policy_e2e import (
    PolicyPipelineStageStatus,
    TerraformSecurityPolicyEndToEndResult,
)
from security_policy_models import (
    PolicyDecision,
    PolicyDecisionStatus,
    PolicyReasonCode,
    PolicyTriggeredFinding,
    SecurityPolicyProfile,
)
from security_policy_report import (
    PolicyDecisionAudit,
    PolicyDecisionReport,
    PolicySecurityContext,
    PolicyTerraformContext,
)
from terraform_e2e import TerraformEngineStatus


CREATED_AT = datetime(2026, 8, 10, 21, 0, tzinfo=timezone.utc)
DECIDED_AT = datetime(2026, 8, 10, 21, 5, tzinfo=timezone.utc)
REPORT_AT = datetime(2026, 8, 10, 21, 10, tzinfo=timezone.utc)
FIXED_UUID = UUID("12345678-1234-5678-1234-567812345678")


def build_policy_decision(status=PolicyDecisionStatus.REQUIRE_APPROVAL, **overrides):
    severity = SecuritySeverity.CRITICAL if status is PolicyDecisionStatus.BLOCK else SecuritySeverity.HIGH
    finding = PolicyTriggeredFinding(
        rule_id="GCP_INTERNAL_NETWORK_001",
        cloud="gcp",
        resource_address="google_compute_network.main",
        severity=severity,
        status=RuleStatus.FAIL,
        title="Synthetic governance finding",
    )
    flags = {
        PolicyDecisionStatus.ALLOW: (False, True),
        PolicyDecisionStatus.REQUIRE_APPROVAL: (True, False),
        PolicyDecisionStatus.BLOCK: (False, False),
    }[status]
    reason = {
        PolicyDecisionStatus.ALLOW: PolicyReasonCode.ALLOW_BASELINE_MET,
        PolicyDecisionStatus.REQUIRE_APPROVAL: PolicyReasonCode.APPROVAL_REQUIRED,
        PolicyDecisionStatus.BLOCK: PolicyReasonCode.BLOCK_CRITICAL_FINDING,
    }[status]
    findings = () if status is PolicyDecisionStatus.ALLOW else (finding,)
    values = {
        "decision": status,
        "policy_id": "INTERNAL_SECURITY_POLICY_BASELINE",
        "policy_version": "1.0",
        "reason_code": reason,
        "message": "Synthetic final governance decision.",
        "triggered_rules": tuple(item.rule_id for item in findings),
        "triggered_findings": findings,
        "severity_summary": {
            "CRITICAL": int(status is PolicyDecisionStatus.BLOCK),
            "HIGH": int(status is PolicyDecisionStatus.REQUIRE_APPROVAL),
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        },
        "requires_human_approval": flags[0],
        "deployment_allowed": flags[1],
        "profile": SecurityPolicyProfile.BASELINE,
        "evaluation_time": "2026-08-10T20:58:00Z",
    }
    values.update(overrides)
    return PolicyDecision(**values)


def build_policy_report(decision, *, terraform=True):
    return PolicyDecisionReport(
        schema_version="1.0",
        run_id="policy_20260810T205900Z_deadbeef",
        generated_at="2026-08-10T20:59:00Z",
        policy={
            "policy_id": decision.policy_id,
            "policy_version": decision.policy_version,
            "profile": decision.profile.value,
            "enabled": True,
            "name": "Synthetic governance policy",
            "description": "Synthetic report fixture.",
        },
        decision={
            "status": decision.decision.value,
            "reason_code": decision.reason_code.value,
            "message": decision.message,
            "requires_human_approval": decision.requires_human_approval,
            "deployment_allowed": decision.deployment_allowed,
            "triggered_rules": list(decision.triggered_rules),
        },
        thresholds={},
        security_context=PolicySecurityContext(
            security_evaluation_status=("PASS" if decision.decision is PolicyDecisionStatus.ALLOW else "FAIL"),
            clouds_evaluated=("gcp",),
            resources_total=1,
            findings_total=len(decision.triggered_findings),
            critical_count=int(decision.decision is PolicyDecisionStatus.BLOCK),
            high_count=int(decision.decision is PolicyDecisionStatus.REQUIRE_APPROVAL),
            medium_count=0,
            security_run_id="security_multicloud_20260810T205800Z_deadbeef",
        ),
        terraform_context=(
            PolicyTerraformContext(
                terraform_run_id="tfplan_gcp_20260810T205700Z_abcdef12",
                terraform_final_status="PASS",
                plan_status="CHANGES_DETECTED",
                plan_exit_code=2,
            )
            if terraform
            else None
        ),
        triggered_findings=decision.triggered_findings,
        applied_exception_ids=decision.applied_exception_ids,
        applied_exceptions=(),
        excepted_findings=decision.excepted_findings,
        audit=PolicyDecisionAudit(
            decision_evaluated_at=decision.evaluation_time,
            policy_report_generated_at="2026-08-10T20:59:00Z",
            decision_source="SecurityPolicyGate",
            profile=decision.profile.value,
            exceptions_applied_count=len(decision.applied_exception_ids),
            triggered_findings_count=len(decision.triggered_findings),
            excepted_findings_count=len(decision.excepted_findings),
        ),
    )


def build_policy_result(decision, *, terraform=True, engine_status=TerraformEngineStatus.PASS):
    report = build_policy_report(decision, terraform=terraform)
    return TerraformSecurityPolicyEndToEndResult(
        engine_status=engine_status,
        cloud="gcp",
        security_pipeline_result=None,
        policy_gate_status=PolicyPipelineStageStatus.PASS,
        policy_report_status=PolicyPipelineStageStatus.PASS,
        policy_decision=decision,
        policy_report=report,
        policy_report_written=False,
        policy_json_path=None,
        policy_text_path=None,
        duration_seconds=0.1,
    )


class GovernanceAuditReportTests(unittest.TestCase):
    @staticmethod
    def _workflow():
        return HumanApprovalWorkflow(
            now_factory=lambda: CREATED_AT,
            uuid_factory=lambda: UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        )

    @staticmethod
    def _builder(root=None):
        return GovernanceAuditReportBuilder(
            repository_root=root,
            now_factory=lambda: REPORT_AT,
            uuid_factory=lambda: FIXED_UUID,
        )

    @classmethod
    def _initial_objects(cls, status=PolicyDecisionStatus.REQUIRE_APPROVAL, **decision_overrides):
        decision = build_policy_decision(status, **decision_overrides)
        policy_result = build_policy_result(decision)
        workflow = cls._workflow()
        request = workflow.create_request(decision, policy_report=policy_result.policy_report)
        authorization = workflow.build_authorization(request, decision=decision)
        return decision, policy_result, workflow, request, authorization

    def test_schema_run_id_timestamp_and_model_immutability(self):
        _, result, _, request, authorization = self._initial_objects()
        report = self._builder().build(
            policy_pipeline_result=result,
            approval_request=request,
            authorization=authorization,
        )
        self.assertIsInstance(report, GovernanceAuditReport)
        self.assertEqual(report.schema_version, "1.0")
        self.assertEqual(report.run_id, "governance_20260810T211000Z_12345678")
        self.assertEqual(report.generated_at, "2026-08-10T21:10:00Z")
        with self.assertRaises(FrozenInstanceError):
            report.run_id = "changed"
        with self.assertRaises(TypeError):
            report.safety["terraform_apply_executed"] = True

    def test_all_safe_contexts_and_run_correlations_are_present(self):
        _, result, _, request, authorization = self._initial_objects()
        report = self._builder().build(
            policy_pipeline_result=result,
            approval_request=request,
            authorization=authorization,
        )
        payload = report.to_dict()
        self.assertEqual(payload["terraform"]["run_id"], request.terraform_run_id)
        self.assertEqual(payload["security"]["run_id"], request.security_run_id)
        self.assertEqual(payload["policy"]["run_id"], request.policy_report_run_id)
        self.assertEqual(payload["approval"]["request_id"], request.request_id)
        self.assertEqual(payload["authorization"]["status"], "PENDING_APPROVAL")

    def test_pending_report_requires_human_action_without_approver(self):
        _, result, _, request, authorization = self._initial_objects()
        report = self._builder().build(
            policy_pipeline_result=result,
            approval_request=request,
            authorization=authorization,
        )
        approval = report.to_dict()["approval"]
        self.assertEqual(approval["status"], "PENDING")
        self.assertTrue(approval["human_action_required"])
        self.assertNotIn("approver_id", approval)
        self.assertIn("Human action required : YES", report.render_text())

    def test_allow_report_is_authorized_without_human_action_or_execution(self):
        _, result, _, request, authorization = self._initial_objects(PolicyDecisionStatus.ALLOW)
        report = self._builder().build(
            policy_pipeline_result=result,
            approval_request=request,
            authorization=authorization,
        )
        payload = report.to_dict()
        self.assertEqual(payload["approval"]["status"], "NOT_REQUIRED")
        self.assertFalse(payload["approval"]["human_action_required"])
        self.assertEqual(payload["authorization"]["status"], "AUTHORIZED")
        self.assertFalse(payload["authorization"]["execution_performed"])

    def test_block_report_is_blocked_by_policy_without_approver(self):
        _, result, _, request, authorization = self._initial_objects(PolicyDecisionStatus.BLOCK)
        report = self._builder().build(
            policy_pipeline_result=result,
            approval_request=request,
            authorization=authorization,
        )
        payload = report.to_dict()
        self.assertEqual(payload["approval"]["status"], "NOT_ALLOWED")
        self.assertEqual(payload["authorization"]["status"], "BLOCKED")
        self.assertNotIn("approver_id", payload["approval"])
        self.assertIn("Blocked by policy : YES", report.render_text())

    def test_approved_offline_report_contains_real_human_audit(self):
        decision, result, workflow, pending, _ = self._initial_objects()
        approved, record = workflow.approve(
            pending,
            approver_id="reviewer-001",
            reason="Reviewed and accepted residual risk.",
            decided_at=DECIDED_AT,
        )
        authorization = workflow.build_authorization(
            approved,
            decision=decision,
            approval_record=record,
        )
        report = self._builder().build(
            policy_pipeline_result=result,
            approval_request=approved,
            approval_record=record,
            authorization=authorization,
        )
        approval = report.to_dict()["approval"]
        self.assertEqual(approval["status"], "APPROVED")
        self.assertEqual(approval["action"], "APPROVE")
        self.assertEqual(approval["approver_id"], "reviewer-001")
        self.assertEqual(approval["decided_at"], "2026-08-10T21:05:00Z")
        self.assertEqual(report.authorization["status"], "AUTHORIZED")
        self.assertFalse(report.authorization["execution_performed"])

    def test_rejected_offline_report_is_not_authorized(self):
        decision, result, workflow, pending, _ = self._initial_objects()
        rejected, record = workflow.reject(
            pending,
            approver_id="reviewer-002",
            reason="Residual risk is not acceptable.",
            decided_at=DECIDED_AT,
        )
        authorization = workflow.build_authorization(
            rejected,
            decision=decision,
            approval_record=record,
        )
        report = self._builder().build(
            policy_pipeline_result=result,
            approval_request=rejected,
            approval_record=record,
            authorization=authorization,
        )
        self.assertEqual(report.approval["status"], "REJECTED")
        self.assertEqual(report.authorization["status"], "REJECTED")
        self.assertFalse(report.authorization["authorized"])

    def test_expired_offline_report_is_not_authorized(self):
        decision = build_policy_decision()
        result = build_policy_result(decision)
        workflow = self._workflow()
        pending = workflow.create_request(
            decision,
            policy_report=result.policy_report,
            expires_at=datetime(2026, 8, 10, 21, 2, tzinfo=timezone.utc),
        )
        expired = workflow.check_expiration(
            pending,
            evaluated_at=datetime(2026, 8, 10, 21, 3, tzinfo=timezone.utc),
        )
        authorization = workflow.build_authorization(expired, decision=decision)
        report = self._builder().build(
            policy_pipeline_result=result,
            approval_request=expired,
            authorization=authorization,
        )
        self.assertEqual(report.approval["status"], "EXPIRED")
        self.assertEqual(report.authorization["status"], "EXPIRED")

    def test_json_and_text_are_deterministic_with_injected_sources(self):
        _, result, _, request, authorization = self._initial_objects()
        first = self._builder().build(
            policy_pipeline_result=result,
            approval_request=request,
            authorization=authorization,
        )
        second = self._builder().build(
            policy_pipeline_result=result,
            approval_request=request,
            authorization=authorization,
        )
        self.assertEqual(first.to_json(), second.to_json())
        self.assertEqual(first.render_text(), second.render_text())
        self.assertEqual(json.loads(first.to_json()), first.to_dict())

    def test_atomic_write_creates_same_basename_and_no_temp_residue(self):
        _, result, _, request, authorization = self._initial_objects()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            builder = self._builder(root)
            report = builder.build(
                policy_pipeline_result=result,
                approval_request=request,
                authorization=authorization,
            )
            json_path, text_path = builder.write_report(report)
            self.assertEqual(json_path.parent, root / "artifacts/governance/reports")
            self.assertEqual(json_path.stem, text_path.stem)
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8")), report.to_dict())
            self.assertEqual(text_path.read_text(encoding="utf-8").rstrip(), report.render_text())
            self.assertEqual(list(json_path.parent.glob("*.tmp")), [])

    def test_missing_terraform_context_remains_none(self):
        decision = build_policy_decision()
        result = build_policy_result(decision, terraform=False)
        workflow = self._workflow()
        request = workflow.create_request(decision, policy_report=result.policy_report)
        authorization = workflow.build_authorization(request, decision=decision)
        report = self._builder().build(
            policy_pipeline_result=result,
            approval_request=request,
            authorization=authorization,
        )
        self.assertIsNone(report.terraform)
        self.assertIsNone(report.to_dict()["terraform"])

    def test_request_policy_authorization_and_record_mismatches_are_rejected(self):
        decision, result, workflow, pending, authorization = self._initial_objects()
        other_request = replace(pending, request_id="approval_20260810T210000Z_bbbbbbbb")
        with self.assertRaises(InvalidGovernanceReportInputError):
            self._builder().build(
                policy_pipeline_result=result,
                approval_request=other_request,
                authorization=authorization,
            )
        approved, record = workflow.approve(
            pending,
            approver_id="reviewer-001",
            reason="Accepted residual risk.",
            decided_at=DECIDED_AT,
        )
        approved_authorization = workflow.build_authorization(
            approved, decision=decision, approval_record=record
        )
        wrong_record = replace(record, request_id="approval_20260810T210000Z_bbbbbbbb")
        with self.assertRaises(InvalidGovernanceReportInputError):
            self._builder().build(
                policy_pipeline_result=result,
                approval_request=approved,
                approval_record=wrong_record,
                authorization=approved_authorization,
            )

    def test_record_presence_must_match_approval_status(self):
        decision, result, workflow, pending, authorization = self._initial_objects()
        approved, record = workflow.approve(
            pending,
            approver_id="reviewer-001",
            reason="Accepted residual risk.",
            decided_at=DECIDED_AT,
        )
        with self.assertRaises(InvalidGovernanceReportInputError):
            self._builder().build(
                policy_pipeline_result=result,
                approval_request=pending,
                approval_record=record,
                authorization=authorization,
            )
        approved_authorization = workflow.build_authorization(
            approved, decision=decision, approval_record=record
        )
        with self.assertRaises(InvalidGovernanceReportInputError):
            self._builder().build(
                policy_pipeline_result=result,
                approval_request=approved,
                authorization=approved_authorization,
            )

    def test_secret_source_values_never_reach_any_report_output(self):
        secrets = (
            "FAKE_PASSWORD_POLICY6",
            "FAKE_TOKEN_POLICY6",
            "FAKE_PRIVATE_KEY_POLICY6",
            "FAKE_SECRET_POLICY6",
        )
        decision = build_policy_decision(message=" ".join(secrets))
        result = build_policy_result(decision)
        workflow = self._workflow()
        request = workflow.create_request(decision, policy_report=result.policy_report)
        authorization = workflow.build_authorization(request, decision=decision)
        with tempfile.TemporaryDirectory() as temporary:
            builder = self._builder(Path(temporary))
            report = builder.build(
                policy_pipeline_result=result,
                approval_request=request,
                authorization=authorization,
            )
            json_path, text_path = builder.write_report(report)
            output = "\n".join(
                (
                    json.dumps(report.to_dict()),
                    report.to_json(),
                    report.render_text(),
                    json_path.read_text(encoding="utf-8"),
                    text_path.read_text(encoding="utf-8"),
                )
            )
        for secret in secrets:
            self.assertNotIn(secret, output)

    def test_raw_runtime_fields_are_absent_from_all_serializations(self):
        _, result, _, request, authorization = self._initial_objects()
        report = self._builder().build(
            policy_pipeline_result=result,
            approval_request=request,
            authorization=authorization,
        )
        outputs = report.to_json() + report.render_text()
        for forbidden in (
            "raw show", "raw_stdout", "raw_stderr", "tfstate", "tfvars",
            "attributes", "credentials", "private_key", "environment",
        ):
            self.assertNotIn(forbidden, outputs.casefold())

    def test_invalid_clock_uuid_schema_and_safety_are_rejected(self):
        _, result, _, request, authorization = self._initial_objects()
        with self.assertRaises(InvalidGovernanceReportInputError):
            GovernanceAuditReportBuilder(now_factory=lambda: REPORT_AT.replace(tzinfo=None)).build(
                policy_pipeline_result=result,
                approval_request=request,
                authorization=authorization,
            )
        with self.assertRaises(InvalidGovernanceReportInputError):
            GovernanceAuditReportBuilder(uuid_factory=lambda: "bad").build(
                policy_pipeline_result=result,
                approval_request=request,
                authorization=authorization,
            )
        report = self._builder().build(
            policy_pipeline_result=result,
            approval_request=request,
            authorization=authorization,
        )
        with self.assertRaises(InvalidGovernanceReportInputError):
            replace(report, schema_version="2.0")
        bad_safety = dict(report.safety)
        bad_safety["terraform_apply_executed"] = True
        with self.assertRaises(InvalidGovernanceReportInputError):
            replace(report, safety=bad_safety)


if __name__ == "__main__":
    unittest.main()
