"""Tests de la machine d'etats et des correlations POLICY-5."""

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

from security_approval_models import (
    ApprovalCorrelationError,
    ApprovalNotAllowedError,
    ApprovalStatus,
    AuthorizationStatus,
    InvalidApprovalModelError,
    InvalidApprovalTransitionError,
)
from security_approval_workflow import HumanApprovalWorkflow
from security_gcp_pack import build_gcp_security_rule_pack
from security_models import RuleStatus, SecuritySeverity
from security_oci_pack import build_oci_security_rule_pack
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


CREATED_AT = datetime(2026, 8, 10, 21, 0, tzinfo=timezone.utc)
DECIDED_AT = datetime(2026, 8, 10, 21, 5, tzinfo=timezone.utc)
EXPIRES_AT = datetime(2026, 8, 10, 22, 0, tzinfo=timezone.utc)
AFTER_EXPIRY = datetime(2026, 8, 10, 22, 1, tzinfo=timezone.utc)
FIXED_UUID = UUID("12345678-1234-5678-1234-567812345678")


class HumanApprovalWorkflowTests(unittest.TestCase):
    @staticmethod
    def _finding(*, severity=SecuritySeverity.HIGH, title="Safe policy finding"):
        return PolicyTriggeredFinding(
            rule_id="GCP_INTERNAL_NETWORK_001",
            cloud="gcp",
            resource_address="google_compute_network.main",
            severity=severity,
            status=RuleStatus.FAIL,
            title=title,
        )

    @classmethod
    def _decision(cls, status=PolicyDecisionStatus.REQUIRE_APPROVAL, **overrides):
        finding = cls._finding(
            severity=(SecuritySeverity.CRITICAL if status is PolicyDecisionStatus.BLOCK else SecuritySeverity.HIGH)
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
        triggered_findings = () if status is PolicyDecisionStatus.ALLOW else (finding,)
        values = {
            "decision": status,
            "policy_id": "INTERNAL_SECURITY_POLICY_BASELINE",
            "policy_version": "1.0",
            "reason_code": reason,
            "message": "Synthetic POLICY-5 decision.",
            "triggered_rules": tuple(item.rule_id for item in triggered_findings),
            "triggered_findings": triggered_findings,
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
            "evaluation_time": "2026-08-10T20:59:00Z",
        }
        values.update(overrides)
        return PolicyDecision(**values)

    @staticmethod
    def _workflow(*, uuid_factory=None):
        return HumanApprovalWorkflow(
            now_factory=lambda: CREATED_AT,
            uuid_factory=uuid_factory or (lambda: FIXED_UUID),
        )

    @classmethod
    def _report(cls, decision):
        return PolicyDecisionReport(
            schema_version="1.0",
            run_id="policy_20260810T205900Z_deadbeef",
            generated_at="2026-08-10T20:59:00Z",
            policy={
                "policy_id": decision.policy_id,
                "policy_version": decision.policy_version,
                "profile": decision.profile.value,
                "enabled": True,
                "name": "Synthetic policy",
                "description": "Synthetic POLICY-5 report context.",
            },
            decision={
                "status": decision.decision.value,
                "reason_code": decision.reason_code.value,
                "message": "Synthetic report decision.",
                "requires_human_approval": decision.requires_human_approval,
                "deployment_allowed": decision.deployment_allowed,
                "triggered_rules": list(decision.triggered_rules),
            },
            thresholds={},
            security_context=PolicySecurityContext(
                security_evaluation_status="FAIL",
                clouds_evaluated=("gcp",),
                resources_total=1,
                findings_total=len(decision.triggered_findings),
                critical_count=int(decision.decision is PolicyDecisionStatus.BLOCK),
                high_count=int(decision.decision is PolicyDecisionStatus.REQUIRE_APPROVAL),
                medium_count=0,
                security_run_id="security_multicloud_20260810T205800Z_deadbeef",
            ),
            terraform_context=PolicyTerraformContext(
                terraform_run_id="tfplan_gcp_20260810T205700Z_abcdef12",
                terraform_final_status="PASS",
                plan_status="CHANGES_DETECTED",
                plan_exit_code=2,
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

    def test_allow_maps_to_not_required_then_authorized_without_execution(self):
        decision = self._decision(PolicyDecisionStatus.ALLOW)
        workflow = self._workflow()
        request = workflow.create_request(decision)
        authorization = workflow.build_authorization(request, decision=decision)
        self.assertEqual(request.status, ApprovalStatus.NOT_REQUIRED)
        self.assertFalse(request.approval_required)
        self.assertEqual(authorization.authorization_status, AuthorizationStatus.AUTHORIZED)
        self.assertTrue(authorization.authorized)
        self.assertFalse(authorization.execution_performed)
        self.assertFalse(authorization.terraform_apply_executed)

    def test_allow_cannot_be_approved_or_rejected(self):
        request = self._workflow().create_request(self._decision(PolicyDecisionStatus.ALLOW))
        for method in (self._workflow().approve, self._workflow().reject):
            with self.subTest(method=method.__name__), self.assertRaises(ApprovalNotAllowedError):
                method(request, approver_id="reviewer-001", reason="Explicit review action.")

    def test_require_approval_starts_pending_with_pending_authorization(self):
        decision = self._decision()
        workflow = self._workflow()
        request = workflow.create_request(decision, expires_at=EXPIRES_AT)
        authorization = workflow.build_authorization(request, decision=decision)
        self.assertEqual(request.status, ApprovalStatus.PENDING)
        self.assertTrue(request.approval_required)
        self.assertEqual(authorization.authorization_status, AuthorizationStatus.PENDING_APPROVAL)
        self.assertFalse(authorization.authorized)

    def test_explicit_approve_creates_record_new_request_and_authorization(self):
        decision = self._decision()
        workflow = self._workflow()
        original = workflow.create_request(decision, expires_at=EXPIRES_AT)
        approved, record = workflow.approve(
            original,
            approver_id="reviewer-001",
            reason="Reviewed security exception and accepted residual risk.",
            decided_at=DECIDED_AT,
        )
        authorization = workflow.build_authorization(
            approved,
            decision=decision,
            approval_record=record,
        )
        self.assertEqual(original.status, ApprovalStatus.PENDING)
        self.assertEqual(approved.status, ApprovalStatus.APPROVED)
        self.assertIsNot(original, approved)
        self.assertEqual(record.request_id, original.request_id)
        self.assertEqual(record.previous_status, ApprovalStatus.PENDING)
        self.assertEqual(record.new_status, ApprovalStatus.APPROVED)
        self.assertEqual(authorization.authorization_status, AuthorizationStatus.AUTHORIZED)
        self.assertEqual(authorization.approver_id, "reviewer-001")
        self.assertFalse(authorization.execution_performed)
        self.assertFalse(authorization.cloud_write_executed)

    def test_explicit_reject_creates_rejected_authorization(self):
        decision = self._decision()
        workflow = self._workflow()
        pending = workflow.create_request(decision)
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
        self.assertEqual(rejected.status, ApprovalStatus.REJECTED)
        self.assertEqual(authorization.authorization_status, AuthorizationStatus.REJECTED)
        self.assertFalse(authorization.authorized)

    def test_block_maps_to_not_allowed_and_blocked(self):
        decision = self._decision(PolicyDecisionStatus.BLOCK)
        workflow = self._workflow()
        request = workflow.create_request(decision)
        authorization = workflow.build_authorization(request, decision=decision)
        self.assertEqual(request.status, ApprovalStatus.NOT_ALLOWED)
        self.assertEqual(authorization.authorization_status, AuthorizationStatus.BLOCKED)
        self.assertFalse(authorization.authorized)

    def test_block_can_never_be_approved_or_rejected(self):
        request = self._workflow().create_request(self._decision(PolicyDecisionStatus.BLOCK))
        for method in (self._workflow().approve, self._workflow().reject):
            with self.subTest(method=method.__name__), self.assertRaises(ApprovalNotAllowedError):
                method(request, approver_id="reviewer-001", reason="Explicit review action.")

    def test_critical_block_invariant_cannot_be_forged_as_authorized(self):
        decision = self._decision(PolicyDecisionStatus.BLOCK)
        request = self._workflow().create_request(decision)
        with self.assertRaises(InvalidApprovalModelError):
            replace(request, status=ApprovalStatus.APPROVED)

    def test_approval_and_rejection_require_identity_and_reason(self):
        pending = self._workflow().create_request(self._decision())
        for method in (self._workflow().approve, self._workflow().reject):
            for kwargs in (
                {"approver_id": "", "reason": "Valid review reason."},
                {"approver_id": "reviewer-001", "reason": ""},
            ):
                with self.subTest(method=method.__name__, kwargs=kwargs), self.assertRaises(InvalidApprovalModelError):
                    method(pending, decided_at=DECIDED_AT, **kwargs)

    def test_expiration_creates_new_terminal_request_and_expired_authorization(self):
        decision = self._decision()
        workflow = self._workflow()
        pending = workflow.create_request(decision, expires_at=EXPIRES_AT)
        expired = workflow.check_expiration(pending, evaluated_at=AFTER_EXPIRY)
        authorization = workflow.build_authorization(expired, decision=decision)
        self.assertEqual(pending.status, ApprovalStatus.PENDING)
        self.assertEqual(expired.status, ApprovalStatus.EXPIRED)
        self.assertEqual(authorization.authorization_status, AuthorizationStatus.EXPIRED)
        self.assertFalse(authorization.authorized)

    def test_not_yet_expired_request_is_returned_unchanged(self):
        workflow = self._workflow()
        pending = workflow.create_request(self._decision(), expires_at=EXPIRES_AT)
        checked = workflow.check_expiration(
            pending,
            evaluated_at=EXPIRES_AT - timedelta(seconds=1),
        )
        self.assertIs(checked, pending)

    def test_expired_request_cannot_be_approved_or_rejected(self):
        workflow = self._workflow()
        pending = workflow.create_request(self._decision(), expires_at=EXPIRES_AT)
        for method in (workflow.approve, workflow.reject):
            with self.subTest(method=method.__name__), self.assertRaises(InvalidApprovalTransitionError):
                method(
                    pending,
                    approver_id="reviewer-001",
                    reason="Explicit review action.",
                    decided_at=AFTER_EXPIRY,
                )

    def test_replay_protection_rejects_every_terminal_human_transition(self):
        workflow = self._workflow()
        pending = workflow.create_request(self._decision())
        approved, _ = workflow.approve(
            pending,
            approver_id="reviewer-001",
            reason="Accepted residual risk.",
            decided_at=DECIDED_AT,
        )
        rejected, _ = workflow.reject(
            pending,
            approver_id="reviewer-002",
            reason="Rejected residual risk.",
            decided_at=DECIDED_AT,
        )
        for terminal in (approved, rejected):
            for method in (workflow.approve, workflow.reject):
                with self.subTest(status=terminal.status, method=method.__name__), self.assertRaises(InvalidApprovalTransitionError):
                    method(
                        terminal,
                        approver_id="reviewer-003",
                        reason="Replay attempt rejected.",
                        decided_at=DECIDED_AT,
                    )

    def test_transition_timestamp_cannot_precede_request(self):
        pending = self._workflow().create_request(self._decision())
        with self.assertRaises(InvalidApprovalTransitionError):
            self._workflow().approve(
                pending,
                approver_id="reviewer-001",
                reason="Explicit review action.",
                decided_at=CREATED_AT - timedelta(seconds=1),
            )

    def test_report_run_security_and_terraform_correlations_are_projected(self):
        decision = self._decision()
        report = self._report(decision)
        request = self._workflow().create_request(decision, policy_report=report)
        self.assertEqual(request.policy_report_run_id, report.run_id)
        self.assertEqual(request.security_run_id, report.security_context.security_run_id)
        self.assertEqual(request.terraform_run_id, report.terraform_context.terraform_run_id)

    def test_policy_report_is_optional_and_never_read_from_disk(self):
        request = self._workflow().create_request(self._decision())
        self.assertIsNone(request.policy_report_run_id)
        self.assertIsNone(request.security_run_id)
        self.assertIsNone(request.terraform_run_id)

    def test_incoherent_policy_report_is_rejected(self):
        decision = self._decision()
        report = self._report(decision)
        bad_policy = dict(report.policy)
        bad_policy["policy_version"] = "9.9"
        with self.assertRaises(ApprovalCorrelationError):
            self._workflow().create_request(
                decision,
                policy_report=replace(report, policy=bad_policy),
            )

    def test_policy_id_and_version_mismatch_are_rejected_at_authorization(self):
        decision = self._decision()
        workflow = self._workflow()
        request = workflow.create_request(decision)
        for changed in (
            replace(decision, policy_id="OTHER_POLICY"),
            replace(decision, policy_version="9.9"),
        ):
            with self.subTest(changed=changed), self.assertRaises(ApprovalCorrelationError):
                workflow.build_authorization(request, decision=changed)

    def test_approval_record_cannot_transfer_between_request_ids(self):
        uuids = iter(
            (
                UUID("11111111-1111-1111-1111-111111111111"),
                UUID("22222222-2222-2222-2222-222222222222"),
            )
        )
        workflow = self._workflow(uuid_factory=lambda: next(uuids))
        decision = self._decision()
        request_a = workflow.create_request(decision)
        request_b = workflow.create_request(decision)
        _, record_a = workflow.approve(
            request_a,
            approver_id="reviewer-001",
            reason="Accepted request A.",
            decided_at=DECIDED_AT,
        )
        approved_b, _ = workflow.approve(
            request_b,
            approver_id="reviewer-002",
            reason="Accepted request B.",
            decided_at=DECIDED_AT,
        )
        with self.assertRaises(ApprovalCorrelationError):
            workflow.build_authorization(
                approved_b,
                decision=decision,
                approval_record=record_a,
            )

    def test_approved_or_rejected_authorization_requires_matching_record(self):
        workflow = self._workflow()
        decision = self._decision()
        pending = workflow.create_request(decision)
        approved, _ = workflow.approve(
            pending,
            approver_id="reviewer-001",
            reason="Accepted residual risk.",
            decided_at=DECIDED_AT,
        )
        with self.assertRaises(ApprovalCorrelationError):
            workflow.build_authorization(approved, decision=decision)

    def test_request_ids_are_unique_with_injected_uuid_and_stable_per_request(self):
        uuids = iter(
            (
                UUID("11111111-1111-1111-1111-111111111111"),
                UUID("22222222-2222-2222-2222-222222222222"),
            )
        )
        workflow = self._workflow(uuid_factory=lambda: next(uuids))
        first = workflow.create_request(self._decision())
        second = workflow.create_request(self._decision())
        self.assertEqual(first.request_id, "approval_20260810T210000Z_11111111")
        self.assertEqual(second.request_id, "approval_20260810T210000Z_22222222")
        self.assertNotEqual(first.request_id, second.request_id)
        self.assertEqual(first.to_dict()["request_id"], first.request_id)

    def test_exception_decision_remains_distinct_then_requires_explicit_approval(self):
        excepted = self._finding()
        decision = self._decision(
            reason_code=PolicyReasonCode.APPROVAL_EXCEPTION_APPLIED,
            triggered_rules=(),
            triggered_findings=(),
            applied_exception_ids=("EXC-POLICY5-001",),
            excepted_findings=(excepted,),
        )
        workflow = self._workflow()
        pending = workflow.create_request(decision)
        approved, record = workflow.approve(
            pending,
            approver_id="reviewer-001",
            reason="Reviewed exception and accepted residual risk.",
            decided_at=DECIDED_AT,
        )
        authorization = workflow.build_authorization(
            approved,
            decision=decision,
            approval_record=record,
        )
        self.assertEqual(pending.status, ApprovalStatus.PENDING)
        self.assertEqual(authorization.authorization_status, AuthorizationStatus.AUTHORIZED)
        self.assertFalse(authorization.terraform_apply_executed)

    def test_scope_contains_only_safe_projection_not_raw_findings(self):
        request = self._workflow().create_request(self._decision())
        payload = request.to_dict()["scope"]
        self.assertEqual(payload["clouds"], ["gcp"])
        self.assertEqual(payload["triggered_rule_ids"], ["GCP_INTERNAL_NETWORK_001"])
        self.assertEqual(payload["resource_addresses"], ["google_compute_network.main"])
        self.assertNotIn("title", payload)
        self.assertNotIn("message", payload)
        self.assertNotIn("attributes", payload)

    def test_source_decision_secrets_never_propagate_to_workflow_outputs(self):
        secrets = (
            "FAKE_PASSWORD_POLICY5",
            "FAKE_TOKEN_POLICY5",
            "FAKE_PRIVATE_KEY_POLICY5",
            "FAKE_SECRET_POLICY5",
        )
        decision = self._decision(
            message=" ".join(secrets),
            triggered_findings=(self._finding(title=" ".join(secrets)),),
        )
        workflow = self._workflow()
        pending = workflow.create_request(decision)
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
        output = pending.to_json() + record.to_json() + authorization.to_json()
        for secret in secrets:
            self.assertNotIn(secret, output)

    def test_factories_must_return_expected_types(self):
        with self.assertRaises(InvalidApprovalModelError):
            HumanApprovalWorkflow(now_factory=lambda: "bad").create_request(self._decision())
        with self.assertRaises(InvalidApprovalModelError):
            HumanApprovalWorkflow(uuid_factory=lambda: "bad").create_request(self._decision())

    def test_source_has_no_execution_scanner_network_prompt_or_persistence(self):
        sources = "\n".join(
            Path(__file__).with_name(name).read_text(encoding="utf-8")
            for name in ("security_approval_models.py", "security_approval_workflow.py")
        )
        for forbidden in (
            "subprocess", "TerraformRunner(", "SecurityPolicyGate(",
            "SecurityComplianceScanner(", "input(", "requests.", "http://", "https://",
            "sqlite3", "psycopg", "redis", "gcloud ", "oci ",
            "terraform apply", "terraform destroy",
        ):
            self.assertNotIn(forbidden, sources)

    def test_rule_inventory_remains_unchanged(self):
        gcp_rules = build_gcp_security_rule_pack()
        oci_rules = build_oci_security_rule_pack()
        self.assertEqual(len(gcp_rules), 12)
        self.assertEqual(len(oci_rules), 12)
        self.assertEqual(len(gcp_rules) + len(oci_rules), 24)


if __name__ == "__main__":
    unittest.main()
