"""Tests unitaires des modeles immuables POLICY-5."""

import json
import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone

from security_approval_models import (
    ApprovalAction,
    ApprovalRecord,
    ApprovalRequest,
    ApprovalScope,
    ApprovalStatus,
    AuthorizationStatus,
    ControlledAuthorization,
    InvalidApprovalModelError,
)
from security_policy_models import (
    PolicyDecisionStatus,
    PolicyReasonCode,
    SecurityPolicyProfile,
)


CREATED_AT = datetime(2026, 8, 10, 21, 0, tzinfo=timezone.utc)
DECIDED_AT = datetime(2026, 8, 10, 21, 5, tzinfo=timezone.utc)
EXPIRES_AT = datetime(2026, 8, 10, 22, 0, tzinfo=timezone.utc)
REQUEST_ID = "approval_20260810T210000Z_12345678"


class SecurityApprovalModelTests(unittest.TestCase):
    @staticmethod
    def _request(**overrides):
        values = {
            "request_id": REQUEST_ID,
            "policy_report_run_id": "policy_20260810T205900Z_deadbeef",
            "security_run_id": "security_multicloud_20260810T205800Z_deadbeef",
            "terraform_run_id": "tfplan_gcp_20260810T205700Z_abcdef12",
            "policy_id": "INTERNAL_SECURITY_POLICY_BASELINE",
            "policy_version": "1.0",
            "profile": SecurityPolicyProfile.BASELINE,
            "policy_decision": PolicyDecisionStatus.REQUIRE_APPROVAL,
            "reason_code": PolicyReasonCode.APPROVAL_REQUIRED,
            "status": ApprovalStatus.PENDING,
            "created_at": CREATED_AT,
            "expires_at": EXPIRES_AT,
            "requested_by": "policy-engine",
            "scope": ApprovalScope(
                clouds=("gcp",),
                triggered_rule_ids=("GCP_INTERNAL_NETWORK_001",),
                resource_addresses=("google_compute_network.main",),
            ),
            "approval_required": True,
        }
        values.update(overrides)
        return ApprovalRequest(**values)

    @staticmethod
    def _record(**overrides):
        values = {
            "request_id": REQUEST_ID,
            "action": ApprovalAction.APPROVE,
            "approver_id": "reviewer-001",
            "reason": "Reviewed and accepted residual risk.",
            "decided_at": DECIDED_AT,
            "previous_status": ApprovalStatus.PENDING,
            "new_status": ApprovalStatus.APPROVED,
        }
        values.update(overrides)
        return ApprovalRecord(**values)

    @staticmethod
    def _authorization(**overrides):
        values = {
            "authorization_status": AuthorizationStatus.AUTHORIZED,
            "policy_decision": PolicyDecisionStatus.REQUIRE_APPROVAL,
            "approval_status": ApprovalStatus.APPROVED,
            "request_id": REQUEST_ID,
            "policy_id": "INTERNAL_SECURITY_POLICY_BASELINE",
            "policy_version": "1.0",
            "policy_report_run_id": "policy_20260810T205900Z_deadbeef",
            "authorized_at": DECIDED_AT,
            "approver_id": "reviewer-001",
            "reason_code": PolicyReasonCode.APPROVAL_REQUIRED,
            "message": "Governance permits a potential next phase.",
        }
        values.update(overrides)
        return ControlledAuthorization(**values)

    def test_enum_values_are_exact_and_exclude_bypass_states(self):
        self.assertEqual(
            [status.value for status in ApprovalStatus],
            ["NOT_REQUIRED", "PENDING", "APPROVED", "REJECTED", "NOT_ALLOWED", "EXPIRED"],
        )
        self.assertEqual(
            [status.value for status in AuthorizationStatus],
            ["AUTHORIZED", "PENDING_APPROVAL", "REJECTED", "BLOCKED", "EXPIRED"],
        )
        self.assertEqual([action.value for action in ApprovalAction], ["APPROVE", "REJECT"])
        serialized = " ".join(status.value for status in ApprovalStatus)
        for forbidden in ("AUTO_APPROVED", "FORCED", "BYPASSED"):
            self.assertNotIn(forbidden, serialized)

    def test_scope_is_stable_deduplicated_and_serializable(self):
        scope = ApprovalScope(
            clouds=("oci", "gcp", "gcp"),
            triggered_rule_ids=("RULE_B", "RULE_A", "RULE_A"),
            resource_addresses=("resource.z", "resource.a"),
        )
        self.assertEqual(scope.clouds, ("gcp", "oci"))
        self.assertEqual(scope.triggered_rule_ids, ("RULE_A", "RULE_B"))
        self.assertEqual(scope.to_dict()["resource_addresses"], ["resource.a", "resource.z"])

    def test_request_is_valid_immutable_and_serializes_utc_enums(self):
        request = self._request()
        payload = request.to_dict()
        self.assertEqual(payload["status"], "PENDING")
        self.assertEqual(payload["created_at"], "2026-08-10T21:00:00Z")
        self.assertEqual(payload["expires_at"], "2026-08-10T22:00:00Z")
        self.assertEqual(json.loads(request.to_json()), payload)
        with self.assertRaises(FrozenInstanceError):
            request.status = ApprovalStatus.APPROVED

    def test_request_requires_valid_request_policy_and_version_identifiers(self):
        for field_name, value in (
            ("request_id", ""),
            ("request_id", "approval_bad"),
            ("policy_id", ""),
            ("policy_id", "bad policy"),
            ("policy_version", ""),
        ):
            with self.subTest(field_name=field_name), self.assertRaises(InvalidApprovalModelError):
                self._request(**{field_name: value})

    def test_request_requires_utc_second_precision_timestamps(self):
        invalid_times = (
            CREATED_AT.replace(tzinfo=None),
            CREATED_AT.astimezone(timezone(timedelta(hours=1))),
            CREATED_AT.replace(microsecond=1),
        )
        for value in invalid_times:
            with self.subTest(value=value), self.assertRaises(InvalidApprovalModelError):
                self._request(created_at=value)
        with self.assertRaises(InvalidApprovalModelError):
            self._request(expires_at=CREATED_AT)

    def test_request_status_and_required_flag_must_match_policy_decision(self):
        invalid = (
            {"policy_decision": PolicyDecisionStatus.ALLOW, "status": ApprovalStatus.PENDING, "approval_required": False},
            {"policy_decision": PolicyDecisionStatus.BLOCK, "status": ApprovalStatus.APPROVED, "approval_required": False},
            {"approval_required": False},
        )
        for overrides in invalid:
            with self.subTest(overrides=overrides), self.assertRaises(InvalidApprovalModelError):
                self._request(**overrides)

    def test_terminal_allow_and_block_requests_reject_expiration(self):
        for decision, status in (
            (PolicyDecisionStatus.ALLOW, ApprovalStatus.NOT_REQUIRED),
            (PolicyDecisionStatus.BLOCK, ApprovalStatus.NOT_ALLOWED),
        ):
            with self.subTest(decision=decision), self.assertRaises(InvalidApprovalModelError):
                self._request(
                    policy_decision=decision,
                    status=status,
                    approval_required=False,
                )

    def test_approval_record_is_valid_immutable_and_auditable(self):
        record = self._record()
        payload = record.to_dict()
        self.assertEqual(payload["action"], "APPROVE")
        self.assertEqual(payload["previous_status"], "PENDING")
        self.assertEqual(payload["new_status"], "APPROVED")
        self.assertEqual(payload["decided_at"], "2026-08-10T21:05:00Z")
        self.assertEqual(json.loads(record.to_json()), payload)
        with self.assertRaises(FrozenInstanceError):
            record.approver_id = "other"

    def test_record_requires_approver_reason_and_consistent_transition(self):
        for overrides in (
            {"approver_id": ""},
            {"reason": ""},
            {"previous_status": ApprovalStatus.APPROVED},
            {"new_status": ApprovalStatus.REJECTED},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(InvalidApprovalModelError):
                self._record(**overrides)

    def test_reject_record_requires_rejected_new_status(self):
        record = self._record(
            action=ApprovalAction.REJECT,
            new_status=ApprovalStatus.REJECTED,
        )
        self.assertEqual(record.action, ApprovalAction.REJECT)
        self.assertEqual(record.new_status, ApprovalStatus.REJECTED)

    def test_controlled_authorization_is_safe_immutable_and_serializable(self):
        authorization = self._authorization()
        payload = authorization.to_dict()
        self.assertTrue(payload["authorized"])
        self.assertFalse(any(payload["safety"].values()))
        self.assertEqual(json.loads(authorization.to_json()), payload)
        with self.assertRaises(FrozenInstanceError):
            authorization.authorization_status = AuthorizationStatus.BLOCKED

    def test_authorization_rejects_incoherent_mapping_and_missing_approver(self):
        with self.assertRaises(InvalidApprovalModelError):
            self._authorization(authorization_status=AuthorizationStatus.BLOCKED)
        with self.assertRaises(InvalidApprovalModelError):
            self._authorization(approver_id=None)
        with self.assertRaises(InvalidApprovalModelError):
            self._authorization(authorized_at=None)

    def test_secret_markers_are_rejected_from_human_and_scope_fields(self):
        for secret in (
            "FAKE_PASSWORD_POLICY5",
            "FAKE_TOKEN_POLICY5",
            "FAKE_PRIVATE_KEY_POLICY5",
            "FAKE_SECRET_POLICY5",
        ):
            with self.subTest(secret=secret), self.assertRaises(InvalidApprovalModelError):
                self._record(reason=secret)
            with self.subTest(scope=secret), self.assertRaises(InvalidApprovalModelError):
                ApprovalScope(resource_addresses=(secret,))

    def test_serialized_models_do_not_contain_runtime_or_raw_data_fields(self):
        payload = self._request().to_json() + self._record().to_json() + self._authorization().to_json()
        for forbidden in (
            "raw_security_attributes", "raw_terraform_values", "stdout", "stderr",
            "tfstate", "tfvars", "saved_plan", "credentials",
        ):
            self.assertNotIn(forbidden, payload)

    def test_replace_creates_new_request_without_mutating_original(self):
        original = self._request()
        updated = replace(original, status=ApprovalStatus.APPROVED)
        self.assertEqual(original.status, ApprovalStatus.PENDING)
        self.assertEqual(updated.status, ApprovalStatus.APPROVED)
        self.assertIsNot(original, updated)


if __name__ == "__main__":
    unittest.main()
