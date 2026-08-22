import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

from plan_approval_binding import (
    PlanApprovalBindingService,
    PlanApprovalError,
    PlanApprovalStatus,
)
from saved_plan import SavedPlanError, SavedPlanLifecycle
from terraform_models import UnsafeTerraformCommandError
from terraform_runner import TerraformRunner
from test_saved_plan import CREATED, FakePlanPipeline, selection


class PlanApprovalBindingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name).resolve()
        self.plan_number = 0
        self.plan = self._create_plan()

    def tearDown(self):
        self.directory.cleanup()

    def _create_plan(self, *, ttl=timedelta(minutes=30)):
        self.plan_number += 1
        plan_root = self.root / f"runtime-{self.plan_number}"
        with patch("saved_plan.build_client_root", return_value=plan_root):
            return SavedPlanLifecycle(
                FakePlanPipeline(), now_factory=lambda: CREATED,
                uuid_factory=lambda: UUID("deadbeef-dead-beef-dead-beefdeadbeef"),
                ttl=ttl,
            ).create(selection())

    def _service(self, now=CREATED, ttl=timedelta(minutes=30)):
        return PlanApprovalBindingService(
            now_factory=lambda: now,
            uuid_factory=lambda: UUID("11111111-1111-1111-1111-111111111111"),
            ttl=ttl,
        )

    def test_create_persists_pending_and_approve_binds_exact_plan(self):
        service = self._service()
        pending = service.create(self.plan, requester_id="requester-1")
        self.assertEqual(pending.status, PlanApprovalStatus.PENDING)
        approved = service.approve(pending, self.plan, "approver-1")
        self.assertTrue(approved.deployment_authorized)
        service.validate(approved, self.plan)
        payload = json.loads((self.plan.plan_path.parent / "deployment_approval.json").read_text())
        self.assertEqual(payload["plan_id"], self.plan.plan_id)
        self.assertNotIn("stdout", payload)
        self.assertNotIn("credential", json.dumps(payload).casefold())

    def test_reject_is_terminal_and_pending_is_not_authorized(self):
        service = self._service()
        pending = service.create(self.plan)
        with self.assertRaisesRegex(PlanApprovalError, "NOT_AUTHORIZED"):
            service.validate(pending, self.plan)
        rejected = service.reject(pending, self.plan, "approver-1")
        self.assertFalse(rejected.deployment_authorized)
        with self.assertRaises(PlanApprovalError):
            service.approve(rejected, self.plan, "approver-2")

    def test_all_context_mismatches_fail(self):
        service = self._service()
        approved = service.approve(service.create(self.plan), self.plan, "approver-1")
        fields = ("plan_id", "plan_sha256", "client_id", "environment", "provider", "state_profile_id")
        replacements = {
            "plan_id": "plan_20260822T120000Z_bbbbbbbb",
            "plan_sha256": "f" * 64,
            "client_id": "client-b",
            "environment": "staging",
            "provider": "oci",
            "state_profile_id": "other-state",
        }
        for field in fields:
            with self.subTest(field=field):
                with self.assertRaises(PlanApprovalError):
                    service.validate(replace(approved, **{field: replacements[field]}), self.plan)

    def test_changed_or_missing_artifact_fails_validation(self):
        service = self._service()
        approved = service.approve(service.create(self.plan), self.plan, "approver-1")
        self.plan.plan_path.write_bytes(b"changed")
        with self.assertRaisesRegex(PlanApprovalError, "HASH_MISMATCH"):
            service.validate(approved, self.plan)
        self.plan.plan_path.unlink()
        with self.assertRaisesRegex(PlanApprovalError, "ARTIFACT_MISSING"):
            service.validate(approved, self.plan)

    def test_expiry_is_utc_bounded_and_expired_values_fail(self):
        plan = self._create_plan(ttl=timedelta(minutes=5))
        service = self._service(ttl=timedelta(minutes=30))
        pending = service.create(plan)
        self.assertEqual(pending.expires_at, CREATED + timedelta(minutes=5))
        with self.assertRaisesRegex(PlanApprovalError, "PLAN_EXPIRED"):
            service.validate(pending, plan, evaluated_at=CREATED + timedelta(minutes=6))
        with self.assertRaisesRegex(PlanApprovalError, "PLAN_EXPIRED"):
            service.approve(pending, plan, "approver-1", CREATED + timedelta(minutes=6))

    def test_approval_expiry_blocks_approved_binding(self):
        service = self._service(ttl=timedelta(minutes=1))
        approved = service.approve(service.create(self.plan), self.plan, "approver-1")
        with self.assertRaisesRegex(PlanApprovalError, "APPROVAL_EXPIRED"):
            service.validate(approved, self.plan, evaluated_at=CREATED + timedelta(minutes=2))

    def test_invalid_saved_plan_path_and_destroy_purpose_are_rejected(self):
        with self.assertRaises(SavedPlanError):
            replace(self.plan, plan_path=self.root / "outside.tfplan")
        with self.assertRaises(PlanApprovalError):
            replace(
                self._service().create(self.plan),
                approval_purpose="DESTROY",
            )

    def test_apply_and_destroy_remain_blocked(self):
        with self.assertRaises(UnsafeTerraformCommandError):
            TerraformRunner._validate_args(("apply",))
        with self.assertRaises(UnsafeTerraformCommandError):
            TerraformRunner._validate_args(("destroy",))


if __name__ == "__main__":
    unittest.main()