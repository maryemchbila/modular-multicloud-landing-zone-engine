import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import UUID

from deployment_gate import DeploymentGate, DeploymentGateStatus
from plan_approval_binding import PlanApprovalBindingService
from saved_plan import SavedPlanLifecycle
from terraform_runner import TerraformRunner
from terraform_models import UnsafeTerraformCommandError
from test_saved_plan import CREATED, FakePlanPipeline, selection


class DeploymentGateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name).resolve()
        self.runtime = selection()
        self.plan = self._plan()
        self.approval_service = PlanApprovalBindingService(
            now_factory=lambda: CREATED,
            uuid_factory=lambda: UUID("11111111-1111-1111-1111-111111111111"),
        )
        self.approval = self.approval_service.approve(
            self.approval_service.create(self.plan), self.plan, "approver-1"
        )
        self.policy = SimpleNamespace(
            policy_decision=SimpleNamespace(decision=SimpleNamespace(value="ALLOW"))
        )
        self.governance = SimpleNamespace(governance_status="AUTHORIZED")

    def tearDown(self):
        self.directory.cleanup()

    def _plan(self, *, client_id="client-a", environment="dev"):
        runtime = selection(client_id, environment)
        plan_root = self.root / f"{client_id}-{environment}"
        with patch("saved_plan.build_client_root", return_value=plan_root):
            return SavedPlanLifecycle(
                FakePlanPipeline(), now_factory=lambda: CREATED,
                uuid_factory=lambda: UUID("deadbeef-dead-beef-dead-beefdeadbeef"),
            ).create(runtime)

    def _evaluate(self, **overrides):
        values = {
            "saved_plan": self.plan,
            "deployment_approval": self.approval,
            "runtime_selection": self.runtime,
            "policy_result": self.policy,
            "governance_result": self.governance,
            "credential_status": "VALID",
        }
        values.update(overrides)
        approval_service = values.pop("approval_service", self.approval_service)
        with patch("deployment_gate.build_client_root", return_value=self.plan.working_directory):
            return DeploymentGate(
                approval_service=approval_service,
                now_factory=lambda: CREATED,
            ).evaluate(**values)

    def test_all_checks_pass_returns_ready(self):
        result = self._evaluate()
        self.assertEqual(result.status, DeploymentGateStatus.READY)
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason_codes, ())

    def test_missing_or_nonapproved_approval_blocks(self):
        for approval in (None, self.approval_service.create(self.plan)):
            with self.subTest(approval=approval):
                result = self._evaluate(deployment_approval=approval)
                self.assertFalse(result.allowed)
                self.assertTrue(result.reason_codes)

    def test_rejected_and_expired_approval_block(self):
        rejected = self.approval_service.reject(
            self.approval_service.create(self.plan), self.plan, "approver-1"
        )
        self.assertIn("APPROVAL_REJECTED", self._evaluate(deployment_approval=rejected).reason_codes)
        short_service = PlanApprovalBindingService(
            now_factory=lambda: CREATED,
            uuid_factory=lambda: UUID("22222222-2222-2222-2222-222222222222"),
            ttl=timedelta(minutes=1),
        )
        short_approval = short_service.approve(
            short_service.create(self.plan), self.plan, "approver-1"
        )
        expired = self._evaluate(
            deployment_approval=short_approval,
            approval_service=short_service,
            evaluated_at=CREATED + timedelta(minutes=2),
        )
        self.assertIn("APPROVAL_EXPIRED", expired.reason_codes)

    def test_plan_integrity_and_expiry_fail_closed(self):
        self.plan.plan_path.write_bytes(b"changed")
        result = self._evaluate()
        self.assertIn("PLAN_HASH_MISMATCH", result.reason_codes)
        self.plan.plan_path.unlink()
        result = self._evaluate()
        self.assertIn("PLAN_MISSING", result.reason_codes)

    def test_context_and_state_mismatches_block(self):
        for runtime in (
            selection("client-b", "dev"),
            selection("client-a", "staging"),
            replace_provider(self.runtime, "oci"),
        ):
            result = self._evaluate(runtime_selection=runtime)
            self.assertFalse(result.allowed)
            self.assertTrue(any(code.endswith("_MISMATCH") for code in result.reason_codes))
        bad_state = replace_state(self.runtime, "other-state")
        result = self._evaluate(runtime_selection=bad_state)
        self.assertIn("STATE_PROFILE_MISMATCH", result.reason_codes)

    def test_policy_governance_credentials_and_legacy_path_block(self):
        self.assertIn("POLICY_BLOCK", self._evaluate(
            policy_result=SimpleNamespace(policy_decision=SimpleNamespace(decision="BLOCK"))
        ).reason_codes)
        self.assertIn("GOVERNANCE_NOT_AUTHORIZED", self._evaluate(
            governance_result=SimpleNamespace(governance_status="BLOCKED")
        ).reason_codes)
        self.assertIn("CREDENTIAL_MISSING", self._evaluate(credential_status=None,
                                                              runtime_selection=None).reason_codes)
        with patch("deployment_gate.build_client_root", return_value=self.root / "legacy-generated"):
            result = DeploymentGate(
                approval_service=self.approval_service, now_factory=lambda: CREATED
            ).evaluate(self.plan, self.approval, self.runtime, self.policy,
                       self.governance, "VALID")
        self.assertIn("UNSAFE_RUNTIME_PATH", result.reason_codes)

    def test_gate_does_not_invoke_terraform_and_runner_guards_remain(self):
        runner = MagicMock()
        result = self._evaluate()
        runner.run.assert_not_called()
        self.assertEqual(result.status, DeploymentGateStatus.READY)
        with self.assertRaises(UnsafeTerraformCommandError):
            TerraformRunner._validate_args(("apply",))
        with self.assertRaises(UnsafeTerraformCommandError):
            TerraformRunner._validate_args(("destroy",))


def replace_provider(runtime, provider):
    return SimpleNamespace(**{**runtime.__dict__, "provider": provider})


def replace_state(runtime, state_profile_id):
    state = SimpleNamespace(**{**runtime.state_profile.__dict__, "state_profile_id": state_profile_id})
    return SimpleNamespace(**{**runtime.__dict__, "state_profile": state})


if __name__ == "__main__":
    unittest.main()