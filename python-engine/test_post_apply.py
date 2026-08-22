import json
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import UUID

from controlled_apply import ApplyResult, ApplyStatus
from deployment_gate import DeploymentGateResult, DeploymentGateStatus
from post_apply import (
    DeploymentAuditRecord,
    PostApplyStatus,
    PostApplyVerifier,
    StateProbeResult,
    StateProbeStatus,
)
from saved_plan import SavedPlanLifecycle
from test_saved_plan import CREATED, FakePlanPipeline, selection


class FakeStateProbe:
    def __init__(self, status=StateProbeStatus.AVAILABLE):
        self.status = status
        self.calls = 0

    def probe(self, runtime_selection):
        self.calls += 1
        return StateProbeResult(self.status, resource_count=1)


class PostApplyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name).resolve()
        self.runtime = selection()
        with patch("saved_plan.build_client_root", return_value=self.root):
            self.plan = SavedPlanLifecycle(
                FakePlanPipeline(), now_factory=lambda: CREATED,
                uuid_factory=lambda: UUID("deadbeef-dead-beef-dead-beefdeadbeef"),
            ).create(self.runtime)
        self.apply = ApplyResult(
            "apply_20260822T120000Z_22222222", self.plan.plan_id,
            self.plan.plan_sha256, ApplyStatus.SUCCESS, 0, CREATED,
            CREATED + timedelta(seconds=1), 1.0, "client-a", "dev", "gcp",
            "gcp-state",
        )
        self.gate = DeploymentGateResult(
            DeploymentGateStatus.READY, True, (), self.plan.plan_id,
            self.plan.plan_sha256, "client-a", "dev", "gcp", "gcp-state",
            "PASS", "APPROVED", "ALLOW", "AUTHORIZED", "VALID", "PASS",
            "PASS", "PASS", CREATED,
        )

    def tearDown(self):
        self.directory.cleanup()

    def _claim(self, **overrides):
        claim = {
            "plan_id": self.plan.plan_id,
            "plan_sha256": self.plan.plan_sha256,
            "status": "SUCCESS",
            "started_at": "2026-08-22T12:00:00Z",
            "finished_at": "2026-08-22T12:00:01Z",
        }
        claim.update(overrides)
        (self.plan.plan_path.parent / "apply_execution.json").write_text(
            json.dumps(claim), encoding="utf-8"
        )

    def _verify(self, probe=None, *, create_claim=True, reset_audit=True, **overrides):
        audit_path = self.plan.plan_path.parent / "deployment_audit.json"
        if reset_audit:
            audit_path.unlink(missing_ok=True)
        if create_claim:
            self._claim()
        values = {
            "saved_plan": self.plan,
            "gate_result": self.gate,
            "apply_result": self.apply,
            "runtime_selection": self.runtime,
            "state_probe": probe or FakeStateProbe(),
        }
        values.update(overrides)
        with patch("post_apply.build_client_root", return_value=self.plan.working_directory):
            return PostApplyVerifier(
                now_factory=lambda: CREATED,
                uuid_factory=lambda: UUID("33333333-3333-3333-3333-333333333333"),
            ).verify(**values)

    def test_successful_apply_with_available_fake_state_is_verified_and_audited(self):
        verification, audit, path = self._verify()
        self.assertEqual(verification.status, PostApplyStatus.VERIFIED)
        self.assertEqual(audit.final_status, "VERIFIED")
        self.assertEqual(path, self.plan.plan_path.parent / "deployment_audit.json")
        self.assertEqual(audit.apply_id, self.apply.apply_id)
        self.assertEqual(audit.plan_sha256, self.plan.plan_sha256)
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(payload["cloud_verification_status"], "NOT_PERFORMED")
        self.assertNotIn("stdout", json.dumps(payload))
        self.assertNotIn("credential", json.dumps(payload).casefold())

    def test_failed_timeout_and_blocked_apply_are_audited_without_retry(self):
        for status, expected in (
            (ApplyStatus.FAILED, PostApplyStatus.FAILED),
            (ApplyStatus.TIMEOUT, PostApplyStatus.FAILED),
            (ApplyStatus.BLOCKED, PostApplyStatus.BLOCKED),
        ):
            with self.subTest(status=status):
                result = replace(self.apply, status=status)
                verification, _, _ = self._verify(apply_result=result)
                self.assertEqual(verification.status, expected)

    def test_claim_and_plan_integrity_mismatches_fail(self):
        cases = (
            ({"plan_id": "other"}, "EXECUTION_CLAIM_INVALID"),
            ({"plan_sha256": "f" * 64}, "EXECUTION_CLAIM_INVALID"),
            ({"status": "FAILED"}, "EXECUTION_CLAIM_NOT_SUCCESS"),
        )
        for changes, reason in cases:
            with self.subTest(reason=reason):
                self._claim(**changes)
                (self.plan.plan_path.parent / "deployment_audit.json").unlink(missing_ok=True)
                with patch("post_apply.build_client_root", return_value=self.plan.working_directory):
                    verification, _, _ = PostApplyVerifier(
                        now_factory=lambda: CREATED,
                        uuid_factory=lambda: UUID("44444444-4444-4444-4444-444444444444"),
                    ).verify(self.plan, self.gate, self.apply, self.runtime, FakeStateProbe())
                self.assertIn(reason, verification.reason_codes)
        self.plan.plan_path.write_bytes(b"changed")
        verification, _, _ = self._verify()
        self.assertIn("PLAN_HASH_MISMATCH", verification.reason_codes)

    def test_missing_context_gate_claim_plan_and_state_probe_fail_closed(self):
        for kwargs, reason in (
            ({"gate_result": replace(self.gate, allowed=False, status=DeploymentGateStatus.BLOCKED)}, "GATE_NOT_READY"),
            ({"runtime_selection": None}, "RUNTIME_CONTEXT_INVALID"),
            ({"state_probe": FakeStateProbe(StateProbeStatus.UNAVAILABLE)}, "STATE_PROBE_UNAVAILABLE"),
        ):
            with self.subTest(reason=reason):
                verification, _, _ = self._verify(**kwargs)
                self.assertIn(reason, verification.reason_codes)
        (self.plan.plan_path.parent / "apply_execution.json").unlink()
        verification, _, _ = self._verify(create_claim=False)
        self.assertIn("EXECUTION_CLAIM_MISSING", verification.reason_codes)

    def test_state_binding_and_context_mismatch_are_rejected(self):
        bad_runtime = replace(self.runtime, environment="staging")
        verification, _, _ = self._verify(runtime_selection=bad_runtime)
        self.assertIn("ENVIRONMENT_MISMATCH", verification.reason_codes)
        bad_state = replace(self.runtime, state_profile=replace(self.runtime.state_profile, state_profile_id="other"))
        verification, _, _ = self._verify(runtime_selection=bad_state)
        self.assertIn("STATE_PROFILE_MISMATCH", verification.reason_codes)

    def test_audit_is_immutable_and_verifier_never_calls_apply_or_terraform(self):
        self._verify()
        audit_path = self.plan.plan_path.parent / "deployment_audit.json"
        with patch.object(__import__("controlled_apply").ControlledApplyRunner, "apply") as apply, patch.object(__import__("terraform_runner").TerraformRunner, "run_controlled_apply") as terraform:
            with self.assertRaisesRegex(Exception, "AUDIT_ALREADY_EXISTS"):
                self._verify(reset_audit=False)
            apply.assert_not_called()
            terraform.assert_not_called()


if __name__ == "__main__":
    unittest.main()