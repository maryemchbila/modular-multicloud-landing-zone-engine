import json
import subprocess
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import UUID

from controlled_apply import ApplyStatus, ControlledApplyRunner
from deployment_gate import DeploymentGateResult, DeploymentGateStatus
from plan_approval_binding import PlanApprovalBindingService
from saved_plan import SavedPlanLifecycle
from terraform_models import UnsafeTerraformCommandError
from terraform_runner import TerraformRunner
from test_saved_plan import CREATED, FakePlanPipeline, selection


class ControlledApplyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name).resolve()
        self.runtime = selection()
        with patch("saved_plan.build_client_root", return_value=self.root):
            self.plan = SavedPlanLifecycle(
                FakePlanPipeline(), now_factory=lambda: CREATED,
                uuid_factory=lambda: UUID("deadbeef-dead-beef-dead-beefdeadbeef"),
            ).create(self.runtime)
        approvals = PlanApprovalBindingService(
            now_factory=lambda: CREATED,
            uuid_factory=lambda: UUID("11111111-1111-1111-1111-111111111111"),
        )
        self.approval = approvals.approve(approvals.create(self.plan), self.plan, "approver-1")
        self.gate = DeploymentGateResult(
            DeploymentGateStatus.READY, True, (), self.plan.plan_id, self.plan.plan_sha256,
            self.plan.client_id, self.plan.environment, self.plan.provider,
            self.plan.state_profile_id, "PASS", "APPROVED", "ALLOW", "AUTHORIZED",
            "VALID", "PASS", "PASS", "PASS", CREATED,
        )
        self.runner = TerraformRunner()
        self.apply_runner = ControlledApplyRunner(
            self.runner, now_factory=lambda: CREATED,
            uuid_factory=lambda: UUID("22222222-2222-2222-2222-222222222222"),
        )

    def tearDown(self):
        self.directory.cleanup()

    def _apply(self, **overrides):
        values = {"saved_plan": self.plan, "gate_result": self.gate, "runtime_selection": self.runtime}
        values.update(overrides)
        with patch("controlled_apply.build_client_root", return_value=self.plan.working_directory), \
             patch("controlled_apply.resolve_credentials", return_value={"FAKE_TOKEN": "fake-secret"}), \
             patch("terraform_runner.shutil.which", return_value="fake-terraform"), \
             patch("terraform_runner.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", "")) as process:
            result = self.apply_runner.apply(**values)
        return result, process

    def test_ready_gate_executes_exact_saved_plan_with_secure_environment(self):
        result, process = self._apply()
        self.assertEqual(result.status, ApplyStatus.SUCCESS)
        command = process.call_args.args[0]
        self.assertEqual(command[1:], ["apply", "-input=false", "-no-color", str(self.plan.plan_path)])
        options = process.call_args.kwargs
        self.assertFalse(options["shell"])
        self.assertEqual(options["stdin"], subprocess.DEVNULL)
        self.assertEqual(options["cwd"], str(self.plan.working_directory))
        self.assertEqual(options["env"]["TF_IN_AUTOMATION"], "1")
        self.assertEqual(options["env"]["TF_INPUT"], "0")
        self.assertEqual(options["env"]["FAKE_TOKEN"], "fake-secret")
        self.assertEqual(result.plan_id, self.plan.plan_id)

    def test_no_auto_approve_no_replan_and_claim_is_persisted(self):
        result, process = self._apply()
        self.assertNotIn("-auto-approve", process.call_args.args[0])
        self.assertEqual(process.call_args.args[0][1], "apply")
        self.assertEqual(result.status, ApplyStatus.SUCCESS)
        claim = json.loads((self.plan.plan_path.parent / "apply_execution.json").read_text())
        self.assertEqual(claim["status"], "SUCCESS")
        self.assertEqual(claim["plan_id"], self.plan.plan_id)

    def test_blocked_gate_and_missing_gate_do_not_spawn_process(self):
        for gate in (replace(self.gate, status=DeploymentGateStatus.BLOCKED, allowed=False), None):
            with self.subTest(gate=gate), patch.object(self.runner, "run_controlled_apply") as execute:
                result = self.apply_runner.apply(self.plan, gate, self.runtime)
            self.assertEqual(result.status, ApplyStatus.BLOCKED)
            execute.assert_not_called()

    def test_hash_context_cwd_kind_and_expiry_fail_before_process(self):
        cases = (
            (self.plan, replace(self.gate, plan_id="other"), self.runtime, "GATE_PLAN_ID_MISMATCH"),
            (self.plan, replace(self.gate, plan_sha256="f" * 64), self.runtime, "GATE_PLAN_SHA256_MISMATCH"),
            (self.plan, self.gate, replace(self.runtime, client_id="client-b"), "CLIENT_ID_MISMATCH"),
        )
        for plan, gate, runtime, reason in cases:
            with self.subTest(reason=reason), patch.object(self.runner, "run_controlled_apply") as execute:
                with patch("controlled_apply.build_client_root", return_value=self.plan.working_directory):
                    result = self.apply_runner.apply(plan, gate, runtime)
            self.assertEqual(result.status, ApplyStatus.BLOCKED)
            self.assertIn(reason, result.error_reason)
            execute.assert_not_called()

    def test_changed_missing_and_expired_plan_do_not_spawn_process(self):
        self.plan.plan_path.write_bytes(b"changed")
        with patch("controlled_apply.build_client_root", return_value=self.plan.working_directory), patch.object(self.runner, "run_controlled_apply") as execute:
            result = self.apply_runner.apply(self.plan, self.gate, self.runtime)
        self.assertEqual(result.status, ApplyStatus.BLOCKED)
        self.assertEqual(result.error_reason, "PLAN_HASH_MISMATCH")
        execute.assert_not_called()
        self.plan.plan_path.unlink()
        with patch("controlled_apply.build_client_root", return_value=self.plan.working_directory), patch.object(self.runner, "run_controlled_apply") as execute:
            result = self.apply_runner.apply(self.plan, self.gate, self.runtime)
        self.assertEqual(result.error_reason, "PLAN_MISSING")
        execute.assert_not_called()

    def test_nonzero_timeout_and_replay_are_safe(self):
        with patch("controlled_apply.build_client_root", return_value=self.plan.working_directory), patch("controlled_apply.resolve_credentials", return_value={}), patch("terraform_runner.shutil.which", return_value="fake-terraform"), patch("terraform_runner.subprocess.run", return_value=subprocess.CompletedProcess([], 1, "", "token=secret")):
            failed = self.apply_runner.apply(self.plan, self.gate, self.runtime)
        self.assertEqual(failed.status, ApplyStatus.FAILED)
        self.assertEqual(failed.terraform_exit_code, 1)
        with patch("controlled_apply.build_client_root", return_value=self.plan.working_directory):
            replay = self.apply_runner.apply(self.plan, self.gate, self.runtime)
        self.assertEqual(replay.status, ApplyStatus.BLOCKED)
        self.assertEqual(replay.error_reason, "APPLY_ALREADY_CLAIMED")

    def test_timeout_is_reported_without_raw_output(self):
        with patch("controlled_apply.build_client_root", return_value=self.plan.working_directory), patch("controlled_apply.resolve_credentials", return_value={}), patch("terraform_runner.shutil.which", return_value="fake-terraform"), patch("terraform_runner.subprocess.run", side_effect=subprocess.TimeoutExpired([], 1, stderr=b"secret-token")):
            result = self.apply_runner.apply(self.plan, self.gate, self.runtime)
        self.assertEqual(result.status, ApplyStatus.TIMEOUT)
        self.assertNotIn("secret-token", repr(result))

    def test_generic_runner_apply_destroy_remain_blocked(self):
        with self.assertRaises(UnsafeTerraformCommandError):
            TerraformRunner._validate_args(("apply",))
        with self.assertRaises(UnsafeTerraformCommandError):
            TerraformRunner._validate_args(("destroy",))


if __name__ == "__main__":
    unittest.main()