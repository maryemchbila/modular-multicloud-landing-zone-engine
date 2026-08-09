"""Tests unitaires du runner Terraform generique."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from terraform_models import (
    TerraformNotFoundError,
    TerraformWorkingDirectoryError,
    UnsafeTerraformCommandError,
)
from terraform_runner import TerraformRunner


TERRAFORM_BINARY = r"C:\tools\terraform.exe"


class TerraformRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.cwd = Path(self.temporary_directory.name)
        self.runner = TerraformRunner()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    @patch("terraform_runner.subprocess.run")
    @patch("terraform_runner.shutil.which", return_value=TERRAFORM_BINARY)
    def test_successful_command_returns_structured_result(
        self, _which_mock, run_mock
    ) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            [TERRAFORM_BINARY, "validate"], 0, "Success!", ""
        )

        result = self.runner.run(["validate", "-no-color"], self.cwd)

        self.assertTrue(result.success)
        self.assertEqual(result.exit_code, 0)
        self.assertFalse(result.timed_out)
        self.assertGreaterEqual(result.duration_seconds, 0)

    @patch("terraform_runner.subprocess.run")
    @patch("terraform_runner.shutil.which", return_value=TERRAFORM_BINARY)
    def test_nonzero_exit_code_and_stderr_are_preserved(
        self, _which_mock, run_mock
    ) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            [TERRAFORM_BINARY, "validate"], 1, "", "invalid configuration"
        )

        result = self.runner.run(["validate"], self.cwd)

        self.assertFalse(result.success)
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.stderr, "invalid configuration")

    @patch("terraform_runner.subprocess.run")
    @patch("terraform_runner.shutil.which", return_value=TERRAFORM_BINARY)
    def test_timeout_returns_partial_output(self, _which_mock, run_mock) -> None:
        run_mock.side_effect = subprocess.TimeoutExpired(
            [TERRAFORM_BINARY, "version"],
            0.01,
            output=b"partial stdout",
            stderr=b"partial stderr",
        )

        result = self.runner.run(["version"], self.cwd, timeout=0.01)

        self.assertTrue(result.timed_out)
        self.assertFalse(result.success)
        self.assertIsNone(result.exit_code)
        self.assertEqual(result.stdout, "partial stdout")
        self.assertEqual(result.stderr, "partial stderr")

    @patch("terraform_runner.subprocess.run")
    @patch("terraform_runner.shutil.which")
    def test_missing_working_directory_is_rejected_before_lookup_and_subprocess(
        self, which_mock, run_mock
    ) -> None:
        missing = self.cwd / "missing directory"

        with self.assertRaisesRegex(
            TerraformWorkingDirectoryError, "n'existe pas"
        ):
            self.runner.run(["validate"], missing)

        which_mock.assert_not_called()
        run_mock.assert_not_called()

    @patch("terraform_runner.subprocess.run")
    @patch("terraform_runner.shutil.which", return_value=None)
    def test_missing_terraform_raises_clear_error(
        self, _which_mock, run_mock
    ) -> None:
        with self.assertRaisesRegex(TerraformNotFoundError, "introuvable"):
            self.runner.run(["version"], self.cwd)

        run_mock.assert_not_called()

    @patch("terraform_runner.subprocess.run")
    @patch("terraform_runner.shutil.which")
    def test_apply_is_blocked_before_lookup_and_subprocess(
        self, which_mock, run_mock
    ) -> None:
        with self.assertRaises(UnsafeTerraformCommandError):
            self.runner.run(["apply", "-auto-approve"], self.cwd)

        which_mock.assert_not_called()
        run_mock.assert_not_called()

    @patch("terraform_runner.subprocess.run")
    @patch("terraform_runner.shutil.which")
    def test_destroy_is_blocked_before_lookup_and_subprocess(
        self, which_mock, run_mock
    ) -> None:
        with self.assertRaises(UnsafeTerraformCommandError):
            self.runner.run(["-chdir=elsewhere", "destroy"], self.cwd)

        which_mock.assert_not_called()
        run_mock.assert_not_called()

    @patch("terraform_runner.subprocess.run")
    @patch("terraform_runner.shutil.which", return_value=TERRAFORM_BINARY)
    def test_stdout_and_stderr_remain_separate(self, _which_mock, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            [TERRAFORM_BINARY, "version"], 0, "stdout value", "stderr value"
        )

        result = self.runner.run(["version"], self.cwd)

        self.assertEqual(result.stdout, "stdout value")
        self.assertEqual(result.stderr, "stderr value")

    @patch("terraform_runner.subprocess.run")
    @patch("terraform_runner.shutil.which", return_value=TERRAFORM_BINARY)
    def test_arguments_with_spaces_are_passed_as_distinct_list_items(
        self, _which_mock, run_mock
    ) -> None:
        run_mock.return_value = subprocess.CompletedProcess([], 0, "", "")
        plan_path = "plans/my planned changes.tfplan"

        self.runner.run(["show", plan_path], self.cwd)

        positional_arguments = run_mock.call_args.args[0]
        self.assertEqual(positional_arguments, [TERRAFORM_BINARY, "show", plan_path])
        self.assertFalse(run_mock.call_args.kwargs["shell"])

    @patch("terraform_runner.subprocess.run")
    @patch("terraform_runner.shutil.which", return_value=TERRAFORM_BINARY)
    def test_automation_environment_is_limited_to_child(
        self, _which_mock, run_mock
    ) -> None:
        run_mock.return_value = subprocess.CompletedProcess([], 0, "", "")

        with patch.dict(os.environ, {"TF_IN_AUTOMATION": "parent"}, clear=False):
            self.runner.run(["version"], self.cwd)
            self.assertEqual(os.environ["TF_IN_AUTOMATION"], "parent")

        child_environment = run_mock.call_args.kwargs["env"]
        self.assertEqual(child_environment["TF_IN_AUTOMATION"], "1")
        self.assertEqual(child_environment["TF_INPUT"], "0")

    @patch("terraform_runner.subprocess.run")
    @patch("terraform_runner.shutil.which", return_value=TERRAFORM_BINARY)
    def test_explicit_cwd_timeout_and_noninteractive_stdin(
        self, _which_mock, run_mock
    ) -> None:
        run_mock.return_value = subprocess.CompletedProcess([], 0, "", "")

        self.runner.run(["fmt", "-check"], self.cwd, timeout=12)

        options = run_mock.call_args.kwargs
        self.assertEqual(options["cwd"], str(self.cwd.resolve()))
        self.assertEqual(options["timeout"], 12.0)
        self.assertEqual(options["stdin"], subprocess.DEVNULL)
        self.assertTrue(options["capture_output"])

    @patch("terraform_runner.subprocess.run")
    @patch("terraform_runner.shutil.which")
    def test_unsafe_token_is_blocked_even_after_safe_subcommand(
        self, which_mock, run_mock
    ) -> None:
        with self.assertRaises(UnsafeTerraformCommandError):
            self.runner.run(["show", "apply"], self.cwd)

        which_mock.assert_not_called()
        run_mock.assert_not_called()

    @patch("terraform_runner.subprocess.run")
    @patch("terraform_runner.shutil.which", return_value=TERRAFORM_BINARY)
    def test_result_can_be_serialised_without_path_conversion(
        self, _which_mock, run_mock
    ) -> None:
        run_mock.return_value = subprocess.CompletedProcess([], 2, "changes", "")

        payload = self.runner.run(["plan", "-detailed-exitcode"], self.cwd).to_dict()

        self.assertEqual(payload["exit_code"], 2)
        self.assertFalse(payload["success"])
        self.assertIsInstance(payload["args"], list)
        self.assertIsInstance(payload["working_directory"], str)


if __name__ == "__main__":
    unittest.main()
