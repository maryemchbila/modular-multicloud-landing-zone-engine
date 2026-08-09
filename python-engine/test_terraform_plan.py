"""Tests unitaires du pipeline Terraform plan."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call

from terraform_error_classifier import TerraformErrorClassifier
from terraform_models import (
    TerraformErrorCategory,
    TerraformErrorClassification,
    TerraformPipelineStatus,
    TerraformPlanStatus,
    TerraformResult,
    TerraformValidationPipelineResult,
    UnknownTerraformCloudError,
)
from terraform_pipeline import TerraformValidationPipeline
from terraform_plan import TerraformPlanPipeline
from terraform_runner import TerraformRunner


class TerraformPlanPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.repository_root = Path(temporary_directory.name)
        self.gcp_directory = (
            self.repository_root / "hcl-generator" / "generated" / "gcp"
        )
        self.oci_directory = (
            self.repository_root / "hcl-generator" / "generated" / "oci"
        )
        self.gcp_directory.mkdir(parents=True)
        self.oci_directory.mkdir(parents=True)
        self.runner = MagicMock(spec=TerraformRunner)
        self.validation_pipeline = MagicMock(spec=TerraformValidationPipeline)
        self.pipeline = TerraformPlanPipeline(
            runner=self.runner,
            validation_pipeline=self.validation_pipeline,
            plan_timeout=44,
        )

    def _terraform_result(
        self,
        args: list[str],
        *,
        exit_code: int | None = 0,
        timed_out: bool = False,
        stdout: str = "stdout",
        stderr: str = "",
        working_directory: Path | None = None,
    ) -> TerraformResult:
        return TerraformResult(
            command="terraform",
            args=tuple(args),
            working_directory=str(working_directory or self.gcp_directory),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=0.5,
            timed_out=timed_out,
            success=exit_code == 0 and not timed_out,
        )

    def _validation_result(
        self,
        *,
        cloud: str = "gcp",
        final_status: TerraformPipelineStatus = TerraformPipelineStatus.PASS,
        failed_step: str | None = None,
        working_directory: Path | None = None,
        error_classification: TerraformErrorClassification | None = None,
    ) -> TerraformValidationPipelineResult:
        directory = working_directory or self.gcp_directory
        passed = self._terraform_result(["validate"], working_directory=directory)
        status = (
            TerraformPipelineStatus.PASS
            if final_status is TerraformPipelineStatus.PASS
            else TerraformPipelineStatus.SKIPPED
        )
        return TerraformValidationPipelineResult(
            cloud=cloud,
            working_directory=str(directory),
            fmt_result=passed if status is TerraformPipelineStatus.PASS else None,
            init_result=passed if status is TerraformPipelineStatus.PASS else None,
            validate_result=passed if status is TerraformPipelineStatus.PASS else None,
            fmt_status=status,
            init_status=status,
            validate_status=status,
            final_status=final_status,
            failed_step=failed_step,
            duration_seconds=1.0,
            error_classification=error_classification,
        )

    def _run_with_plan_result(self, plan_result: TerraformResult):
        self.validation_pipeline.run.return_value = self._validation_result()
        self.runner.run.return_value = plan_result
        return self.pipeline.run("gcp")

    def test_plan_exit_zero_means_no_changes(self) -> None:
        result = self._run_with_plan_result(
            self._terraform_result(TerraformPlanPipeline.PLAN_ARGS, exit_code=0)
        )

        self.assertEqual(result.plan_status, TerraformPlanStatus.NO_CHANGES)
        self.assertEqual(result.final_status, TerraformPlanStatus.NO_CHANGES)
        self.assertIsNone(result.failed_step)
        self.assertIsNone(result.error_classification)

    def test_plan_exit_two_means_changes_detected(self) -> None:
        result = self._run_with_plan_result(
            self._terraform_result(TerraformPlanPipeline.PLAN_ARGS, exit_code=2)
        )

        self.assertEqual(result.plan_status, TerraformPlanStatus.CHANGES_DETECTED)
        self.assertEqual(result.final_status, TerraformPlanStatus.CHANGES_DETECTED)
        self.assertIsNone(result.failed_step)
        self.assertIsNone(result.error_classification)

    def test_plan_exit_one_means_error(self) -> None:
        result = self._run_with_plan_result(
            self._terraform_result(
                TerraformPlanPipeline.PLAN_ARGS, exit_code=1, stderr="plan error"
            )
        )

        self.assertEqual(result.plan_status, TerraformPlanStatus.ERROR)
        self.assertEqual(result.final_status, TerraformPlanStatus.ERROR)
        self.assertEqual(result.failed_step, "plan")
        self.assertEqual(
            result.error_classification.category,
            TerraformErrorCategory.UNKNOWN_ERROR,
        )

    def test_fmt_validation_failure_skips_plan(self) -> None:
        self.validation_pipeline.run.return_value = self._validation_result(
            final_status=TerraformPipelineStatus.FAIL,
            failed_step="fmt",
        )

        result = self.pipeline.run("gcp")

        self.assertEqual(result.plan_status, TerraformPlanStatus.SKIPPED)
        self.assertEqual(result.failed_step, "fmt")
        self.runner.run.assert_not_called()

    def test_init_validation_failure_skips_plan(self) -> None:
        self.validation_pipeline.run.return_value = self._validation_result(
            final_status=TerraformPipelineStatus.FAIL,
            failed_step="init",
        )

        result = self.pipeline.run("gcp")

        self.assertEqual(result.plan_status, TerraformPlanStatus.SKIPPED)
        self.assertEqual(result.failed_step, "init")
        self.runner.run.assert_not_called()

    def test_validate_failure_skips_plan(self) -> None:
        self.validation_pipeline.run.return_value = self._validation_result(
            final_status=TerraformPipelineStatus.FAIL,
            failed_step="validate",
        )

        result = self.pipeline.run("gcp")

        self.assertEqual(result.plan_status, TerraformPlanStatus.SKIPPED)
        self.assertEqual(result.failed_step, "validate")
        self.runner.run.assert_not_called()

    def test_blocked_validation_skips_plan_and_blocks_final_status(self) -> None:
        self.validation_pipeline.run.return_value = self._validation_result(
            final_status=TerraformPipelineStatus.BLOCKED,
            failed_step="init",
        )

        result = self.pipeline.run("gcp")

        self.assertEqual(result.plan_status, TerraformPlanStatus.SKIPPED)
        self.assertEqual(result.final_status, TerraformPlanStatus.BLOCKED)
        self.runner.run.assert_not_called()

    def test_plan_timeout_is_blocked(self) -> None:
        result = self._run_with_plan_result(
            self._terraform_result(
                TerraformPlanPipeline.PLAN_ARGS,
                exit_code=None,
                timed_out=True,
            )
        )

        self.assertEqual(result.plan_status, TerraformPlanStatus.BLOCKED)
        self.assertEqual(result.final_status, TerraformPlanStatus.BLOCKED)
        self.assertEqual(result.failed_step, "plan")

    def test_plan_uses_exact_arguments_and_timeout(self) -> None:
        self._run_with_plan_result(
            self._terraform_result(TerraformPlanPipeline.PLAN_ARGS)
        )

        self.runner.run.assert_called_once_with(
            ["plan", "-input=false", "-no-color", "-detailed-exitcode"],
            cwd=self.gcp_directory,
            timeout=44.0,
        )

    def test_plan_uses_gcp_working_directory(self) -> None:
        self.validation_pipeline.run.return_value = self._validation_result(
            cloud="gcp", working_directory=self.gcp_directory
        )
        self.runner.run.return_value = self._terraform_result(
            TerraformPlanPipeline.PLAN_ARGS
        )

        result = self.pipeline.run("gcp")

        self.assertEqual(result.working_directory, str(self.gcp_directory))
        self.assertEqual(self.runner.run.call_args.kwargs["cwd"], self.gcp_directory)

    def test_plan_uses_oci_working_directory(self) -> None:
        self.validation_pipeline.run.return_value = self._validation_result(
            cloud="oci", working_directory=self.oci_directory
        )
        self.runner.run.return_value = self._terraform_result(
            TerraformPlanPipeline.PLAN_ARGS,
            working_directory=self.oci_directory,
        )

        result = self.pipeline.run("oci")

        self.assertEqual(result.cloud, "oci")
        self.assertEqual(self.runner.run.call_args.kwargs["cwd"], self.oci_directory)

    def test_unknown_cloud_is_rejected_before_any_terraform_command(self) -> None:
        real_validation = TerraformValidationPipeline(
            self.runner, repository_root=self.repository_root
        )
        pipeline = TerraformPlanPipeline(
            self.runner, validation_pipeline=real_validation
        )

        with self.assertRaises(UnknownTerraformCloudError):
            pipeline.run("azure")

        self.runner.run.assert_not_called()

    def test_plan_stdout_is_preserved(self) -> None:
        result = self._run_with_plan_result(
            self._terraform_result(
                TerraformPlanPipeline.PLAN_ARGS,
                exit_code=2,
                stdout="Plan: 1 to add, 0 to change, 0 to destroy.",
            )
        )

        self.assertEqual(
            result.plan_result.stdout,
            "Plan: 1 to add, 0 to change, 0 to destroy.",
        )

    def test_plan_stderr_is_preserved(self) -> None:
        result = self._run_with_plan_result(
            self._terraform_result(
                TerraformPlanPipeline.PLAN_ARGS,
                exit_code=1,
                stderr="missing required variable",
            )
        )

        self.assertEqual(result.plan_result.stderr, "missing required variable")

    def test_plan_missing_variable_is_classified(self) -> None:
        result = self._run_with_plan_result(
            self._terraform_result(
                TerraformPlanPipeline.PLAN_ARGS,
                exit_code=1,
                stderr="No value for required variable",
            )
        )

        self.assertEqual(result.failed_step, "plan")
        self.assertEqual(
            result.error_classification.category,
            TerraformErrorCategory.VARIABLES_MISSING,
        )
        self.assertEqual(
            result.to_dict()["error_classification"]["reason_code"],
            "VAR_REQUIRED_MISSING",
        )

    def test_validation_failure_classification_is_propagated(self) -> None:
        failed_result = self._terraform_result(
            TerraformValidationPipeline.INIT_ARGS,
            exit_code=1,
            stderr="GetProviderSchema failed",
        )
        classification = TerraformErrorClassifier().classify("init", failed_result)
        self.validation_pipeline.run.return_value = self._validation_result(
            final_status=TerraformPipelineStatus.FAIL,
            failed_step="init",
            error_classification=classification,
        )

        result = self.pipeline.run("gcp")

        self.assertEqual(result.plan_status, TerraformPlanStatus.SKIPPED)
        self.assertIs(result.error_classification, classification)
        self.assertEqual(
            result.error_classification.category,
            TerraformErrorCategory.PROVIDER_ERROR,
        )
        self.runner.run.assert_not_called()

    def test_exit_code_two_is_preserved_and_serialised(self) -> None:
        result = self._run_with_plan_result(
            self._terraform_result(TerraformPlanPipeline.PLAN_ARGS, exit_code=2)
        )

        self.assertEqual(result.plan_result.exit_code, 2)
        payload = result.to_dict()
        self.assertEqual(payload["plan"]["result"]["exit_code"], 2)
        self.assertEqual(payload["final_status"], "CHANGES_DETECTED")

    def test_plan_command_never_contains_apply(self) -> None:
        self._run_with_plan_result(
            self._terraform_result(TerraformPlanPipeline.PLAN_ARGS)
        )

        self.assertNotIn("apply", self.runner.run.call_args.args[0])

    def test_plan_command_never_contains_destroy(self) -> None:
        self._run_with_plan_result(
            self._terraform_result(TerraformPlanPipeline.PLAN_ARGS)
        )

        self.assertNotIn("destroy", self.runner.run.call_args.args[0])

    def test_plan_command_never_uses_out(self) -> None:
        self._run_with_plan_result(
            self._terraform_result(TerraformPlanPipeline.PLAN_ARGS)
        )

        self.assertFalse(
            any(argument.startswith("-out") for argument in self.runner.run.call_args.args[0])
        )

    def test_validation_pipeline_is_called_before_plan(self) -> None:
        self.validation_pipeline.run.return_value = self._validation_result()
        self.runner.run.return_value = self._terraform_result(
            TerraformPlanPipeline.PLAN_ARGS
        )
        calls = MagicMock()
        calls.attach_mock(self.validation_pipeline.run, "validation")
        calls.attach_mock(self.runner.run, "plan")

        self.pipeline.run("gcp")

        self.assertEqual(
            calls.mock_calls,
            [
                call.validation("gcp"),
                call.plan(
                    TerraformPlanPipeline.PLAN_ARGS,
                    cwd=self.gcp_directory,
                    timeout=44.0,
                ),
            ],
        )

    def test_plan_runs_only_when_validation_passes(self) -> None:
        for status in (
            TerraformPipelineStatus.FAIL,
            TerraformPipelineStatus.BLOCKED,
            TerraformPipelineStatus.SKIPPED,
        ):
            with self.subTest(status=status):
                self.runner.reset_mock()
                self.validation_pipeline.run.return_value = self._validation_result(
                    final_status=status,
                    failed_step="validate",
                )

                self.pipeline.run("gcp")

                self.runner.run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
