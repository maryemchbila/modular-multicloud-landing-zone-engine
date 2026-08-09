"""Tests unitaires du pipeline de validation Terraform."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call

from terraform_models import (
    TerraformErrorCategory,
    TerraformPipelineStatus,
    TerraformResult,
    UnknownTerraformCloudError,
)
from terraform_pipeline import TerraformValidationPipeline
from terraform_runner import TerraformRunner


class TerraformValidationPipelineTests(unittest.TestCase):
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
        self.pipeline = TerraformValidationPipeline(
            self.runner,
            repository_root=self.repository_root,
            fmt_timeout=11,
            init_timeout=22,
            validate_timeout=33,
        )

    def _result(
        self,
        args: list[str],
        *,
        exit_code: int | None = 0,
        timed_out: bool = False,
        stdout: str = "stdout",
        stderr: str | None = None,
    ) -> TerraformResult:
        return TerraformResult(
            command="terraform",
            args=tuple(args),
            working_directory=str(self.gcp_directory),
            exit_code=exit_code,
            stdout=stdout,
            stderr=("stderr" if exit_code else "") if stderr is None else stderr,
            duration_seconds=0.25,
            timed_out=timed_out,
            success=exit_code == 0 and not timed_out,
        )

    def _pass_results(self) -> list[TerraformResult]:
        return [
            self._result(TerraformValidationPipeline.FMT_ARGS),
            self._result(TerraformValidationPipeline.INIT_ARGS),
            self._result(TerraformValidationPipeline.VALIDATE_ARGS),
        ]

    def test_all_steps_pass(self) -> None:
        self.runner.run.side_effect = self._pass_results()

        result = self.pipeline.run("gcp")

        self.assertEqual(result.final_status, TerraformPipelineStatus.PASS)
        self.assertIsNone(result.failed_step)
        self.assertIsNone(result.error_classification)
        self.assertEqual(self.runner.run.call_count, 3)

    def test_fmt_failure_skips_init_and_validate(self) -> None:
        self.runner.run.return_value = self._result(
            TerraformValidationPipeline.FMT_ARGS, exit_code=1
        )

        result = self.pipeline.run("gcp")

        self.assertEqual(result.final_status, TerraformPipelineStatus.FAIL)
        self.assertEqual(result.failed_step, "fmt")
        self.assertEqual(result.init_status, TerraformPipelineStatus.SKIPPED)
        self.assertEqual(result.validate_status, TerraformPipelineStatus.SKIPPED)
        self.runner.run.assert_called_once()

    def test_init_failure_skips_validate(self) -> None:
        self.runner.run.side_effect = [
            self._result(TerraformValidationPipeline.FMT_ARGS),
            self._result(TerraformValidationPipeline.INIT_ARGS, exit_code=1),
        ]

        result = self.pipeline.run("gcp")

        self.assertEqual(result.final_status, TerraformPipelineStatus.FAIL)
        self.assertEqual(result.failed_step, "init")
        self.assertEqual(result.validate_status, TerraformPipelineStatus.SKIPPED)
        self.assertEqual(self.runner.run.call_count, 2)

    def test_validate_failure_marks_pipeline_failed(self) -> None:
        self.runner.run.side_effect = [
            *self._pass_results()[:2],
            self._result(TerraformValidationPipeline.VALIDATE_ARGS, exit_code=1),
        ]

        result = self.pipeline.run("gcp")

        self.assertEqual(result.final_status, TerraformPipelineStatus.FAIL)
        self.assertEqual(result.failed_step, "validate")
        self.assertEqual(result.validate_status, TerraformPipelineStatus.FAIL)

    def test_fmt_timeout_blocks_pipeline(self) -> None:
        self.runner.run.return_value = self._result(
            TerraformValidationPipeline.FMT_ARGS,
            exit_code=None,
            timed_out=True,
        )

        result = self.pipeline.run("gcp")

        self.assertEqual(result.final_status, TerraformPipelineStatus.BLOCKED)
        self.assertEqual(result.failed_step, "fmt")
        self.assertEqual(result.init_status, TerraformPipelineStatus.SKIPPED)
        self.runner.run.assert_called_once()

    def test_init_timeout_skips_validate(self) -> None:
        self.runner.run.side_effect = [
            self._result(TerraformValidationPipeline.FMT_ARGS),
            self._result(
                TerraformValidationPipeline.INIT_ARGS,
                exit_code=None,
                timed_out=True,
            ),
        ]

        result = self.pipeline.run("gcp")

        self.assertEqual(result.final_status, TerraformPipelineStatus.BLOCKED)
        self.assertEqual(result.failed_step, "init")
        self.assertEqual(result.validate_status, TerraformPipelineStatus.SKIPPED)
        self.assertEqual(self.runner.run.call_count, 2)

    def test_validate_timeout_blocks_pipeline(self) -> None:
        self.runner.run.side_effect = [
            *self._pass_results()[:2],
            self._result(
                TerraformValidationPipeline.VALIDATE_ARGS,
                exit_code=None,
                timed_out=True,
            ),
        ]

        result = self.pipeline.run("gcp")

        self.assertEqual(result.final_status, TerraformPipelineStatus.BLOCKED)
        self.assertEqual(result.failed_step, "validate")
        self.assertEqual(result.validate_status, TerraformPipelineStatus.BLOCKED)

    def test_gcp_resolves_to_repository_generated_root(self) -> None:
        self.assertEqual(
            self.pipeline.resolve_working_directory("gcp"),
            self.gcp_directory.resolve(),
        )

    def test_oci_resolves_to_repository_generated_root(self) -> None:
        self.assertEqual(
            self.pipeline.resolve_working_directory("oci"),
            self.oci_directory.resolve(),
        )

    def test_unknown_cloud_is_rejected_before_runner_call(self) -> None:
        with self.assertRaisesRegex(UnknownTerraformCloudError, "inconnu"):
            self.pipeline.run("azure")

        self.runner.run.assert_not_called()

    def test_fmt_uses_exact_arguments_and_timeout(self) -> None:
        self.runner.run.return_value = self._result(
            TerraformValidationPipeline.FMT_ARGS, exit_code=1
        )

        self.pipeline.run("gcp")

        self.runner.run.assert_called_once_with(
            ["fmt", "-check", "-recursive"],
            cwd=self.gcp_directory.resolve(),
            timeout=11.0,
        )

    def test_init_uses_exact_arguments_without_upgrade(self) -> None:
        self.runner.run.side_effect = [
            self._result(TerraformValidationPipeline.FMT_ARGS),
            self._result(TerraformValidationPipeline.INIT_ARGS, exit_code=1),
        ]

        self.pipeline.run("gcp")

        init_call = self.runner.run.call_args_list[1]
        self.assertEqual(
            init_call,
            call(
                ["init", "-backend=false", "-input=false", "-no-color"],
                cwd=self.gcp_directory.resolve(),
                timeout=22.0,
            ),
        )
        self.assertNotIn("-upgrade", init_call.args[0])

    def test_validate_uses_exact_arguments(self) -> None:
        self.runner.run.side_effect = self._pass_results()

        self.pipeline.run("gcp")

        self.assertEqual(
            self.runner.run.call_args_list[2],
            call(
                ["validate", "-no-color"],
                cwd=self.gcp_directory.resolve(),
                timeout=33.0,
            ),
        )

    def test_pipeline_never_requests_forbidden_commands(self) -> None:
        self.runner.run.side_effect = self._pass_results()

        self.pipeline.run("gcp")

        commands = [runner_call.args[0][0] for runner_call in self.runner.run.call_args_list]
        self.assertEqual(commands, ["fmt", "init", "validate"])
        self.assertTrue(
            {"plan", "apply", "destroy", "import", "state", "taint", "untaint"}
            .isdisjoint(commands)
        )

    def test_execution_order_is_strict_and_result_is_serialisable(self) -> None:
        self.runner.run.side_effect = self._pass_results()

        result = self.pipeline.run("GCP")

        self.assertEqual(
            [runner_call.args[0][0] for runner_call in self.runner.run.call_args_list],
            ["fmt", "init", "validate"],
        )
        payload = result.to_dict()
        self.assertEqual(payload["cloud"], "gcp")
        self.assertEqual(payload["final_status"], "PASS")
        self.assertEqual(payload["fmt"]["status"], "PASS")
        self.assertEqual(payload["init"]["status"], "PASS")
        self.assertEqual(payload["validate"]["status"], "PASS")
        self.assertIsNone(payload["error_classification"])

    def test_init_provider_failure_is_classified_on_failed_step(self) -> None:
        self.runner.run.side_effect = [
            self._result(TerraformValidationPipeline.FMT_ARGS),
            self._result(
                TerraformValidationPipeline.INIT_ARGS,
                exit_code=1,
                stderr="Failed to load plugin schemas",
            ),
        ]

        result = self.pipeline.run("gcp")

        self.assertEqual(result.failed_step, "init")
        self.assertEqual(
            result.error_classification.category,
            TerraformErrorCategory.PROVIDER_ERROR,
        )
        self.assertEqual(result.error_classification.failed_step, "init")

    def test_validate_provider_failure_is_classified(self) -> None:
        self.runner.run.side_effect = [
            *self._pass_results()[:2],
            self._result(
                TerraformValidationPipeline.VALIDATE_ARGS,
                exit_code=1,
                stderr="Plugin did not respond",
            ),
        ]

        result = self.pipeline.run("oci")

        self.assertEqual(
            result.error_classification.category,
            TerraformErrorCategory.PROVIDER_ERROR,
        )
        self.assertEqual(result.error_classification.failed_step, "validate")

    def test_init_network_failure_is_classified_and_serialised(self) -> None:
        self.runner.run.side_effect = [
            self._result(TerraformValidationPipeline.FMT_ARGS),
            self._result(
                TerraformValidationPipeline.INIT_ARGS,
                exit_code=1,
                stderr="connection refused",
            ),
        ]

        payload = self.pipeline.run("gcp").to_dict()

        self.assertEqual(payload["error_classification"]["category"], "NETWORK_ERROR")
        self.assertEqual(payload["error_classification"]["failed_step"], "init")

    def test_timeout_is_integrated_as_timeout_classification(self) -> None:
        self.runner.run.return_value = self._result(
            TerraformValidationPipeline.FMT_ARGS,
            exit_code=None,
            timed_out=True,
            stderr="",
        )

        result = self.pipeline.run("gcp")

        self.assertEqual(
            result.error_classification.category,
            TerraformErrorCategory.TIMEOUT,
        )


if __name__ == "__main__":
    unittest.main()
