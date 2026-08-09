"""Tests unitaires de l'orchestration Terraform end-to-end PLAN-6."""

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock
from uuid import UUID

from terraform_e2e import (
    TerraformEndToEndPipeline,
    TerraformEngineStatus,
)
from terraform_models import (
    TerraformErrorCategory,
    TerraformErrorClassification,
    TerraformPipelineStatus,
    TerraformPlanPipelineResult,
    TerraformPlanStatus,
    TerraformResult,
    TerraformValidationPipelineResult,
    UnknownTerraformCloudError,
)
from terraform_plan import TerraformPlanPipeline
from terraform_report import TerraformReportBuilder


class TerraformEndToEndPipelineTests(unittest.TestCase):
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
        self.plan_pipeline = MagicMock(spec=TerraformPlanPipeline)
        real_builder = TerraformReportBuilder(
            repository_root=self.repository_root,
            now_factory=lambda: datetime(
                2026, 8, 9, 19, 35, 0, tzinfo=timezone.utc
            ),
            uuid_factory=lambda: UUID(
                "ab12cd34-0000-0000-0000-000000000000"
            ),
        )
        self.report_builder = MagicMock(
            spec=TerraformReportBuilder,
            wraps=real_builder,
        )
        self.engine = TerraformEndToEndPipeline(
            self.plan_pipeline,
            self.report_builder,
        )

    def _terraform_result(
        self,
        command: str,
        *,
        cloud: str = "gcp",
        exit_code: int | None = 0,
        stdout: str = "",
        stderr: str = "",
        duration: float = 0.1,
        timed_out: bool = False,
    ) -> TerraformResult:
        directory = self.gcp_directory if cloud == "gcp" else self.oci_directory
        return TerraformResult(
            command="terraform",
            args=(command,),
            working_directory=str(directory),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
            timed_out=timed_out,
            success=exit_code == 0 and not timed_out,
        )

    def _passed_validation(self, cloud: str) -> TerraformValidationPipelineResult:
        directory = self.gcp_directory if cloud == "gcp" else self.oci_directory
        return TerraformValidationPipelineResult(
            cloud=cloud,
            working_directory=str(directory),
            fmt_result=self._terraform_result("fmt", cloud=cloud, duration=0.1),
            init_result=self._terraform_result("init", cloud=cloud, duration=0.2),
            validate_result=self._terraform_result(
                "validate", cloud=cloud, duration=0.3
            ),
            fmt_status=TerraformPipelineStatus.PASS,
            init_status=TerraformPipelineStatus.PASS,
            validate_status=TerraformPipelineStatus.PASS,
            final_status=TerraformPipelineStatus.PASS,
            failed_step=None,
            duration_seconds=0.6,
        )

    @staticmethod
    def _classification(
        category: TerraformErrorCategory,
        *,
        failed_step: str = "plan",
        reason_code: str = "TEST_REASON",
        timed_out: bool = False,
    ) -> TerraformErrorClassification:
        messages = {
            TerraformErrorCategory.AUTHENTICATION_REQUIRED: (
                "Terraform authentication is required."
            ),
            TerraformErrorCategory.VARIABLES_MISSING: (
                "A required Terraform variable is missing."
            ),
            TerraformErrorCategory.PROVIDER_ERROR: (
                "Terraform provider failed to start or respond."
            ),
            TerraformErrorCategory.NETWORK_ERROR: (
                "Terraform encountered a network error."
            ),
            TerraformErrorCategory.STATE_ERROR: (
                "Terraform could not access the state."
            ),
            TerraformErrorCategory.TIMEOUT: "Terraform execution timed out.",
            TerraformErrorCategory.UNKNOWN_ERROR: (
                "Terraform failed with an unclassified error."
            ),
        }
        return TerraformErrorClassification(
            category=category,
            failed_step=failed_step,
            exit_code=None if timed_out else 1,
            timed_out=timed_out,
            reason_code=reason_code,
            message=messages[category],
        )

    def _pipeline_result(
        self,
        *,
        cloud: str = "gcp",
        plan_status: TerraformPlanStatus = TerraformPlanStatus.NO_CHANGES,
        final_status: TerraformPlanStatus | None = None,
        plan_result: TerraformResult | None = None,
        validation_result: TerraformValidationPipelineResult | None = None,
        failed_step: str | None = None,
        classification: TerraformErrorClassification | None = None,
    ) -> TerraformPlanPipelineResult:
        directory = self.gcp_directory if cloud == "gcp" else self.oci_directory
        if plan_result is None and plan_status is not TerraformPlanStatus.SKIPPED:
            plan_result = self._terraform_result(
                "plan",
                cloud=cloud,
                stdout="No changes.",
                duration=0.4,
            )
        return TerraformPlanPipelineResult(
            cloud=cloud,
            working_directory=str(directory),
            validation_result=(
                validation_result or self._passed_validation(cloud)
            ),
            plan_result=plan_result,
            plan_status=plan_status,
            final_status=final_status or plan_status,
            failed_step=failed_step,
            duration_seconds=1.0,
            error_classification=classification,
        )

    def _error_result(
        self,
        category: TerraformErrorCategory,
        *,
        cloud: str = "gcp",
        reason_code: str = "TEST_REASON",
        stdout: str = "",
        stderr: str = "Terraform error",
    ) -> TerraformPlanPipelineResult:
        classification = self._classification(
            category,
            reason_code=reason_code,
        )
        return self._pipeline_result(
            cloud=cloud,
            plan_status=TerraformPlanStatus.ERROR,
            plan_result=self._terraform_result(
                "plan",
                cloud=cloud,
                exit_code=1,
                stdout=stdout,
                stderr=stderr,
            ),
            failed_step="plan",
            classification=classification,
        )

    def _run(self, result: TerraformPlanPipelineResult, **kwargs):
        self.plan_pipeline.run.return_value = result
        return self.engine.run(result.cloud, **kwargs)

    def test_gcp_no_changes_is_engine_pass(self) -> None:
        result = self._run(self._pipeline_result(cloud="gcp"))

        self.assertEqual(result.engine_status, TerraformEngineStatus.PASS)
        self.assertEqual(result.terraform_final_status, "NO_CHANGES")

    def test_oci_no_changes_is_engine_pass(self) -> None:
        result = self._run(self._pipeline_result(cloud="oci"))

        self.assertEqual(result.engine_status, TerraformEngineStatus.PASS)
        self.assertEqual(result.cloud, "oci")

    def test_gcp_exit_two_changes_detected_is_engine_pass(self) -> None:
        pipeline_result = self._pipeline_result(
            plan_status=TerraformPlanStatus.CHANGES_DETECTED,
            plan_result=self._terraform_result(
                "plan",
                exit_code=2,
                stdout="Plan: 1 to add, 0 to change, 0 to destroy.",
            ),
        )

        result = self._run(pipeline_result)

        self.assertEqual(result.engine_status, TerraformEngineStatus.PASS)
        self.assertEqual(result.terraform_final_status, "CHANGES_DETECTED")

    def test_oci_exit_two_changes_detected_is_engine_pass(self) -> None:
        pipeline_result = self._pipeline_result(
            cloud="oci",
            plan_status=TerraformPlanStatus.CHANGES_DETECTED,
            plan_result=self._terraform_result(
                "plan",
                cloud="oci",
                exit_code=2,
                stdout="Plan: 2 to add, 0 to change, 0 to destroy.",
            ),
        )

        result = self._run(pipeline_result)

        self.assertEqual(result.engine_status, TerraformEngineStatus.PASS)
        self.assertEqual(result.report.plan_exit_code, 2)

    def test_plan_authentication_error_is_reported_with_engine_pass(self) -> None:
        pipeline_result = self._error_result(
            TerraformErrorCategory.AUTHENTICATION_REQUIRED,
            reason_code="AUTH_NO_GCP_ADC",
            stderr="could not find default credentials",
        )

        result = self._run(pipeline_result)

        self.assertEqual(result.engine_status, TerraformEngineStatus.PASS)
        self.assertEqual(result.terraform_final_status, "ERROR")
        self.assertEqual(result.report.error_category, "AUTHENTICATION_REQUIRED")

    def test_variables_missing_error_is_reported(self) -> None:
        result = self._run(
            self._error_result(TerraformErrorCategory.VARIABLES_MISSING)
        )

        self.assertEqual(result.report.error_category, "VARIABLES_MISSING")

    def test_provider_error_on_validate_skips_plan_and_is_reported(self) -> None:
        classification = self._classification(
            TerraformErrorCategory.PROVIDER_ERROR,
            failed_step="validate",
            reason_code="PROVIDER_SCHEMA_FAILURE",
        )
        validation = TerraformValidationPipelineResult(
            cloud="gcp",
            working_directory=str(self.gcp_directory),
            fmt_result=self._terraform_result("fmt"),
            init_result=self._terraform_result("init"),
            validate_result=self._terraform_result(
                "validate",
                exit_code=1,
                stderr="Plugin did not respond: GetProviderSchema",
            ),
            fmt_status=TerraformPipelineStatus.PASS,
            init_status=TerraformPipelineStatus.PASS,
            validate_status=TerraformPipelineStatus.FAIL,
            final_status=TerraformPipelineStatus.FAIL,
            failed_step="validate",
            duration_seconds=0.3,
            error_classification=classification,
        )
        pipeline_result = self._pipeline_result(
            plan_status=TerraformPlanStatus.SKIPPED,
            final_status=TerraformPlanStatus.ERROR,
            validation_result=validation,
            failed_step="validate",
            classification=classification,
        )

        result = self._run(pipeline_result)

        self.assertEqual(result.report.plan_status, "SKIPPED")
        self.assertEqual(result.report.error_category, "PROVIDER_ERROR")

    def test_network_error_is_reported(self) -> None:
        result = self._run(
            self._error_result(TerraformErrorCategory.NETWORK_ERROR)
        )

        self.assertEqual(result.report.error_category, "NETWORK_ERROR")

    def test_state_error_is_reported(self) -> None:
        result = self._run(
            self._error_result(TerraformErrorCategory.STATE_ERROR)
        )

        self.assertEqual(result.report.error_category, "STATE_ERROR")

    def test_timeout_is_reported_with_engine_pass(self) -> None:
        classification = self._classification(
            TerraformErrorCategory.TIMEOUT,
            reason_code="TERRAFORM_TIMEOUT",
            timed_out=True,
        )
        pipeline_result = self._pipeline_result(
            plan_status=TerraformPlanStatus.BLOCKED,
            plan_result=self._terraform_result(
                "plan", exit_code=None, timed_out=True
            ),
            failed_step="plan",
            classification=classification,
        )

        result = self._run(pipeline_result)

        self.assertEqual(result.engine_status, TerraformEngineStatus.PASS)
        self.assertEqual(result.report.error_category, "TIMEOUT")

    def test_unknown_error_is_reported(self) -> None:
        result = self._run(
            self._error_result(TerraformErrorCategory.UNKNOWN_ERROR)
        )

        self.assertEqual(result.report.error_category, "UNKNOWN_ERROR")

    def test_write_report_false_creates_no_files(self) -> None:
        output_directory = self.repository_root / "reports-disabled"

        result = self._run(
            self._pipeline_result(),
            write_report=False,
            report_directory=output_directory,
        )

        self.assertFalse(result.report_written)
        self.assertFalse(output_directory.exists())
        self.report_builder.write_report.assert_not_called()

    def test_write_report_true_creates_json(self) -> None:
        output_directory = self.repository_root / "reports-json"

        result = self._run(
            self._pipeline_result(),
            write_report=True,
            report_directory=output_directory,
        )

        self.assertTrue(result.json_path.is_file())
        json.loads(result.json_path.read_text(encoding="utf-8"))

    def test_write_report_true_creates_text(self) -> None:
        output_directory = self.repository_root / "reports-text"

        result = self._run(
            self._pipeline_result(),
            write_report=True,
            report_directory=output_directory,
        )

        self.assertTrue(result.text_path.is_file())
        self.assertIn(
            "TERRAFORM PLAN REPORT",
            result.text_path.read_text(encoding="utf-8"),
        )

    def test_written_json_and_text_use_same_run_id(self) -> None:
        result = self._run(
            self._pipeline_result(),
            write_report=True,
            report_directory=self.repository_root / "same-run-id",
        )

        self.assertEqual(result.json_path.stem, result.report.run_id)
        self.assertEqual(result.text_path.stem, result.report.run_id)

    def test_one_e2e_run_never_calls_plan_pipeline_twice(self) -> None:
        self._run(self._pipeline_result())

        self.assertEqual(self.plan_pipeline.run.call_count, 1)

    def test_plan_pipeline_is_called_exactly_once_with_cloud(self) -> None:
        self._run(self._pipeline_result(cloud="gcp"))

        self.plan_pipeline.run.assert_called_once_with("gcp")

    def test_report_builder_is_called_exactly_once(self) -> None:
        pipeline_result = self._pipeline_result()

        self._run(pipeline_result)

        self.report_builder.build.assert_called_once_with(pipeline_result)

    def test_exit_two_never_sets_engine_fail(self) -> None:
        pipeline_result = self._pipeline_result(
            plan_status=TerraformPlanStatus.CHANGES_DETECTED,
            plan_result=self._terraform_result("plan", exit_code=2),
        )

        self.assertEqual(
            self._run(pipeline_result).engine_status,
            TerraformEngineStatus.PASS,
        )

    def test_exit_one_terraform_never_sets_engine_fail(self) -> None:
        result = self._run(
            self._error_result(TerraformErrorCategory.UNKNOWN_ERROR)
        )

        self.assertEqual(result.engine_status, TerraformEngineStatus.PASS)

    def test_internal_report_builder_exception_sets_engine_fail(self) -> None:
        self.plan_pipeline.run.return_value = self._pipeline_result()
        self.report_builder.build.side_effect = RuntimeError("sensitive detail")

        result = self.engine.run("gcp")

        self.assertEqual(result.engine_status, TerraformEngineStatus.FAIL)
        self.assertEqual(result.engine_error, "Internal Terraform engine error.")
        self.assertNotIn("sensitive detail", result.to_dict().values())

    def test_unknown_cloud_is_rejected_before_pipeline_call(self) -> None:
        with self.assertRaises(UnknownTerraformCloudError):
            self.engine.run("azure")

        self.plan_pipeline.run.assert_not_called()
        self.report_builder.build.assert_not_called()

    def test_gcp_report_path_is_relative_and_correct(self) -> None:
        result = self._run(self._pipeline_result(cloud="gcp"))

        self.assertEqual(
            result.report.working_directory,
            "hcl-generator/generated/gcp",
        )

    def test_oci_report_path_is_relative_and_correct(self) -> None:
        result = self._run(self._pipeline_result(cloud="oci"))

        self.assertEqual(
            result.report.working_directory,
            "hcl-generator/generated/oci",
        )

    def test_report_contains_no_raw_stdout(self) -> None:
        marker = "RAW_STDOUT_MARKER"
        pipeline_result = self._pipeline_result(
            plan_result=self._terraform_result("plan", stdout=marker)
        )

        result = self._run(pipeline_result)

        self.assertNotIn(marker, result.json)
        self.assertNotIn(marker, result.text)

    def test_report_contains_no_raw_stderr(self) -> None:
        marker = "RAW_STDERR_MARKER"
        result = self._run(
            self._error_result(
                TerraformErrorCategory.UNKNOWN_ERROR,
                stderr=marker,
            )
        )

        self.assertNotIn(marker, result.json)
        self.assertNotIn(marker, result.text)

    def test_fake_secret_is_absent_from_json(self) -> None:
        secret = "fake-token-sensitive-value"
        result = self._run(
            self._error_result(
                TerraformErrorCategory.AUTHENTICATION_REQUIRED,
                stderr=f"token={secret}",
            )
        )

        self.assertNotIn(secret, result.json)

    def test_report_safety_apply_is_false(self) -> None:
        safety = self._run(self._pipeline_result()).report.to_dict()["safety"]

        self.assertFalse(safety["apply_executed"])

    def test_report_safety_destroy_is_false(self) -> None:
        safety = self._run(self._pipeline_result()).report.to_dict()["safety"]

        self.assertFalse(safety["destroy_executed"])

    def test_report_schema_version_is_one(self) -> None:
        result = self._run(self._pipeline_result())

        self.assertEqual(result.report.schema_version, "1.0")

    def test_result_exposes_json_and_text_in_memory(self) -> None:
        result = self._run(self._pipeline_result())

        self.assertEqual(json.loads(result.json)["cloud"], "gcp")
        self.assertIn("TERRAFORM PLAN REPORT", result.text)

    def test_result_to_dict_keeps_engine_and_terraform_status_separate(self) -> None:
        result = self._run(
            self._error_result(TerraformErrorCategory.UNKNOWN_ERROR)
        )

        payload = result.to_dict()
        self.assertEqual(payload["engine_status"], "PASS")
        self.assertEqual(payload["terraform_final_status"], "ERROR")

    def test_plan_pipeline_exception_sets_engine_fail_without_report(self) -> None:
        self.plan_pipeline.run.side_effect = RuntimeError("runner failed")

        result = self.engine.run("oci")

        self.assertEqual(result.engine_status, TerraformEngineStatus.FAIL)
        self.assertIsNone(result.report)
        self.assertIsNone(result.terraform_final_status)

    def test_report_write_exception_sets_engine_fail(self) -> None:
        self.plan_pipeline.run.return_value = self._pipeline_result()
        self.report_builder.write_report.side_effect = OSError("disk detail")

        result = self.engine.run("gcp", write_report=True)

        self.assertEqual(result.engine_status, TerraformEngineStatus.FAIL)
        self.assertIsNotNone(result.report)
        self.assertFalse(result.report_written)


if __name__ == "__main__":
    unittest.main()
