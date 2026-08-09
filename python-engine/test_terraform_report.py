"""Tests unitaires du reporting Terraform structure PLAN-5."""

import json
import re
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from terraform_models import (
    TerraformErrorCategory,
    TerraformErrorClassification,
    TerraformPipelineStatus,
    TerraformPlanPipelineResult,
    TerraformPlanStatus,
    TerraformResult,
    TerraformValidationPipelineResult,
)
from terraform_report import TerraformExecutionReport, TerraformReportBuilder


class TerraformReportBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.repository_root = Path(temporary_directory.name)
        self.working_directory = (
            self.repository_root / "hcl-generator" / "generated" / "gcp"
        )
        self.working_directory.mkdir(parents=True)
        self.generated_datetime = datetime(
            2026, 8, 9, 19, 35, 0, tzinfo=timezone.utc
        )
        self.builder = TerraformReportBuilder(
            repository_root=self.repository_root,
            now_factory=lambda: self.generated_datetime,
            uuid_factory=lambda: UUID("ab12cd34-0000-0000-0000-000000000000"),
        )

    def _result(
        self,
        command: str,
        *,
        exit_code: int | None = 0,
        stdout: str = "",
        stderr: str = "",
        duration: float = 0.1,
        timed_out: bool = False,
    ) -> TerraformResult:
        return TerraformResult(
            command="terraform",
            args=(command,),
            working_directory=str(self.working_directory),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
            timed_out=timed_out,
            success=exit_code == 0 and not timed_out,
        )

    def _passed_validation(
        self,
        *,
        cloud: str = "gcp",
        fmt_duration: float = 0.1,
        init_duration: float = 0.2,
        validate_duration: float = 0.3,
    ) -> TerraformValidationPipelineResult:
        return TerraformValidationPipelineResult(
            cloud=cloud,
            working_directory=str(self.working_directory),
            fmt_result=self._result("fmt", duration=fmt_duration),
            init_result=self._result("init", duration=init_duration),
            validate_result=self._result("validate", duration=validate_duration),
            fmt_status=TerraformPipelineStatus.PASS,
            init_status=TerraformPipelineStatus.PASS,
            validate_status=TerraformPipelineStatus.PASS,
            final_status=TerraformPipelineStatus.PASS,
            failed_step=None,
            duration_seconds=fmt_duration + init_duration + validate_duration,
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
        error_classification: TerraformErrorClassification | None = None,
    ) -> TerraformPlanPipelineResult:
        validation = validation_result or self._passed_validation(cloud=cloud)
        effective_plan_result = plan_result
        if (
            effective_plan_result is None
            and plan_status is not TerraformPlanStatus.SKIPPED
        ):
            effective_plan_result = self._result(
                "plan",
                stdout="No changes.",
                duration=0.4,
            )
        return TerraformPlanPipelineResult(
            cloud=cloud,
            working_directory=str(self.working_directory),
            validation_result=validation,
            plan_result=effective_plan_result,
            plan_status=plan_status,
            final_status=final_status or plan_status,
            failed_step=failed_step,
            duration_seconds=1.0,
            error_classification=error_classification,
        )

    def _build(self, **kwargs) -> TerraformExecutionReport:
        return self.builder.build(self._pipeline_result(**kwargs))

    @staticmethod
    def _classification(
        category: TerraformErrorCategory,
        *,
        failed_step: str = "plan",
        reason_code: str = "TEST_REASON",
        message: str = "Sanitised Terraform error.",
        timed_out: bool = False,
    ) -> TerraformErrorClassification:
        return TerraformErrorClassification(
            category=category,
            failed_step=failed_step,
            exit_code=None if timed_out else 1,
            timed_out=timed_out,
            reason_code=reason_code,
            message=message,
        )

    def test_no_changes_preserves_final_status_and_has_no_error(self) -> None:
        report = self._build()

        self.assertEqual(report.final_status, "NO_CHANGES")
        self.assertIsNone(report.to_dict()["error"])

    def test_exit_two_preserves_changes_detected_as_functional_success(self) -> None:
        report = self._build(
            plan_status=TerraformPlanStatus.CHANGES_DETECTED,
            plan_result=self._result(
                "plan",
                exit_code=2,
                stdout="Plan: 1 to add, 0 to change, 0 to destroy.",
            ),
        )

        self.assertEqual(report.final_status, "CHANGES_DETECTED")
        self.assertEqual(report.plan_exit_code, 2)
        self.assertIsNone(report.to_dict()["error"])

    def test_authentication_error_is_included(self) -> None:
        classification = self._classification(
            TerraformErrorCategory.AUTHENTICATION_REQUIRED,
            reason_code="AUTH_NO_GCP_ADC",
            message="Terraform authentication is required.",
        )
        report = self._build(
            plan_status=TerraformPlanStatus.ERROR,
            plan_result=self._result("plan", exit_code=1),
            failed_step="plan",
            error_classification=classification,
        )

        error = report.to_dict()["error"]
        self.assertEqual(error["category"], "AUTHENTICATION_REQUIRED")
        self.assertEqual(error["reason_code"], "AUTH_NO_GCP_ADC")

    def test_blocked_timeout_is_included(self) -> None:
        classification = self._classification(
            TerraformErrorCategory.TIMEOUT,
            reason_code="TERRAFORM_TIMEOUT",
            message="Terraform execution timed out.",
            timed_out=True,
        )
        report = self._build(
            plan_status=TerraformPlanStatus.BLOCKED,
            plan_result=self._result(
                "plan", exit_code=None, timed_out=True, duration=4.5
            ),
            failed_step="plan",
            error_classification=classification,
        )

        self.assertEqual(report.final_status, "BLOCKED")
        self.assertTrue(report.plan_timed_out)
        self.assertEqual(report.error_category, "TIMEOUT")

    def test_init_validation_failure_skips_plan(self) -> None:
        fmt_result = self._result("fmt", duration=0.1)
        init_result = self._result("init", exit_code=1, duration=0.2)
        classification = self._classification(
            TerraformErrorCategory.PROVIDER_ERROR,
            failed_step="init",
            reason_code="PROVIDER_LOAD_FAILURE",
        )
        validation = TerraformValidationPipelineResult(
            cloud="gcp",
            working_directory=str(self.working_directory),
            fmt_result=fmt_result,
            init_result=init_result,
            validate_result=None,
            fmt_status=TerraformPipelineStatus.PASS,
            init_status=TerraformPipelineStatus.FAIL,
            validate_status=TerraformPipelineStatus.SKIPPED,
            final_status=TerraformPipelineStatus.FAIL,
            failed_step="init",
            duration_seconds=0.3,
            error_classification=classification,
        )
        report = self._build(
            plan_status=TerraformPlanStatus.SKIPPED,
            final_status=TerraformPlanStatus.ERROR,
            validation_result=validation,
            failed_step="init",
            error_classification=classification,
        )

        self.assertEqual(report.failed_step, "init")
        self.assertEqual(report.plan_status, "SKIPPED")
        self.assertIsNone(report.plan_exit_code)

    def test_run_id_is_not_empty(self) -> None:
        self.assertTrue(self._build().run_id)

    def test_successive_run_ids_are_unique(self) -> None:
        builder = TerraformReportBuilder(
            repository_root=self.repository_root,
            now_factory=lambda: self.generated_datetime,
        )

        first = builder.build(self._pipeline_result()).run_id
        second = builder.build(self._pipeline_result()).run_id

        self.assertNotEqual(first, second)

    def test_generated_at_is_utc_iso_8601(self) -> None:
        generated_at = self._build().generated_at

        self.assertEqual(generated_at, "2026-08-09T19:35:00Z")
        self.assertRegex(generated_at, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_to_dict_returns_stable_top_level_fields(self) -> None:
        payload = self._build().to_dict()

        self.assertEqual(
            list(payload),
            [
                "schema_version",
                "run_id",
                "generated_at",
                "cloud",
                "working_directory",
                "steps",
                "changes",
                "error",
                "failed_step",
                "final_status",
                "total_duration_seconds",
                "safety",
            ],
        )

    def test_to_json_returns_valid_json(self) -> None:
        payload = json.loads(self._build().to_json())

        self.assertEqual(payload["schema_version"], "1.0")

    def test_render_text_contains_cloud(self) -> None:
        self.assertIn("Cloud           : GCP", self._build().render_text())

    def test_render_text_contains_final_status(self) -> None:
        self.assertIn(
            "Final Status    : NO_CHANGES",
            self._build().render_text(),
        )

    def test_render_text_states_that_changes_were_not_applied(self) -> None:
        self.assertIn(
            "Infrastructure changes applied : NO",
            self._build().render_text(),
        )

    def test_json_safety_says_apply_was_not_executed(self) -> None:
        self.assertFalse(self._build().to_dict()["safety"]["apply_executed"])

    def test_json_safety_says_destroy_was_not_executed(self) -> None:
        self.assertFalse(self._build().to_dict()["safety"]["destroy_executed"])

    def test_total_duration_sums_only_executed_steps(self) -> None:
        report = self._build(
            plan_result=self._result("plan", stdout="No changes.", duration=0.4)
        )

        self.assertEqual(report.total_duration_seconds, 1.0)

    def test_skipped_step_has_null_exit_code_duration_and_timeout(self) -> None:
        validation = TerraformValidationPipelineResult(
            cloud="gcp",
            working_directory=str(self.working_directory),
            fmt_result=self._result("fmt"),
            init_result=None,
            validate_result=None,
            fmt_status=TerraformPipelineStatus.FAIL,
            init_status=TerraformPipelineStatus.SKIPPED,
            validate_status=TerraformPipelineStatus.SKIPPED,
            final_status=TerraformPipelineStatus.FAIL,
            failed_step="fmt",
            duration_seconds=0.1,
        )
        report = self._build(
            plan_status=TerraformPlanStatus.SKIPPED,
            final_status=TerraformPlanStatus.ERROR,
            validation_result=validation,
            failed_step="fmt",
        )

        plan_step = report.to_dict()["steps"]["plan"]
        self.assertIsNone(plan_step["exit_code"])
        self.assertIsNone(plan_step["duration_seconds"])
        self.assertIsNone(plan_step["timed_out"])

    def test_plan_summary_counts_are_extracted(self) -> None:
        report = self._build(
            plan_status=TerraformPlanStatus.CHANGES_DETECTED,
            plan_result=self._result(
                "plan",
                exit_code=2,
                stdout="Plan: 3 to add, 1 to change, 0 to destroy.",
            ),
        )

        self.assertEqual(
            (report.add_count, report.change_count, report.destroy_count),
            (3, 1, 0),
        )

    def test_no_changes_output_produces_zero_counts(self) -> None:
        report = self._build(
            plan_result=self._result("plan", stdout="No changes.")
        )

        self.assertEqual(
            (report.add_count, report.change_count, report.destroy_count),
            (0, 0, 0),
        )

    def test_unknown_plan_output_keeps_counts_null(self) -> None:
        report = self._build(
            plan_result=self._result("plan", stdout="Planning completed.")
        )

        self.assertEqual(
            (report.add_count, report.change_count, report.destroy_count),
            (None, None, None),
        )

    def test_json_does_not_include_full_stdout(self) -> None:
        raw_stdout = "RAW_STDOUT_DO_NOT_PROPAGATE"
        report = self._build(
            plan_result=self._result("plan", stdout=raw_stdout)
        )

        self.assertNotIn(raw_stdout, report.to_json())
        self.assertNotIn("stdout", report.to_dict())

    def test_json_does_not_include_full_stderr(self) -> None:
        raw_stderr = "RAW_STDERR_DO_NOT_PROPAGATE"
        report = self._build(
            plan_status=TerraformPlanStatus.ERROR,
            plan_result=self._result("plan", exit_code=1, stderr=raw_stderr),
            failed_step="plan",
        )

        self.assertNotIn(raw_stderr, report.to_json())
        self.assertNotIn("stderr", report.to_dict())

    def test_fake_token_from_source_is_absent_from_report(self) -> None:
        secret = "fake-token-123456"
        report = self._build(
            plan_status=TerraformPlanStatus.ERROR,
            plan_result=self._result(
                "plan", exit_code=1, stderr=f"token={secret}"
            ),
            failed_step="plan",
        )

        self.assertNotIn(secret, report.to_json())
        self.assertNotIn(secret, report.render_text())

    def test_fake_password_from_source_is_absent_from_report(self) -> None:
        secret = "fake-password-123456"
        report = self._build(
            plan_status=TerraformPlanStatus.ERROR,
            plan_result=self._result(
                "plan", exit_code=1, stderr=f"password={secret}"
            ),
            failed_step="plan",
        )

        self.assertNotIn(secret, report.to_json())
        self.assertNotIn(secret, report.render_text())

    def test_fake_private_key_from_source_is_absent_from_report(self) -> None:
        secret = "FAKE_PRIVATE_KEY_MATERIAL"
        report = self._build(
            plan_status=TerraformPlanStatus.ERROR,
            plan_result=self._result(
                "plan", exit_code=1, stderr=f"private_key={secret}"
            ),
            failed_step="plan",
        )

        self.assertNotIn(secret, report.to_json())
        self.assertNotIn(secret, report.render_text())

    def test_write_report_writes_json_as_utf8(self) -> None:
        report = replace(self._build(), working_directory="répertoire/détecté")
        output_directory = self.repository_root / "reports-json"

        json_path, _ = self.builder.write_report(report, output_directory)

        self.assertIn("détecté", json_path.read_text(encoding="utf-8"))
        self.assertEqual(
            json.loads(json_path.read_text(encoding="utf-8"))["cloud"],
            "gcp",
        )

    def test_write_report_writes_text_as_utf8(self) -> None:
        report = replace(self._build(), working_directory="répertoire/gcp")
        output_directory = self.repository_root / "reports-text"

        _, text_path = self.builder.write_report(report, output_directory)

        self.assertIn("répertoire/gcp", text_path.read_text(encoding="utf-8"))

    def test_report_filenames_are_derived_only_from_safe_run_id(self) -> None:
        report = self._build()
        json_path, text_path = self.builder.write_report(
            report, self.repository_root / "safe-reports"
        )

        self.assertEqual(json_path.name, f"{report.run_id}.json")
        self.assertEqual(text_path.name, f"{report.run_id}.txt")
        self.assertRegex(
            report.run_id,
            r"^tfplan_gcp_\d{8}T\d{6}Z_[0-9a-f]{8}$",
        )

    def test_unsafe_run_id_is_rejected_before_file_creation(self) -> None:
        report = replace(self._build(), run_id="../unsafe")
        output_directory = self.repository_root / "unsafe-reports"

        with self.assertRaisesRegex(ValueError, "run_id invalide"):
            self.builder.write_report(report, output_directory)

        self.assertFalse(output_directory.exists())

    def test_gcp_cloud_is_preserved(self) -> None:
        self.assertEqual(self._build(cloud="gcp").cloud, "gcp")

    def test_oci_cloud_is_preserved(self) -> None:
        oci_working_directory = (
            self.repository_root / "hcl-generator" / "generated" / "oci"
        )
        oci_working_directory.mkdir(parents=True)
        validation = replace(
            self._passed_validation(cloud="oci"),
            cloud="oci",
            working_directory=str(oci_working_directory),
        )
        pipeline_result = replace(
            self._pipeline_result(cloud="oci", validation_result=validation),
            working_directory=str(oci_working_directory),
        )

        report = self.builder.build(pipeline_result)

        self.assertEqual(report.cloud, "oci")
        self.assertTrue(report.run_id.startswith("tfplan_oci_"))

    def test_working_directory_is_relative_to_repository(self) -> None:
        self.assertEqual(
            self._build().working_directory,
            "hcl-generator/generated/gcp",
        )

    def test_build_has_no_disk_side_effect(self) -> None:
        default_directory = (
            self.repository_root / TerraformReportBuilder.DEFAULT_REPORT_DIRECTORY
        )

        self._build()

        self.assertFalse(default_directory.exists())

    def test_schema_version_is_one(self) -> None:
        self.assertEqual(self._build().schema_version, "1.0")

    def test_step_durations_remain_numeric(self) -> None:
        steps = self._build().to_dict()["steps"]

        self.assertIsInstance(steps["fmt"]["duration_seconds"], float)
        self.assertIsInstance(steps["plan"]["duration_seconds"], float)

    def test_unknown_counts_render_as_na(self) -> None:
        report = self._build(
            plan_result=self._result("plan", stdout="Unknown plan summary")
        )

        self.assertIn("Add             : N/A", report.render_text())

    def test_atomic_write_leaves_no_temporary_files(self) -> None:
        output_directory = self.repository_root / "atomic-reports"

        self.builder.write_report(self._build(), output_directory)

        self.assertEqual(list(output_directory.glob("*.tmp")), [])

    def test_run_id_does_not_depend_on_windows_user_profile(self) -> None:
        run_id = self._build().run_id

        self.assertIsNone(re.search(r"LENOVO|Users|Desktop", run_id, re.IGNORECASE))


if __name__ == "__main__":
    unittest.main()
