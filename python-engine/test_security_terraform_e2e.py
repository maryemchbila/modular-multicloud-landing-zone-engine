"""Tests CIS-8 du pipeline Terraform vers evaluation de securite."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from security_evaluation import (
    MultiCloudSecurityEvaluationResult,
    build_default_multicloud_security_engine,
)
from security_models import (
    RuleStatus,
    SecurityFinding,
    SecurityScanResult,
    SecuritySeverity,
)
from security_report import SecurityComplianceReportBuilder
from security_terraform_adapter import TerraformSecurityResourceAdapter
from security_terraform_e2e import (
    TerraformSecurityEndToEndPipeline,
    TerraformSecurityStageStatus,
    _print_safe_summary,
    build_default_terraform_security_engine,
)
from terraform_e2e import (
    TerraformEndToEndPipeline,
    TerraformEngineStatus,
)
from terraform_error_classifier import TerraformErrorClassifier
from terraform_models import (
    TerraformPlanStatus,
    TerraformResult,
    UnsafeTerraformCommandError,
)
from terraform_pipeline import TerraformValidationPipeline
from terraform_plan import TerraformPlanPipeline
from terraform_report import TerraformReportBuilder
from terraform_runner import TerraformRunner


FAKE_SECRETS = (
    "FAKE_PASSWORD_CIS8",
    "FAKE_TOKEN_CIS8",
    "FAKE_PRIVATE_KEY_CIS8",
    "FAKE_SECRET_CIS8",
)


def _resource(resource_type: str, name: str, values: dict) -> dict:
    return {
        "address": f"{resource_type}.{name}",
        "mode": "managed",
        "type": resource_type,
        "name": name,
        "values": {
            **values,
            "password": FAKE_SECRETS[0],
            "token": FAKE_SECRETS[1],
            "private_key": FAKE_SECRETS[2],
            "secret": FAKE_SECRETS[3],
        },
    }


def _synthetic_plan() -> dict:
    return {
        "format_version": "1.2",
        "planned_values": {
            "root_module": {
                "resources": [
                    _resource(
                        "google_compute_instance",
                        "gcp_vm",
                        {
                            "network_interface": [{"access_config": [{}]}],
                            "shielded_instance_config": [
                                {"enable_secure_boot": False}
                            ],
                            "deletion_protection": False,
                        },
                    ),
                    _resource(
                        "google_compute_firewall",
                        "gcp_fw",
                        {
                            "direction": "INGRESS",
                            "source_ranges": ["0.0.0.0/0"],
                            "allow": [{"protocol": "tcp", "ports": ["22"]}],
                        },
                    ),
                    _resource(
                        "google_storage_bucket",
                        "gcp_bucket",
                        {
                            "public_access_prevention": "inherited",
                            "uniform_bucket_level_access": False,
                            "versioning": [{"enabled": False}],
                        },
                    ),
                    _resource(
                        "google_project_iam_member",
                        "gcp_iam",
                        {"role": "roles/editor", "member": "allUsers"},
                    ),
                    _resource(
                        "oci_core_instance",
                        "oci_vm",
                        {
                            "create_vnic_details": [{"assign_public_ip": True}],
                            "platform_config": [{"is_secure_boot_enabled": False}],
                        },
                    ),
                    _resource(
                        "oci_core_security_list",
                        "oci_sl",
                        {
                            "ingress_security_rules": [
                                {
                                    "source": "0.0.0.0/0",
                                    "protocol": "6",
                                    "tcp_options": [
                                        {
                                            "destination_port_range": [
                                                {"min": 22, "max": 22}
                                            ]
                                        }
                                    ],
                                }
                            ]
                        },
                    ),
                    _resource(
                        "oci_objectstorage_bucket",
                        "oci_bucket",
                        {"access_type": "ObjectRead", "versioning": "Disabled"},
                    ),
                    _resource(
                        "oci_identity_policy",
                        "oci_policy",
                        {"statements": ["Allow group Admins to manage all-resources"]},
                    ),
                ]
            }
        },
        "sensitive_values": {"raw": FAKE_SECRETS[3]},
    }


class _FakeTerraformRunner:
    def __init__(self, plan_data: dict | None = None) -> None:
        self.plan_data = plan_data or _synthetic_plan()
        self.calls: list[tuple[tuple[str, ...], Path]] = []
        self.plan_exit_code = 2
        self.plan_stderr = ""
        self.show_exit_code = 0
        self.show_stdout: str | None = None
        self.show_stderr = ""
        self.create_saved_plan = True
        self.fail_step: str | None = None
        self.fail_stderr = "Terraform error"

    def run(self, args, cwd, timeout=None) -> TerraformResult:
        safe_args = tuple(args)
        working_directory = Path(cwd).resolve()
        self.calls.append((safe_args, working_directory))
        step = safe_args[0]
        exit_code = 0
        stderr = ""
        stdout = ""
        if step == self.fail_step:
            exit_code = 1
            stderr = self.fail_stderr
        elif step == "plan":
            exit_code = self.plan_exit_code
            stderr = self.plan_stderr
            stdout = (
                "Plan: 8 to add, 0 to change, 0 to destroy."
                if exit_code == 2
                else "No changes."
            )
            output_arguments = [
                argument for argument in safe_args if argument.startswith("-out=")
            ]
            if self.create_saved_plan and exit_code in {0, 2} and output_arguments:
                Path(output_arguments[0].split("=", 1)[1]).write_bytes(b"CIS8-PLAN")
        elif step == "show":
            exit_code = self.show_exit_code
            stderr = self.show_stderr
            stdout = (
                self.show_stdout
                if self.show_stdout is not None
                else json.dumps(self.plan_data)
            )
        return TerraformResult(
            command="terraform",
            args=safe_args,
            working_directory=str(working_directory),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=0.01,
            timed_out=False,
            success=exit_code == 0,
        )


class TerraformSecurityEndToEndPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.repository_root = Path(temporary_directory.name).resolve()
        for cloud in ("gcp", "oci"):
            (
                self.repository_root / "hcl-generator" / "generated" / cloud
            ).mkdir(parents=True)
        self.runner = _FakeTerraformRunner()
        self.engine = self._build_engine(self.runner)

    def _build_engine(
        self,
        runner: _FakeTerraformRunner,
    ) -> TerraformSecurityEndToEndPipeline:
        classifier = TerraformErrorClassifier()
        validation = TerraformValidationPipeline(
            runner,
            repository_root=self.repository_root,
            error_classifier=classifier,
        )
        plan = TerraformPlanPipeline(
            runner,
            validation_pipeline=validation,
            error_classifier=classifier,
        )
        terraform_e2e = TerraformEndToEndPipeline(
            plan,
            TerraformReportBuilder(repository_root=self.repository_root),
        )
        evaluation = build_default_multicloud_security_engine()
        return TerraformSecurityEndToEndPipeline(
            terraform_pipeline=terraform_e2e,
            runner=runner,
            error_classifier=classifier,
            adapter=TerraformSecurityResourceAdapter(),
            evaluation_engine=evaluation,
            report_builder=SecurityComplianceReportBuilder(
                repository_root=self.repository_root,
                catalog=evaluation.catalog,
            ),
        )

    def _run(self, cloud: str = "gcp", **kwargs):
        return self.engine.run(cloud=cloud, **kwargs)

    def _calls_for(self, step: str) -> list[tuple[tuple[str, ...], Path]]:
        return [call for call in self.runner.calls if call[0][0] == step]

    def _plan_path(self) -> Path:
        plan_call = self._calls_for("plan")[0][0]
        output = next(arg for arg in plan_call if arg.startswith("-out="))
        return Path(output.split("=", 1)[1])

    def test_factory_builds_cis8_engine(self) -> None:
        engine = build_default_terraform_security_engine(self.repository_root)
        self.assertIsInstance(engine, TerraformSecurityEndToEndPipeline)

    def test_gcp_pipeline_builds(self) -> None:
        self.assertEqual(self._run("gcp").cloud, "gcp")

    def test_oci_pipeline_builds(self) -> None:
        self.assertEqual(self._run("oci").cloud, "oci")

    def test_temporary_directory_is_used(self) -> None:
        self._run()
        self.assertNotEqual(self._plan_path().parent, self.repository_root)

    def test_saved_plan_path_is_internal_temp(self) -> None:
        self._run()
        self.assertEqual(self._plan_path().name, "security_plan.tfplan")
        self.assertFalse(self._plan_path().is_relative_to(self.repository_root))

    def test_plan_is_called_once(self) -> None:
        self._run()
        self.assertEqual(len(self._calls_for("plan")), 1)

    def test_show_is_called_once_after_plan_success(self) -> None:
        self._run()
        self.assertEqual(len(self._calls_for("show")), 1)

    def test_show_is_absent_after_plan_error(self) -> None:
        self.runner.plan_exit_code = 1
        self._run()
        self.assertFalse(self._calls_for("show"))

    def test_show_has_exact_explicit_arguments(self) -> None:
        self._run()
        self.assertEqual(
            self._calls_for("show")[0][0],
            ("show", "-json", str(self._plan_path())),
        )

    def test_cis8_module_has_no_direct_subprocess(self) -> None:
        source = Path(__file__).with_name("security_terraform_e2e.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("subprocess", source)

    def test_plan_exit_zero_continues_security(self) -> None:
        self.runner.plan_exit_code = 0
        result = self._run()
        self.assertEqual(result.show_status, TerraformSecurityStageStatus.PASS)

    def test_plan_exit_two_continues_security(self) -> None:
        result = self._run()
        self.assertEqual(result.terraform_final_status, "CHANGES_DETECTED")

    def test_plan_exit_one_stops_security_cleanly(self) -> None:
        self.runner.plan_exit_code = 1
        result = self._run()
        self.assertEqual(result.engine_status, TerraformEngineStatus.PASS)
        self.assertEqual(result.adaptation_status, TerraformSecurityStageStatus.SKIPPED)

    def test_variables_missing_stops_show(self) -> None:
        self.runner.plan_exit_code = 1
        self.runner.plan_stderr = "No value for required variable"
        result = self._run()
        self.assertEqual(result.terraform_result.report.error_category, "VARIABLES_MISSING")
        self.assertEqual(result.show_status, TerraformSecurityStageStatus.SKIPPED)

    def test_authentication_error_stops_show(self) -> None:
        self.runner.plan_exit_code = 1
        self.runner.plan_stderr = "could not find default credentials"
        result = self._run()
        self.assertEqual(
            result.terraform_result.report.error_category,
            "AUTHENTICATION_REQUIRED",
        )

    def test_provider_error_stops_show(self) -> None:
        self.runner.fail_step = "validate"
        self.runner.fail_stderr = "Plugin did not respond: GetProviderSchema"
        result = self._run()
        self.assertEqual(result.terraform_result.report.error_category, "PROVIDER_ERROR")
        self.assertFalse(self._calls_for("show"))

    def test_show_nonzero_is_handled(self) -> None:
        self.runner.show_exit_code = 1
        self.runner.show_stderr = "could not find default credentials"
        result = self._run()
        self.assertEqual(result.engine_status, TerraformEngineStatus.PASS)
        self.assertEqual(result.show_status, TerraformSecurityStageStatus.ERROR)
        self.assertEqual(
            result.show_error_classification.category.value,
            "AUTHENTICATION_REQUIRED",
        )

    def test_show_invalid_json_is_sanitized(self) -> None:
        marker = "NOT_JSON_FAKE_SECRET"
        self.runner.show_stdout = marker
        result = self._run()
        self.assertEqual(result.engine_status, TerraformEngineStatus.FAIL)
        self.assertEqual(result.engine_error, "Terraform show returned invalid JSON.")
        self.assertNotIn(marker, repr(result))

    def test_show_valid_non_mapping_json_is_rejected(self) -> None:
        self.runner.show_stdout = "[]"
        result = self._run()
        self.assertEqual(result.engine_status, TerraformEngineStatus.FAIL)
        self.assertEqual(result.engine_error, "Terraform show returned invalid JSON.")

    def test_plan_success_without_file_is_handled(self) -> None:
        self.runner.create_saved_plan = False
        result = self._run()
        self.assertEqual(result.engine_status, TerraformEngineStatus.FAIL)
        self.assertEqual(result.engine_error, "Terraform saved plan is unavailable.")
        self.assertFalse(self._calls_for("show"))

    def test_adapter_runs_after_valid_json(self) -> None:
        adapter = MagicMock(wraps=self.engine.adapter)
        self.engine.adapter = adapter
        self._run()
        adapter.from_plan_dict.assert_called_once()

    def test_security_engine_runs_after_adaptation(self) -> None:
        evaluation = MagicMock(wraps=self.engine.evaluation_engine)
        self.engine.evaluation_engine = evaluation
        self._run()
        evaluation.evaluate.assert_called_once()

    def test_report_builder_runs_after_evaluation(self) -> None:
        builder = MagicMock(wraps=self.engine.report_builder)
        self.engine.report_builder = builder
        self._run()
        builder.build.assert_called_once()

    def test_gcp_security_fail_does_not_fail_engine(self) -> None:
        result = self._run("gcp")
        self.assertEqual(result.security_evaluation_status, TerraformSecurityStageStatus.FAIL)
        self.assertEqual(result.engine_status, TerraformEngineStatus.PASS)

    def test_oci_security_fail_does_not_fail_engine(self) -> None:
        result = self._run("oci")
        self.assertEqual(result.security_evaluation_status, TerraformSecurityStageStatus.FAIL)
        self.assertEqual(result.engine_status, TerraformEngineStatus.PASS)

    def test_security_pass_is_preserved(self) -> None:
        self.runner.plan_data = {"planned_values": {"root_module": {"resources": []}}}
        result = self._run()
        self.assertEqual(result.security_evaluation_status, TerraformSecurityStageStatus.PASS)

    def test_security_pass_with_warnings_is_preserved(self) -> None:
        finding = SecurityFinding(
            rule_id="GCP-TEST",
            cloud="gcp",
            resource_type="google_compute_instance",
            resource_name="gcp_vm",
            resource_address="google_compute_instance.gcp_vm",
            status=RuleStatus.WARNING,
            severity=SecuritySeverity.MEDIUM,
            title="Test warning",
            message="Safe warning.",
            recommendation="Use the secure setting.",
        )
        scan = SecurityScanResult.build("gcp", [finding])
        evaluation = MultiCloudSecurityEvaluationResult(
            cloud_results={"gcp": scan}, resources_total=8
        )
        self.engine.evaluation_engine = MagicMock()
        self.engine.evaluation_engine.evaluate.return_value = evaluation
        result = self._run()
        self.assertEqual(
            result.security_evaluation_status,
            TerraformSecurityStageStatus.PASS_WITH_WARNINGS,
        )

    def test_security_fail_is_preserved(self) -> None:
        self.assertEqual(
            self._run().security_evaluation_status,
            TerraformSecurityStageStatus.FAIL,
        )

    def test_write_report_false_writes_no_security_files(self) -> None:
        result = self._run(write_report=False)
        self.assertFalse(result.security_report_written)
        self.assertIsNone(result.security_json_path)

    def test_write_report_true_writes_security_files(self) -> None:
        result = self._run(write_report=True)
        self.assertTrue(result.security_json_path.is_file())
        self.assertTrue(result.security_text_path.is_file())

    def test_terraform_run_id_is_available(self) -> None:
        result = self._run()
        self.assertTrue(result.terraform_result.report.run_id.startswith("tfplan_"))

    def test_security_report_context_is_correlated(self) -> None:
        result = self._run()
        self.assertEqual(
            result.security_report.terraform_context.terraform_run_id,
            result.terraform_result.report.run_id,
        )

    def test_temp_plan_is_cleaned_after_success(self) -> None:
        result = self._run()
        self.assertTrue(result.temporary_plan_created)
        self.assertTrue(result.temporary_plan_cleaned)
        self.assertFalse(self._plan_path().exists())

    def test_temp_plan_is_cleaned_after_show_error(self) -> None:
        self.runner.show_exit_code = 1
        result = self._run()
        self.assertTrue(result.temporary_plan_cleaned)

    def test_temp_plan_is_cleaned_after_invalid_json(self) -> None:
        self.runner.show_stdout = "invalid"
        result = self._run()
        self.assertTrue(result.temporary_plan_cleaned)

    def test_temp_plan_is_cleaned_after_adapter_error(self) -> None:
        self.engine.adapter = MagicMock()
        self.engine.adapter.from_plan_dict.side_effect = RuntimeError(FAKE_SECRETS[3])
        result = self._run()
        self.assertTrue(result.temporary_plan_cleaned)
        self.assertNotIn(FAKE_SECRETS[3], repr(result))

    def test_temp_plan_is_cleaned_after_evaluation_error(self) -> None:
        self.engine.evaluation_engine = MagicMock()
        self.engine.evaluation_engine.evaluate.side_effect = RuntimeError("detail")
        result = self._run()
        self.assertTrue(result.temporary_plan_cleaned)

    def test_temp_plan_is_cleaned_after_report_error(self) -> None:
        self.engine.report_builder = MagicMock()
        self.engine.report_builder.build.side_effect = RuntimeError("detail")
        result = self._run()
        self.assertTrue(result.temporary_plan_cleaned)

    def test_temp_plan_is_cleaned_after_write_report_error(self) -> None:
        builder = MagicMock(wraps=self.engine.report_builder)
        builder.write_report.side_effect = OSError("disk detail")
        self.engine.report_builder = builder
        result = self._run(write_report=True)
        self.assertEqual(result.engine_status, TerraformEngineStatus.FAIL)
        self.assertTrue(result.temporary_plan_cleaned)

    def test_plan_error_leaves_no_temporary_plan(self) -> None:
        self.runner.plan_exit_code = 1
        result = self._run()
        self.assertFalse(result.temporary_plan_created)
        self.assertTrue(result.temporary_plan_cleaned)

    def test_cleanup_failure_is_reported_safely(self) -> None:
        real_temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(real_temporary_directory.cleanup)

        class _FailingCleanupDirectory:
            name = real_temporary_directory.name

            @staticmethod
            def cleanup() -> None:
                raise OSError("sensitive cleanup detail")

        with patch(
            "security_terraform_e2e.tempfile.TemporaryDirectory",
            return_value=_FailingCleanupDirectory(),
        ):
            result = self._run()

        self.assertFalse(result.temporary_plan_cleaned)
        self.assertEqual(
            result.engine_error,
            "Terraform temporary saved plan cleanup failed.",
        )
        self.assertNotIn("sensitive cleanup detail", repr(result))

    def test_repository_contains_no_tfplan(self) -> None:
        self._run()
        self.assertFalse(list(self.repository_root.rglob("*.tfplan")))

    def test_no_raw_show_json_file_is_created(self) -> None:
        self._run(write_report=True)
        names = {path.name for path in self.repository_root.rglob("*") if path.is_file()}
        self.assertNotIn("show.json", names)
        self.assertNotIn("raw-plan.json", names)

    def test_artifacts_contain_no_raw_json(self) -> None:
        self._run(write_report=True)
        files = [path.name for path in (self.repository_root / "artifacts").rglob("*")]
        self.assertNotIn("show.json", files)
        self.assertNotIn("raw-plan.json", files)

    def _all_safe_outputs(self, result) -> str:
        output = [json.dumps(result.to_dict()), repr(result)]
        if result.adaptation_result is not None:
            output.append(result.adaptation_result.to_json())
        if result.security_evaluation_result is not None:
            output.append(result.security_evaluation_result.to_json())
        if result.security_report is not None:
            output.extend((result.security_report.to_json(), result.security_report.render_text()))
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            _print_safe_summary(result)
        output.append(stream.getvalue())
        return "\n".join(output)

    def test_fake_password_is_absent(self) -> None:
        self.assertNotIn(FAKE_SECRETS[0], self._all_safe_outputs(self._run()))

    def test_fake_token_is_absent(self) -> None:
        self.assertNotIn(FAKE_SECRETS[1], self._all_safe_outputs(self._run()))

    def test_fake_private_key_is_absent(self) -> None:
        self.assertNotIn(FAKE_SECRETS[2], self._all_safe_outputs(self._run()))

    def test_fake_secret_is_absent(self) -> None:
        self.assertNotIn(FAKE_SECRETS[3], self._all_safe_outputs(self._run()))

    def test_written_reports_contain_no_fake_secrets(self) -> None:
        result = self._run(write_report=True)
        written = result.security_json_path.read_text(encoding="utf-8")
        written += result.security_text_path.read_text(encoding="utf-8")
        self.assertTrue(all(secret not in written for secret in FAKE_SECRETS))

    def test_no_new_security_rules_are_defined(self) -> None:
        source = Path(__file__).with_name("security_terraform_e2e.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("class SecurityRule", source)

    def test_gcp_rule_inventory_is_twelve(self) -> None:
        catalog = build_default_multicloud_security_engine().catalog
        self.assertEqual(len(catalog.select(cloud="gcp")), 12)

    def test_oci_rule_inventory_is_twelve(self) -> None:
        catalog = build_default_multicloud_security_engine().catalog
        self.assertEqual(len(catalog.select(cloud="oci")), 12)

    def test_total_rule_inventory_is_twenty_four(self) -> None:
        self.assertEqual(len(build_default_multicloud_security_engine().catalog.rules), 24)

    def test_apply_remains_blocked(self) -> None:
        with self.assertRaises(UnsafeTerraformCommandError):
            TerraformRunner._validate_args(["apply"])

    def test_destroy_remains_blocked(self) -> None:
        with self.assertRaises(UnsafeTerraformCommandError):
            TerraformRunner._validate_args(["destroy"])

    def test_default_plan3_command_is_unchanged(self) -> None:
        validation = TerraformValidationPipeline(
            self.runner, repository_root=self.repository_root
        )
        TerraformPlanPipeline(self.runner, validation_pipeline=validation).run("gcp")
        self.assertEqual(
            self._calls_for("plan")[0][0],
            ("plan", "-input=false", "-no-color", "-detailed-exitcode"),
        )

    def test_plan3_adds_only_one_out_argument(self) -> None:
        validation = TerraformValidationPipeline(
            self.runner, repository_root=self.repository_root
        )
        output = self.repository_root / "capture.tfplan"
        TerraformPlanPipeline(self.runner, validation_pipeline=validation).run(
            "gcp", plan_output_path=output
        )
        plan_args = self._calls_for("plan")[0][0]
        self.assertEqual(plan_args[:-1], tuple(TerraformPlanPipeline.PLAN_ARGS))
        self.assertEqual(plan_args[-1], f"-out={output.resolve()}")

    def test_plan6_default_call_shape_is_unchanged(self) -> None:
        validation = TerraformValidationPipeline(
            self.runner, repository_root=self.repository_root
        )
        plan_result = TerraformPlanPipeline(
            self.runner, validation_pipeline=validation
        ).run("gcp")
        plan_pipeline = MagicMock(spec=TerraformPlanPipeline)
        plan_pipeline.run.return_value = plan_result
        engine = TerraformEndToEndPipeline(
            plan_pipeline, TerraformReportBuilder(self.repository_root)
        )
        engine.run("gcp")
        plan_pipeline.run.assert_called_once_with("gcp")

    def test_plan6_forwards_plan_output_path_only(self) -> None:
        validation = TerraformValidationPipeline(
            self.runner, repository_root=self.repository_root
        )
        plan_result = TerraformPlanPipeline(
            self.runner, validation_pipeline=validation
        ).run("gcp")
        plan_pipeline = MagicMock(spec=TerraformPlanPipeline)
        plan_pipeline.run.return_value = plan_result
        engine = TerraformEndToEndPipeline(
            plan_pipeline, TerraformReportBuilder(self.repository_root)
        )
        output = self.repository_root / "forward.tfplan"
        engine.run("gcp", plan_output_path=output)
        plan_pipeline.run.assert_called_once_with("gcp", plan_output_path=output)

    def test_fmt_init_validate_plan_show_each_run_once(self) -> None:
        self._run()
        for step in ("fmt", "init", "validate", "plan", "show"):
            self.assertEqual(len(self._calls_for(step)), 1, step)

    def test_result_does_not_expose_show_stdout_or_stderr(self) -> None:
        payload = json.dumps(self._run().to_dict()).casefold()
        self.assertNotIn("show_stdout", payload)
        self.assertNotIn("show_stderr", payload)

    def test_show_error_raw_outputs_are_not_exposed(self) -> None:
        self.runner.show_exit_code = 1
        self.runner.show_stdout = "RAW_SHOW_STDOUT_CIS8"
        self.runner.show_stderr = "RAW_SHOW_STDERR_CIS8"
        payload = json.dumps(self._run().to_dict())
        self.assertNotIn("RAW_SHOW_STDOUT_CIS8", payload)
        self.assertNotIn("RAW_SHOW_STDERR_CIS8", payload)

    def test_result_does_not_expose_raw_plan(self) -> None:
        payload = json.dumps(self._run().to_dict()).casefold()
        self.assertNotIn("raw_plan", payload)
        self.assertNotIn("planned_values", payload)

    def test_cli_has_no_apply_or_destroy_option(self) -> None:
        source = Path(__file__).with_name("security_terraform_e2e.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn('add_argument("--apply"', source)
        self.assertNotIn('add_argument("--destroy"', source)

    def test_no_supported_resources_is_not_security_fail(self) -> None:
        self.runner.plan_data = {
            "planned_values": {
                "root_module": {
                    "resources": [_resource("random_pet", "name", {})]
                }
            }
        }
        result = self._run()
        self.assertEqual(result.adaptation_result.resources_adapted, 0)
        self.assertEqual(result.security_evaluation_status, TerraformSecurityStageStatus.PASS)


if __name__ == "__main__":
    unittest.main()
