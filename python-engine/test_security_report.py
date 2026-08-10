"""Tests du reporting de conformite securite structure et deterministe."""

import json
import re
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID
from unittest.mock import patch

import security_report
from security_evaluation import build_default_multicloud_security_engine
from security_models import SecurityScanStatus, SecuritySeverity
from security_report import (
    SecurityComplianceReport,
    SecurityComplianceReportBuilder,
    SecurityTerraformContext,
)
from security_terraform_adapter import TerraformSecurityResourceAdapter
from terraform_report import TerraformExecutionReport
from terraform_runner import TerraformRunner


class SecurityComplianceReportTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.repository_root = Path(temporary_directory.name)
        self.generated_datetime = datetime(
            2026,
            8,
            10,
            14,
            30,
            0,
            tzinfo=timezone.utc,
        )
        self.builder = SecurityComplianceReportBuilder(
            repository_root=self.repository_root,
            now_factory=lambda: self.generated_datetime,
            uuid_factory=lambda: UUID(
                "ab12cd34-0000-0000-0000-000000000000"
            ),
        )
        self.adapter = TerraformSecurityResourceAdapter()

    @staticmethod
    def _entry(resource_type: str, name: str, values: dict) -> dict:
        return {
            "address": f"{resource_type}.{name}",
            "mode": "managed",
            "type": resource_type,
            "name": name,
            "values": values,
        }

    @staticmethod
    def _plan(resources: list[dict]) -> dict:
        return {
            "format_version": "1.2",
            "planned_values": {
                "root_module": {
                    "resources": resources,
                }
            },
        }

    @classmethod
    def _gcp_compute(
        cls,
        name: str = "gcp_secure",
        *,
        public: bool = False,
        shielded: bool = True,
        deletion: bool = True,
        extra: dict | None = None,
    ) -> dict:
        interface = {"network": "default"}
        if public:
            interface["access_config"] = [{}]
        values = {
            "network_interface": [interface],
            "shielded_instance_config": [
                {"enable_secure_boot": shielded}
            ],
            "deletion_protection": deletion,
        }
        values.update(extra or {})
        return cls._entry("google_compute_instance", name, values)

    @classmethod
    def _oci_compute(
        cls,
        name: str = "oci_secure",
        *,
        public: bool = False,
        secure_boot: bool = True,
        in_transit: bool = True,
        extra: dict | None = None,
    ) -> dict:
        values = {
            "create_vnic_details": [{"assign_public_ip": public}],
            "platform_config": [{"is_secure_boot_enabled": secure_boot}],
            "launch_options": [
                {"is_pv_encryption_in_transit_enabled": in_transit}
            ],
        }
        values.update(extra or {})
        return cls._entry("oci_core_instance", name, values)

    @classmethod
    def _gcp_firewall(cls) -> dict:
        return cls._entry(
            "google_compute_firewall",
            "gcp_ssh",
            {
                "direction": "INGRESS",
                "source_ranges": ["0.0.0.0/0"],
                "allow": [{"protocol": "tcp", "ports": ["22"]}],
            },
        )

    @classmethod
    def _oci_security_list(cls) -> dict:
        return cls._entry(
            "oci_core_security_list",
            "oci_ssh",
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
        )

    @classmethod
    def _full_plan(cls, *, include_secrets: bool = False) -> dict:
        extra = {}
        if include_secrets:
            extra = {
                "password": "FAKE_PASSWORD_CIS7",
                "token": "FAKE_TOKEN_CIS7",
                "private_key": "FAKE_PRIVATE_KEY_CIS7",
                "secret": "FAKE_SECRET_CIS7",
            }
        resources = [
            cls._gcp_compute(
                "gcp_public",
                public=True,
                shielded=False,
                deletion=False,
                extra=extra,
            ),
            cls._gcp_firewall(),
            cls._entry(
                "google_storage_bucket",
                "gcp_bucket",
                {
                    "public_access_prevention": "enforced",
                    "uniform_bucket_level_access": True,
                    "versioning": [{"enabled": True}],
                },
            ),
            cls._entry(
                "google_project_iam_member",
                "gcp_owner",
                {
                    "role": "roles/owner",
                    "member": "user:test@example.test",
                },
            ),
            cls._oci_compute(
                "oci_public",
                public=True,
                secure_boot=False,
                in_transit=False,
                extra=extra,
            ),
            cls._oci_security_list(),
            cls._entry(
                "oci_objectstorage_bucket",
                "oci_bucket",
                {
                    "access_type": "NoPublicAccess",
                    "versioning": "Enabled",
                    "kms_key_id": "ocid1.key.synthetic",
                },
            ),
            cls._entry(
                "oci_identity_policy",
                "oci_manage_all",
                {"statements": ["manage all-resources"]},
            ),
        ]
        plan = cls._plan(resources)
        if include_secrets:
            plan["configuration"] = {"marker": "FAKE_SECRET_CIS7"}
            plan["resource_changes"] = {"marker": "FAKE_TOKEN_CIS7"}
            plan["sensitive_values"] = {"marker": "FAKE_PASSWORD_CIS7"}
            plan["before_sensitive"] = {
                "marker": "FAKE_PRIVATE_KEY_CIS7"
            }
            plan["after_sensitive"] = {"marker": "FAKE_SECRET_CIS7"}
        return plan

    def _build(
        self,
        plan: dict | None = None,
        *,
        terraform_report: TerraformExecutionReport | None = None,
    ) -> SecurityComplianceReport:
        adaptation = self.adapter.from_plan_dict(
            plan if plan is not None else self._plan([self._gcp_compute()])
        )
        evaluation = build_default_multicloud_security_engine().evaluate(
            adaptation.resources
        )
        return self.builder.build(
            adaptation_result=adaptation,
            evaluation_result=evaluation,
            terraform_report=terraform_report,
        )

    @staticmethod
    def _terraform_report(
        *,
        error_message: str | None = None,
    ) -> TerraformExecutionReport:
        return TerraformExecutionReport(
            schema_version="1.0",
            run_id="tfplan_gcp_20260810T140000Z_12345678",
            generated_at="2026-08-10T14:00:00Z",
            cloud="gcp",
            working_directory="hcl-generator/generated/gcp",
            fmt_status="PASS",
            init_status="PASS",
            validate_status="PASS",
            plan_status="CHANGES_DETECTED",
            final_status="CHANGES_DETECTED",
            failed_step=None,
            total_duration_seconds=1.0,
            fmt_exit_code=0,
            init_exit_code=0,
            validate_exit_code=0,
            plan_exit_code=2,
            fmt_duration_seconds=0.1,
            init_duration_seconds=0.2,
            validate_duration_seconds=0.3,
            plan_duration_seconds=0.4,
            fmt_timed_out=False,
            init_timed_out=False,
            validate_timed_out=False,
            plan_timed_out=False,
            error_category="UNKNOWN_ERROR" if error_message else None,
            reason_code="TEST" if error_message else None,
            error_message=error_message,
            add_count=2,
            change_count=1,
            destroy_count=0,
        )

    def test_report_exists(self) -> None:
        self.assertIsInstance(self._build(), SecurityComplianceReport)

    def test_schema_version_is_one(self) -> None:
        self.assertEqual(self._build().schema_version, "1.0")

    def test_run_id_is_stable_with_injection(self) -> None:
        self.assertEqual(
            self._build().run_id,
            "security_gcp_20260810T143000Z_ab12cd34",
        )

    def test_generated_at_is_stable_with_injection(self) -> None:
        self.assertEqual(self._build().generated_at, "2026-08-10T14:30:00Z")

    def test_framework_is_internal(self) -> None:
        self.assertEqual(self._build().framework, "INTERNAL_SECURITY_BASELINE")

    def test_framework_versions_gcp(self) -> None:
        self.assertEqual(self._build().framework_versions, {"gcp": "gcp-v1"})

    def test_framework_versions_oci(self) -> None:
        report = self._build(self._plan([self._oci_compute()]))
        self.assertEqual(report.framework_versions, {"oci": "oci-v1"})

    def test_framework_versions_multicloud(self) -> None:
        report = self._build(
            self._plan([self._gcp_compute(), self._oci_compute()])
        )
        self.assertEqual(
            dict(report.framework_versions),
            {"gcp": "gcp-v1", "oci": "oci-v1"},
        )

    def test_evaluation_status_pass(self) -> None:
        self.assertIs(self._build().evaluation_status, SecurityScanStatus.PASS)

    def test_evaluation_status_pass_with_warnings(self) -> None:
        report = self._build(
            self._plan([self._gcp_compute(shielded=False)])
        )
        self.assertIs(
            report.evaluation_status,
            SecurityScanStatus.PASS_WITH_WARNINGS,
        )

    def test_evaluation_status_fail(self) -> None:
        report = self._build(self._plan([self._gcp_compute(public=True)]))
        self.assertIs(report.evaluation_status, SecurityScanStatus.FAIL)

    def test_resources_seen_is_preserved(self) -> None:
        report = self._build(self._full_plan())
        self.assertEqual(report.resources_seen, 8)

    def test_resources_adapted_is_preserved(self) -> None:
        report = self._build(self._full_plan())
        self.assertEqual(report.resources_adapted, 8)

    def test_resources_skipped_is_preserved(self) -> None:
        plan = self._plan(
            [
                self._gcp_compute(),
                self._entry("google_sql_database_instance", "db", {}),
            ]
        )
        self.assertEqual(self._build(plan).resources_skipped, 1)

    def test_unsupported_resource_types_are_preserved(self) -> None:
        plan = self._plan(
            [self._entry("google_sql_database_instance", "db", {})]
        )
        self.assertEqual(
            self._build(plan).unsupported_resource_types,
            ("google_sql_database_instance",),
        )

    def test_unsupported_resource_types_are_sorted(self) -> None:
        plan = self._plan(
            [
                self._entry("oci_z_unknown", "z", {}),
                self._entry("google_a_unknown", "a", {}),
            ]
        )
        self.assertEqual(
            self._build(plan).unsupported_resource_types,
            ("google_a_unknown", "oci_z_unknown"),
        )

    def test_raw_values_are_absent_from_adaptation_summary(self) -> None:
        payload = self._build(self._full_plan(include_secrets=True)).to_dict()
        self.assertNotIn("values", payload["adaptation"])
        self.assertNotIn("resources", payload["adaptation"])

    def test_findings_total_is_preserved(self) -> None:
        self.assertEqual(self._build(self._full_plan()).findings_total, 24)

    def test_passed_count_is_preserved(self) -> None:
        self.assertEqual(self._build(self._full_plan()).passed, 11)

    def test_failed_count_is_preserved(self) -> None:
        self.assertEqual(self._build(self._full_plan()).failed, 6)

    def test_warning_count_is_preserved(self) -> None:
        self.assertEqual(self._build(self._full_plan()).warnings, 4)

    def test_skipped_count_is_preserved(self) -> None:
        self.assertEqual(self._build(self._full_plan()).skipped, 3)

    def test_not_applicable_count_is_preserved(self) -> None:
        self.assertEqual(self._build(self._full_plan()).not_applicable, 0)

    def test_critical_severity_count(self) -> None:
        report = self._build(self._full_plan())
        self.assertEqual(report.severity_counts[SecuritySeverity.CRITICAL], 0)

    def test_high_severity_count(self) -> None:
        report = self._build(self._full_plan())
        self.assertEqual(report.severity_counts[SecuritySeverity.HIGH], 6)

    def test_medium_severity_count(self) -> None:
        report = self._build(self._full_plan())
        self.assertEqual(report.severity_counts[SecuritySeverity.MEDIUM], 4)

    def test_low_severity_count(self) -> None:
        report = self._build(self._full_plan())
        self.assertEqual(report.severity_counts[SecuritySeverity.LOW], 0)

    def test_info_severity_count(self) -> None:
        report = self._build(self._full_plan())
        self.assertEqual(report.severity_counts[SecuritySeverity.INFO], 0)

    def test_gcp_only_cloud_result(self) -> None:
        report = self._build()
        self.assertEqual(tuple(report.cloud_results), ("gcp",))

    def test_oci_only_cloud_result(self) -> None:
        report = self._build(self._plan([self._oci_compute()]))
        self.assertEqual(tuple(report.cloud_results), ("oci",))

    def test_multicloud_results(self) -> None:
        report = self._build(self._full_plan())
        self.assertEqual(set(report.cloud_results), {"gcp", "oci"})

    def test_cloud_results_order_is_gcp_then_oci(self) -> None:
        report = self._build(
            self._plan([self._oci_compute(), self._gcp_compute()])
        )
        self.assertEqual(tuple(report.cloud_results), ("gcp", "oci"))

    def test_absent_cloud_is_not_invented(self) -> None:
        payload = self._build().to_dict()
        self.assertNotIn("oci", payload["cloud_results"])

    def test_finding_rule_id_is_preserved(self) -> None:
        report = self._build(self._plan([self._gcp_compute(public=True)]))
        self.assertIn(
            "GCP_INTERNAL_COMPUTE_001",
            {item.rule_id for item in report.findings},
        )

    def test_finding_resource_address_value_is_preserved(self) -> None:
        report = self._build(self._plan([self._gcp_compute(public=True)]))
        public = next(
            item
            for item in report.findings
            if item.rule_id == "GCP_INTERNAL_COMPUTE_001"
        )
        self.assertEqual(
            public.resource_address,
            "google_compute_instance.gcp_secure",
        )

    def test_finding_severity_is_preserved(self) -> None:
        report = self._build(self._plan([self._gcp_compute(public=True)]))
        public = next(
            item
            for item in report.findings
            if item.rule_id == "GCP_INTERNAL_COMPUTE_001"
        )
        self.assertIs(public.severity, SecuritySeverity.HIGH)

    def test_finding_status_is_preserved(self) -> None:
        report = self._build(self._plan([self._gcp_compute(public=True)]))
        payload = report.to_dict()["findings"]
        public = next(
            item for item in payload if item["rule_id"] == "GCP_INTERNAL_COMPUTE_001"
        )
        self.assertEqual(public["status"], "FAIL")

    def test_finding_recommendation_is_preserved(self) -> None:
        report = self._build(self._plan([self._gcp_compute(public=True)]))
        public = next(
            item
            for item in report.findings
            if item.rule_id == "GCP_INTERNAL_COMPUTE_001"
        )
        self.assertTrue(public.recommendation)

    def test_finding_order_is_deterministic(self) -> None:
        first = self._build(self._full_plan())
        second = self._build(self._full_plan())
        self.assertEqual(first.to_json(), second.to_json())

    def test_raw_attributes_are_absent_from_findings(self) -> None:
        payload = self._build(self._full_plan()).to_dict()["findings"]
        self.assertTrue(all("attributes" not in item for item in payload))

    def test_report_works_without_terraform_report(self) -> None:
        self.assertIsNone(self._build().terraform_context)

    def test_report_accepts_terraform_report(self) -> None:
        report = self._build(terraform_report=self._terraform_report())
        self.assertIsInstance(report.terraform_context, SecurityTerraformContext)

    def test_terraform_run_id_is_preserved(self) -> None:
        report = self._build(terraform_report=self._terraform_report())
        self.assertEqual(
            report.terraform_context.terraform_run_id,
            "tfplan_gcp_20260810T140000Z_12345678",
        )

    def test_terraform_final_status_is_preserved(self) -> None:
        report = self._build(terraform_report=self._terraform_report())
        self.assertEqual(
            report.terraform_context.terraform_final_status,
            "CHANGES_DETECTED",
        )

    def test_terraform_plan_exit_code_is_preserved(self) -> None:
        report = self._build(terraform_report=self._terraform_report())
        self.assertEqual(report.terraform_context.plan_exit_code, 2)

    def test_terraform_stdout_is_absent(self) -> None:
        payload = json.dumps(
            self._build(terraform_report=self._terraform_report()).to_dict()
        )
        self.assertNotIn("stdout", payload.casefold())

    def test_terraform_stderr_is_absent(self) -> None:
        payload = self._build(
            terraform_report=self._terraform_report(
                error_message="FAKE_STDERR_CIS7"
            )
        ).to_json()
        self.assertNotIn("stderr", payload.casefold())
        self.assertNotIn("FAKE_STDERR_CIS7", payload)

    def test_to_dict_has_expected_schema(self) -> None:
        payload = self._build().to_dict()
        self.assertEqual(payload["schema_version"], "1.0")
        self.assertIn("adaptation", payload)
        self.assertIn("summary", payload)
        self.assertIn("safety", payload)

    def test_to_json_is_valid_json(self) -> None:
        report = self._build()
        self.assertEqual(json.loads(report.to_json()), report.to_dict())

    def test_render_text_contains_run_id(self) -> None:
        report = self._build()
        self.assertIn(report.run_id, report.render_text())

    def test_render_text_contains_status(self) -> None:
        report = self._build(self._plan([self._gcp_compute(public=True)]))
        self.assertIn("Status       : FAIL", report.render_text())

    def test_render_text_contains_summary(self) -> None:
        self.assertIn(" SUMMARY", self._build().render_text())

    def test_render_text_contains_gcp(self) -> None:
        self.assertIn(" GCP", self._build().render_text())

    def test_render_text_contains_oci(self) -> None:
        report = self._build(self._plan([self._oci_compute()]))
        self.assertIn(" OCI", report.render_text())

    def test_render_text_contains_findings(self) -> None:
        report = self._build(self._plan([self._gcp_compute(public=True)]))
        self.assertIn("GCP_INTERNAL_COMPUTE_001", report.render_text())

    def test_render_text_contains_no_ansi_sequence(self) -> None:
        self.assertIsNone(re.search(r"\x1b\[[0-9;]*m", self._build().render_text()))

    def test_write_report_creates_json(self) -> None:
        json_path, _ = self.builder.write_report(self._build())
        self.assertTrue(json_path.is_file())

    def test_write_report_creates_text(self) -> None:
        _, text_path = self.builder.write_report(self._build())
        self.assertTrue(text_path.is_file())

    def test_written_files_use_same_basename(self) -> None:
        json_path, text_path = self.builder.write_report(self._build())
        self.assertEqual(json_path.stem, text_path.stem)

    def test_written_json_matches_report(self) -> None:
        report = self._build()
        json_path, _ = self.builder.write_report(report)
        self.assertEqual(
            json.loads(json_path.read_text(encoding="utf-8")),
            report.to_dict(),
        )

    def test_written_text_matches_report(self) -> None:
        report = self._build()
        _, text_path = self.builder.write_report(report)
        self.assertEqual(
            text_path.read_text(encoding="utf-8").rstrip("\n"),
            report.render_text(),
        )

    def test_write_uses_atomic_helper_for_both_files(self) -> None:
        report = self._build()
        with patch.object(
            self.builder,
            "_write_atomic",
            wraps=self.builder._write_atomic,
        ) as atomic_write:
            self.builder.write_report(report)
        self.assertEqual(atomic_write.call_count, 2)

    def test_write_creates_output_directory(self) -> None:
        output = self.repository_root / "nested" / "security" / "reports"
        self.builder.write_report(self._build(), output_directory=output)
        self.assertTrue(output.is_dir())

    def test_atomic_write_leaves_no_temporary_files(self) -> None:
        output = self.repository_root / "reports"
        self.builder.write_report(self._build(), output_directory=output)
        self.assertEqual(list(output.glob("*.tmp")), [])
        self.assertEqual(list(output.glob(".*.tmp")), [])

    def test_default_output_directory_is_security_reports(self) -> None:
        self.assertEqual(
            self.builder.DEFAULT_REPORT_DIRECTORY.as_posix(),
            "artifacts/security/reports",
        )

    def test_security_reports_directory_is_git_ignored(self) -> None:
        gitignore = (Path(__file__).resolve().parent.parent / ".gitignore").read_text(
            encoding="utf-8"
        )
        self.assertIn("/artifacts/security/reports/", gitignore.splitlines())

    def test_fake_password_is_absent_everywhere(self) -> None:
        self._assert_fake_secret_absent("FAKE_PASSWORD_CIS7")

    def test_fake_token_is_absent_everywhere(self) -> None:
        self._assert_fake_secret_absent("FAKE_TOKEN_CIS7")

    def test_fake_private_key_is_absent_everywhere(self) -> None:
        self._assert_fake_secret_absent("FAKE_PRIVATE_KEY_CIS7")

    def test_fake_secret_is_absent_everywhere(self) -> None:
        self._assert_fake_secret_absent("FAKE_SECRET_CIS7")

    def _assert_fake_secret_absent(self, secret: str) -> None:
        report = self._build(self._full_plan(include_secrets=True))
        output = self.repository_root / "secret-check"
        json_path, text_path = self.builder.write_report(
            report,
            output_directory=output,
        )
        payloads = (
            json.dumps(report.to_dict()),
            report.to_json(),
            report.render_text(),
            json_path.read_text(encoding="utf-8"),
            text_path.read_text(encoding="utf-8"),
        )
        for payload in payloads:
            self.assertNotIn(secret, payload)

    def test_raw_plan_sections_are_absent(self) -> None:
        payload = self._build(self._full_plan(include_secrets=True)).to_json()
        for marker in (
            "planned_values",
            "configuration",
            "resource_changes",
            "sensitive_values",
            "before_sensitive",
            "after_sensitive",
        ):
            self.assertNotIn(marker, payload)

    def test_terraform_working_directory_is_absent(self) -> None:
        payload = self._build(
            terraform_report=self._terraform_report()
        ).to_dict()["terraform_context"]
        self.assertNotIn("working_directory", payload)

    def test_builder_does_not_mutate_inputs(self) -> None:
        adaptation = self.adapter.from_plan_dict(self._full_plan())
        evaluation = build_default_multicloud_security_engine().evaluate(
            adaptation.resources
        )
        terraform_report = self._terraform_report()
        before = (
            adaptation.to_dict(),
            evaluation.to_dict(),
            terraform_report.to_dict(),
        )
        self.builder.build(
            adaptation_result=adaptation,
            evaluation_result=evaluation,
            terraform_report=terraform_report,
        )
        self.assertEqual(
            before,
            (
                adaptation.to_dict(),
                evaluation.to_dict(),
                terraform_report.to_dict(),
            ),
        )

    def test_rules_available_total_is_twenty_four(self) -> None:
        self.assertEqual(self._build().rules_available_total, 24)

    def test_rules_available_by_cloud_are_twelve_each(self) -> None:
        self.assertEqual(
            dict(self._build().rules_available_by_cloud),
            {"gcp": 12, "oci": 12},
        )

    def test_rules_evaluated_are_distinct_rule_ids(self) -> None:
        report = self._build(self._full_plan())
        self.assertEqual(report.rules_evaluated_total, 24)

    def test_cloud_results_do_not_duplicate_findings(self) -> None:
        payload = self._build(self._full_plan()).to_dict()
        self.assertTrue(
            all("findings" not in value for value in payload["cloud_results"].values())
        )

    def test_safety_section_has_all_false_guarantees(self) -> None:
        safety = self._build().to_dict()["safety"]
        self.assertEqual(len(safety), 6)
        self.assertTrue(all(value is False for value in safety.values()))

    def test_report_introduces_no_policy_gate_fields(self) -> None:
        payload = self._build(self._full_plan()).to_dict()
        for field_name in ("allow", "deny", "approval_required", "block_reason"):
            self.assertNotIn(field_name, payload)

    def test_report_makes_no_official_claim(self) -> None:
        payload = self._build().to_json().casefold()
        for phrase in ("cis certified", "cis compliant", "official cis compliance"):
            self.assertNotIn(phrase, payload)

    def test_fixed_inputs_produce_byte_identical_json_and_text(self) -> None:
        first = self._build(self._full_plan())
        second = self._build(self._full_plan())
        self.assertEqual(first.to_json(), second.to_json())
        self.assertEqual(first.render_text(), second.render_text())

    def test_successive_uuid_values_produce_unique_run_ids(self) -> None:
        values = iter(
            (
                UUID("11111111-0000-0000-0000-000000000000"),
                UUID("22222222-0000-0000-0000-000000000000"),
            )
        )
        builder = SecurityComplianceReportBuilder(
            repository_root=self.repository_root,
            now_factory=lambda: self.generated_datetime,
            uuid_factory=lambda: next(values),
        )
        adaptation = self.adapter.from_plan_dict(self._plan([self._gcp_compute()]))
        evaluation = build_default_multicloud_security_engine().evaluate(
            adaptation.resources
        )
        first = builder.build(
            adaptation_result=adaptation,
            evaluation_result=evaluation,
        )
        second = builder.build(
            adaptation_result=adaptation,
            evaluation_result=evaluation,
        )
        self.assertNotEqual(first.run_id, second.run_id)

    def test_naive_clock_is_rejected(self) -> None:
        builder = SecurityComplianceReportBuilder(
            repository_root=self.repository_root,
            now_factory=lambda: datetime(2026, 8, 10, 14, 30, 0),
        )
        adaptation = self.adapter.from_plan_dict(self._plan([]))
        evaluation = build_default_multicloud_security_engine().evaluate([])
        with self.assertRaises(ValueError):
            builder.build(
                adaptation_result=adaptation,
                evaluation_result=evaluation,
            )

    def test_empty_evaluation_uses_none_run_id_label(self) -> None:
        self.assertTrue(self._build(self._plan([])).run_id.startswith("security_none_"))

    def test_multicloud_run_id_label(self) -> None:
        self.assertTrue(
            self._build(self._full_plan()).run_id.startswith("security_multicloud_")
        )

    def test_mismatched_adaptation_and_evaluation_are_rejected(self) -> None:
        adaptation = self.adapter.from_plan_dict(self._plan([self._gcp_compute()]))
        empty_evaluation = build_default_multicloud_security_engine().evaluate([])
        with self.assertRaisesRegex(ValueError, "correspondent"):
            self.builder.build(
                adaptation_result=adaptation,
                evaluation_result=empty_evaluation,
            )

    def test_invalid_terraform_report_type_is_rejected(self) -> None:
        adaptation = self.adapter.from_plan_dict(self._plan([]))
        evaluation = build_default_multicloud_security_engine().evaluate([])
        with self.assertRaises(TypeError):
            self.builder.build(
                adaptation_result=adaptation,
                evaluation_result=evaluation,
                terraform_report=object(),
            )

    def test_full_synthetic_pipeline_writes_stable_reports(self) -> None:
        report = self._build(self._full_plan(include_secrets=True))
        json_path, text_path = self.builder.write_report(report)
        self.assertEqual(report.clouds_evaluated, ("gcp", "oci"))
        self.assertIs(report.evaluation_status, SecurityScanStatus.FAIL)
        self.assertEqual(report.findings_total, 24)
        self.assertEqual(report.failed, 6)
        self.assertEqual(report.severity_counts[SecuritySeverity.HIGH], 6)
        self.assertEqual(json.loads(json_path.read_text()), report.to_dict())
        self.assertEqual(text_path.read_text().rstrip("\n"), report.render_text())

    def test_builder_never_runs_terraform_or_subprocess(self) -> None:
        with (
            patch.object(TerraformRunner, "run") as terraform_run,
            patch.object(subprocess, "run") as process_run,
        ):
            report = self._build(self._full_plan())
        self.assertEqual(report.resources_seen, 8)
        terraform_run.assert_not_called()
        process_run.assert_not_called()

    def test_report_module_has_no_cloud_or_environment_dependency(self) -> None:
        module_names = set(security_report.__dict__)
        self.assertTrue(
            {
                "google",
                "google.auth",
                "google.cloud",
                "oci",
                "os",
                "subprocess",
            }.isdisjoint(module_names)
        )


if __name__ == "__main__":
    unittest.main()
