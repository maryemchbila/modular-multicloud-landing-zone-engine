"""Tests de l'integration entre l'application et la gouvernance finale."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import app
import app_governance
from go_client import GoClientError
from models import ClientContext, GCPContext


def _status(value: str) -> SimpleNamespace:
    return SimpleNamespace(value=value)


def _governance_result(
    decision: str | None = "ALLOW",
    *,
    cloud: str = "gcp",
    terraform_status: str = "PASS",
    security_status: str = "PASS",
) -> SimpleNamespace:
    terraform_report = SimpleNamespace(plan_status="CHANGES_DETECTED")
    terraform_result = SimpleNamespace(
        engine_status=_status(terraform_status),
        report=terraform_report,
        stdout="raw show JSON fake-password fake-token",
        stderr="fake-private-key fake-secret",
        tfstate="sensitive tfstate",
    )
    security_result = SimpleNamespace(
        terraform_result=terraform_result,
        security_json_path=Path("reports/security.json"),
        security_text_path=Path("reports/security.txt"),
        resources=SimpleNamespace(
            attributes={"password": "fake-password"}
        ),
    )
    statuses = {
        "ALLOW": ("NOT_REQUIRED", "AUTHORIZED", "AUTHORIZED"),
        "REQUIRE_APPROVAL": (
            "PENDING",
            "PENDING_APPROVAL",
            "PENDING_APPROVAL",
        ),
        "BLOCK": ("NOT_ALLOWED", "BLOCKED", "BLOCKED"),
    }
    if decision is None:
        approval, authorization, governance = (
            "SKIPPED",
            "SKIPPED",
            "SKIPPED",
        )
        policy_decision = None
        policy_gate_status = _status("SKIPPED")
    else:
        approval, authorization, governance = statuses[decision]
        policy_decision = SimpleNamespace(
            decision=_status(decision),
            reason_code=_status("POLICY_EVALUATED"),
        )
        policy_gate_status = _status("PASS")
    policy_result = SimpleNamespace(
        security_pipeline_result=security_result,
        policy_gate_status=policy_gate_status,
        policy_decision=policy_decision,
        policy_json_path=Path("reports/policy.json"),
        policy_text_path=Path("reports/policy.txt"),
    )
    return SimpleNamespace(
        engine_status=_status(terraform_status),
        cloud=cloud,
        policy_pipeline_result=policy_result,
        terraform_final_status=terraform_status,
        security_evaluation_status=security_status,
        approval_status=approval,
        authorization_status=authorization,
        governance_status=governance,
        governance_json_path=Path("reports/governance.json"),
        governance_text_path=Path("reports/governance.txt"),
        raw_show_json="fake-token",
    )


class AppGovernanceIntegrationTests(unittest.TestCase):
    def test_generation_success_calls_governance_once_for_each_cloud(self) -> None:
        for cloud in ("gcp", "oci"):
            with self.subTest(cloud=cloud), patch(
                "app.choose_provider", return_value=cloud
            ), patch(
                "app.ask_client_context",
                return_value=ClientContext(
                    client_id="example-client",
                    environment="dev",
                ),
            ), patch(
                "app.ask_gcp_context",
                return_value=GCPContext("example-test-project"),
            ), patch("app.choose_module", return_value="compute"), patch(
                "app.choose_action", return_value="create"
            ), patch("app.dispatch", return_value=True) as dispatch_mock, patch(
                "app.run_governance_after_generation"
            ) as governance_mock, redirect_stdout(io.StringIO()):
                self.assertEqual(app.main(), 0)
                dispatch_mock.assert_called_once_with(
                    cloud,
                    "compute",
                    "create",
                    gcp_context=(
                        GCPContext("example-test-project")
                        if cloud == "gcp"
                        else None
                    ),
                )
                governance_mock.assert_called_once_with(cloud)

    def test_generation_failure_never_calls_governance(self) -> None:
        stderr = io.StringIO()
        with patch("app.choose_provider", return_value="gcp"), patch(
            "app.ask_client_context",
            return_value=ClientContext(
                client_id="example-client",
                environment="dev",
            ),
        ), patch(
            "app.ask_gcp_context",
            return_value=GCPContext("example-test-project"),
        ), patch(
            "app.choose_module", return_value="compute"
        ), patch("app.choose_action", return_value="create"), patch(
            "app.dispatch",
            side_effect=GoClientError("generation failed"),
        ), patch("app.run_governance_after_generation") as governance_mock, (
            redirect_stdout(io.StringIO())
        ), redirect_stderr(stderr):
            self.assertEqual(app.main(), 1)

        governance_mock.assert_not_called()
        self.assertIn("Generation : FAIL", stderr.getvalue())
        self.assertIn("Governance : NOT_RUN", stderr.getvalue())

    def test_cancelled_generation_does_not_run_governance(self) -> None:
        output = io.StringIO()
        with patch("app.choose_provider", return_value="oci"), patch(
            "app.ask_client_context",
            return_value=ClientContext(
                client_id="example-client",
                environment="dev",
            ),
        ), patch(
            "app.choose_module", return_value="compute"
        ), patch("app.choose_action", return_value="delete"), patch(
            "app.dispatch", return_value=False
        ), patch("app.run_governance_after_generation") as governance_mock, (
            redirect_stdout(output)
        ):
            self.assertEqual(app.main(), 0)

        governance_mock.assert_not_called()
        self.assertIn("Generation : NOT_RUN", output.getvalue())

    def test_final_factory_and_report_options_are_reused(self) -> None:
        result = _governance_result()
        pipeline = Mock()
        pipeline.run.return_value = result
        with patch(
            "app_governance.build_default_terraform_security_governance_engine",
            return_value=pipeline,
        ) as factory_mock, patch(
            "app_governance.print_governance_summary"
        ) as summary_mock:
            returned = app_governance.run_governance_after_generation(" GCP ")

        self.assertIs(returned, result)
        factory_mock.assert_called_once_with(profile="baseline")
        pipeline.run.assert_called_once_with(
            cloud="gcp",
            write_security_report=True,
            write_policy_report=True,
            write_governance_report=True,
        )
        summary_mock.assert_called_once_with(result)

    def test_cloud_mapping_accepts_only_gcp_and_oci(self) -> None:
        self.assertEqual(app_governance.normalize_cloud(" GCP "), "gcp")
        self.assertEqual(app_governance.normalize_cloud("OCI"), "oci")
        for invalid in ("aws", "", 12, None):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                app_governance.normalize_cloud(invalid)  # type: ignore[arg-type]

    def test_allow_require_approval_and_block_are_displayed(self) -> None:
        expected = {
            "ALLOW": ("NOT_REQUIRED", "AUTHORIZED", "AUTHORIZED"),
            "REQUIRE_APPROVAL": (
                "PENDING",
                "PENDING_APPROVAL",
                "PENDING_APPROVAL",
            ),
            "BLOCK": ("NOT_ALLOWED", "BLOCKED", "BLOCKED"),
        }
        for decision, statuses in expected.items():
            with self.subTest(decision=decision):
                output = io.StringIO()
                with redirect_stdout(output):
                    app_governance.print_governance_summary(
                        _governance_result(decision)
                    )
                rendered = output.getvalue()
                self.assertIn(decision, rendered)
                for status in statuses:
                    self.assertIn(status, rendered)
                self.assertIn("Terraform Apply        : NOT EXECUTED", rendered)
                self.assertIn("Terraform Destroy      : NOT EXECUTED", rendered)
                if decision == "REQUIRE_APPROVAL":
                    self.assertIn("Human action required  : YES", rendered)

    def test_terraform_error_keeps_later_stages_skipped(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            app_governance.print_governance_summary(
                _governance_result(
                    None,
                    terraform_status="FAIL",
                    security_status="SKIPPED",
                )
            )
        rendered = output.getvalue()
        self.assertIn("Terraform Engine       : FAIL", rendered)
        self.assertIn("Security Status        : SKIPPED", rendered)
        self.assertIn("Policy Gate Status     : SKIPPED", rendered)
        self.assertIn("Policy Decision        : SKIPPED", rendered)
        self.assertIn("Approval Status        : SKIPPED", rendered)
        self.assertNotIn("Policy Decision        : ALLOW", rendered)
        self.assertNotIn("Policy Decision        : BLOCK", rendered)

    def test_summary_prints_report_paths_but_no_sensitive_or_raw_data(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            app_governance.print_governance_summary(_governance_result())
        rendered = output.getvalue()
        for report in ("security.json", "policy.json", "governance.json"):
            self.assertIn(report, rendered)
        for forbidden in (
            "fake-password",
            "fake-token",
            "fake-private-key",
            "fake-secret",
            "raw show JSON",
            "sensitive tfstate",
            "stdout",
            "stderr",
        ):
            self.assertNotIn(forbidden, rendered)

    def test_app_contains_no_duplicated_pipeline_components(self) -> None:
        app_source = Path(app.__file__).read_text(encoding="utf-8")
        for forbidden in (
            "TerraformRunner",
            "SecurityComplianceScanner",
            "MultiCloudSecurityEvaluationEngine",
            "SecurityPolicyGate",
            "HumanApprovalWorkflow",
        ):
            self.assertNotIn(forbidden, app_source)

        integration_source = Path(app_governance.__file__).read_text(
            encoding="utf-8"
        )
        for forbidden_call in (".apply(", ".destroy(", ".approve("):
            self.assertNotIn(forbidden_call, integration_source)

    def test_generator_success_signal_is_explicit(self) -> None:
        request_path = Path("request.json")
        with patch("app.save_request", return_value=request_path), patch(
            "app.run_generator", return_value="generated"
        ) as generator_mock, redirect_stdout(io.StringIO()):
            self.assertIs(app._generate({"provider": "gcp"}), True)
        generator_mock.assert_called_once_with(request_path)


if __name__ == "__main__":
    unittest.main()
