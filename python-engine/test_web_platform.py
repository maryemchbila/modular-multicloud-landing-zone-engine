from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from go_client import GoClientError
from web import create_app
from web.services import ReportService, WebServiceError


FAKE_VALUES = (
    "FAKE_WEB_SECRET_123",
    "FAKE_WEB_PRIVATE_KEY_456",
    "FAKE_WEB_TOKEN_789",
)


def _status(value: str):
    return SimpleNamespace(value=value)


def _governance_result():
    report = SimpleNamespace(
        fmt_status="PASS",
        init_status="PASS",
        validate_status="PASS",
        plan_status="NO_CHANGES",
        add_count=0,
        change_count=0,
        destroy_count=0,
    )
    terraform = SimpleNamespace(report=report)
    security_report = SimpleNamespace(findings=())
    security = SimpleNamespace(terraform_result=terraform, security_report=security_report)
    decision = SimpleNamespace(
        profile=_status("BASELINE"),
        decision=_status("ALLOW"),
        reason_code=_status("POLICY_EVALUATED"),
    )
    policy = SimpleNamespace(
        security_pipeline_result=security,
        policy_decision=decision,
    )
    return SimpleNamespace(
        policy_pipeline_result=policy,
        terraform_final_status="PASS",
        security_evaluation_status="PASS",
        approval_status="NOT_REQUIRED",
        authorization_status="AUTHORIZED",
        governance_status="AUTHORIZED",
    )


class WebPlatformTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = create_app(
            {"TESTING": True, "SECRET_KEY": "test-only-not-a-cloud-secret"}
        )
        self.client = self.app.test_client()

    def csrf(self) -> str:
        self.client.get("/")
        with self.client.session_transaction() as session:
            return session["_csrf_token"]

    def configure(self):
        return self.client.post(
            "/client",
            data={
                "csrf_token": self.csrf(),
                "client_id": "example-client",
                "environment": "dev",
                "provider": "gcp",
            },
            follow_redirects=True,
        )

    def test_all_required_get_routes_return_200(self) -> None:
        for route in (
            "/",
            "/client",
            "/infrastructure",
            "/plan",
            "/security",
            "/governance",
            "/reports",
        ):
            with self.subTest(route=route):
                self.assertEqual(self.client.get(route).status_code, 200)

    def test_valid_client_post_loads_safe_config(self) -> None:
        response = self.configure()
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        for expected in (
            "example-client",
            "example-project",
            "gcp-example",
            "gcp-example-state",
            "clients/example-client/dev/gcp/terraform.tfstate",
        ):
            self.assertIn(expected, html)

    def test_client_and_template_traversal_are_rejected(self) -> None:
        token = self.csrf()
        invalid_forms = (
            {"client_id": "../../client", "environment": "dev", "provider": "gcp"},
            {"client_id": "example-client", "environment": "../prod", "provider": "gcp"},
            {"client_id": "example-client", "environment": "dev", "provider": "../gcp"},
        )
        for form in invalid_forms:
            with self.subTest(form=form):
                form = {**form, "csrf_token": token}
                self.assertEqual(self.client.post("/client", data=form).status_code, 400)
        self.assertEqual(
            self.client.get("/infrastructure?template_id=../../template").status_code,
            400,
        )

    def test_csrf_is_required_and_validated(self) -> None:
        form = {"client_id": "example-client", "environment": "dev", "provider": "gcp"}
        self.assertEqual(self.client.post("/client", data=form).status_code, 400)
        form["csrf_token"] = "wrong"
        self.assertEqual(self.client.post("/client", data=form).status_code, 400)

    def test_server_validation_precedes_every_filesystem_mutation(self) -> None:
        self.configure()
        with patch("web.services.write_backend_runtime_files") as backend_write, patch(
            "web.services.generate_request"
        ) as generator:
            response = self.client.post(
                "/infrastructure",
                data={
                    "csrf_token": self.csrf(),
                    "template_id": "gcp-network-standard",
                    "resource_name": "vpc_web",
                    "name": "vpc-web",
                    "subnet_resource_name": "subnet_web",
                    "subnet_name": "subnet-web",
                    "cidr": "not-a-cidr",
                    "region": "europe-west1",
                },
            )
        self.assertEqual(response.status_code, 400)
        backend_write.assert_not_called()
        generator.assert_not_called()

    def test_generator_rejection_is_a_controlled_web_error(self) -> None:
        self.configure()
        with patch("web.services.write_backend_runtime_files"), patch(
            "web.services.generate_request", side_effect=GoClientError("duplicate path")
        ):
            response = self.client.post(
                "/infrastructure",
                data={
                    "csrf_token": self.csrf(),
                    "template_id": "gcp-network-standard",
                    "resource_name": "vpc_web",
                    "name": "vpc-web",
                    "subnet_resource_name": "subnet_web",
                    "subnet_name": "subnet-web",
                    "cidr": "10.42.0.0/24",
                    "region": "europe-west1",
                },
            )
        self.assertEqual(response.status_code, 400)
        self.assertIn("generator rejected", response.get_data(as_text=True))

    def test_get_routes_never_call_mutating_pipeline(self) -> None:
        self.configure()
        service = self.app.extensions["web_orchestration"]
        with patch.object(service, "execute") as execute, patch(
            "web.services.write_backend_runtime_files"
        ) as backend_write, patch("web.services.run_generator") as generator, patch(
            "web.services.detect_terraform_version"
        ) as terraform_probe:
            for route in ("/", "/client", "/infrastructure", "/plan", "/security", "/governance", "/reports"):
                self.assertEqual(self.client.get(route).status_code, 200)
        execute.assert_not_called()
        backend_write.assert_not_called()
        generator.assert_not_called()
        terraform_probe.assert_not_called()

    def test_secret_values_never_reach_html_session_logs_or_reports(self) -> None:
        service = self.app.extensions["web_orchestration"]
        runtime = service.load_runtime("example-client", "dev", "gcp")
        unsafe_profile = replace(
            runtime.credential_profile,
            reference=FAKE_VALUES[0],
            metadata={"private_key": FAKE_VALUES[1], "token": FAKE_VALUES[2]},
        )
        unsafe_runtime = replace(runtime, credential_profile=unsafe_profile)
        with patch.object(service, "load_runtime", return_value=unsafe_runtime):
            response = self.configure()
        html = response.get_data(as_text=True)
        with self.client.session_transaction() as session:
            serialized_session = repr(dict(session))
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            self.client.get("/")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_id = "security_gcp_example"
            (root / f"{report_id}.json").write_text(
                json.dumps(
                    {
                        "generated_at": "2026-08-21T00:00:00Z",
                        "cloud": "gcp",
                        "evaluation_status": FAKE_VALUES[2],
                        "message": FAKE_VALUES[0],
                        "private_key": FAKE_VALUES[1],
                    }
                ),
                encoding="utf-8",
            )
            with patch.dict(
                "web.services._REPORT_ROOTS",
                {"security": root, "policy": root / "policy", "governance": root / "governance"},
                clear=True,
            ):
                report_service = ReportService()
                reports = repr(report_service.list_reports())
                report_view = repr(report_service.read_report("security", report_id))
        for secret in FAKE_VALUES:
            self.assertNotIn(secret, html)
            self.assertNotIn(secret, serialized_session)
            self.assertNotIn(secret, output.getvalue())
            self.assertNotIn(secret, reports)
            self.assertNotIn(secret, report_view)
        with self.client.session_transaction() as session:
            session_keys = set(session.keys())
        self.assertLessEqual(
            session_keys,
            {
                "_csrf_token",
                "client_id",
                "environment",
                "provider",
                "credential_profile_id",
                "state_profile_id",
                "template_id",
            },
        )

    def test_controlled_post_uses_real_shared_orchestration(self) -> None:
        self.configure()
        service = self.app.extensions["web_orchestration"]
        runtime = replace(service.load_runtime("example-client", "dev", "gcp"), credential_status="VALID")
        self.app.extensions["web_runtimes"][("example-client", "dev", "gcp")] = runtime
        parameters = {
            "resource_name": "vpc_web",
            "name": "vpc-web",
            "subnet_resource_name": "subnet_web",
            "subnet_name": "subnet-web",
            "cidr": "10.42.0.0/24",
            "region": "europe-west1",
        }
        import web.services as services_module

        real_shared = services_module.run_governed_workflow
        with patch.object(service, "load_runtime", return_value=runtime), patch(
            "web.services.write_backend_runtime_files"
        ), patch(
            "web.services.generate_request",
            return_value=SimpleNamespace(request_path=Path("request.json")),
        ), patch(
            "web.services.run_governance_after_generation",
            return_value=_governance_result(),
        ), patch(
            "web.services.run_governed_workflow", wraps=real_shared
        ) as shared:
            response = self.client.post(
                "/infrastructure",
                data={
                    "csrf_token": self.csrf(),
                    "template_id": "gcp-network-standard",
                    **parameters,
                },
                follow_redirects=True,
            )
        self.assertEqual(response.status_code, 200)
        self.assertIn("AUTHORIZED", response.get_data(as_text=True))
        shared.assert_called_once()

    def test_report_path_traversal_is_rejected(self) -> None:
        service = ReportService()
        for report_type, report_id in (
            ("../security", "report"),
            ("security", "../../report"),
            ("security", "C:\\report"),
        ):
            with self.subTest(report_type=report_type, report_id=report_id), self.assertRaises(WebServiceError):
                service.read_report(report_type, report_id)


if __name__ == "__main__":
    unittest.main()
