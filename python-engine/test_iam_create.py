"""Tests du routage et des validations Python IAM Create."""

import unittest
from unittest.mock import patch

import app
from models import CreateIAMRequest, GCPContext, IAMResource
from request_builder import GCP_IAM_OUTPUT, ask_gcp_iam_parameters
from validators import ValidationError, validate_request


class IAMCreateTests(unittest.TestCase):
    def test_builder_creates_complete_iam_request(self) -> None:
        answers = iter(
            [
                "sa_logging_01",
                "sa-logging-01",
                "Service Account Logging 01",
                "Compte de service pour l'ecriture des journaux",
                "roles/logging.logWriter",
            ]
        )
        request = ask_gcp_iam_parameters(
            lambda _: next(answers),
            gcp_context=GCPContext("example-test-project"),
        )

        self.assertIsInstance(request, CreateIAMRequest)
        self.assertEqual(request.module_path, str(GCP_IAM_OUTPUT.resolve()))
        self.assertEqual(request.resource.resource_name, "sa_logging_01")
        self.assertEqual(request.resource.account_id, "sa-logging-01")
        self.assertEqual(request.resource.role, "roles/logging.logWriter")
        validate_request(request)

    @patch("app.create_gcp_iam")
    def test_dispatch_routes_iam_create(self, create_mock) -> None:
        app.dispatch("gcp", "iam", "create")
        create_mock.assert_called_once_with()

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_gcp_iam_parameters")
    def test_forbidden_roles_do_not_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        for role in ("roles/owner", "roles/editor"):
            with self.subTest(role=role):
                ask_mock.return_value = self._request(role)
                with self.assertRaisesRegex(
                    ValidationError,
                    "Rôle IAM trop permissif interdit",
                ):
                    app.create_gcp_iam()

        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_gcp_iam_parameters")
    def test_invalid_fields_do_not_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        invalid_resources = [
            IAMResource(
                resource_name="",
                account_id="sa-app-01",
                display_name="Service Account Application 01",
                description="Description",
                project_id="example-test-project",
                role="roles/logging.logWriter",
            ),
            IAMResource(
                resource_name="1-invalid",
                account_id="sa-app-01",
                display_name="Service Account Application 01",
                description="Description",
                project_id="example-test-project",
                role="roles/logging.logWriter",
            ),
            IAMResource(
                resource_name="sa_app_01",
                account_id="",
                display_name="Service Account Application 01",
                description="Description",
                project_id="example-test-project",
                role="roles/logging.logWriter",
            ),
            IAMResource(
                resource_name="sa_app_01",
                account_id="sa-app-01",
                display_name="Service Account Application 01",
                description="Description",
                project_id="",
                role="roles/logging.logWriter",
            ),
            IAMResource(
                resource_name="sa_app_01",
                account_id="sa-app-01",
                display_name="Service Account Application 01",
                description="Description",
                project_id="example-test-project",
                role="logging.logWriter",
            ),
        ]

        for resource in invalid_resources:
            with self.subTest(resource=resource):
                ask_mock.return_value = CreateIAMRequest(
                    module_path=str(GCP_IAM_OUTPUT.resolve()),
                    resource=resource,
                    project_id="example-test-project",
                )
                with self.assertRaises(ValidationError):
                    app.create_gcp_iam()

        save_mock.assert_not_called()
        run_mock.assert_not_called()

    def test_targeted_role_is_allowed(self) -> None:
        validate_request(self._request("roles/storage.objectViewer"))

    @staticmethod
    def _request(role: str) -> CreateIAMRequest:
        return CreateIAMRequest(
            module_path=str(GCP_IAM_OUTPUT.resolve()),
            project_id="example-test-project",
            resource=IAMResource(
                resource_name="sa_app_01",
                account_id="sa-app-01",
                display_name="Service Account Application 01",
                description="Description",
                project_id="example-test-project",
                role=role,
            ),
        )


if __name__ == "__main__":
    unittest.main()
