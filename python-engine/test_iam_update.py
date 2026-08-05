"""Tests du routage et des validations Python IAM Update."""

import unittest
from unittest.mock import patch

import app
from models import IAMResource, UpdateIAMRequest
from request_builder import GCP_IAM_OUTPUT, ask_gcp_iam_update_parameters
from validators import ValidationError, validate_request


class IAMUpdateTests(unittest.TestCase):
    def test_builder_creates_complete_update_request(self) -> None:
        answers = iter(
            [
                "sa_logging_01",
                "sa-logging-prod-01",
                "Service Account Logging Production",
                "Compte de service de production pour les journaux",
                "stage2026-project",
                "roles/logging.logWriter",
            ]
        )
        request = ask_gcp_iam_update_parameters(lambda _: next(answers))

        self.assertIsInstance(request, UpdateIAMRequest)
        self.assertEqual(request.action, "update")
        self.assertEqual(request.module_path, str(GCP_IAM_OUTPUT.resolve()))
        self.assertEqual(request.resource.account_id, "sa-logging-prod-01")
        self.assertEqual(
            request.resource.display_name,
            "Service Account Logging Production",
        )
        validate_request(request)

    @patch("app.update_gcp_iam")
    def test_dispatch_routes_iam_update(self, update_mock) -> None:
        app.dispatch("gcp", "iam", "update")
        update_mock.assert_called_once_with()

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_gcp_iam_update_parameters")
    def test_forbidden_roles_do_not_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        for role in ("roles/owner", "roles/editor"):
            with self.subTest(role=role):
                ask_mock.return_value = self._request(role=role)
                with self.assertRaisesRegex(
                    ValidationError,
                    "Rôle IAM trop permissif interdit",
                ):
                    app.update_gcp_iam()

        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_gcp_iam_update_parameters")
    def test_malformed_role_does_not_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = self._request(role="logging.logWriter")

        with self.assertRaisesRegex(
            ValidationError,
            "Le rôle IAM doit commencer par roles/",
        ):
            app.update_gcp_iam()

        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_gcp_iam_update_parameters")
    def test_all_final_values_are_required_before_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        invalid = [
            {"resource_name": ""},
            {"account_id": ""},
            {"display_name": ""},
            {"description": ""},
            {"project_id": ""},
            {"role": ""},
        ]
        for replacement in invalid:
            with self.subTest(replacement=replacement):
                values = {
                    "resource_name": "sa_logging_01",
                    "account_id": "sa-logging-01",
                    "display_name": "Service Account Logging Production",
                    "description": "Compte de service pour les journaux",
                    "project_id": "stage2026-project",
                    "role": "roles/logging.logWriter",
                }
                values.update(replacement)
                ask_mock.return_value = UpdateIAMRequest(
                    module_path=str(GCP_IAM_OUTPUT.resolve()),
                    resource=IAMResource(**values),
                )
                with self.assertRaises(ValidationError):
                    app.update_gcp_iam()

        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @staticmethod
    def _request(role: str) -> UpdateIAMRequest:
        return UpdateIAMRequest(
            module_path=str(GCP_IAM_OUTPUT.resolve()),
            resource=IAMResource(
                resource_name="sa_logging_01",
                account_id="sa-logging-01",
                display_name="Service Account Logging Production",
                description="Compte de service pour les journaux",
                project_id="stage2026-project",
                role=role,
            ),
        )


if __name__ == "__main__":
    unittest.main()
