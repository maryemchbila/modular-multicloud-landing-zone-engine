"""Tests du routage, de la confirmation et du contrat IAM Delete."""

import unittest
from pathlib import Path
from unittest.mock import patch

import app
from models import DeleteIAMRequest, IAMDeleteResource
from request_builder import GCP_IAM_OUTPUT, ask_gcp_iam_delete_parameters
from validators import ValidationError, validate_request


class IAMDeleteTests(unittest.TestCase):
    def test_builder_creates_minimal_delete_request(self) -> None:
        request = ask_gcp_iam_delete_parameters(
            lambda _: "sa_delete_test_01"
        )

        self.assertIsInstance(request, DeleteIAMRequest)
        self.assertEqual(request.action, "delete")
        self.assertEqual(request.module_path, str(GCP_IAM_OUTPUT.resolve()))
        self.assertEqual(
            request.to_dict()["resource"],
            {"resource_name": "sa_delete_test_01"},
        )
        validate_request(request)

    @patch("app.delete_gcp_iam")
    def test_dispatch_routes_iam_delete(self, delete_mock) -> None:
        app.dispatch("gcp", "iam", "delete")
        delete_mock.assert_called_once_with()

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_gcp_iam_delete_parameters")
    def test_cancellation_does_not_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = self._request()

        app.delete_gcp_iam(lambda _: "n")

        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @patch("app.run_generator", return_value="ok")
    @patch("app.save_request", return_value=Path("delete-iam.json"))
    @patch("app.ask_gcp_iam_delete_parameters")
    def test_explicit_confirmation_calls_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = self._request()

        for confirmation in ("y", "yes", "oui", "o"):
            with self.subTest(confirmation=confirmation):
                save_mock.reset_mock()
                run_mock.reset_mock()
                app.delete_gcp_iam(lambda _: confirmation)
                save_mock.assert_called_once_with(
                    self._request().to_dict()
                )
                run_mock.assert_called_once_with(Path("delete-iam.json"))

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_gcp_iam_delete_parameters")
    def test_invalid_identifier_does_not_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = DeleteIAMRequest(
            module_path=str(GCP_IAM_OUTPUT.resolve()),
            resource=IAMDeleteResource(resource_name="1-invalid"),
        )

        with self.assertRaisesRegex(
            ValidationError,
            "identifiant Terraform valide",
        ):
            app.delete_gcp_iam(lambda _: "y")

        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @staticmethod
    def _request() -> DeleteIAMRequest:
        return DeleteIAMRequest(
            module_path=str(GCP_IAM_OUTPUT.resolve()),
            resource=IAMDeleteResource(
                resource_name="sa_delete_test_01",
            ),
        )


if __name__ == "__main__":
    unittest.main()
