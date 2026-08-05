"""Tests du contrat, de la confirmation et du routage Compute Delete."""

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import app
from models import ComputeDeleteResource, DeleteVMRequest
from request_builder import (
    GCP_COMPUTE_OUTPUT,
    ask_gcp_compute_delete_parameters,
)
from validators import ValidationError, validate_request


class ComputeDeleteTests(unittest.TestCase):
    def test_builder_creates_minimal_delete_request(self) -> None:
        request = ask_gcp_compute_delete_parameters(lambda _: "vm_web_05")

        self.assertIsInstance(request, DeleteVMRequest)
        self.assertEqual(request.action, "delete")
        self.assertEqual(request.resource.resource_name, "vm_web_05")
        self.assertEqual(
            request.to_dict()["resource"],
            {"resource_name": "vm_web_05"},
        )
        validate_request(request)

    @patch("app.delete_gcp_compute")
    def test_dispatch_routes_compute_delete(self, delete_mock) -> None:
        app.dispatch("gcp", "compute", "delete")
        delete_mock.assert_called_once_with()

    @patch("app.run_generator", return_value="ok")
    @patch("app.save_request", return_value=Path("delete.json"))
    @patch("app.ask_gcp_compute_delete_parameters")
    def test_explicit_confirmation_calls_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        request = self._valid_request()
        ask_mock.return_value = request

        app.delete_gcp_compute(lambda _: "oui")

        save_mock.assert_called_once_with(request.to_dict())
        run_mock.assert_called_once_with(Path("delete.json"))

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_gcp_compute_delete_parameters")
    def test_cancellation_does_not_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = self._valid_request()
        output = io.StringIO()

        with redirect_stdout(output):
            app.delete_gcp_compute(lambda _: "n")

        self.assertIn("Suppression annulée.", output.getvalue())
        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_gcp_compute_delete_parameters")
    def test_invalid_resource_name_does_not_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = DeleteVMRequest(
            module_path=str(GCP_COMPUTE_OUTPUT.resolve()),
            resource=ComputeDeleteResource(resource_name="invalid resource"),
        )

        with self.assertRaisesRegex(
            ValidationError,
            "resource.resource_name doit etre un identifiant Terraform valide",
        ):
            app.delete_gcp_compute(lambda _: "y")

        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @staticmethod
    def _valid_request() -> DeleteVMRequest:
        return DeleteVMRequest(
            module_path=str(GCP_COMPUTE_OUTPUT.resolve()),
            resource=ComputeDeleteResource(resource_name="vm_delete_test_01"),
        )


if __name__ == "__main__":
    unittest.main()
