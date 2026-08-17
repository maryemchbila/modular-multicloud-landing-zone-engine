"""Tests du contrat, de la confirmation et du routage Storage Delete."""

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import app
from models import DeleteStorageRequest, GCPContext, StorageDeleteResource
from request_builder import (
    GCP_STORAGE_OUTPUT,
    ask_gcp_storage_delete_parameters,
)
from validators import ValidationError, validate_request


class StorageDeleteTests(unittest.TestCase):
    def test_builder_creates_minimal_delete_request(self) -> None:
        request = ask_gcp_storage_delete_parameters(
            lambda _: "bucket_delete_test_01",
            gcp_context=GCPContext("example-test-project"),
        )

        self.assertIsInstance(request, DeleteStorageRequest)
        self.assertEqual(request.action, "delete")
        self.assertEqual(
            request.to_dict()["resource"],
            {"resource_name": "bucket_delete_test_01"},
        )
        validate_request(request)

    @patch("app.delete_gcp_storage")
    def test_dispatch_routes_storage_delete(self, delete_mock) -> None:
        app.dispatch("gcp", "storage", "delete")
        delete_mock.assert_called_once_with()

    @patch("app.run_generator", return_value="ok")
    @patch("app.save_request", return_value=Path("delete-storage.json"))
    @patch("app.ask_gcp_storage_delete_parameters")
    def test_explicit_confirmation_calls_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        request = self._valid_request()
        ask_mock.return_value = request
        output = io.StringIO()

        with redirect_stdout(output):
            app.delete_gcp_storage(lambda _: "yes")

        save_mock.assert_called_once_with(request.to_dict())
        run_mock.assert_called_once_with(Path("delete-storage.json"))
        self.assertIn(
            "Terraform code deleted locally. No cloud resource was destroyed.",
            output.getvalue(),
        )

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_gcp_storage_delete_parameters")
    def test_cancellation_does_not_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = self._valid_request()
        output = io.StringIO()

        with redirect_stdout(output):
            app.delete_gcp_storage(lambda _: "n")

        self.assertIn("Suppression annulée.", output.getvalue())
        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_gcp_storage_delete_parameters")
    def test_invalid_identifier_does_not_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = DeleteStorageRequest(
            module_path=str(GCP_STORAGE_OUTPUT.resolve()),
            project_id="example-test-project",
            resource=StorageDeleteResource(resource_name="invalid bucket"),
        )

        with self.assertRaisesRegex(
            ValidationError,
            "resource.resource_name doit etre un identifiant Terraform valide",
        ):
            app.delete_gcp_storage(lambda _: "y")

        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @staticmethod
    def _valid_request() -> DeleteStorageRequest:
        return DeleteStorageRequest(
            module_path=str(GCP_STORAGE_OUTPUT.resolve()),
            project_id="example-test-project",
            resource=StorageDeleteResource(
                resource_name="bucket_delete_test_01"
            ),
        )


if __name__ == "__main__":
    unittest.main()
