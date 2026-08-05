"""Tests du contrat, de la confirmation et du routage OCI Storage Delete."""

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import app
from models import DeleteOCIStorageRequest, OCIStorageDeleteResource
from request_builder import (
    OCI_STORAGE_OUTPUT,
    ask_oci_storage_delete_parameters,
)
from validators import ValidationError, validate_request


class OCIStorageDeleteTests(unittest.TestCase):
    def test_builder_requests_only_resource_name(self) -> None:
        request = ask_oci_storage_delete_parameters(
            lambda _: "oci_bucket_delete_test_01"
        )

        self.assertIsInstance(request, DeleteOCIStorageRequest)
        self.assertEqual(request.action, "delete")
        self.assertEqual(request.provider, "oci")
        self.assertEqual(request.module, "storage")
        self.assertEqual(request.module_path, str(OCI_STORAGE_OUTPUT.resolve()))
        self.assertEqual(
            request.to_dict()["resource"],
            {"resource_name": "oci_bucket_delete_test_01"},
        )
        validate_request(request)

    @patch("app.delete_oci_storage")
    def test_dispatch_routes_oci_storage_delete(
        self,
        delete_mock,
    ) -> None:
        app.dispatch("oci", "storage", "delete")
        delete_mock.assert_called_once_with()

    @patch("app.delete_oci_storage")
    @patch("builtins.input", side_effect=["2", "3", "3"])
    def test_menu_choices_2_3_3_launch_delete(
        self,
        _input_mock,
        delete_mock,
    ) -> None:
        self.assertEqual(app.main(), 0)
        delete_mock.assert_called_once_with()

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_oci_storage_delete_parameters")
    def test_cancellation_does_not_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = self._request()
        answers = iter(["n"])
        output = io.StringIO()

        with redirect_stdout(output):
            app.delete_oci_storage(lambda _: next(answers))

        self.assertIn("Suppression annulée.", output.getvalue())
        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @patch("app.run_generator", return_value="ok")
    @patch("app.save_request", return_value=Path("delete-oci-storage.json"))
    @patch("app.ask_oci_storage_delete_parameters")
    def test_confirmation_variants_call_go_and_print_local_only_message(
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
                output = io.StringIO()

                with redirect_stdout(output):
                    app.delete_oci_storage(lambda _: confirmation)

                text = output.getvalue()
                self.assertIn(
                    "oci_objectstorage_bucket.oci_bucket_delete_test_01",
                    text,
                )
                self.assertIn(
                    "Les variables, tfvars et outputs associés seront "
                    "également supprimés.",
                    text,
                )
                self.assertIn(
                    "Aucun bucket OCI réel ne sera détruit automatiquement.",
                    text,
                )
                self.assertIn(
                    "Terraform OCI Storage code deleted locally. "
                    "No OCI bucket was destroyed.",
                    text,
                )
                save_mock.assert_called_once()
                run_mock.assert_called_once_with(
                    Path("delete-oci-storage.json")
                )

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_oci_storage_delete_parameters")
    def test_invalid_resource_name_does_not_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = DeleteOCIStorageRequest(
            module_path=str(OCI_STORAGE_OUTPUT.resolve()),
            resource=OCIStorageDeleteResource(
                resource_name="999 invalid",
            ),
        )

        with self.assertRaisesRegex(ValidationError, "resource_name"):
            app.delete_oci_storage(lambda _: "y")

        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @staticmethod
    def _request() -> DeleteOCIStorageRequest:
        return DeleteOCIStorageRequest(
            module_path=str(OCI_STORAGE_OUTPUT.resolve()),
            resource=OCIStorageDeleteResource(
                resource_name="oci_bucket_delete_test_01",
            ),
        )


if __name__ == "__main__":
    unittest.main()
