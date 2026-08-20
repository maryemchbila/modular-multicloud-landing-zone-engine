"""Tests du contrat, du menu et de la confirmation OCI Compute Delete."""

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import app
from models import DeleteOCIComputeRequest, OCIComputeDeleteResource
from request_builder import (
    OCI_COMPUTE_OUTPUT,
    ask_oci_compute_delete_parameters,
)
from validators import ValidationError, validate_request


class OCIComputeDeleteTests(unittest.TestCase):
    def test_builder_requests_only_resource_name(self) -> None:
        prompts = []

        def answer(prompt: str) -> str:
            prompts.append(prompt)
            return "oci_vm_delete_test_01"

        request = ask_oci_compute_delete_parameters(answer)

        self.assertIsInstance(request, DeleteOCIComputeRequest)
        self.assertEqual(len(prompts), 1)
        self.assertEqual(request.action, "delete")
        self.assertEqual(request.provider, "oci")
        self.assertEqual(request.module, "compute")
        self.assertEqual(
            request.module_path,
            str(OCI_COMPUTE_OUTPUT.resolve()),
        )
        self.assertEqual(
            request.to_dict()["resource"],
            {"resource_name": "oci_vm_delete_test_01"},
        )
        validate_request(request)

    @patch("app.delete_oci_compute")
    def test_dispatch_routes_oci_compute_delete(
        self,
        delete_mock,
    ) -> None:
        app.dispatch("oci", "compute", "delete")
        delete_mock.assert_called_once_with()

    @patch("app.delete_oci_compute")
    @patch("builtins.input", side_effect=["2", "example-client", "dev", "1", "3"])
    def test_menu_choices_2_1_3_launch_delete(
        self,
        _input_mock,
        delete_mock,
    ) -> None:
        self.assertEqual(app.main(), 0)
        delete_mock.assert_called_once_with()

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_oci_compute_delete_parameters")
    def test_cancellation_does_not_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = self._request()
        output = io.StringIO()

        with redirect_stdout(output):
            app.delete_oci_compute(lambda _: "n")

        self.assertIn("Suppression annulée.", output.getvalue())
        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @patch("app.run_generator", return_value="ok")
    @patch("app.save_request", return_value=Path("delete-oci.json"))
    @patch("app.ask_oci_compute_delete_parameters")
    def test_confirmation_variants_call_go_and_print_local_only_message(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        request = self._request()
        ask_mock.return_value = request

        for answer in ("y", "yes", "oui", "o"):
            with self.subTest(answer=answer):
                save_mock.reset_mock()
                run_mock.reset_mock()
                output = io.StringIO()
                with redirect_stdout(output):
                    app.delete_oci_compute(lambda _: answer)

                self.assertIn(
                    "oci_core_instance.oci_vm_delete_test_01",
                    output.getvalue(),
                )
                self.assertIn(
                    "Aucune instance OCI réelle ne sera détruite "
                    "automatiquement.",
                    output.getvalue(),
                )
                self.assertIn(
                    "Terraform OCI Compute code deleted locally. "
                    "No cloud instance was destroyed.",
                    output.getvalue(),
                )
                save_mock.assert_called_once_with(request.to_dict())
                run_mock.assert_called_once_with(Path("delete-oci.json"))

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_oci_compute_delete_parameters")
    def test_invalid_resource_name_does_not_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = self._request("999_invalid")

        with self.assertRaises(ValidationError):
            app.delete_oci_compute(lambda _: "y")

        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @staticmethod
    def _request(
        resource_name: str = "oci_vm_delete_test_01",
    ) -> DeleteOCIComputeRequest:
        return DeleteOCIComputeRequest(
            module_path=str(OCI_COMPUTE_OUTPUT.resolve()),
            resource=OCIComputeDeleteResource(
                resource_name=resource_name,
            ),
        )


if __name__ == "__main__":
    unittest.main()
