"""Tests du contrat, du routage et de la validation OCI Storage Update."""

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import app
from models import OCIStorageResource, UpdateOCIStorageRequest
from request_builder import (
    OCI_STORAGE_OUTPUT,
    ask_oci_storage_update_parameters,
)
from validators import ValidationError, validate_request


class OCIStorageUpdateTests(unittest.TestCase):
    def test_builder_requests_all_values_and_normalizes_them(self) -> None:
        answers = iter(
            [
                "oci_bucket_test_01",
                "ocid1.compartment.oc1..exampleuniqueID",
                "exampletenancynamespace",
                "stage2026-oci-bucket-production-01",
                "objectreadwithoutlist",
                "archive",
                "disabled",
                "false",
            ]
        )
        request = ask_oci_storage_update_parameters(
            lambda _: next(answers)
        )

        self.assertIsInstance(request, UpdateOCIStorageRequest)
        self.assertEqual(request.action, "update")
        self.assertEqual(request.provider, "oci")
        self.assertEqual(request.module, "storage")
        self.assertEqual(request.module_path, str(OCI_STORAGE_OUTPUT.resolve()))
        self.assertEqual(
            request.resource.access_type,
            "ObjectReadWithoutList",
        )
        self.assertEqual(request.resource.storage_tier, "Archive")
        self.assertEqual(request.resource.versioning, "Disabled")
        self.assertIs(request.resource.object_events_enabled, False)
        self.assertIs(
            request.to_dict()["resource"]["object_events_enabled"],
            False,
        )
        validate_request(request)

    @patch("app.update_oci_storage")
    def test_dispatch_routes_oci_storage_update(
        self,
        update_mock,
    ) -> None:
        app.dispatch("oci", "storage", "update")
        update_mock.assert_called_once_with()

    @patch("app.update_oci_storage")
    @patch("builtins.input", side_effect=["2", "example-client", "dev", "3", "2"])
    def test_menu_choices_2_3_2_launch_update(
        self,
        _input_mock,
        update_mock,
    ) -> None:
        self.assertEqual(app.main(), 0)
        update_mock.assert_called_once_with()

    @patch("app.run_generator", return_value="ok")
    @patch("app.save_request", return_value=Path("update-oci-storage.json"))
    @patch("app.ask_oci_storage_update_parameters")
    def test_secure_update_has_no_warning_and_calls_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = self._request()
        output = io.StringIO()

        with redirect_stdout(output):
            app.update_oci_storage()

        self.assertNotIn("Avertissement sécurité", output.getvalue())
        save_mock.assert_called_once()
        run_mock.assert_called_once_with(Path("update-oci-storage.json"))

    @patch("app.run_generator", return_value="ok")
    @patch("app.save_request", return_value=Path("update-oci-storage.json"))
    @patch("app.ask_oci_storage_update_parameters")
    def test_public_access_prints_warning(
        self,
        ask_mock,
        _save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = self._request(access_type="ObjectRead")
        output = io.StringIO()

        with redirect_stdout(output):
            app.update_oci_storage()

        self.assertIn(
            "Avertissement sécurité : le bucket OCI autorise un accès "
            "public en lecture.",
            output.getvalue(),
        )
        run_mock.assert_called_once()

    @patch("app.run_generator", return_value="ok")
    @patch("app.save_request", return_value=Path("update-oci-storage.json"))
    @patch("app.ask_oci_storage_update_parameters")
    def test_disabled_versioning_prints_warning(
        self,
        ask_mock,
        _save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = self._request(versioning="Disabled")
        output = io.StringIO()

        with redirect_stdout(output):
            app.update_oci_storage()

        self.assertIn(
            "Avertissement sécurité : le versioning du bucket OCI est "
            "désactivé.",
            output.getvalue(),
        )
        run_mock.assert_called_once()

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_oci_storage_update_parameters")
    def test_invalid_values_do_not_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        invalid_values = (
            ("access_type", "PublicReadWrite", "access_type"),
            ("storage_tier", "Coldline", "storage_tier"),
            ("versioning", "Active", "versioning"),
            ("compartment_id", "compartment-invalid", "ocid1.compartment."),
        )
        for field, value, expected in invalid_values:
            with self.subTest(field=field):
                request = self._request()
                values = request.resource.__dict__.copy()
                values[field] = value
                ask_mock.return_value = UpdateOCIStorageRequest(
                    module_path=request.module_path,
                    resource=OCIStorageResource(**values),
                )
                with self.assertRaisesRegex(ValidationError, expected):
                    app.update_oci_storage()

        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @staticmethod
    def _request(
        access_type: str = "NoPublicAccess",
        storage_tier: str = "Standard",
        versioning: str = "Enabled",
        object_events_enabled: bool = True,
    ) -> UpdateOCIStorageRequest:
        return UpdateOCIStorageRequest(
            module_path=str(OCI_STORAGE_OUTPUT.resolve()),
            resource=OCIStorageResource(
                resource_name="oci_bucket_test_01",
                compartment_id=(
                    "ocid1.compartment.oc1..exampleuniqueID"
                ),
                namespace="exampletenancynamespace",
                name="stage2026-oci-bucket-production-01",
                access_type=access_type,
                storage_tier=storage_tier,
                versioning=versioning,
                object_events_enabled=object_events_enabled,
            ),
        )


if __name__ == "__main__":
    unittest.main()
