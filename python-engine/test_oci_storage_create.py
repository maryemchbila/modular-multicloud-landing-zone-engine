"""Tests du contrat, du routage et de la validation OCI Storage Create."""

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import app
from models import CreateOCIStorageRequest, OCIStorageResource
from request_builder import OCI_STORAGE_OUTPUT, ask_oci_storage_parameters
from validators import ValidationError, validate_request


class OCIStorageCreateTests(unittest.TestCase):
    def test_builder_normalizes_values_and_keeps_real_boolean(self) -> None:
        answers = iter(
            [
                "oci_bucket_test_01",
                "ocid1.compartment.oc1..exampleuniqueID",
                "exampletenancy",
                "oci-bucket-test-01",
                "nopublicaccess",
                "archive",
                "enabled",
                "false",
            ]
        )
        request = ask_oci_storage_parameters(lambda _: next(answers))

        self.assertIsInstance(request, CreateOCIStorageRequest)
        self.assertEqual(request.module_path, str(OCI_STORAGE_OUTPUT.resolve()))
        self.assertEqual(request.resource.access_type, "NoPublicAccess")
        self.assertEqual(request.resource.storage_tier, "Archive")
        self.assertEqual(request.resource.versioning, "Enabled")
        self.assertIs(request.resource.object_events_enabled, False)
        self.assertIs(
            request.to_dict()["resource"]["object_events_enabled"],
            False,
        )
        validate_request(request)

    @patch("app.create_oci_storage")
    @patch("builtins.input", side_effect=["2", "3", "1"])
    def test_menu_choices_2_3_1_launch_create(
        self,
        _input_mock,
        create_mock,
    ) -> None:
        self.assertEqual(app.main(), 0)
        create_mock.assert_called_once_with()

    @patch("app.run_generator", return_value="ok")
    @patch("app.save_request", return_value=Path("create-oci-storage.json"))
    @patch("app.ask_oci_storage_parameters")
    def test_secure_standard_bucket_has_no_warning(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = self._request()
        output = io.StringIO()

        with redirect_stdout(output):
            app.create_oci_storage()

        self.assertNotIn("Avertissement sécurité", output.getvalue())
        save_mock.assert_called_once()
        run_mock.assert_called_once_with(Path("create-oci-storage.json"))

    @patch("app.run_generator", return_value="ok")
    @patch("app.save_request", return_value=Path("create-oci-storage.json"))
    @patch("app.ask_oci_storage_parameters")
    def test_public_access_prints_security_warning(
        self,
        ask_mock,
        _save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = self._request(access_type="ObjectRead")
        output = io.StringIO()

        with redirect_stdout(output):
            app.create_oci_storage()

        self.assertIn(
            "Avertissement sécurité : le bucket OCI autorise un accès "
            "public en lecture.",
            output.getvalue(),
        )
        run_mock.assert_called_once()

    @patch("app.run_generator", return_value="ok")
    @patch("app.save_request", return_value=Path("create-oci-storage.json"))
    @patch("app.ask_oci_storage_parameters")
    def test_disabled_versioning_prints_security_warning(
        self,
        ask_mock,
        _save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = self._request(versioning="Disabled")
        output = io.StringIO()

        with redirect_stdout(output):
            app.create_oci_storage()

        self.assertIn(
            "Avertissement sécurité : le versioning du bucket OCI est "
            "désactivé.",
            output.getvalue(),
        )
        run_mock.assert_called_once()

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_oci_storage_parameters")
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
            ("compartment_id", "invalid-ocid", "ocid1.compartment."),
        )
        for field, value, expected in invalid_values:
            with self.subTest(field=field):
                request = self._request()
                values = request.resource.__dict__.copy()
                values[field] = value
                ask_mock.return_value = CreateOCIStorageRequest(
                    module_path=request.module_path,
                    resource=OCIStorageResource(**values),
                )
                with self.assertRaisesRegex(ValidationError, expected):
                    app.create_oci_storage()

        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @staticmethod
    def _request(
        access_type: str = "NoPublicAccess",
        storage_tier: str = "Standard",
        versioning: str = "Enabled",
        object_events_enabled: bool = True,
    ) -> CreateOCIStorageRequest:
        return CreateOCIStorageRequest(
            module_path=str(OCI_STORAGE_OUTPUT.resolve()),
            resource=OCIStorageResource(
                resource_name="oci_bucket_test_01",
                compartment_id=(
                    "ocid1.compartment.oc1..exampleuniqueID"
                ),
                namespace="exampletenancy",
                name="oci-bucket-test-01",
                access_type=access_type,
                storage_tier=storage_tier,
                versioning=versioning,
                object_events_enabled=object_events_enabled,
            ),
        )


if __name__ == "__main__":
    unittest.main()
