"""Tests du contrat, du routage et de la sécurité OCI Compute Update."""

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import app
from models import OCIComputeResource, UpdateOCIComputeRequest
from request_builder import (
    OCI_COMPUTE_OUTPUT,
    ask_oci_compute_update_parameters,
)
from validators import ValidationError, validate_request


class OCIComputeUpdateTests(unittest.TestCase):
    def test_builder_creates_complete_update_with_real_boolean(self) -> None:
        answers = iter(
            [
                "oci_vm_test_01",
                "oci-vm-production-01",
                "Uocm:EU-FRANKFURT-1-AD-1",
                "ocid1.compartment.oc1..exampleuniqueID",
                "VM.Standard.E5.Flex",
                "ocid1.subnet.oc1.eu-frankfurt-1.exampleuniqueID",
                "ocid1.image.oc1.eu-frankfurt-1.exampleuniqueID",
                "false",
            ]
        )
        request = ask_oci_compute_update_parameters(
            lambda _: next(answers)
        )

        self.assertIsInstance(request, UpdateOCIComputeRequest)
        self.assertEqual(request.action, "update")
        self.assertEqual(request.provider, "oci")
        self.assertEqual(request.module, "compute")
        self.assertEqual(
            request.module_path,
            str(OCI_COMPUTE_OUTPUT.resolve()),
        )
        self.assertIs(request.resource.assign_public_ip, False)
        self.assertIs(
            request.to_dict()["resource"]["assign_public_ip"],
            False,
        )
        validate_request(request)

    @patch("app.update_oci_compute")
    def test_dispatch_routes_oci_compute_update(
        self,
        update_mock,
    ) -> None:
        app.dispatch("oci", "compute", "update")
        update_mock.assert_called_once_with()

    @patch("app.update_oci_compute")
    @patch("builtins.input", side_effect=["2", "1", "2"])
    def test_menu_choices_2_1_2_launch_update(
        self,
        _input_mock,
        update_mock,
    ) -> None:
        self.assertEqual(app.main(), 0)
        update_mock.assert_called_once_with()

    @patch("app.run_generator", return_value="ok")
    @patch("app.save_request", return_value=Path("update-oci.json"))
    @patch("app.ask_oci_compute_update_parameters")
    def test_public_ip_warning_and_go_call(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        request = self._request(assign_public_ip=True)
        ask_mock.return_value = request
        output = io.StringIO()

        with redirect_stdout(output):
            app.update_oci_compute()

        self.assertIn(
            "Avertissement sécurité : une adresse IP publique sera "
            "configurée sur l’instance OCI.",
            output.getvalue(),
        )
        save_mock.assert_called_once_with(request.to_dict())
        run_mock.assert_called_once_with(Path("update-oci.json"))

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_oci_compute_update_parameters")
    def test_invalid_ocids_do_not_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        invalid_values = {
            "compartment_id": "compartment-invalid",
            "subnet_id": "subnet-invalid",
            "image_id": "image-invalid",
        }
        for field, value in invalid_values.items():
            with self.subTest(field=field):
                request = self._request()
                values = request.resource.__dict__.copy()
                values[field] = value
                ask_mock.return_value = UpdateOCIComputeRequest(
                    module_path=request.module_path,
                    resource=OCIComputeResource(**values),
                )
                with self.assertRaises(ValidationError):
                    app.update_oci_compute()

        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @staticmethod
    def _request(
        assign_public_ip: bool = False,
    ) -> UpdateOCIComputeRequest:
        return UpdateOCIComputeRequest(
            module_path=str(OCI_COMPUTE_OUTPUT.resolve()),
            resource=OCIComputeResource(
                resource_name="oci_vm_test_01",
                display_name="oci-vm-production-01",
                availability_domain="Uocm:EU-FRANKFURT-1-AD-1",
                compartment_id=(
                    "ocid1.compartment.oc1..exampleuniqueID"
                ),
                shape="VM.Standard.E5.Flex",
                subnet_id=(
                    "ocid1.subnet.oc1.eu-frankfurt-1.exampleuniqueID"
                ),
                image_id=(
                    "ocid1.image.oc1.eu-frankfurt-1.exampleuniqueID"
                ),
                assign_public_ip=assign_public_ip,
            ),
        )


if __name__ == "__main__":
    unittest.main()
