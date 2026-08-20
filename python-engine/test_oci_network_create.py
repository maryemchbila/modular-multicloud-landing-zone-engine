"""Tests du contrat, du routage et de la validation OCI Network Create."""

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import app
from models import CreateOCINetworkRequest, OCINetworkResource
from request_builder import (
    OCI_NETWORK_OUTPUT,
    ask_oci_network_parameters,
)
from validators import ValidationError, validate_request


class OCINetworkCreateTests(unittest.TestCase):
    def test_builder_creates_complete_request_with_real_boolean(self) -> None:
        answers = iter(
            [
                "oci_vcn_test_01",
                "oci-vcn-test-01",
                "ocid1.compartment.oc1..exampleuniqueID",
                "10.30.0.0/16",
                "vcntest01",
                "oci_subnet_test_01",
                "oci-subnet-test-01",
                "10.30.1.0/24",
                "subtest01",
                "Uocm:EU-FRANKFURT-1-AD-1",
                "false",
                "oci_igw_test_01",
                "oci-igw-test-01",
                "oci_rt_test_01",
                "oci-rt-test-01",
            ]
        )
        request = ask_oci_network_parameters(lambda _: next(answers))

        self.assertIsInstance(request, CreateOCINetworkRequest)
        self.assertEqual(request.provider, "oci")
        self.assertEqual(request.module, "network")
        self.assertEqual(
            request.module_path,
            str(OCI_NETWORK_OUTPUT.resolve()),
        )
        self.assertIs(request.resource.prohibit_public_ip_on_vnic, False)
        self.assertIs(
            request.to_dict()["resource"]["prohibit_public_ip_on_vnic"],
            False,
        )
        validate_request(request)

    @patch("app.create_oci_network")
    def test_dispatch_routes_only_oci_network_create(
        self,
        create_mock,
    ) -> None:
        app.dispatch("oci", "network", "create")
        create_mock.assert_called_once_with()

    @patch("app.create_oci_network")
    @patch("builtins.input", side_effect=["2", "example-client", "dev", "2", "1"])
    def test_menu_choices_2_2_1_launch_create(
        self,
        _input_mock,
        create_mock,
    ) -> None:
        self.assertEqual(app.main(), 0)
        create_mock.assert_called_once_with()

    @patch("app.run_generator", return_value="ok")
    @patch("app.save_request", return_value=Path("create-oci-network.json"))
    @patch("app.ask_oci_network_parameters")
    def test_public_subnet_warning_and_go_call(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = self._request(False)
        output = io.StringIO()

        with redirect_stdout(output):
            app.create_oci_network()

        self.assertIn(
            "Avertissement sécurité : le subnet autorise potentiellement "
            "des IP publiques sur les VNIC.",
            output.getvalue(),
        )
        save_mock.assert_called_once()
        run_mock.assert_called_once_with(Path("create-oci-network.json"))

    @patch("app.run_generator", return_value="ok")
    @patch("app.save_request", return_value=Path("create-oci-network.json"))
    @patch("app.ask_oci_network_parameters")
    def test_restricted_subnet_has_no_warning_and_uses_true(
        self,
        ask_mock,
        _save_mock,
        run_mock,
    ) -> None:
        request = self._request(True)
        ask_mock.return_value = request
        output = io.StringIO()

        with redirect_stdout(output):
            app.create_oci_network()

        self.assertNotIn("Avertissement sécurité", output.getvalue())
        self.assertIs(
            request.to_dict()["resource"]["prohibit_public_ip_on_vnic"],
            True,
        )
        run_mock.assert_called_once()

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_oci_network_parameters")
    def test_invalid_network_data_does_not_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        invalid_values = (
            ("compartment_id", "compartment-invalid", "ocid1.compartment."),
            ("vcn_cidr", "10.500.0.0/16", "vcn_cidr"),
            ("subnet_cidr", "10.60.1.0/24", "doit appartenir"),
        )
        for field, value, expected in invalid_values:
            with self.subTest(field=field):
                request = self._request(False)
                values = request.resource.__dict__.copy()
                values[field] = value
                ask_mock.return_value = CreateOCINetworkRequest(
                    module_path=request.module_path,
                    resource=OCINetworkResource(**values),
                )
                with self.assertRaisesRegex(ValidationError, expected):
                    app.create_oci_network()

        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @staticmethod
    def _request(
        prohibit_public_ip_on_vnic: bool,
    ) -> CreateOCINetworkRequest:
        return CreateOCINetworkRequest(
            module_path=str(OCI_NETWORK_OUTPUT.resolve()),
            resource=OCINetworkResource(
                resource_name="oci_vcn_test_01",
                display_name="oci-vcn-test-01",
                compartment_id=(
                    "ocid1.compartment.oc1..exampleuniqueID"
                ),
                vcn_cidr="10.30.0.0/16",
                dns_label="vcntest01",
                subnet_resource_name="oci_subnet_test_01",
                subnet_display_name="oci-subnet-test-01",
                subnet_cidr="10.30.1.0/24",
                subnet_dns_label="subtest01",
                availability_domain="Uocm:EU-FRANKFURT-1-AD-1",
                prohibit_public_ip_on_vnic=(
                    prohibit_public_ip_on_vnic
                ),
                internet_gateway_resource_name="oci_igw_test_01",
                internet_gateway_display_name="oci-igw-test-01",
                route_table_resource_name="oci_rt_test_01",
                route_table_display_name="oci-rt-test-01",
            ),
        )


if __name__ == "__main__":
    unittest.main()
