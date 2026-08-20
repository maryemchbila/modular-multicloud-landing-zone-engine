"""Tests du contrat, du routage et de la validation OCI Network Update."""

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import app
from models import OCINetworkResource, UpdateOCINetworkRequest
from request_builder import (
    OCI_NETWORK_OUTPUT,
    ask_oci_network_update_parameters,
)
from validators import ValidationError, validate_request


class OCINetworkUpdateTests(unittest.TestCase):
    def test_builder_requests_all_final_values_and_normalizes_dns(self) -> None:
        answers = iter(
            [
                "oci_vcn_test_01",
                "oci-vcn-production-01",
                "ocid1.compartment.oc1..exampleuniqueID",
                "10.30.0.0/16",
                "VCNPROD01",
                "oci_subnet_test_01",
                "oci-subnet-production-01",
                "10.30.20.0/24",
                "SUBPROD01",
                "Uocm:EU-FRANKFURT-1-AD-1",
                "true",
                "oci_igw_test_01",
                "oci-igw-production-01",
                "oci_rt_test_01",
                "oci-rt-production-01",
            ]
        )
        request = ask_oci_network_update_parameters(
            lambda _: next(answers)
        )

        self.assertIsInstance(request, UpdateOCINetworkRequest)
        self.assertEqual(request.action, "update")
        self.assertEqual(request.provider, "oci")
        self.assertEqual(request.module, "network")
        self.assertEqual(request.resource.dns_label, "vcnprod01")
        self.assertEqual(request.resource.subnet_dns_label, "subprod01")
        self.assertIs(request.resource.prohibit_public_ip_on_vnic, True)
        validate_request(request)

    @patch("app.update_oci_network")
    def test_dispatch_routes_oci_network_update(self, update_mock) -> None:
        app.dispatch("oci", "network", "update")
        update_mock.assert_called_once_with()

    @patch("app.update_oci_network")
    @patch("builtins.input", side_effect=["2", "example-client", "dev", "2", "2"])
    def test_menu_choices_2_2_2_launch_update(
        self,
        _input_mock,
        update_mock,
    ) -> None:
        self.assertEqual(app.main(), 0)
        update_mock.assert_called_once_with()

    @patch("app.run_generator", return_value="ok")
    @patch("app.save_request", return_value=Path("update-oci-network.json"))
    @patch("app.ask_oci_network_update_parameters")
    def test_false_displays_warning_and_calls_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = self._request(False)
        output = io.StringIO()

        with redirect_stdout(output):
            app.update_oci_network()

        self.assertIn(
            "Avertissement sécurité : le subnet autorise potentiellement "
            "des adresses IP publiques sur ses VNIC.",
            output.getvalue(),
        )
        save_mock.assert_called_once()
        run_mock.assert_called_once_with(Path("update-oci-network.json"))

    @patch("app.run_generator", return_value="ok")
    @patch("app.save_request", return_value=Path("update-oci-network.json"))
    @patch("app.ask_oci_network_update_parameters")
    def test_true_has_no_warning(
        self,
        ask_mock,
        _save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = self._request(True)
        output = io.StringIO()

        with redirect_stdout(output):
            app.update_oci_network()

        self.assertNotIn("Avertissement sécurité", output.getvalue())
        run_mock.assert_called_once()

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_oci_network_update_parameters")
    def test_invalid_cidr_and_dns_do_not_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        invalid_values = (
            ("subnet_cidr", "10.80.1.0/24", "doit appartenir"),
            ("dns_label", "vcn-test", "dns_label"),
            ("dns_label", "01vcn", "dns_label"),
            ("subnet_dns_label", "sub_net", "subnet_dns_label"),
        )
        for field, value, expected in invalid_values:
            with self.subTest(field=field, value=value):
                request = self._request(True)
                values = request.resource.__dict__.copy()
                values[field] = value
                ask_mock.return_value = UpdateOCINetworkRequest(
                    module_path=request.module_path,
                    resource=OCINetworkResource(**values),
                )
                with self.assertRaisesRegex(ValidationError, expected):
                    app.update_oci_network()

        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @staticmethod
    def _request(
        prohibit_public_ip_on_vnic: bool,
    ) -> UpdateOCINetworkRequest:
        return UpdateOCINetworkRequest(
            module_path=str(OCI_NETWORK_OUTPUT.resolve()),
            resource=OCINetworkResource(
                resource_name="oci_vcn_test_01",
                display_name="oci-vcn-production-01",
                compartment_id=(
                    "ocid1.compartment.oc1..exampleuniqueID"
                ),
                vcn_cidr="10.30.0.0/16",
                dns_label="vcnprod01",
                subnet_resource_name="oci_subnet_test_01",
                subnet_display_name="oci-subnet-production-01",
                subnet_cidr="10.30.20.0/24",
                subnet_dns_label="subprod01",
                availability_domain="Uocm:EU-FRANKFURT-1-AD-1",
                prohibit_public_ip_on_vnic=(
                    prohibit_public_ip_on_vnic
                ),
                internet_gateway_resource_name="oci_igw_test_01",
                internet_gateway_display_name=(
                    "oci-igw-production-01"
                ),
                route_table_resource_name="oci_rt_test_01",
                route_table_display_name="oci-rt-production-01",
            ),
        )


if __name__ == "__main__":
    unittest.main()
