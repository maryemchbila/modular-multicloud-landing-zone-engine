"""Tests du contrat, de la confirmation et du routage OCI Network Delete."""

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import app
from models import DeleteOCINetworkRequest, OCINetworkDeleteResource
from request_builder import (
    OCI_NETWORK_OUTPUT,
    ask_oci_network_delete_parameters,
)
from validators import ValidationError


class OCINetworkDeleteTests(unittest.TestCase):
    def test_builder_requests_only_four_identifiers(self) -> None:
        answers = iter(
            [
                "oci_vcn_delete_test_01",
                "oci_subnet_delete_test_01",
                "oci_igw_delete_test_01",
                "oci_rt_delete_test_01",
            ]
        )
        request = ask_oci_network_delete_parameters(
            lambda _: next(answers)
        )

        self.assertIsInstance(request, DeleteOCINetworkRequest)
        self.assertEqual(request.action, "delete")
        self.assertEqual(request.provider, "oci")
        self.assertEqual(request.module, "network")
        self.assertEqual(
            request.module_path,
            str(OCI_NETWORK_OUTPUT.resolve()),
        )
        self.assertEqual(
            set(request.to_dict()["resource"]),
            {
                "resource_name",
                "subnet_resource_name",
                "internet_gateway_resource_name",
                "route_table_resource_name",
            },
        )

    @patch("app.delete_oci_network")
    def test_dispatch_routes_oci_network_delete(self, delete_mock) -> None:
        app.dispatch("oci", "network", "delete")
        delete_mock.assert_called_once_with()

    @patch("app.delete_oci_network")
    @patch("builtins.input", side_effect=["2", "example-client", "dev", "2", "3"])
    def test_menu_choices_2_2_3_launch_delete(
        self,
        _input_mock,
        delete_mock,
    ) -> None:
        self.assertEqual(app.main(), 0)
        delete_mock.assert_called_once_with()

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_oci_network_delete_parameters")
    def test_cancellation_does_not_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = self._request()
        output = io.StringIO()

        with redirect_stdout(output):
            app.delete_oci_network(lambda _: "n")

        self.assertIn("Suppression annulée.", output.getvalue())
        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @patch("app.run_generator", return_value="ok")
    @patch("app.save_request", return_value=Path("delete-oci-network.json"))
    @patch("app.ask_oci_network_delete_parameters")
    def test_confirmation_calls_go_and_prints_local_only_message(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = self._request()
        output = io.StringIO()

        with redirect_stdout(output):
            app.delete_oci_network(lambda _: "oui")

        text = output.getvalue()
        for address in (
            "oci_core_subnet.oci_subnet_delete_test_01",
            "oci_core_route_table.oci_rt_delete_test_01",
            "oci_core_internet_gateway.oci_igw_delete_test_01",
            "oci_core_vcn.oci_vcn_delete_test_01",
        ):
            self.assertIn(address, text)
        self.assertIn(
            "Aucune ressource OCI réelle ne sera détruite automatiquement.",
            text,
        )
        self.assertIn(
            "Terraform OCI Network code deleted locally. "
            "No OCI network resource was destroyed.",
            text,
        )
        save_mock.assert_called_once()
        run_mock.assert_called_once_with(Path("delete-oci-network.json"))

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_oci_network_delete_parameters")
    def test_invalid_identifiers_do_not_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        invalid_values = (
            ("resource_name", ""),
            ("subnet_resource_name", "999 invalid"),
            ("internet_gateway_resource_name", ""),
            ("route_table_resource_name", "invalid route table"),
        )
        for field, value in invalid_values:
            with self.subTest(field=field):
                request = self._request()
                values = request.resource.__dict__.copy()
                values[field] = value
                ask_mock.return_value = DeleteOCINetworkRequest(
                    module_path=request.module_path,
                    resource=OCINetworkDeleteResource(**values),
                )
                with self.assertRaises(ValidationError):
                    app.delete_oci_network(lambda _: "y")

        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @staticmethod
    def _request() -> DeleteOCINetworkRequest:
        return DeleteOCINetworkRequest(
            module_path=str(OCI_NETWORK_OUTPUT.resolve()),
            resource=OCINetworkDeleteResource(
                resource_name="oci_vcn_delete_test_01",
                subnet_resource_name="oci_subnet_delete_test_01",
                internet_gateway_resource_name="oci_igw_delete_test_01",
                route_table_resource_name="oci_rt_delete_test_01",
            ),
        )


if __name__ == "__main__":
    unittest.main()
