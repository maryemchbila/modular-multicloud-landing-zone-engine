"""Tests du routage, du contrat et de la validation Network Update."""

import unittest
from unittest.mock import patch

import app
from models import NetworkResource, UpdateNetworkRequest
from request_builder import (
    GCP_NETWORK_OUTPUT,
    ask_gcp_network_update_parameters,
)
from validators import ValidationError, validate_request


class NetworkUpdateTests(unittest.TestCase):
    def test_builder_creates_complete_update_request(self) -> None:
        answers = iter(
            [
                "vpc_dev_01",
                "vpc-dev-production",
                "subnet_dev_01",
                "subnet-dev-production",
                "10.81.0.0/24",
                "europe-west1",
                "",
            ]
        )
        request = ask_gcp_network_update_parameters(lambda _: next(answers))

        self.assertIsInstance(request, UpdateNetworkRequest)
        self.assertEqual(request.action, "update")
        self.assertEqual(request.resource.resource_name, "vpc_dev_01")
        self.assertEqual(
            request.resource.subnet_resource_name,
            "subnet_dev_01",
        )
        validate_request(request)

    @patch("app.update_gcp_network")
    def test_dispatch_routes_network_update(self, update_mock) -> None:
        app.dispatch("gcp", "network", "update")
        update_mock.assert_called_once_with()

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_gcp_network_update_parameters")
    def test_invalid_cidr_does_not_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = UpdateNetworkRequest(
            module_path=str(GCP_NETWORK_OUTPUT.resolve()),
            resource=NetworkResource(
                resource_name="vpc_dev_01",
                name="vpc-dev-production",
                subnet_resource_name="subnet_dev_01",
                subnet_name="subnet-dev-production",
                cidr="10.500.0.0/24",
                region="europe-west1",
            ),
        )

        with self.assertRaisesRegex(
            ValidationError,
            "resource.cidr doit etre un CIDR IPv4 valide",
        ):
            app.update_gcp_network()

        save_mock.assert_not_called()
        run_mock.assert_not_called()

    def test_network_identifiers_are_required_and_valid(self) -> None:
        request = UpdateNetworkRequest(
            module_path=str(GCP_NETWORK_OUTPUT.resolve()),
            resource=NetworkResource(
                resource_name="",
                name="vpc-dev-production",
                subnet_resource_name="invalid subnet",
                subnet_name="subnet-dev-production",
                cidr="10.81.0.0/24",
                region="europe-west1",
            ),
        )

        with self.assertRaises(ValidationError) as context:
            validate_request(request)

        message = str(context.exception)
        self.assertIn("resource.resource_name est obligatoire", message)
        self.assertIn(
            "resource.subnet_resource_name doit etre un identifiant Terraform valide",
            message,
        )


if __name__ == "__main__":
    unittest.main()
