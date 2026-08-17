"""Tests du contrat, de la confirmation et du routage Network Delete."""

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import app
from models import DeleteNetworkRequest, GCPContext, NetworkDeleteResource
from request_builder import (
    GCP_NETWORK_OUTPUT,
    ask_gcp_network_delete_parameters,
)
from validators import ValidationError, validate_request


class NetworkDeleteTests(unittest.TestCase):
    def test_builder_creates_minimal_delete_request(self) -> None:
        answers = iter(["vpc_delete_test_01", "subnet_delete_test_01"])
        request = ask_gcp_network_delete_parameters(
            lambda _: next(answers),
            gcp_context=GCPContext("example-test-project"),
        )

        self.assertIsInstance(request, DeleteNetworkRequest)
        self.assertEqual(request.action, "delete")
        self.assertEqual(
            request.to_dict()["resource"],
            {
                "resource_name": "vpc_delete_test_01",
                "subnet_resource_name": "subnet_delete_test_01",
            },
        )
        validate_request(request)

    @patch("app.delete_gcp_network")
    def test_dispatch_routes_network_delete(self, delete_mock) -> None:
        app.dispatch("gcp", "network", "delete")
        delete_mock.assert_called_once_with()

    @patch("app.run_generator", return_value="ok")
    @patch("app.save_request", return_value=Path("delete-network.json"))
    @patch("app.ask_gcp_network_delete_parameters")
    def test_explicit_confirmation_calls_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        request = self._valid_request()
        ask_mock.return_value = request

        app.delete_gcp_network(lambda _: "o")

        save_mock.assert_called_once_with(request.to_dict())
        run_mock.assert_called_once_with(Path("delete-network.json"))

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_gcp_network_delete_parameters")
    def test_cancellation_does_not_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = self._valid_request()
        output = io.StringIO()

        with redirect_stdout(output):
            app.delete_gcp_network(lambda _: "n")

        self.assertIn("Suppression annulée.", output.getvalue())
        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_gcp_network_delete_parameters")
    def test_invalid_identifier_does_not_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = DeleteNetworkRequest(
            module_path=str(GCP_NETWORK_OUTPUT.resolve()),
            project_id="example-test-project",
            resource=NetworkDeleteResource(
                resource_name="vpc_delete_test_01",
                subnet_resource_name="invalid subnet",
            ),
        )

        with self.assertRaisesRegex(
            ValidationError,
            "resource.subnet_resource_name doit etre un identifiant Terraform valide",
        ):
            app.delete_gcp_network(lambda _: "y")

        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @staticmethod
    def _valid_request() -> DeleteNetworkRequest:
        return DeleteNetworkRequest(
            module_path=str(GCP_NETWORK_OUTPUT.resolve()),
            project_id="example-test-project",
            resource=NetworkDeleteResource(
                resource_name="vpc_delete_test_01",
                subnet_resource_name="subnet_delete_test_01",
            ),
        )


if __name__ == "__main__":
    unittest.main()
