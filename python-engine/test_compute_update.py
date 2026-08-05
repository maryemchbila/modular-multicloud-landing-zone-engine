"""Tests du routage et du contrat Python Compute Update."""

import unittest
from unittest.mock import patch

import app
from models import UpdateVMRequest, VMResource
from request_builder import (
    GCP_COMPUTE_OUTPUT,
    ask_gcp_compute_update_parameters,
)
from validators import ValidationError, validate_request


class ComputeUpdateTests(unittest.TestCase):
    def test_builder_creates_complete_update_request(self) -> None:
        answers = iter(
            [
                "vm_clean_test_01",
                "vm-clean-prod-01",
                "e2-standard-4",
                "europe-west1-b",
                "debian-cloud/debian-12",
                "default",
                "",
            ]
        )
        request = ask_gcp_compute_update_parameters(lambda _: next(answers))

        self.assertIsInstance(request, UpdateVMRequest)
        self.assertEqual(request.action, "update")
        self.assertEqual(request.resource.resource_name, "vm_clean_test_01")
        self.assertEqual(request.resource.name, "vm-clean-prod-01")
        validate_request(request)

    def test_update_requires_valid_resource_name(self) -> None:
        request = UpdateVMRequest(
            module_path=str(GCP_COMPUTE_OUTPUT.resolve()),
            resource=VMResource(
                resource_name="",
                name="vm-clean-prod-01",
                machine_type="e2-standard-4",
                zone="europe-west1-b",
                image="debian-cloud/debian-12",
                network="default",
            ),
        )

        with self.assertRaisesRegex(
            ValidationError,
            "resource.resource_name est obligatoire",
        ):
            validate_request(request)

    @patch("app.update_gcp_compute")
    def test_dispatch_routes_compute_update(self, update_mock) -> None:
        app.dispatch("gcp", "compute", "update")
        update_mock.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
