"""Tests du contrat GCP Compute Create jusqu'au JSON Go."""

from dataclasses import replace
import unittest

from models import GCPContext
from request_builder import GCP_COMPUTE_OUTPUT, build_request
from validators import ValidationError, validate_request


class GCPComputeCreateContractTests(unittest.TestCase):
    def test_build_request_carries_required_project_id_to_json(self) -> None:
        answers = iter(
            (
                "vm_contract_01",
                "vm-contract-01",
                "e2-medium",
                "europe-west1-b",
                "debian-cloud/debian-12",
                "default",
                "",
            )
        )

        request = build_request(
            lambda _prompt: next(answers),
            gcp_context=GCPContext("example-test-project"),
        )
        validate_request(request)

        self.assertEqual(
            request.module_path,
            str(GCP_COMPUTE_OUTPUT.resolve()),
        )
        self.assertEqual(
            request.to_dict()["project_id"],
            "example-test-project",
        )

    def test_create_compute_rejects_missing_project_id(self) -> None:
        answers = iter(("", "", "", "", "", "", ""))
        request = build_request(
            lambda _prompt: next(answers),
            gcp_context=GCPContext("example-test-project"),
        )

        with self.assertRaisesRegex(
            ValidationError,
            "project_id est obligatoire",
        ):
            validate_request(replace(request, project_id=""))


if __name__ == "__main__":
    unittest.main()
