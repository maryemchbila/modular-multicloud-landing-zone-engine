"""Tests du contrat, du routage et de la validation OCI IAM Update."""

import unittest
from pathlib import Path
from unittest.mock import patch

import app
from models import OCIIAMResource, UpdateOCIIAMRequest
from request_builder import OCI_IAM_OUTPUT, ask_oci_iam_update_parameters
from validators import ValidationError, validate_request


class OCIIAMUpdateTests(unittest.TestCase):
    def test_builder_collects_complete_final_state_and_real_list(
        self,
    ) -> None:
        answers = iter(
            [
                "  ocid1.tenancy.oc1..exampleuniqueID  ",
                "  oci_user_observability_01  ",
                "  stage2026-observability-user-prod  ",
                "  Utilisateur OCI de production  ",
                "  oci_group_observability_01  ",
                "  stage2026-observability-group  ",
                "  Groupe OCI de production  ",
                "  oci_membership_observability_01  ",
                "  oci_policy_observability_01  ",
                "  stage2026-observability-policy-prod  ",
                "  Politique OCI de production  ",
                "  ocid1.compartment.oc1..exampleuniqueID  ",
                "2",
                (
                    " Allow group stage2026-observability-group to read "
                    "metrics in compartment stage2026 "
                ),
                (
                    "Allow group stage2026-observability-group to read "
                    "log-groups in compartment stage2026"
                ),
            ]
        )

        request = ask_oci_iam_update_parameters(lambda _: next(answers))

        self.assertIsInstance(request, UpdateOCIIAMRequest)
        self.assertEqual(request.action, "update")
        self.assertEqual(request.provider, "oci")
        self.assertEqual(request.module, "iam")
        self.assertEqual(request.module_path, str(OCI_IAM_OUTPUT.resolve()))
        self.assertEqual(
            request.resource.user_name,
            "stage2026-observability-user-prod",
        )
        self.assertEqual(len(request.resource.policy_statements), 2)
        self.assertIsInstance(
            request.to_dict()["resource"]["policy_statements"],
            list,
        )
        validate_request(request)

    @patch("app.update_oci_iam")
    @patch("builtins.input", side_effect=["2", "example-client", "dev", "4", "2"])
    def test_menu_choices_2_4_2_launch_update(
        self,
        _input_mock,
        update_mock,
    ) -> None:
        self.assertEqual(app.main(), 0)
        update_mock.assert_called_once_with()

    @patch("app.run_generator", return_value="ok")
    @patch("app.save_request", return_value=Path("update-oci-iam.json"))
    @patch("app.ask_oci_iam_update_parameters")
    def test_valid_update_is_saved_then_sent_to_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        request = self._request()
        ask_mock.return_value = request

        app.update_oci_iam()

        save_mock.assert_called_once_with(request.to_dict())
        run_mock.assert_called_once_with(Path("update-oci-iam.json"))

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_oci_iam_update_parameters")
    def test_invalid_update_never_calls_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        invalid_cases = (
            (
                {"tenancy_ocid": "ocid1.compartment.oc1..incorrect"},
                "ocid1.tenancy.",
            ),
            (
                {"policy_compartment_id": "compartment-invalid"},
                "ocid1.tenancy. ou ocid1.compartment.",
            ),
            (
                {
                    "policy_statements": [
                        "Permit group stage2026-observability-group "
                        "to read metrics in compartment stage2026"
                    ]
                },
                "start with 'Allow'",
            ),
            (
                {
                    "group_name": (
                        "stage2026-observability-group-prod"
                    ),
                    "policy_statements": [
                        "Allow group stage2026-observability-group "
                        "to read metrics in compartment stage2026"
                    ],
                },
                "does not target the configured group",
            ),
            (
                {
                    "policy_statements": [
                        "Allow group stage2026-observability-group "
                        "to manage all-resources in tenancy"
                    ]
                },
                "too permissive",
            ),
            (
                {
                    "policy_statements": [
                        "Allow any-user to read object-family in tenancy"
                    ]
                },
                "any-user",
            ),
            ({"policy_statements": []}, "cannot be empty"),
        )
        for changes, expected in invalid_cases:
            with self.subTest(changes=changes):
                ask_mock.return_value = self._request(**changes)
                with self.assertRaisesRegex(ValidationError, expected):
                    app.update_oci_iam()

        save_mock.assert_not_called()
        run_mock.assert_not_called()

    def test_builder_rejects_invalid_statement_count(self) -> None:
        prompt_prefix = [""] * 12
        for count in ("0", "invalid"):
            with self.subTest(count=count):
                answers = iter(prompt_prefix + [count])
                with self.assertRaisesRegex(ValueError, "nombre"):
                    ask_oci_iam_update_parameters(
                        lambda _: next(answers)
                    )

    def test_update_payload_has_no_credentials(self) -> None:
        payload = repr(self._request().to_dict()).casefold()
        for forbidden in (
            "private_key",
            "fingerprint",
            "auth_token",
            "password",
            "smtp",
            "customer_secret",
            "api_key",
            "secret_key",
        ):
            self.assertNotIn(forbidden, payload)

    @classmethod
    def _request(cls, **changes) -> UpdateOCIIAMRequest:
        values = {
            "tenancy_ocid": "ocid1.tenancy.oc1..exampleuniqueID",
            "user_resource_name": "oci_user_observability_01",
            "user_name": "stage2026-observability-user-prod",
            "user_description": "Utilisateur OCI de production",
            "group_resource_name": "oci_group_observability_01",
            "group_name": "stage2026-observability-group",
            "group_description": "Groupe OCI de production",
            "membership_resource_name": (
                "oci_membership_observability_01"
            ),
            "policy_resource_name": "oci_policy_observability_01",
            "policy_name": "stage2026-observability-policy-prod",
            "policy_description": "Politique OCI de production",
            "policy_compartment_id": (
                "ocid1.compartment.oc1..exampleuniqueID"
            ),
            "policy_statements": [
                (
                    "Allow group stage2026-observability-group to read "
                    "metrics in compartment stage2026"
                )
            ],
        }
        values.update(changes)
        return UpdateOCIIAMRequest(
            module_path=str(OCI_IAM_OUTPUT.resolve()),
            resource=OCIIAMResource(**values),
        )


if __name__ == "__main__":
    unittest.main()
