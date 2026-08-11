"""Tests du contrat, du routage et de la validation OCI IAM Create."""

import unittest
from pathlib import Path
from unittest.mock import patch

import app
from models import CreateOCIIAMRequest, OCIIAMResource
from request_builder import OCI_IAM_OUTPUT, ask_oci_iam_create_parameters
from validators import ValidationError, validate_request


class OCIIAMCreateTests(unittest.TestCase):
    def test_builder_preserves_statement_list_and_normalizes_strings(
        self,
    ) -> None:
        answers = iter(
            [
                "  ocid1.tenancy.oc1..exampleuniqueID  ",
                "  oci_user_observability_01  ",
                "  stage2026-observability-user  ",
                "  Utilisateur OCI d'observabilite  ",
                "  oci_group_observability_01  ",
                "  stage2026-observability-group  ",
                "  Groupe OCI d'observabilite  ",
                "  oci_membership_observability_01  ",
                "  oci_policy_observability_01  ",
                "  stage2026-observability-policy  ",
                "  Politique OCI minimale  ",
                "  ocid1.compartment.oc1..exampleuniqueID  ",
                "2",
                (
                    "  Allow group stage2026-observability-group to read "
                    "metrics in compartment stage2026  "
                ),
                (
                    "Allow group stage2026-observability-group to read "
                    "log-groups in compartment stage2026"
                ),
            ]
        )

        request = ask_oci_iam_create_parameters(lambda _: next(answers))

        self.assertIsInstance(request, CreateOCIIAMRequest)
        self.assertEqual(request.module_path, str(OCI_IAM_OUTPUT.resolve()))
        self.assertEqual(
            request.resource.user_resource_name,
            "oci_user_observability_01",
        )
        self.assertEqual(len(request.resource.policy_statements), 2)
        self.assertIsInstance(
            request.to_dict()["resource"]["policy_statements"],
            list,
        )
        self.assertTrue(
            request.resource.policy_statements[0].startswith("Allow group")
        )
        validate_request(request)

    @patch("app.create_oci_iam")
    @patch("builtins.input", side_effect=["2", "4", "1"])
    def test_menu_choices_2_4_1_launch_create(
        self,
        _input_mock,
        create_mock,
    ) -> None:
        self.assertEqual(app.main(), 0)
        create_mock.assert_called_once_with()

    @patch("app.run_generator", return_value="ok")
    @patch("app.save_request", return_value=Path("create-oci-iam.json"))
    @patch("app.ask_oci_iam_create_parameters")
    def test_valid_request_is_saved_then_sent_to_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        request = self._request()
        ask_mock.return_value = request

        app.create_oci_iam()

        save_mock.assert_called_once_with(request.to_dict())
        run_mock.assert_called_once_with(Path("create-oci-iam.json"))

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_oci_iam_create_parameters")
    def test_invalid_requests_are_never_saved_or_sent_to_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        valid_statement = self._statement()
        invalid_cases = (
            (
                {"tenancy_ocid": "ocid1.compartment.oc1..invalid"},
                "ocid1.tenancy.",
            ),
            (
                {"policy_compartment_id": "ocid1.user.oc1..invalid"},
                "ocid1.tenancy. ou ocid1.compartment.",
            ),
            ({"policy_statements": []}, "at least one"),
            ({"policy_statements": ["  "]}, "empty values"),
            (
                {
                    "policy_statements": [
                        "Permit group stage2026-observability-group "
                        "to read metrics in tenancy"
                    ]
                },
                "start with 'Allow'",
            ),
            (
                {
                    "policy_statements": [
                        "Allow group another-group to read metrics in tenancy"
                    ]
                },
                "configured group",
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
                        "Allow any-user to read objects in tenancy"
                    ]
                },
                "any-user",
            ),
            (
                {"policy_statements": [valid_statement, valid_statement]},
                "duplicates",
            ),
            ({"user_resource_name": "oci-user-01"}, "identifiant Terraform"),
            ({"group_resource_name": "01_oci_group"}, "identifiant Terraform"),
            (
                {"membership_resource_name": "oci membership"},
                "identifiant Terraform",
            ),
            (
                {"policy_resource_name": "oci-policy-01"},
                "identifiant Terraform",
            ),
        )
        for changes, expected in invalid_cases:
            with self.subTest(changes=changes):
                ask_mock.return_value = self._request(**changes)
                with self.assertRaisesRegex(ValidationError, expected):
                    app.create_oci_iam()

        save_mock.assert_not_called()
        run_mock.assert_not_called()

    def test_duplicate_logical_identifiers_are_rejected(self) -> None:
        request = self._request(
            policy_resource_name="oci_user_observability_01"
        )
        with self.assertRaisesRegex(
            ValidationError,
            "doivent etre differents",
        ):
            validate_request(request)

    def test_wrong_path_and_non_create_actions_are_rejected(self) -> None:
        request = self._request(
            module_path=str(
                OCI_IAM_OUTPUT.resolve().parent / "compute"
            )
        )
        with self.assertRaisesRegex(
            ValidationError,
            "generated/oci/modules/iam",
        ):
            validate_request(request)

        for action in ("update", "delete"):
            with self.subTest(action=action):
                request = CreateOCIIAMRequest(
                    module_path=str(OCI_IAM_OUTPUT.resolve()),
                    resource=self._request().resource,
                    action=action,
                )
                with self.assertRaisesRegex(
                    ValidationError,
                    "action doit valoir 'create'",
                ):
                    validate_request(request)

    def test_builder_rejects_invalid_statement_count(self) -> None:
        prefix = [
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
        ]
        for count in ("0", "not-a-number"):
            with self.subTest(count=count):
                answers = iter(prefix + [count])
                with self.assertRaisesRegex(ValueError, "nombre"):
                    ask_oci_iam_create_parameters(
                        lambda _: next(answers)
                    )

    def test_payload_contains_no_credential_fields(self) -> None:
        payload_text = repr(self._request().to_dict()).casefold()
        for forbidden in (
            "private_key",
            "fingerprint",
            "auth_token",
            "password",
            "smtp",
            "customer_secret",
            "secret_key",
            "api_key",
        ):
            self.assertNotIn(forbidden, payload_text)

    @staticmethod
    def _statement() -> str:
        return (
            "Allow group stage2026-observability-group to read metrics "
            "in compartment stage2026"
        )

    @classmethod
    def _request(cls, **changes) -> CreateOCIIAMRequest:
        module_path = changes.pop(
            "module_path",
            str(OCI_IAM_OUTPUT.resolve()),
        )
        values = {
            "tenancy_ocid": "ocid1.tenancy.oc1..exampleuniqueID",
            "user_resource_name": "oci_user_observability_01",
            "user_name": "stage2026-observability-user",
            "user_description": "Utilisateur OCI d'observabilite",
            "group_resource_name": "oci_group_observability_01",
            "group_name": "stage2026-observability-group",
            "group_description": "Groupe OCI d'observabilite",
            "membership_resource_name": (
                "oci_membership_observability_01"
            ),
            "policy_resource_name": "oci_policy_observability_01",
            "policy_name": "stage2026-observability-policy",
            "policy_description": "Politique OCI minimale",
            "policy_compartment_id": (
                "ocid1.compartment.oc1..exampleuniqueID"
            ),
            "policy_statements": [cls._statement()],
        }
        values.update(changes)
        return CreateOCIIAMRequest(
            module_path=module_path,
            resource=OCIIAMResource(**values),
        )


if __name__ == "__main__":
    unittest.main()
