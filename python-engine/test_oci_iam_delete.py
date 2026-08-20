"""Tests du contrat, de la confirmation et du routage OCI IAM Delete."""

import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import app
from models import DeleteOCIIAMRequest, OCIIAMDeleteResource
from request_builder import OCI_IAM_OUTPUT, ask_oci_iam_delete_parameters
from validators import ValidationError, validate_request


class OCIIAMDeleteTests(unittest.TestCase):
    def test_builder_creates_minimal_trimmed_request(self) -> None:
        answers = iter(
            [
                "  oci_user_delete_test_01  ",
                "  oci_group_delete_test_01  ",
                "  oci_membership_delete_test_01  ",
                "  oci_policy_delete_test_01  ",
            ]
        )

        request = ask_oci_iam_delete_parameters(lambda _: next(answers))

        self.assertIsInstance(request, DeleteOCIIAMRequest)
        self.assertEqual(request.action, "delete")
        self.assertEqual(request.provider, "oci")
        self.assertEqual(request.module, "iam")
        self.assertEqual(request.module_path, str(OCI_IAM_OUTPUT.resolve()))
        self.assertEqual(
            set(request.to_dict()["resource"]),
            {
                "user_resource_name",
                "group_resource_name",
                "membership_resource_name",
                "policy_resource_name",
            },
        )
        validate_request(request)

    @patch("app.delete_oci_iam")
    @patch("builtins.input", side_effect=["2", "example-client", "dev", "4", "3"])
    def test_menu_choices_2_4_3_launch_delete(
        self,
        _input_mock,
        delete_mock,
    ) -> None:
        self.assertEqual(app.main(), 0)
        delete_mock.assert_called_once_with()

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_oci_iam_delete_parameters")
    def test_cancellation_does_not_save_or_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = self._request()
        answers = iter(["n"])
        output = io.StringIO()

        with redirect_stdout(output):
            app.delete_oci_iam(lambda _: next(answers))

        self.assertIn("Suppression annulee.", output.getvalue())
        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @patch("app.run_generator", return_value="ok")
    @patch("app.save_request", return_value=Path("delete-oci-iam.json"))
    @patch("app.ask_oci_iam_delete_parameters")
    def test_confirmation_variants_call_go_and_show_local_only_message(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        for confirmation in ("y", "yes", "oui", "o"):
            with self.subTest(confirmation=confirmation):
                ask_mock.reset_mock()
                save_mock.reset_mock()
                run_mock.reset_mock()
                request = self._request()
                ask_mock.return_value = request
                answers = iter([confirmation])
                output = io.StringIO()

                with redirect_stdout(output):
                    app.delete_oci_iam(lambda _: next(answers))

                text = output.getvalue()
                membership = request.resource.membership_resource_name
                policy = request.resource.policy_resource_name
                user = request.resource.user_resource_name
                group = request.resource.group_resource_name
                expected_order = [
                    f"oci_identity_user_group_membership.{membership}",
                    f"oci_identity_policy.{policy}",
                    f"oci_identity_user.{user}",
                    f"oci_identity_group.{group}",
                ]
                positions = [text.index(item) for item in expected_order]
                self.assertEqual(positions, sorted(positions))
                self.assertIn(
                    "Terraform OCI IAM code deleted locally. "
                    "No OCI identity or policy was destroyed.",
                    text,
                )
                save_mock.assert_called_once_with(request.to_dict())
                run_mock.assert_called_once_with(
                    Path("delete-oci-iam.json")
                )

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_oci_iam_delete_parameters")
    def test_invalid_identifiers_never_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        invalid_cases = (
            ({"user_resource_name": ""}, "user_resource_name"),
            (
                {"group_resource_name": "oci-group-delete"},
                "identifiant Terraform OCI IAM",
            ),
            (
                {"membership_resource_name": "01_membership"},
                "identifiant Terraform OCI IAM",
            ),
            (
                {"policy_resource_name": "oci policy delete"},
                "identifiant Terraform OCI IAM",
            ),
        )
        for changes, expected in invalid_cases:
            with self.subTest(changes=changes):
                ask_mock.return_value = self._request(**changes)
                with self.assertRaisesRegex(ValidationError, expected):
                    app.delete_oci_iam(lambda _: "y")

        save_mock.assert_not_called()
        run_mock.assert_not_called()

    def test_payload_contains_no_non_identifier_or_secret_fields(self) -> None:
        payload = self._request().to_dict()["resource"]
        self.assertEqual(len(payload), 4)
        serialized = repr(payload).casefold()
        for forbidden in (
            "ocid",
            "description",
            "statement",
            "private_key",
            "fingerprint",
            "auth_token",
            "password",
            "smtp",
            "customer_secret",
            "api_key",
            "secret_key",
        ):
            self.assertNotIn(forbidden, serialized)

    @staticmethod
    def _request(**changes) -> DeleteOCIIAMRequest:
        values = {
            "user_resource_name": "oci_user_delete_test_01",
            "group_resource_name": "oci_group_delete_test_01",
            "membership_resource_name": (
                "oci_membership_delete_test_01"
            ),
            "policy_resource_name": "oci_policy_delete_test_01",
        }
        values.update(changes)
        return DeleteOCIIAMRequest(
            module_path=str(OCI_IAM_OUTPUT.resolve()),
            resource=OCIIAMDeleteResource(**values),
        )


if __name__ == "__main__":
    unittest.main()
