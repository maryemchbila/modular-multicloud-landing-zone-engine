"""Tests du routage et des validations Python Storage Update."""

import unittest
from unittest.mock import patch

import app
from models import StorageResource, UpdateStorageRequest
from request_builder import (
    GCP_STORAGE_OUTPUT,
    _ask_bool,
    ask_gcp_storage_update_parameters,
)
from validators import ValidationError, validate_request


class StorageUpdateTests(unittest.TestCase):
    def test_builder_normalizes_class_and_boolean(self) -> None:
        answers = iter(
            [
                "bucket_test_01",
                "stage2026-storage-production-01",
                "EU",
                "nearline",
                "yes",
                "",
            ]
        )
        request = ask_gcp_storage_update_parameters(lambda _: next(answers))

        self.assertIsInstance(request, UpdateStorageRequest)
        self.assertEqual(request.action, "update")
        self.assertEqual(request.resource.storage_class, "NEARLINE")
        self.assertIs(request.resource.uniform_bucket_level_access, True)
        validate_request(request)

    def test_boolean_parser_accepts_explicit_variants(self) -> None:
        variants = {
            "true": True,
            "yes": True,
            "y": True,
            "1": True,
            "false": False,
            "no": False,
            "n": False,
            "0": False,
        }
        for raw_value, expected in variants.items():
            with self.subTest(raw_value=raw_value):
                self.assertIs(
                    _ask_bool("Uniform access", True, lambda _: raw_value),
                    expected,
                )

    @patch("app.update_gcp_storage")
    def test_dispatch_routes_storage_update(self, update_mock) -> None:
        app.dispatch("gcp", "storage", "update")
        update_mock.assert_called_once_with()

    @patch("app.run_generator")
    @patch("app.save_request")
    @patch("app.ask_gcp_storage_update_parameters")
    def test_invalid_storage_class_does_not_call_go(
        self,
        ask_mock,
        save_mock,
        run_mock,
    ) -> None:
        ask_mock.return_value = UpdateStorageRequest(
            module_path=str(GCP_STORAGE_OUTPUT.resolve()),
            resource=StorageResource(
                resource_name="bucket_test_01",
                name="stage2026-storage-production-01",
                location="EU",
                storage_class="HOTLINE",
                uniform_bucket_level_access=True,
            ),
        )

        with self.assertRaisesRegex(
            ValidationError,
            "resource.storage_class doit valoir",
        ):
            app.update_gcp_storage()

        save_mock.assert_not_called()
        run_mock.assert_not_called()

    @patch("app.run_generator")
    @patch("app.save_request")
    def test_invalid_boolean_does_not_call_go(
        self,
        save_mock,
        run_mock,
    ) -> None:
        answers = iter(
            [
                "bucket_test_01",
                "stage2026-storage-production-01",
                "EU",
                "STANDARD",
                "peut-etre",
                "",
            ]
        )

        with patch(
            "app.ask_gcp_storage_update_parameters",
            side_effect=lambda: ask_gcp_storage_update_parameters(
                lambda _: next(answers)
            ),
        ):
            with self.assertRaisesRegex(ValueError, "doit valoir"):
                app.update_gcp_storage()

        save_mock.assert_not_called()
        run_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
