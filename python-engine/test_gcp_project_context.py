"""Tests du contexte GCP partage entre CLI, requests et generateur Go."""

from dataclasses import replace
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import app
from models import GCPContext
from request_builder import (
    ask_gcp_compute_delete_parameters,
    ask_gcp_compute_update_parameters,
    ask_gcp_iam_delete_parameters,
    ask_gcp_iam_parameters,
    ask_gcp_iam_update_parameters,
    ask_gcp_network_delete_parameters,
    ask_gcp_network_parameters,
    ask_gcp_network_update_parameters,
    ask_gcp_storage_delete_parameters,
    ask_gcp_storage_parameters,
    ask_gcp_storage_update_parameters,
    build_request,
)
from validators import ValidationError, validate_request


class GCPProjectContextTests(unittest.TestCase):
    PROJECT_ID = "example-test-project"

    def test_all_gcp_requests_carry_shared_project_id(self) -> None:
        context = GCPContext(self.PROJECT_ID)
        builders = (
            build_request,
            ask_gcp_compute_update_parameters,
            ask_gcp_compute_delete_parameters,
            ask_gcp_network_parameters,
            ask_gcp_network_update_parameters,
            ask_gcp_network_delete_parameters,
            ask_gcp_storage_parameters,
            ask_gcp_storage_update_parameters,
            ask_gcp_storage_delete_parameters,
            ask_gcp_iam_parameters,
            ask_gcp_iam_update_parameters,
            ask_gcp_iam_delete_parameters,
        )

        for builder in builders:
            with self.subTest(builder=builder.__name__), redirect_stdout(
                io.StringIO()
            ):
                request = builder(
                    lambda _prompt: "",
                    gcp_context=context,
                )
                validate_request(request)
                self.assertEqual(request.project_id, self.PROJECT_ID)
                self.assertEqual(
                    request.to_dict()["project_id"],
                    self.PROJECT_ID,
                )
                if request.module == "iam" and request.action != "delete":
                    self.assertEqual(
                        request.resource.project_id,
                        self.PROJECT_ID,
                    )

    def test_all_gcp_requests_reject_missing_project_id(self) -> None:
        context = GCPContext(self.PROJECT_ID)
        builders = (
            build_request,
            ask_gcp_compute_update_parameters,
            ask_gcp_compute_delete_parameters,
            ask_gcp_network_parameters,
            ask_gcp_network_update_parameters,
            ask_gcp_network_delete_parameters,
            ask_gcp_storage_parameters,
            ask_gcp_storage_update_parameters,
            ask_gcp_storage_delete_parameters,
            ask_gcp_iam_parameters,
            ask_gcp_iam_update_parameters,
            ask_gcp_iam_delete_parameters,
        )

        for builder in builders:
            with self.subTest(builder=builder.__name__), redirect_stdout(
                io.StringIO()
            ):
                request = builder(
                    lambda _prompt: "",
                    gcp_context=context,
                )
                with self.assertRaisesRegex(
                    ValidationError,
                    "project_id est obligatoire",
                ):
                    validate_request(replace(request, project_id=""))

    def test_cli_collects_context_once_before_module_and_routes_all_modules(
        self,
    ) -> None:
        context = GCPContext(self.PROJECT_ID)
        for module in ("compute", "network", "storage", "iam"):
            events: list[str] = []
            output = io.StringIO()
            with self.subTest(module=module), patch(
                "app.choose_provider",
                side_effect=lambda: events.append("provider") or "gcp",
            ), patch(
                "app.ask_gcp_context",
                side_effect=lambda: events.append("context") or context,
            ) as context_mock, patch(
                "app.choose_module",
                side_effect=lambda: events.append("module") or module,
            ), patch(
                "app.choose_action",
                side_effect=lambda: events.append("action") or "create",
            ), patch(
                "app.dispatch",
                side_effect=lambda *_args, **_kwargs: events.append("dispatch")
                or False,
            ) as dispatch_mock, redirect_stdout(output):
                self.assertEqual(app.main(), 0)

            context_mock.assert_called_once_with()
            dispatch_mock.assert_called_once_with(
                "gcp",
                module,
                "create",
                gcp_context=context,
            )
            self.assertEqual(
                events,
                ["provider", "context", "module", "action", "dispatch"],
            )
            self.assertIn(
                f"Projet GCP cible : {self.PROJECT_ID}",
                output.getvalue(),
            )

    def test_iam_resource_project_matches_shared_context(self) -> None:
        with redirect_stdout(io.StringIO()):
            request = ask_gcp_iam_parameters(
                lambda _prompt: "",
                gcp_context=GCPContext(self.PROJECT_ID),
            )
        mismatched = replace(
            request,
            resource=replace(request.resource, project_id="another-project"),
        )
        with self.assertRaisesRegex(
            ValidationError,
            "doit correspondre au contexte GCP project_id",
        ):
            validate_request(mismatched)


if __name__ == "__main__":
    unittest.main()
