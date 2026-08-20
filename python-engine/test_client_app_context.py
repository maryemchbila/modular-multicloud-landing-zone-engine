"""Tests cibles du contexte client/environnement de l'application."""

import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

import app
from go_client import GoClientError, run_generator
from models import ClientContext, GCPContext
from request_builder import build_request


class ClientAppContextTests(unittest.TestCase):
    @patch("builtins.input", side_effect=["example-client", "staging"])
    def test_client_context_is_prompted_once_and_validated(self, input_mock) -> None:
        context = app.ask_client_context()

        self.assertEqual(context.client_id, "example-client")
        self.assertEqual(context.environment, "staging")
        self.assertEqual(input_mock.call_count, 2)

    @patch("builtins.input", side_effect=["../../foo", "dev"])
    def test_invalid_client_is_rejected_before_generation(self, _input_mock) -> None:
        with self.assertRaises(ValueError):
            app.ask_client_context()

    def test_active_context_overrides_legacy_module_path_in_json(self) -> None:
        payload = {
            "provider": "gcp",
            "module": "network",
            "action": "create",
            "module_path": "C:/user-controlled/path",
        }
        context = ClientContext(client_id="client-a", environment="prod")
        token = app.ACTIVE_CLIENT_CONTEXT.set(context)
        try:
            with patch("app.save_request", return_value=Path("request.json")) as save_mock, patch(
                "app.run_generator", return_value="ok"
            ):
                self.assertTrue(app._generate(payload))
        finally:
            app.ACTIVE_CLIENT_CONTEXT.reset(token)

        saved = save_mock.call_args.args[0]
        self.assertEqual(saved["client_id"], "client-a")
        self.assertEqual(saved["environment"], "prod")
        self.assertTrue(
            Path(saved["module_path"]).parts[-7:]
            == ("runtime", "clients", "client-a", "prod", "gcp", "modules", "network")
        )
        self.assertNotIn("user-controlled", saved["module_path"])

    def test_client_aware_compute_builder_has_no_path_prompt(self) -> None:
        prompts: list[str] = []
        answers = iter(["", "", "", "", "", ""])

        def input_fn(prompt: str) -> str:
            prompts.append(prompt)
            return next(answers)

        build_request(
            input_fn,
            gcp_context=GCPContext("example-project"),
            prompt_module_path=False,
        )
        self.assertFalse(any("Dossier Terraform cible" in prompt for prompt in prompts))

    @patch("go_client.subprocess.run")
    def test_go_client_timeout_becomes_controlled_error(self, run_mock) -> None:
        run_mock.side_effect = subprocess.TimeoutExpired(["hcl-generator.exe"], 30)

        with self.assertRaisesRegex(GoClientError, "30 secondes"):
            run_generator(Path("request.json"))

        options = run_mock.call_args.kwargs
        self.assertEqual(options["stdin"], subprocess.DEVNULL)
        self.assertEqual(options["timeout"], 30)


if __name__ == "__main__":
    unittest.main()
