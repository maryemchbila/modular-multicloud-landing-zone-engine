"""Tests J2 du modele et du chargement de configuration client."""

from __future__ import annotations

import copy
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import app
from client_config import (
    ClientConfigError,
    discover_client_config,
    load_client_config,
    select_runtime_configuration,
    validate_client_config,
)
from models import ClientContext


EXAMPLE = (
    Path(__file__).resolve().parent.parent
    / "config"
    / "clients"
    / "examples"
    / "client.example.yaml"
)


def valid_raw() -> dict:
    return {
        "client": {"id": "client-a", "name": "Client A"},
        "environments": {
            "dev": {"enabled": True},
            "staging": {"enabled": True},
            "prod": {"enabled": True},
        },
        "clouds": {
            "gcp": {
                "enabled": True,
                "project_id": "example-project",
                "default_region": "europe-west1",
                "default_zone": "europe-west1-b",
                "credential_profile": "gcp-adc",
            },
            "oci": {
                "enabled": True,
                "region": "eu-frankfurt-1",
                "compartment_ocid": "ocid1.compartment.example",
                "credential_profile": "oci-instance",
            },
        },
        "credential_profiles": {
            "gcp-adc": {
                "provider": "gcp",
                "auth_mode": "ADC",
                "source_type": "OS_PROFILE",
                "reference": "application-default",
            },
            "oci-instance": {
                "provider": "oci",
                "auth_mode": "INSTANCE_PRINCIPAL",
                "source_type": "EPHEMERAL_SESSION",
                "reference": "instance-principal",
            },
        },
        "state": {
            "mode": "remote",
            "backend_profile": {"gcp": "gcp-state", "oci": "oci-state"},
        },
        "state_profiles": {
            "gcp-state": {
                "provider": "gcp",
                "backend_type": "gcs",
                "bucket": "example-state-bucket",
                "credential_profile": "gcp-adc",
            },
            "oci-state": {
                "provider": "oci",
                "backend_type": "oci",
                "bucket": "example-state-bucket",
                "namespace": "example-namespace",
                "region": "eu-frankfurt-1",
                "credential_profile": "oci-instance",
            },
        },
        "security": {"profile": "BASELINE"},
        "governance": {
            "apply_requires_approval": True,
            "destroy_requires_approval": True,
            "production_destroy_enabled": False,
        },
    }


class ClientConfigurationTests(unittest.TestCase):
    def test_example_client_is_discovered_by_id_not_filename(self) -> None:
        discovered = discover_client_config("example-client")
        self.assertEqual(discovered, EXAMPLE.resolve())
        self.assertNotEqual(discovered.name, "example-client.yaml")

    def test_discovery_rejects_two_configs_with_same_client_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            examples = root / "examples"
            examples.mkdir()
            content = EXAMPLE.read_text(encoding="utf-8")
            (examples / "first.yaml").write_text(content, encoding="utf-8")
            (examples / "second.yaml").write_text(content, encoding="utf-8")
            with patch("client_config.CLIENT_CONFIG_ROOT", root), self.assertRaisesRegex(
                ClientConfigError, "CLIENT_CONFIG_AMBIGUOUS"
            ):
                discover_client_config("example-client")

    def test_versioned_example_loads_and_selects_gcp(self) -> None:
        config = load_client_config(EXAMPLE, runtime_client_id="example-client")
        selected = select_runtime_configuration(
            config, "dev", "gcp", terraform_version="1.15.7"
        )
        self.assertEqual(config.client_id, "example-client")
        self.assertEqual(selected.cloud["project_id"], "example-project")
        self.assertEqual(selected.credential_profile.credential_id, "gcp-example")
        self.assertEqual(selected.state_profile.state_profile_id, "gcp-example-state")

    def test_runtime_client_must_match_config(self) -> None:
        with self.assertRaisesRegex(ClientConfigError, "CLIENT_ID_RUNTIME_MISMATCH"):
            validate_client_config(valid_raw(), runtime_client_id="client-b")

    def test_invalid_client_unknown_environment_and_provider_fail(self) -> None:
        mutations = []
        invalid_client = valid_raw()
        invalid_client["client"]["id"] = "../../client"
        mutations.append((invalid_client, "CLIENT_ID_INVALID"))
        unknown_environment = valid_raw()
        unknown_environment["environments"]["qa"] = {"enabled": True}
        mutations.append((unknown_environment, "UNKNOWN_ENVIRONMENT"))
        unknown_provider = valid_raw()
        unknown_provider["clouds"]["aws"] = copy.deepcopy(
            unknown_provider["clouds"]["gcp"]
        )
        mutations.append((unknown_provider, "UNKNOWN_PROVIDER"))
        for raw, reason in mutations:
            with self.subTest(reason=reason), self.assertRaisesRegex(
                ClientConfigError, reason
            ):
                validate_client_config(raw)

    def test_missing_credential_and_state_profiles_fail(self) -> None:
        missing_credential = valid_raw()
        missing_credential["clouds"]["gcp"]["credential_profile"] = "missing"
        missing_state = valid_raw()
        missing_state["state"]["backend_profile"]["gcp"] = "missing"
        for raw, reason in (
            (missing_credential, "CREDENTIAL_PROFILE_NOT_FOUND"),
            (missing_state, "STATE_PROFILE_NOT_FOUND"),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex(
                ClientConfigError, reason
            ):
                validate_client_config(raw)

    def test_duplicate_cloud_config_is_rejected_before_dict_creation(self) -> None:
        yaml = """client:\n  id: client-a\n  name: A\nclouds:\n  gcp:\n    enabled: true\n  gcp:\n    enabled: true\n"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.yaml"
            path.write_text(yaml, encoding="utf-8")
            with self.assertRaisesRegex(ClientConfigError, "YAML_DUPLICATE_KEY"):
                load_client_config(path)

    def test_duplicate_json_cloud_config_is_rejected(self) -> None:
        payload = '{"clouds":{"gcp":{},"gcp":{}}}'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text(payload, encoding="utf-8")
            with self.assertRaisesRegex(ClientConfigError, "JSON_DUPLICATE_KEY"):
                load_client_config(path)

    def test_raw_secret_fields_are_forbidden(self) -> None:
        for field in ("password", "client_secret", "private_key_content", "token_value"):
            raw = valid_raw()
            raw["credential_profiles"]["gcp-adc"][field] = "forbidden"
            with self.subTest(field=field), self.assertRaisesRegex(
                ClientConfigError, "SENSITIVE_FIELD_FORBIDDEN"
            ):
                validate_client_config(raw)

    def test_user_supplied_final_state_prefix_is_rejected(self) -> None:
        raw = valid_raw()
        raw["state_profiles"]["gcp-state"]["prefix"] = "../../state"
        with self.assertRaisesRegex(
            ClientConfigError, "STATE_PROFILE_FIELD_UNSUPPORTED"
        ):
            validate_client_config(raw)

    def test_app_loads_profiles_and_prints_only_safe_summary(self) -> None:
        output = io.StringIO()
        context = ClientContext(client_id="example-client", environment="dev")
        with patch("app.discover_client_config", return_value=EXAMPLE), patch(
            "app.detect_terraform_version", return_value="1.15.7"
        ), patch("app.write_backend_runtime_files") as write_mock:
            selection = app.load_client_runtime(context, "gcp")
            self.assertIsNotNone(selection)
            selection = replace(
                selection,  # type: ignore[arg-type]
                cloud={
                    **selection.cloud,  # type: ignore[union-attr]
                    "client_secret": "FAKE_SECRET_J21_123",
                },
            )
            with redirect_stdout(output):
                app.print_client_runtime_summary(selection)
        write_mock.assert_called_once()
        rendered = output.getvalue()
        for expected in (
            "example-client",
            "example-project",
            "gcp-example",
            "clients/example-client/dev/gcp/terraform.tfstate",
        ):
            self.assertIn(expected, rendered)
        self.assertNotIn("reference", rendered.casefold())
        self.assertNotIn("C:\\secure", rendered)
        self.assertNotIn("FAKE_SECRET_J21_123", rendered)

    def test_real_main_flow_uses_config_before_module_and_never_prompts_project(
        self,
    ) -> None:
        output = io.StringIO()
        context = ClientContext(client_id="example-client", environment="dev")

        def choose_module_after_summary() -> str:
            rendered = output.getvalue()
            self.assertIn("CLIENT CLOUD RUNTIME", rendered)
            self.assertIn("Runtime Mode           : CONFIG_MODE", rendered)
            self.assertIn("Credential Profile     : gcp-example", rendered)
            self.assertIn("Credential Status      : VALID", rendered)
            self.assertIn("Backend Type           : gcs", rendered)
            self.assertIn(
                "clients/example-client/dev/gcp/terraform.tfstate",
                rendered,
            )
            return "compute"

        with patch("app.choose_provider", return_value="gcp"), patch(
            "app.ask_client_context", return_value=context
        ), patch("app.detect_terraform_version", return_value="1.15.7"), patch(
            "app.write_backend_runtime_files"
        ), patch("app.ask_gcp_context") as project_prompt, patch(
            "app.choose_module", side_effect=choose_module_after_summary
        ), patch("app.choose_action", return_value="create"), patch(
            "app.dispatch", return_value=False
        ), redirect_stdout(output):
            self.assertEqual(app.main(), 0)

        project_prompt.assert_not_called()
        rendered = output.getvalue()
        self.assertIn("Projet GCP cible : example-project", rendered)
        self.assertLess(
            rendered.index("CLIENT CLOUD RUNTIME"),
            rendered.index("Generation : NOT_RUN"),
        )

    def test_invalid_credential_allows_offline_generation_but_skips_governance(
        self,
    ) -> None:
        output = io.StringIO()
        context = ClientContext(client_id="example-client", environment="dev")
        with patch("app.choose_provider", return_value="oci"), patch(
            "app.ask_client_context", return_value=context
        ), patch("app.detect_terraform_version", return_value="1.15.7"), patch(
            "app.write_backend_runtime_files"
        ), patch("app.choose_module", return_value="compute"), patch(
            "app.choose_action", return_value="create"
        ), patch("app.dispatch", return_value=True), patch(
            "app.run_governance_after_generation"
        ) as governance_mock, redirect_stdout(output):
            self.assertEqual(app.main(), 0)

        governance_mock.assert_not_called()
        rendered = output.getvalue()
        self.assertIn("Credential Status      : MISSING", rendered)
        self.assertIn("Reason                 : CRED_PROFILE_NOT_FOUND", rendered)
        self.assertIn("offline HCL generation remains available", rendered)
        self.assertIn("Governance : NOT_RUN_CREDENTIAL_INVALID", rendered)


if __name__ == "__main__":
    unittest.main()
