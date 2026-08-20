"""Tests J2 des references credentials et de la redaction."""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
import unittest
from dataclasses import fields
from pathlib import Path
from unittest.mock import patch

import app
from cloud_runtime_models import (
    CredentialProfile,
    CredentialSourceType,
    CredentialStatus,
)
from credential_resolver import resolve_credentials, validate_credentials
from safe_data import REDACTED, redact_sensitive_data
from terraform_runner import TerraformRunner


FAKE_SECRETS = (
    "FAKE_SUPER_SECRET_123",
    "FAKE_PRIVATE_KEY_456",
    "FAKE_TOKEN_789",
    "FAKE_SECRET_J21_123",
)


class CredentialRuntimeTests(unittest.TestCase):
    def test_model_has_no_raw_secret_field(self) -> None:
        names = {field.name for field in fields(CredentialProfile)}
        self.assertTrue({"credential_id", "provider", "auth_mode", "source_type", "reference"} <= names)
        self.assertTrue(
            {"secret", "password", "private_key_content", "token_value"}.isdisjoint(names)
        )

    def test_gcp_adc_and_file_reference_valid_missing(self) -> None:
        adc = CredentialProfile(
            "gcp-adc", "gcp", "ADC", CredentialSourceType.OS_PROFILE, "application-default"
        )
        self.assertEqual(validate_credentials(adc).status, CredentialStatus.VALID)
        with tempfile.TemporaryDirectory() as directory:
            existing = Path(directory) / "gcp-reference.json"
            existing.touch()
            valid = CredentialProfile(
                "gcp-file", "gcp", "SERVICE_ACCOUNT_FILE",
                CredentialSourceType.FILE_REFERENCE, str(existing.resolve()),
            )
            missing = CredentialProfile(
                "gcp-missing", "gcp", "WIF_REFERENCE",
                CredentialSourceType.FILE_REFERENCE, str((existing.parent / "missing.json").resolve()),
            )
            self.assertEqual(validate_credentials(valid).status, CredentialStatus.VALID)
            self.assertEqual(
                resolve_credentials(valid)["GOOGLE_APPLICATION_CREDENTIALS"],
                str(existing.resolve()),
            )
            result = validate_credentials(missing)
            self.assertEqual(result.status, CredentialStatus.MISSING)
            self.assertEqual(result.reason_code, "CRED_FILE_NOT_FOUND")

    def test_oci_api_profile_reference_valid_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "oci-config"
            config.write_text("[EXAMPLE]\nregion=eu-frankfurt-1\n", encoding="utf-8")
            valid = CredentialProfile(
                "oci-profile", "oci", "API_KEY_PROFILE",
                CredentialSourceType.OS_PROFILE, str(config.resolve()), "EXAMPLE",
            )
            missing = CredentialProfile(
                "oci-missing", "oci", "API_KEY_PROFILE",
                CredentialSourceType.OS_PROFILE, str(config.resolve()), "ABSENT",
            )
            self.assertEqual(validate_credentials(valid).status, CredentialStatus.VALID)
            self.assertEqual(resolve_credentials(valid)["OCI_CONFIG_PROFILE"], "EXAMPLE")
            self.assertEqual(validate_credentials(missing).reason_code, "CRED_PROFILE_NOT_FOUND")

    def test_environment_source_is_local_and_ephemeral(self) -> None:
        profile = CredentialProfile(
            "gcp-env", "gcp", "ADC", CredentialSourceType.ENVIRONMENT,
            "GOOGLE_TEST_REFERENCE",
        )
        self.assertEqual(
            validate_credentials(profile, environ={}).reason_code,
            "CRED_ENV_MISSING",
        )

    def test_unsupported_auth_mode_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "CRED_AUTH_MODE_UNSUPPORTED"):
            CredentialProfile(
                "bad", "gcp", "PASSWORD", CredentialSourceType.ENVIRONMENT, "VALUE"
            )

    def test_fake_secrets_are_redacted_from_request_and_reports(self) -> None:
        payload = {
            "provider": "gcp",
            "module": "compute",
            "action": "create",
            "password": FAKE_SECRETS[0],
            "nested": {
                "private_key": FAKE_SECRETS[1],
                "token": FAKE_SECRETS[2],
            },
            "client_secret": FAKE_SECRETS[3],
        }
        report = json.dumps(redact_sensitive_data(payload))
        self.assertIn(REDACTED, report)
        for secret in FAKE_SECRETS:
            self.assertNotIn(secret, report)
        with tempfile.TemporaryDirectory() as directory, patch.object(
            app, "REQUEST_DIRECTORY", Path(directory)
        ):
            request_path = app.save_request(payload)
            request_json = request_path.read_text(encoding="utf-8")
        for secret in FAKE_SECRETS:
            self.assertNotIn(secret, request_json)

    @patch("terraform_runner.subprocess.run")
    @patch("terraform_runner.shutil.which", return_value=r"C:\tools\terraform.exe")
    def test_runner_keeps_credentials_child_only_and_redacts_output(
        self, _which_mock, run_mock
    ) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            [], 1, f"token={FAKE_SECRETS[2]}", f"secret={FAKE_SECRETS[0]}"
        )
        with tempfile.TemporaryDirectory() as directory, self.assertLogs(
            "terraform_runner", logging.INFO
        ) as captured:
            result = TerraformRunner().run(
                ["validate"],
                Path(directory),
                env_overrides={"ACCESS_TOKEN": FAKE_SECRETS[2], "AUTH_VALUE": FAKE_SECRETS[0]},
            )
        child_env = run_mock.call_args.kwargs["env"]
        self.assertEqual(child_env["ACCESS_TOKEN"], FAKE_SECRETS[2])
        self.assertFalse(run_mock.call_args.kwargs["shell"])
        rendered = "\n".join(captured.output) + result.stdout + result.stderr + repr(result.args)
        for secret in FAKE_SECRETS:
            self.assertNotIn(secret, rendered)


if __name__ == "__main__":
    unittest.main()
