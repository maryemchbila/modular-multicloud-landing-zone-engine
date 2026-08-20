"""Tests J2 d'isolation et de configuration des backends."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cloud_runtime_models import StateProfile
from state_config import (
    build_backend_configuration,
    build_state_identity,
    supports_oci_native_backend,
    write_backend_runtime_files,
)


class StateConfigurationTests(unittest.TestCase):
    def test_all_client_environment_provider_identities_are_distinct(self) -> None:
        identities = {
            build_state_identity("client-a", "dev", "gcp"),
            build_state_identity("client-a", "staging", "gcp"),
            build_state_identity("client-b", "dev", "gcp"),
            build_state_identity("client-a", "dev", "oci"),
        }
        self.assertEqual(len(identities), 4)

    def test_state_path_traversal_is_rejected(self) -> None:
        for client, environment in (("../../state", "dev"), ("client-a", "../prod")):
            with self.subTest(client=client, environment=environment), self.assertRaises(ValueError):
                build_state_identity(client, environment, "gcp")

    def test_gcs_prefix_is_calculated_and_contains_full_identity(self) -> None:
        profile = StateProfile(
            "gcp-state", "gcp", "gcs", bucket="existing-bucket",
            credential_profile="gcp-credential", locking_expected=True,
            versioning_expected=True,
        )
        backend = build_backend_configuration(
            profile, "client-a", "dev", "gcp", terraform_version="1.15.7"
        )
        self.assertEqual(backend.values["prefix"], "clients/client-a/dev/gcp")
        self.assertEqual(backend.backend_type, "gcs")
        self.assertNotIn("credential", backend.backend_hcl.casefold())
        self.assertNotIn("credential", repr(backend.values).casefold())

    def test_oci_native_backend_version_gate_is_explicit(self) -> None:
        profile = StateProfile(
            "oci-state", "oci", "oci", bucket="existing-bucket",
            namespace="example-namespace", region="eu-frankfurt-1",
        )
        unavailable = build_backend_configuration(
            profile, "client-a", "dev", "oci", terraform_version="1.11.9"
        )
        available = build_backend_configuration(
            profile, "client-a", "dev", "oci", terraform_version="1.12.0"
        )
        self.assertFalse(unavailable.native_backend_available)
        self.assertEqual(unavailable.reason, "TERRAFORM_VERSION_LT_1_12")
        self.assertEqual(unavailable.values, {})
        self.assertTrue(available.native_backend_available)
        self.assertEqual(available.values["key"], "clients/client-a/dev/oci/terraform.tfstate")
        self.assertTrue(supports_oci_native_backend("Terraform v1.15.7"))

    def test_local_mode_and_runtime_files_remain_non_sensitive(self) -> None:
        profile = StateProfile("local-gcp", "gcp", "local")
        backend = build_backend_configuration(
            profile, "client-a", "dev", "gcp", terraform_version="1.15.7"
        )
        self.assertEqual(backend.values, {"path": "terraform.tfstate"})
        with tempfile.TemporaryDirectory() as directory, patch(
            "state_config.build_client_root", return_value=Path(directory)
        ):
            backend_file, runtime_file = write_backend_runtime_files(
                backend, "client-a", "dev", "gcp"
            )
            content = backend_file.read_text(encoding="utf-8") + runtime_file.read_text(encoding="utf-8")
        self.assertIn('backend "local"', content)
        for forbidden in (
            "password",
            "private_key",
            "FAKE_SUPER_SECRET_123",
            "FAKE_SECRET_J21_123",
        ):
            self.assertNotIn(forbidden, content)


if __name__ == "__main__":
    unittest.main()
