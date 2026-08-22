import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID
from unittest.mock import patch

from cloud_runtime_models import CredentialProfile, CredentialSourceType, StateProfile
from client_config import ClientRuntimeSelection
from saved_plan import SavedPlan, SavedPlanError, SavedPlanLifecycle, sha256_file
from state_config import BackendRuntimeConfiguration
from terraform_models import TerraformPlanStatus


CREATED = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)


def selection(client_id="client-a", environment="dev"):
    credential = CredentialProfile(
        "gcp-adc", "gcp", "ADC", CredentialSourceType.OS_PROFILE,
        "application-default",
    )
    state = StateProfile("gcp-state", "gcp", "local")
    backend = BackendRuntimeConfiguration(
        "local", f"clients/{client_id}/{environment}/gcp/terraform.tfstate",
        'terraform { backend "local" {} }\n', {"path": "terraform.tfstate"},
    )
    return ClientRuntimeSelection(
        client_id, environment, "gcp", {"project_id": "example-project"},
        credential, "VALID", "CRED_VALID", state, "local",
        backend.state_identity, backend,
    )


class FakePlanPipeline:
    def __init__(self, exit_code=2, content=b"approved-plan"):
        self.exit_code = exit_code
        self.content = content
        self.calls = []

    def run(self, cloud, plan_output_path=None, **kwargs):
        self.calls.append((cloud, Path(plan_output_path), kwargs))
        if self.exit_code in (0, 2):
            Path(plan_output_path).write_bytes(self.content)
        return SimpleNamespace(
            plan_status=(TerraformPlanStatus.NO_CHANGES if self.exit_code == 0
                         else TerraformPlanStatus.CHANGES_DETECTED
                         if self.exit_code == 2 else TerraformPlanStatus.ERROR),
            report=SimpleNamespace(run_id="tfplan_gcp_20260822T120000Z_deadbeef",
                                   add_count=1, change_count=0, destroy_count=0),
        )


class SavedPlanTests(unittest.TestCase):
    def test_hash_is_streamed_and_changes_with_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.tfplan"
            path.write_bytes(b"same")
            first = sha256_file(path)
            self.assertEqual(first, hashlib.sha256(b"same").hexdigest())
            path.write_bytes(b"changed")
            self.assertNotEqual(first, sha256_file(path))

    def test_model_rejects_invalid_hash_and_unsafe_path(self):
        values = dict(
            plan_id="plan_20260822T120000Z_deadbeef", plan_kind="DEPLOYMENT",
            plan_path=Path("/tmp/plans/plan_20260822T120000Z_deadbeef/approved.tfplan"),
            plan_sha256="0" * 64, client_id="client-a", environment="dev",
            provider="gcp", state_profile_id="gcp-state", backend_type="local",
            state_identity="clients/client-a/dev/gcp/terraform.tfstate",
            working_directory=Path("/tmp"), created_at="2026-08-22T12:00:00Z",
            expires_at="2026-08-22T12:30:00Z",
        )
        with self.assertRaises(SavedPlanError):
            SavedPlan(**{**values, "plan_sha256": "bad"})
        with self.assertRaises(SavedPlanError):
            SavedPlan(**{**values, "plan_path": Path("/tmp/other.tfplan")})

    def test_creates_exact_runtime_artifact_with_state_binding_and_safe_metadata(self):
        pipeline = FakePlanPipeline(exit_code=2)
        with tempfile.TemporaryDirectory() as directory, patch(
            "saved_plan.build_client_root", return_value=Path(directory)
        ):
            saved = SavedPlanLifecycle(
                pipeline, now_factory=lambda: CREATED,
                uuid_factory=lambda: UUID("deadbeef-dead-beef-dead-beefdeadbeef"),
            ).create(selection())
            self.assertEqual(pipeline.calls[0][1], saved.plan_path)
            self.assertEqual(pipeline.calls[0][2]["working_directory"], Path(directory).resolve())
            self.assertEqual(saved.plan_sha256, sha256_file(saved.plan_path))
            self.assertEqual(saved.state_profile_id, "gcp-state")
            metadata = json.loads(saved.plan_path.with_name("metadata.json").read_text())
            self.assertNotIn("stdout", metadata)
            self.assertNotIn("credentials", json.dumps(metadata).casefold())
            self.assertEqual(metadata["plan_sha256"], saved.plan_sha256)

    def test_failed_plan_leaves_no_usable_artifact(self):
        pipeline = FakePlanPipeline(exit_code=1)
        with tempfile.TemporaryDirectory() as directory, patch(
            "saved_plan.build_client_root", return_value=Path(directory)
        ):
            with self.assertRaises(SavedPlanError):
                SavedPlanLifecycle(pipeline, now_factory=lambda: CREATED).create(selection())
            self.assertEqual(list(Path(directory).glob("plans/*")), [])


if __name__ == "__main__":
    unittest.main()