"""Creation et stockage runtime d'un plan Terraform deployable."""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

from client_config import ClientRuntimeSelection
from client_paths import build_client_root
from credential_resolver import resolve_credentials
from terraform_models import TerraformPlanStatus
from terraform_plan import TerraformPlanPipeline


class SavedPlanError(ValueError):
    """Erreur de validation ou de persistance d'un plan sauvegarde."""


_PLAN_ID = re.compile(r"\Aplan_\d{8}T\d{6}Z_[0-9a-f]{8}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_UTC = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise SavedPlanError("SAVED_PLAN_FILE_UNREADABLE") from exc
    return digest.hexdigest()


def _utc_text(value: datetime, field_name: str) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise SavedPlanError(f"{field_name}_MUST_BE_UTC")
    if value.microsecond:
        raise SavedPlanError(f"{field_name}_MUST_HAVE_SECOND_PRECISION")
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class SavedPlan:
    plan_id: str
    plan_kind: str
    plan_path: Path
    plan_sha256: str
    client_id: str
    environment: str
    provider: str
    state_profile_id: str
    backend_type: str
    state_identity: str
    working_directory: Path
    created_at: str
    expires_at: str
    terraform_run_id: str | None = None
    add_count: int | None = None
    change_count: int | None = None
    destroy_count: int | None = None

    def __post_init__(self) -> None:
        if not _PLAN_ID.fullmatch(self.plan_id):
            raise SavedPlanError("PLAN_ID_INVALID")
        if self.plan_kind != "DEPLOYMENT":
            raise SavedPlanError("PLAN_KIND_INVALID")
        if not _SHA256.fullmatch(self.plan_sha256):
            raise SavedPlanError("PLAN_SHA256_INVALID")
        if self.provider not in {"gcp", "oci"}:
            raise SavedPlanError("PROVIDER_INVALID")
        if not self.client_id or not self.environment or not self.state_profile_id:
            raise SavedPlanError("PLAN_BINDING_INCOMPLETE")
        working = Path(self.working_directory).expanduser().resolve()
        plan = Path(self.plan_path).expanduser().resolve()
        expected = working / "plans" / self.plan_id / "approved.tfplan"
        if plan != expected:
            raise SavedPlanError("PLAN_PATH_UNSAFE")
        if not _UTC.fullmatch(self.created_at) or not _UTC.fullmatch(self.expires_at):
            raise SavedPlanError("PLAN_TIMESTAMP_INVALID")
        object.__setattr__(self, "working_directory", working)
        object.__setattr__(self, "plan_path", plan)

    def to_dict(self) -> dict[str, object]:
        return {
            "plan_id": self.plan_id,
            "plan_kind": self.plan_kind,
            "plan_path": self.plan_path.name,
            "plan_sha256": self.plan_sha256,
            "client_id": self.client_id,
            "environment": self.environment,
            "provider": self.provider,
            "state_profile_id": self.state_profile_id,
            "backend_type": self.backend_type,
            "state_identity": self.state_identity,
            "working_directory": str(self.working_directory),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "terraform_run_id": self.terraform_run_id,
            "changes": {
                "add": self.add_count,
                "change": self.change_count,
                "destroy": self.destroy_count,
            },
        }


class SavedPlanLifecycle:
    """Creates exactly one retained deployment plan for a client runtime."""

    DEFAULT_TTL = timedelta(minutes=30)

    def __init__(
        self,
        plan_pipeline: TerraformPlanPipeline,
        *,
        now_factory: Callable[[], datetime] | None = None,
        uuid_factory: Callable[[], UUID] | None = None,
        ttl: timedelta = DEFAULT_TTL,
    ) -> None:
        self.plan_pipeline = plan_pipeline
        self._now_factory = now_factory or (lambda: datetime.now(timezone.utc))
        self._uuid_factory = uuid_factory or uuid4
        if ttl <= timedelta(0):
            raise ValueError("ttl must be positive")
        self.ttl = ttl

    def create(self, selection: ClientRuntimeSelection) -> SavedPlan:
        if not isinstance(selection, ClientRuntimeSelection):
            raise TypeError("selection must be a ClientRuntimeSelection")
        root = build_client_root(
            selection.client_id, selection.environment, selection.provider
        ).resolve()
        created = self._now_factory().astimezone(timezone.utc).replace(microsecond=0)
        expires = created + self.ttl
        plan_id = f"plan_{created.strftime('%Y%m%dT%H%M%SZ')}_{self._uuid_factory().hex[:8]}"
        plan_directory = root / "plans" / plan_id
        plan_path = plan_directory / "approved.tfplan"
        plan_directory.mkdir(parents=True, exist_ok=False)
        try:
            result = self.plan_pipeline.run(
                selection.provider,
                plan_output_path=plan_path,
                working_directory=root,
                env_overrides=resolve_credentials(selection.credential_profile),
            )
            if result.plan_status not in {
                TerraformPlanStatus.NO_CHANGES,
                TerraformPlanStatus.CHANGES_DETECTED,
            } or not plan_path.is_file():
                raise SavedPlanError("SAVED_PLAN_NOT_CREATED")
            report = getattr(result, "report", None)
            saved = SavedPlan(
                plan_id=plan_id,
                plan_kind="DEPLOYMENT",
                plan_path=plan_path,
                plan_sha256=sha256_file(plan_path),
                client_id=selection.client_id,
                environment=selection.environment,
                provider=selection.provider,
                state_profile_id=selection.state_profile.state_profile_id,
                backend_type=selection.backend.backend_type,
                state_identity=selection.backend.state_identity,
                working_directory=root,
                created_at=_utc_text(created, "created_at"),
                expires_at=_utc_text(expires, "expires_at"),
                terraform_run_id=getattr(report, "run_id", None),
                add_count=getattr(report, "add_count", None),
                change_count=getattr(report, "change_count", None),
                destroy_count=getattr(report, "destroy_count", None),
            )
            self._write_metadata(plan_directory / "metadata.json", saved)
            return saved
        except Exception:
            self._cleanup_incomplete(plan_directory)
            raise

    @staticmethod
    def _write_metadata(path: Path, saved: SavedPlan) -> None:
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=path.parent,
                prefix=".metadata.", suffix=".tmp", delete=False
            ) as stream:
                json.dump(saved.to_dict(), stream, ensure_ascii=True, indent=2)
                stream.write("\n")
                temporary = Path(stream.name)
            temporary.replace(path)
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()

    @staticmethod
    def _cleanup_incomplete(directory: Path) -> None:
        metadata = directory / "metadata.json"
        if metadata.exists():
            metadata.unlink(missing_ok=True)
        plan = directory / "approved.tfplan"
        plan.unlink(missing_ok=True)
        directory.rmdir()