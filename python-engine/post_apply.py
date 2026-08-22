"""Read-only post-apply verification and sanitized deployment audit."""

from __future__ import annotations

import json
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID, uuid4

from client_config import ClientRuntimeSelection
from client_paths import build_client_root
from controlled_apply import ApplyResult, ApplyStatus
from deployment_gate import DeploymentGateResult, DeploymentGateStatus
from saved_plan import SavedPlan, SavedPlanError, sha256_file


class PostApplyStatus(str, Enum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


class StateProbeStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"


@dataclass(frozen=True)
class StateProbeResult:
    status: StateProbeStatus
    resource_count: int | None = None
    reason: str | None = None


class ReadOnlyStateProbe(Protocol):
    def probe(self, runtime_selection: ClientRuntimeSelection) -> StateProbeResult:
        """Return safe state visibility without returning state contents."""


@dataclass(frozen=True)
class PostApplyVerificationResult:
    verification_id: str
    status: PostApplyStatus
    apply_id: str
    plan_id: str
    plan_sha256: str
    client_id: str
    environment: str
    provider: str
    state_profile_id: str
    apply_status: str
    execution_claim_status: str
    plan_integrity_status: str
    state_binding_status: str
    state_probe_status: str
    cloud_verification_status: str
    reason_codes: tuple[str, ...]
    verified_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "verification_id": self.verification_id,
            "status": self.status.value,
            "apply_id": self.apply_id,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "client_id": self.client_id,
            "environment": self.environment,
            "provider": self.provider,
            "state_profile_id": self.state_profile_id,
            "apply_status": self.apply_status,
            "execution_claim_status": self.execution_claim_status,
            "plan_integrity_status": self.plan_integrity_status,
            "state_binding_status": self.state_binding_status,
            "state_probe_status": self.state_probe_status,
            "cloud_verification_status": self.cloud_verification_status,
            "reason_codes": list(self.reason_codes),
            "verified_at": _stamp(self.verified_at),
        }


@dataclass(frozen=True)
class DeploymentAuditRecord:
    audit_id: str
    verification_id: str
    apply_id: str
    plan_id: str
    plan_sha256: str
    client_id: str
    environment: str
    provider: str
    state_profile_id: str
    deployment_gate_status: str
    apply_status: str
    terraform_exit_code: int | None
    execution_claim_status: str
    plan_integrity_status: str
    state_binding_status: str
    state_probe_status: str
    cloud_verification_status: str
    started_at: datetime
    finished_at: datetime
    verified_at: datetime
    final_status: str
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "verification_id": self.verification_id,
            "apply_id": self.apply_id,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "client_id": self.client_id,
            "environment": self.environment,
            "provider": self.provider,
            "state_profile_id": self.state_profile_id,
            "deployment_gate_status": self.deployment_gate_status,
            "apply_status": self.apply_status,
            "terraform_exit_code": self.terraform_exit_code,
            "execution_claim_status": self.execution_claim_status,
            "plan_integrity_status": self.plan_integrity_status,
            "state_binding_status": self.state_binding_status,
            "state_probe_status": self.state_probe_status,
            "cloud_verification_status": self.cloud_verification_status,
            "started_at": _stamp(self.started_at),
            "finished_at": _stamp(self.finished_at),
            "verified_at": _stamp(self.verified_at),
            "final_status": self.final_status,
            "reason_codes": list(self.reason_codes),
        }


class PostApplyVerifier:
    AUDIT_FILENAME = "deployment_audit.json"
    _ID = re.compile(r"\A(?:verify|audit)_\d{8}T\d{6}Z_[0-9a-f]{8}\Z")

    def __init__(self, *, now_factory=None, uuid_factory=None):
        self._now_factory = now_factory or (lambda: datetime.now(timezone.utc))
        self._uuid_factory = uuid_factory or uuid4

    def verify(
        self,
        saved_plan: SavedPlan | None,
        gate_result: DeploymentGateResult | None,
        apply_result: ApplyResult | None,
        runtime_selection: ClientRuntimeSelection | None,
        state_probe: ReadOnlyStateProbe,
    ) -> tuple[PostApplyVerificationResult, DeploymentAuditRecord, Path]:
        verified_at = self._now()
        fields = self._fields(saved_plan, apply_result, verified_at)
        reasons: list[str] = []
        plan_integrity = "PASS"
        state_binding = "PASS"
        claim_status = "MISSING"
        probe_status = "NOT_PERFORMED"

        if not isinstance(saved_plan, SavedPlan):
            reasons.append("PLAN_MISSING")
        if not isinstance(gate_result, DeploymentGateResult) or gate_result.status is not DeploymentGateStatus.READY or not gate_result.allowed:
            reasons.append("GATE_NOT_READY")
        if not isinstance(apply_result, ApplyResult):
            reasons.append("APPLY_RESULT_MISMATCH")
        elif apply_result.status is ApplyStatus.BLOCKED:
            reasons.append("APPLY_NOT_SUCCESSFUL")
        elif apply_result.status is not ApplyStatus.SUCCESS:
            reasons.append("APPLY_NOT_SUCCESSFUL")

        claim = None
        if isinstance(saved_plan, SavedPlan):
            claim_path = saved_plan.plan_path.parent / "apply_execution.json"
            claim, claim_error = self._read_claim(claim_path)
            if claim_error:
                reasons.append(claim_error)
            else:
                claim_status = str(claim.get("status", ""))
                if claim_status != "SUCCESS":
                    reasons.append("EXECUTION_CLAIM_NOT_SUCCESS")
                if isinstance(apply_result, ApplyResult):
                    if claim_status != apply_result.status.value:
                        reasons.append("EXECUTION_CLAIM_INVALID")
                    if claim.get("plan_id") != apply_result.plan_id or claim.get("plan_sha256") != apply_result.plan_sha256:
                        reasons.append("EXECUTION_CLAIM_INVALID")
                for field_name in ("started_at", "finished_at"):
                    try:
                        _parse_timestamp(claim[field_name])
                    except (KeyError, TypeError, ValueError):
                        reasons.append("EXECUTION_CLAIM_INVALID")
            try:
                expected_root = build_client_root(saved_plan.client_id, saved_plan.environment, saved_plan.provider).resolve()
                expected_plan = expected_root / "plans" / saved_plan.plan_id / "approved.tfplan"
                if saved_plan.working_directory != expected_root or saved_plan.plan_path != expected_plan:
                    reasons.append("PLAN_PATH_INVALID")
                    plan_integrity = "BLOCKED"
                if verified_at >= datetime.fromisoformat(saved_plan.expires_at.replace("Z", "+00:00")):
                    reasons.append("PLAN_EXPIRED")
                if not saved_plan.plan_path.is_file():
                    reasons.append("PLAN_MISSING")
                    plan_integrity = "BLOCKED"
                elif sha256_file(saved_plan.plan_path) != saved_plan.plan_sha256:
                    reasons.append("PLAN_HASH_MISMATCH")
                    plan_integrity = "BLOCKED"
            except (OSError, SavedPlanError, ValueError):
                reasons.append("PLAN_PATH_INVALID")
                plan_integrity = "BLOCKED"

        if isinstance(saved_plan, SavedPlan) and isinstance(apply_result, ApplyResult):
            for field_name in ("plan_id", "plan_sha256", "client_id", "environment", "provider", "state_profile_id"):
                if getattr(saved_plan, field_name) != getattr(apply_result, field_name):
                    reasons.append(f"{field_name.upper()}_MISMATCH")
            if isinstance(gate_result, DeploymentGateResult):
                for field_name in ("plan_id", "plan_sha256", "client_id", "environment", "provider", "state_profile_id"):
                    if getattr(gate_result, field_name) != getattr(saved_plan, field_name):
                        reasons.append(f"{field_name.upper()}_MISMATCH")

        if runtime_selection is None:
            reasons.append("RUNTIME_CONTEXT_INVALID")
            state_binding = "BLOCKED"
        elif isinstance(saved_plan, SavedPlan):
            for field_name in ("client_id", "environment", "provider"):
                if getattr(runtime_selection, field_name) != getattr(saved_plan, field_name):
                    reasons.append(f"{field_name.upper()}_MISMATCH")
            if runtime_selection.state_profile.state_profile_id != saved_plan.state_profile_id:
                reasons.append("STATE_PROFILE_MISMATCH")
                state_binding = "BLOCKED"
            if runtime_selection.backend.backend_type != saved_plan.backend_type or runtime_selection.backend.state_identity != saved_plan.state_identity:
                reasons.append("STATE_BINDING_INVALID")
                state_binding = "BLOCKED"
            try:
                if saved_plan.working_directory != build_client_root(runtime_selection.client_id, runtime_selection.environment, runtime_selection.provider).resolve():
                    reasons.append("PLAN_PATH_INVALID")
                    state_binding = "BLOCKED"
            except (OSError, ValueError):
                reasons.append("PLAN_PATH_INVALID")
                state_binding = "BLOCKED"

        if not reasons and isinstance(runtime_selection, ClientRuntimeSelection):
            try:
                probe = state_probe.probe(runtime_selection)
                probe_status = str(getattr(probe.status, "value", probe.status))
                if probe_status != StateProbeStatus.AVAILABLE.value:
                    reasons.append("STATE_PROBE_UNAVAILABLE" if probe_status == "UNAVAILABLE" else "STATE_PROBE_ERROR")
            except Exception:
                probe_status = StateProbeStatus.ERROR.value
                reasons.append("STATE_PROBE_ERROR")

        unique = tuple(dict.fromkeys(reasons))
        status = PostApplyStatus.VERIFIED if not unique else PostApplyStatus.BLOCKED if (
            isinstance(apply_result, ApplyResult)
            and apply_result.status is ApplyStatus.BLOCKED
        ) or any(code in unique for code in ("GATE_NOT_READY", "PLAN_MISSING", "PLAN_PATH_INVALID", "PLAN_HASH_MISMATCH")) else PostApplyStatus.FAILED
        verification = PostApplyVerificationResult(
            verification_id=self._new_id("verify", verified_at), status=status,
            apply_status=apply_result.status.value if isinstance(apply_result, ApplyResult) else "MISSING",
            plan_sha256=fields["plan_sha256"], execution_claim_status=claim_status,
            plan_integrity_status=plan_integrity, state_binding_status=state_binding,
            state_probe_status=probe_status, cloud_verification_status="NOT_PERFORMED",
            reason_codes=unique, verified_at=verified_at, **{key: fields[key] for key in ("apply_id", "plan_id", "client_id", "environment", "provider", "state_profile_id")},
        )
        audit = DeploymentAuditRecord(
            audit_id=self._new_id("audit", verified_at), verification_id=verification.verification_id,
            apply_id=verification.apply_id, plan_id=verification.plan_id, plan_sha256=verification.plan_sha256,
            client_id=verification.client_id, environment=verification.environment, provider=verification.provider,
            state_profile_id=verification.state_profile_id,
            deployment_gate_status=gate_result.status.value if isinstance(gate_result, DeploymentGateResult) else "MISSING",
            apply_status=verification.apply_status, terraform_exit_code=apply_result.terraform_exit_code if isinstance(apply_result, ApplyResult) else None,
            execution_claim_status=claim_status, plan_integrity_status=plan_integrity, state_binding_status=state_binding,
            state_probe_status=probe_status, cloud_verification_status="NOT_PERFORMED",
            started_at=apply_result.started_at if isinstance(apply_result, ApplyResult) else verified_at,
            finished_at=apply_result.finished_at if isinstance(apply_result, ApplyResult) else verified_at,
            verified_at=verified_at, final_status=status.value, reason_codes=unique,
        )
        audit_path = self._write_audit(saved_plan, audit)
        return verification, audit, audit_path

    def _write_audit(self, saved_plan: SavedPlan | None, audit: DeploymentAuditRecord) -> Path:
        if not isinstance(saved_plan, SavedPlan):
            raise SavedPlanError("PLAN_MISSING")
        path = saved_plan.plan_path.parent / self.AUDIT_FILENAME
        if path.exists():
            raise SavedPlanError("AUDIT_ALREADY_EXISTS")
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, prefix=".deployment-audit.", suffix=".tmp", delete=False) as stream:
                json.dump(audit.to_dict(), stream, indent=2)
                stream.write("\n")
                temporary = Path(stream.name)
            temporary.replace(path)
            return path
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()

    @staticmethod
    def _read_claim(path: Path) -> tuple[dict[str, Any] | None, str | None]:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None, "EXECUTION_CLAIM_MISSING" if not path.exists() else "EXECUTION_CLAIM_INVALID"
        if not isinstance(raw, dict) or not isinstance(raw.get("status"), str) or not isinstance(raw.get("plan_id"), str) or not isinstance(raw.get("plan_sha256"), str):
            return None, "EXECUTION_CLAIM_INVALID"
        return raw, None

    def _fields(self, plan, result, now):
        return {
            "apply_id": getattr(result, "apply_id", "UNKNOWN"),
            "plan_id": getattr(plan, "plan_id", getattr(result, "plan_id", "UNKNOWN")),
            "plan_sha256": getattr(plan, "plan_sha256", getattr(result, "plan_sha256", "UNKNOWN")),
            "client_id": getattr(plan, "client_id", getattr(result, "client_id", "UNKNOWN")),
            "environment": getattr(plan, "environment", getattr(result, "environment", "UNKNOWN")),
            "provider": getattr(plan, "provider", getattr(result, "provider", "UNKNOWN")),
            "state_profile_id": getattr(plan, "state_profile_id", getattr(result, "state_profile_id", "UNKNOWN")),
        }

    def _new_id(self, prefix, now):
        return f"{prefix}_{now.strftime('%Y%m%dT%H%M%SZ')}_{self._uuid_factory().hex[:8]}"

    def _now(self):
        value = self._now_factory()
        if value.tzinfo is None:
            raise ValueError("now_factory must return timezone-aware UTC")
        return value.astimezone(timezone.utc).replace(microsecond=0)


def _stamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError("timestamp must be UTC-aware")
    return parsed