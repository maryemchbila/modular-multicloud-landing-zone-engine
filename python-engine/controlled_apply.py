"""Controlled execution of one exact, approved deployment plan."""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from client_config import ClientRuntimeSelection
from client_paths import build_client_root
from credential_resolver import resolve_credentials
from deployment_gate import DeploymentGateResult, DeploymentGateStatus
from saved_plan import SavedPlan, SavedPlanError, sha256_file
from terraform_models import TerraformExecutionError, TerraformResult
from terraform_runner import TerraformRunner


class ApplyStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    TIMEOUT = "TIMEOUT"


@dataclass(frozen=True)
class ApplyRequest:
    plan_id: str
    plan_sha256: str
    client_id: str
    environment: str
    provider: str
    state_profile_id: str
    working_directory: Path
    requested_at: datetime


@dataclass(frozen=True)
class ApplyResult:
    apply_id: str
    plan_id: str
    plan_sha256: str
    status: ApplyStatus
    terraform_exit_code: int | None
    started_at: datetime
    finished_at: datetime
    duration_seconds: float
    client_id: str
    environment: str
    provider: str
    state_profile_id: str
    error_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "apply_id": self.apply_id,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "status": self.status.value,
            "terraform_exit_code": self.terraform_exit_code,
            "started_at": self.started_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "finished_at": self.finished_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "duration_seconds": self.duration_seconds,
            "client_id": self.client_id,
            "environment": self.environment,
            "provider": self.provider,
            "state_profile_id": self.state_profile_id,
            "error_reason": self.error_reason,
        }


class ControlledApplyRunner:
    """Applies only a READY gate's exact deployment plan, once."""

    CLAIM_FILENAME = "apply_execution.json"

    def __init__(self, runner: TerraformRunner | None = None, *, timeout=180.0, now_factory=None, uuid_factory=None):
        self.runner = runner or TerraformRunner()
        self.timeout = timeout
        self._now_factory = now_factory or (lambda: datetime.now(timezone.utc))
        self._uuid_factory = uuid_factory or uuid4

    def apply(
        self,
        saved_plan: SavedPlan | None,
        gate_result: DeploymentGateResult | None,
        runtime_selection: ClientRuntimeSelection | None,
    ) -> ApplyResult:
        started = self._now()
        plan = saved_plan
        result_fields = self._safe_fields(plan, runtime_selection)
        reasons = self._preflight(plan, gate_result, runtime_selection, started)
        if reasons:
            return self._result(ApplyStatus.BLOCKED, started, result_fields, reasons[0])

        claim_path = plan.plan_path.parent / self.CLAIM_FILENAME
        claim_reason = self._claim(claim_path, plan, started)
        if claim_reason:
            return self._result(ApplyStatus.BLOCKED, started, result_fields, claim_reason)

        try:
            current_hash = sha256_file(plan.plan_path)
            if current_hash != plan.plan_sha256 or current_hash != gate_result.plan_sha256:
                self._finish_claim(claim_path, plan, "FAILED", started, "PLAN_HASH_MISMATCH")
                return self._result(ApplyStatus.BLOCKED, started, result_fields, "PLAN_HASH_MISMATCH")
            result = self.runner.run_controlled_apply(
                plan.plan_path,
                plan.working_directory,
                timeout=self.timeout,
                env_overrides=resolve_credentials(runtime_selection.credential_profile),
            )
        except (OSError, SavedPlanError, TerraformExecutionError, ValueError) as exc:
            self._finish_claim(claim_path, plan, "FAILED", started, "APPLY_EXECUTION_FAILED")
            return self._result(ApplyStatus.FAILED, started, result_fields, "APPLY_EXECUTION_FAILED")

        status = ApplyStatus.TIMEOUT if result.timed_out else ApplyStatus.SUCCESS if result.success else ApplyStatus.FAILED
        reason = None if status is ApplyStatus.SUCCESS else "APPLY_TIMEOUT" if status is ApplyStatus.TIMEOUT else "APPLY_FAILED"
        self._finish_claim(claim_path, plan, status.value, started, reason)
        return self._result(status, started, result_fields, reason, result)

    def _preflight(self, plan, gate, runtime, evaluated_at):
        reasons = []
        if not isinstance(gate, DeploymentGateResult) or gate.status is not DeploymentGateStatus.READY or not gate.allowed:
            reasons.append("GATE_NOT_READY")
        if not isinstance(plan, SavedPlan):
            reasons.append("PLAN_MISSING")
            return reasons
        if plan.plan_kind != "DEPLOYMENT":
            reasons.append("PLAN_KIND_INVALID")
        if runtime is None:
            reasons.append("RUNTIME_CONTEXT_INVALID")
            return reasons
        for field in ("client_id", "environment", "provider"):
            if getattr(plan, field) != getattr(runtime, field):
                reasons.append(f"{field.upper()}_MISMATCH")
        if plan.state_profile_id != getattr(runtime.state_profile, "state_profile_id", None):
            reasons.append("STATE_PROFILE_MISMATCH")
        if plan.working_directory != build_client_root(runtime.client_id, runtime.environment, runtime.provider).resolve():
            reasons.append("UNSAFE_RUNTIME_PATH")
        if gate is not None and isinstance(gate, DeploymentGateResult):
            for field in ("plan_id", "plan_sha256", "client_id", "environment", "provider", "state_profile_id"):
                if getattr(gate, field) != getattr(plan, field):
                    reasons.append(f"GATE_{field.upper()}_MISMATCH")
        try:
            if evaluated_at >= self._parse(plan.expires_at):
                reasons.append("PLAN_EXPIRED")
            if not plan.plan_path.is_file():
                reasons.append("PLAN_MISSING")
            elif sha256_file(plan.plan_path) != plan.plan_sha256:
                reasons.append("PLAN_HASH_MISMATCH")
        except (OSError, SavedPlanError, ValueError):
            reasons.append("PLAN_PATH_INVALID")
        if getattr(runtime, "credential_status", None) != "VALID":
            reasons.append("CREDENTIAL_INVALID")
        return list(dict.fromkeys(reasons))

    def _claim(self, path, plan, started):
        payload = {"plan_id": plan.plan_id, "plan_sha256": plan.plan_sha256, "status": "IN_PROGRESS", "started_at": self._stamp(started)}
        try:
            with path.open("x", encoding="utf-8") as stream:
                json.dump(payload, stream, indent=2)
                stream.write("\n")
        except FileExistsError:
            return "APPLY_ALREADY_CLAIMED"
        except OSError:
            return "APPLY_CLAIM_FAILED"
        return None

    def _finish_claim(self, path, plan, status, started, reason):
        payload = {"plan_id": plan.plan_id, "plan_sha256": plan.plan_sha256, "status": status, "started_at": self._stamp(started), "finished_at": self._stamp(self._now()), "error_reason": reason}
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, prefix=".apply-execution.", suffix=".tmp", delete=False) as stream:
                json.dump(payload, stream, indent=2)
                stream.write("\n")
                temporary = Path(stream.name)
            temporary.replace(path)
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()

    def _result(self, status, started, fields, reason, terraform=None):
        finished = self._now()
        return ApplyResult(
            apply_id=fields["apply_id"], plan_id=fields["plan_id"], plan_sha256=fields["plan_sha256"],
            status=status, terraform_exit_code=terraform.exit_code if terraform else None,
            started_at=started, finished_at=finished, duration_seconds=max(0.0, (finished - started).total_seconds()),
            client_id=fields["client_id"], environment=fields["environment"], provider=fields["provider"],
            state_profile_id=fields["state_profile_id"], error_reason=reason,
        )

    def _safe_fields(self, plan, runtime):
        return {"apply_id": f"apply_{self._now().strftime('%Y%m%dT%H%M%SZ')}_{self._uuid_factory().hex[:8]}", "plan_id": getattr(plan, "plan_id", "UNKNOWN"), "plan_sha256": getattr(plan, "plan_sha256", "UNKNOWN"), "client_id": getattr(plan, "client_id", getattr(runtime, "client_id", "UNKNOWN")), "environment": getattr(plan, "environment", getattr(runtime, "environment", "UNKNOWN")), "provider": getattr(plan, "provider", getattr(runtime, "provider", "UNKNOWN")), "state_profile_id": getattr(plan, "state_profile_id", "UNKNOWN")}

    def _now(self):
        value = self._now_factory()
        return value.astimezone(timezone.utc).replace(microsecond=0)

    @staticmethod
    def _parse(value):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    @staticmethod
    def _stamp(value):
        return value.isoformat(timespec="seconds").replace("+00:00", "Z")