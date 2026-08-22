"""Read-only gate deciding whether an exact saved plan is ready for apply."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from client_config import ClientRuntimeSelection
from client_paths import build_client_root
from plan_approval_binding import (
    PlanApprovalBinding,
    PlanApprovalBindingService,
    PlanApprovalError,
    PlanApprovalStatus,
)
from saved_plan import SavedPlan, SavedPlanError, sha256_file


class DeploymentGateStatus(str, Enum):
    READY = "READY"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class DeploymentGateResult:
    status: DeploymentGateStatus
    allowed: bool
    reason_codes: tuple[str, ...]
    plan_id: str | None
    plan_sha256: str | None
    client_id: str | None
    environment: str | None
    provider: str | None
    state_profile_id: str | None
    plan_integrity_status: str
    approval_status: str
    policy_status: str
    governance_status: str
    credential_status: str
    state_binding_status: str
    context_status: str
    expiry_status: str
    evaluated_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "allowed": self.allowed,
            "reason_codes": list(self.reason_codes),
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "client_id": self.client_id,
            "environment": self.environment,
            "provider": self.provider,
            "state_profile_id": self.state_profile_id,
            "plan_integrity_status": self.plan_integrity_status,
            "approval_status": self.approval_status,
            "policy_status": self.policy_status,
            "governance_status": self.governance_status,
            "credential_status": self.credential_status,
            "state_binding_status": self.state_binding_status,
            "context_status": self.context_status,
            "expiry_status": self.expiry_status,
            "evaluated_at": self.evaluated_at.isoformat(timespec="seconds").replace(
                "+00:00", "Z"
            ),
        }


class DeploymentGate:
    """Evaluates a deployment authorization without invoking Terraform."""

    def __init__(
        self,
        *,
        approval_service: PlanApprovalBindingService | None = None,
        now_factory=None,
    ) -> None:
        self.approval_service = approval_service or PlanApprovalBindingService()
        self._now_factory = now_factory or (lambda: datetime.now(timezone.utc))

    def evaluate(
        self,
        saved_plan: SavedPlan | None,
        deployment_approval: PlanApprovalBinding | None,
        runtime_selection: ClientRuntimeSelection | None,
        policy_result: object | None,
        governance_result: object | None,
        credential_status: str | None = None,
        state_profile: object | None = None,
        *,
        evaluated_at: datetime | None = None,
    ) -> DeploymentGateResult:
        evaluation_time = self._utc(evaluated_at or self._now_factory())
        reasons: list[str] = []
        plan_integrity = "PASS"
        expiry = "PASS"
        context = "PASS"
        state_binding = "PASS"

        if not isinstance(saved_plan, SavedPlan):
            reasons.append("PLAN_MISSING")
            plan_integrity = "BLOCKED"
        else:
            try:
                expected_root = build_client_root(
                    saved_plan.client_id,
                    saved_plan.environment,
                    saved_plan.provider,
                ).resolve()
                if saved_plan.working_directory != expected_root:
                    reasons.append("UNSAFE_RUNTIME_PATH")
                    plan_integrity = "BLOCKED"
                expected_plan = expected_root / "plans" / saved_plan.plan_id / "approved.tfplan"
                if saved_plan.plan_path != expected_plan:
                    reasons.append("PLAN_PATH_INVALID")
                    plan_integrity = "BLOCKED"
                if evaluation_time >= self._parse(saved_plan.expires_at):
                    reasons.append("PLAN_EXPIRED")
                    expiry = "BLOCKED"
                if not saved_plan.plan_path.is_file():
                    reasons.append("PLAN_MISSING")
                    plan_integrity = "BLOCKED"
                elif sha256_file(saved_plan.plan_path) != saved_plan.plan_sha256:
                    reasons.append("PLAN_HASH_MISMATCH")
                    plan_integrity = "BLOCKED"
            except (OSError, SavedPlanError, ValueError):
                reasons.append("PLAN_PATH_INVALID")
                plan_integrity = "BLOCKED"

        approval_status = "MISSING"
        if deployment_approval is None:
            reasons.append("APPROVAL_MISSING")
        elif not isinstance(deployment_approval, PlanApprovalBinding):
            reasons.append("APPROVAL_BINDING_MISMATCH")
            approval_status = "INVALID"
        else:
            approval_status = deployment_approval.status.value
            status_reasons = {
                PlanApprovalStatus.PENDING: "APPROVAL_PENDING",
                PlanApprovalStatus.REJECTED: "APPROVAL_REJECTED",
                PlanApprovalStatus.EXPIRED: "APPROVAL_EXPIRED",
            }
            if deployment_approval.approval_purpose != "DEPLOYMENT":
                reasons.append("APPROVAL_BINDING_MISMATCH")
            if deployment_approval.status is not PlanApprovalStatus.APPROVED:
                reasons.append(status_reasons.get(deployment_approval.status, "APPROVAL_BINDING_MISMATCH"))
            if saved_plan is not None:
                try:
                    self.approval_service.validate(
                        deployment_approval,
                        saved_plan,
                        evaluated_at=evaluation_time,
                    )
                except PlanApprovalError as exc:
                    reasons.append(self._approval_reason(str(exc)))

        policy_status = self._policy_status(policy_result)
        if policy_status == "MISSING":
            reasons.append("POLICY_MISSING")
        elif policy_status == "BLOCK":
            reasons.append("POLICY_BLOCK")

        governance_status = self._governance_status(governance_result)
        if governance_status != "AUTHORIZED":
            reasons.append("GOVERNANCE_NOT_AUTHORIZED")

        selected_credential = credential_status
        if selected_credential is None and runtime_selection is not None:
            selected_credential = getattr(runtime_selection, "credential_status", None)
        credential_value = str(selected_credential) if selected_credential is not None else "MISSING"
        if credential_value != "VALID":
            reasons.append("CREDENTIAL_INVALID" if credential_value == "INVALID" else "CREDENTIAL_MISSING")

        if runtime_selection is None:
            reasons.append("CLIENT_MISMATCH")
            reasons.append("ENVIRONMENT_MISMATCH")
            reasons.append("PROVIDER_MISMATCH")
            context = "BLOCKED"
            state_binding = "BLOCKED"
        elif saved_plan is not None:
            for field_name, reason in (
                ("client_id", "CLIENT_MISMATCH"),
                ("environment", "ENVIRONMENT_MISMATCH"),
                ("provider", "PROVIDER_MISMATCH"),
            ):
                if getattr(saved_plan, field_name) != getattr(runtime_selection, field_name):
                    reasons.append(reason)
                    context = "BLOCKED"
            selected_state = state_profile or getattr(runtime_selection, "state_profile", None)
            backend = getattr(runtime_selection, "backend", None)
            if selected_state is None or getattr(selected_state, "state_profile_id", None) != saved_plan.state_profile_id:
                reasons.append("STATE_PROFILE_MISMATCH")
                state_binding = "BLOCKED"
            if backend is None or getattr(backend, "backend_type", None) != saved_plan.backend_type:
                reasons.append("STATE_BINDING_INVALID")
                state_binding = "BLOCKED"
            if backend is None or getattr(backend, "state_identity", None) != saved_plan.state_identity:
                reasons.append("STATE_BINDING_INVALID")
                state_binding = "BLOCKED"
            try:
                expected_root = build_client_root(
                    runtime_selection.client_id,
                    runtime_selection.environment,
                    runtime_selection.provider,
                ).resolve()
                if saved_plan.working_directory != expected_root:
                    reasons.append("UNSAFE_RUNTIME_PATH")
                    context = "BLOCKED"
            except (OSError, ValueError):
                reasons.append("UNSAFE_RUNTIME_PATH")
                context = "BLOCKED"

        unique_reasons = tuple(dict.fromkeys(reasons))
        allowed = not unique_reasons
        return DeploymentGateResult(
            status=DeploymentGateStatus.READY if allowed else DeploymentGateStatus.BLOCKED,
            allowed=allowed,
            reason_codes=unique_reasons,
            plan_id=getattr(saved_plan, "plan_id", None),
            plan_sha256=getattr(saved_plan, "plan_sha256", None),
            client_id=getattr(saved_plan, "client_id", None),
            environment=getattr(saved_plan, "environment", None),
            provider=getattr(saved_plan, "provider", None),
            state_profile_id=getattr(saved_plan, "state_profile_id", None),
            plan_integrity_status=plan_integrity,
            approval_status=approval_status,
            policy_status=policy_status,
            governance_status=governance_status,
            credential_status=credential_value,
            state_binding_status=state_binding,
            context_status=context,
            expiry_status=expiry,
            evaluated_at=evaluation_time,
        )

    @staticmethod
    def _policy_status(value: object | None) -> str:
        decision = getattr(value, "policy_decision", value)
        decision = getattr(decision, "decision", decision)
        if decision is None:
            return "MISSING"
        result = str(getattr(decision, "value", decision)).upper()
        return result if result in {"ALLOW", "REQUIRE_APPROVAL", "BLOCK"} else "MISSING"

    @staticmethod
    def _governance_status(value: object | None) -> str:
        if value is None:
            return "MISSING"
        authorization = getattr(value, "authorization", None)
        status = getattr(authorization, "authorization_status", authorization)
        if status is None:
            status = getattr(value, "authorization_status", None)
        status = getattr(value, "governance_status", status)
        status = getattr(status, "value", status)
        return str(status).upper() if status is not None else "MISSING"

    @staticmethod
    def _approval_reason(error: str) -> str:
        return {
            "PLAN_EXPIRED": "PLAN_EXPIRED",
            "PLAN_ARTIFACT_MISSING": "PLAN_MISSING",
            "PLAN_ARTIFACT_HASH_MISMATCH": "PLAN_HASH_MISMATCH",
            "APPROVAL_EXPIRED": "APPROVAL_EXPIRED",
            "APPROVAL_NOT_AUTHORIZED": "APPROVAL_BINDING_MISMATCH",
            "APPROVAL_BINDING_MISMATCH": "APPROVAL_BINDING_MISMATCH",
            "APPROVAL_EXPIRY_EXCEEDS_PLAN": "APPROVAL_EXPIRED",
        }.get(error, "APPROVAL_BINDING_MISMATCH")

    @staticmethod
    def _parse(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    @staticmethod
    def _utc(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timezone.utc.utcoffset(value):
            raise ValueError("evaluated_at must be UTC-aware")
        return value.astimezone(timezone.utc).replace(microsecond=0)