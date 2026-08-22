"""Exact deployment approval bindings for retained Terraform plans."""

from __future__ import annotations

import json
import re
import tempfile
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from saved_plan import SavedPlan, SavedPlanError, sha256_file


class PlanApprovalError(ValueError):
    """Validation or lifecycle error for a deployment approval binding."""


class PlanApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


_APPROVAL_ID = re.compile(r"\Aapproval_deployment_\d{8}T\d{6}Z_[0-9a-f]{8}\Z")
_SAFE_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:@/-]*\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")


def _utc(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise PlanApprovalError(f"{field_name}_MUST_BE_UTC")
    if value.microsecond:
        raise PlanApprovalError(f"{field_name}_MUST_HAVE_SECOND_PRECISION")
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return _utc(value, "timestamp").isoformat(timespec="seconds").replace("+00:00", "Z")


def _identifier(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _SAFE_IDENTIFIER.fullmatch(value.strip()):
        raise PlanApprovalError(f"{field_name}_INVALID")
    return value.strip()


@dataclass(frozen=True)
class PlanApprovalBinding:
    approval_id: str
    approval_purpose: str
    plan_id: str
    plan_sha256: str
    client_id: str
    environment: str
    provider: str
    state_profile_id: str
    status: PlanApprovalStatus
    requested_at: datetime
    approved_at: datetime | None
    rejected_at: datetime | None
    expires_at: datetime
    requester_id: str | None = None
    approver_id: str | None = None

    def __post_init__(self) -> None:
        if not _APPROVAL_ID.fullmatch(self.approval_id):
            raise PlanApprovalError("APPROVAL_ID_INVALID")
        if self.approval_purpose != "DEPLOYMENT":
            raise PlanApprovalError("APPROVAL_PURPOSE_INVALID")
        for value, field_name in (
            (self.plan_id, "plan_id"),
            (self.client_id, "client_id"),
            (self.environment, "environment"),
            (self.provider, "provider"),
            (self.state_profile_id, "state_profile_id"),
        ):
            if not isinstance(value, str) or not _SAFE_IDENTIFIER.fullmatch(value):
                raise PlanApprovalError(f"{field_name}_INVALID")
        if self.provider not in {"gcp", "oci"}:
            raise PlanApprovalError("provider_INVALID")
        if not _SHA256.fullmatch(self.plan_sha256):
            raise PlanApprovalError("PLAN_SHA256_INVALID")
        if not isinstance(self.status, PlanApprovalStatus):
            raise PlanApprovalError("APPROVAL_STATUS_INVALID")
        requested = _utc(self.requested_at, "requested_at")
        expires = _utc(self.expires_at, "expires_at")
        approved = _utc(self.approved_at, "approved_at") if self.approved_at else None
        rejected = _utc(self.rejected_at, "rejected_at") if self.rejected_at else None
        if expires < requested:
            raise PlanApprovalError("APPROVAL_EXPIRY_INVALID")
        if self.status is PlanApprovalStatus.PENDING and (approved or rejected):
            raise PlanApprovalError("PENDING_DECISION_FIELDS_INVALID")
        if self.status is PlanApprovalStatus.APPROVED and (not approved or rejected or not self.approver_id):
            raise PlanApprovalError("APPROVED_FIELDS_INVALID")
        if self.status is PlanApprovalStatus.REJECTED and (not rejected or approved):
            raise PlanApprovalError("REJECTED_FIELDS_INVALID")
        if self.status is PlanApprovalStatus.EXPIRED and (approved or rejected):
            raise PlanApprovalError("EXPIRED_FIELDS_INVALID")
        object.__setattr__(self, "requested_at", requested)
        object.__setattr__(self, "expires_at", expires)
        object.__setattr__(self, "approved_at", approved)
        object.__setattr__(self, "rejected_at", rejected)
        object.__setattr__(self, "requester_id", _identifier(self.requester_id, "requester_id"))
        object.__setattr__(self, "approver_id", _identifier(self.approver_id, "approver_id"))

    @property
    def deployment_authorized(self) -> bool:
        return self.status is PlanApprovalStatus.APPROVED

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "approval_purpose": self.approval_purpose,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "client_id": self.client_id,
            "environment": self.environment,
            "provider": self.provider,
            "state_profile_id": self.state_profile_id,
            "status": self.status.value,
            "requested_at": _timestamp(self.requested_at),
            "approved_at": _timestamp(self.approved_at) if self.approved_at else None,
            "rejected_at": _timestamp(self.rejected_at) if self.rejected_at else None,
            "expires_at": _timestamp(self.expires_at),
            "requester_id": self.requester_id,
            "approver_id": self.approver_id,
            "deployment_authorized": self.deployment_authorized,
        }


class PlanApprovalBindingService:
    DEFAULT_TTL = timedelta(minutes=30)
    APPROVAL_FILENAME = "deployment_approval.json"

    def __init__(self, *, now_factory=None, uuid_factory=None, ttl=DEFAULT_TTL):
        self._now_factory = now_factory or (lambda: datetime.now(timezone.utc))
        self._uuid_factory = uuid_factory or uuid4
        if ttl <= timedelta(0):
            raise ValueError("ttl must be positive")
        self.ttl = ttl

    def create(self, saved_plan: SavedPlan, requester_id: str | None = None) -> PlanApprovalBinding:
        now = _utc(self._now_factory(), "requested_at")
        self._validate_plan(saved_plan, now)
        expires = min(now + self.ttl, _parse_timestamp(saved_plan.expires_at))
        binding = PlanApprovalBinding(
            approval_id=f"approval_deployment_{now.strftime('%Y%m%dT%H%M%SZ')}_{self._uuid_factory().hex[:8]}",
            approval_purpose="DEPLOYMENT",
            plan_id=saved_plan.plan_id,
            plan_sha256=saved_plan.plan_sha256,
            client_id=saved_plan.client_id,
            environment=saved_plan.environment,
            provider=saved_plan.provider,
            state_profile_id=saved_plan.state_profile_id,
            status=PlanApprovalStatus.PENDING,
            requested_at=now,
            approved_at=None,
            rejected_at=None,
            expires_at=expires,
            requester_id=requester_id,
        )
        self._persist(saved_plan, binding)
        return binding

    def approve(
        self,
        binding: PlanApprovalBinding,
        saved_plan: SavedPlan,
        approver_id: str,
        approved_at: datetime | None = None,
    ) -> PlanApprovalBinding:
        if binding.status is not PlanApprovalStatus.PENDING:
            raise PlanApprovalError("APPROVAL_TRANSITION_INVALID")
        decided_at = _utc(approved_at or self._now_factory(), "approved_at")
        self._validate_plan(saved_plan, decided_at)
        self._validate_binding(binding, saved_plan, evaluated_at=decided_at, require_approved=False)
        approved = replace(binding, status=PlanApprovalStatus.APPROVED, approved_at=decided_at, approver_id=approver_id)
        self._persist(saved_plan, approved)
        return approved

    def reject(
        self,
        binding: PlanApprovalBinding,
        saved_plan: SavedPlan,
        approver_id: str,
        rejected_at: datetime | None = None,
    ) -> PlanApprovalBinding:
        if binding.status is not PlanApprovalStatus.PENDING:
            raise PlanApprovalError("APPROVAL_TRANSITION_INVALID")
        decided_at = _utc(rejected_at or self._now_factory(), "rejected_at")
        self._validate_plan(saved_plan, decided_at)
        self._validate_binding(binding, saved_plan, evaluated_at=decided_at, require_approved=False)
        rejected = replace(binding, status=PlanApprovalStatus.REJECTED, rejected_at=decided_at, approver_id=approver_id)
        self._persist(saved_plan, rejected)
        return rejected

    def validate(
        self,
        binding: PlanApprovalBinding,
        saved_plan: SavedPlan,
        *,
        evaluated_at: datetime | None = None,
    ) -> None:
        if not isinstance(binding, PlanApprovalBinding):
            raise TypeError("binding must be a PlanApprovalBinding")
        if not isinstance(saved_plan, SavedPlan):
            raise TypeError("saved_plan must be a SavedPlan")
        evaluation_time = _utc(evaluated_at or self._now_factory(), "evaluated_at")
        self._validate_plan(saved_plan, evaluation_time)
        self._validate_binding(binding, saved_plan, evaluated_at=evaluation_time, require_approved=True)

    @staticmethod
    def _validate_binding(
        binding: PlanApprovalBinding,
        saved_plan: SavedPlan,
        *,
        evaluated_at: datetime,
        require_approved: bool,
    ) -> None:
        if binding.expires_at > _parse_timestamp(saved_plan.expires_at):
            raise PlanApprovalError("APPROVAL_EXPIRY_EXCEEDS_PLAN")
        if evaluated_at >= binding.expires_at:
            raise PlanApprovalError("APPROVAL_EXPIRED")
        if any(
            left != right
            for left, right in (
                (binding.approval_purpose, "DEPLOYMENT"),
                (binding.plan_id, saved_plan.plan_id),
                (binding.plan_sha256, saved_plan.plan_sha256),
                (binding.client_id, saved_plan.client_id),
                (binding.environment, saved_plan.environment),
                (binding.provider, saved_plan.provider),
                (binding.state_profile_id, saved_plan.state_profile_id),
            )
        ):
            raise PlanApprovalError("APPROVAL_BINDING_MISMATCH")
        if require_approved and binding.status is not PlanApprovalStatus.APPROVED:
            raise PlanApprovalError("APPROVAL_NOT_AUTHORIZED")

    @staticmethod
    def _validate_plan(saved_plan: SavedPlan, evaluated_at: datetime) -> None:
        try:
            plan_expiry = _parse_timestamp(saved_plan.expires_at)
            if evaluated_at >= plan_expiry:
                raise PlanApprovalError("PLAN_EXPIRED")
            if not saved_plan.plan_path.is_file():
                raise PlanApprovalError("PLAN_ARTIFACT_MISSING")
            if sha256_file(saved_plan.plan_path) != saved_plan.plan_sha256:
                raise PlanApprovalError("PLAN_ARTIFACT_HASH_MISMATCH")
        except SavedPlanError as exc:
            raise PlanApprovalError(str(exc)) from exc

    def _persist(self, saved_plan: SavedPlan, binding: PlanApprovalBinding) -> None:
        directory = saved_plan.plan_path.parent
        path = directory / self.APPROVAL_FILENAME
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=directory,
                prefix=".deployment-approval.", suffix=".tmp", delete=False
            ) as stream:
                json.dump(binding.to_dict(), stream, ensure_ascii=True, indent=2)
                stream.write("\n")
                temporary = Path(stream.name)
            temporary.replace(path)
        except OSError as exc:
            raise PlanApprovalError("APPROVAL_PERSISTENCE_FAILED") from exc
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()


def _parse_timestamp(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise PlanApprovalError("PLAN_TIMESTAMP_INVALID") from exc