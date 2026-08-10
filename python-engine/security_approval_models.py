"""Modeles immuables du workflow d'approbation humaine POLICY-5.

Une autorisation de gouvernance n'execute aucun deploiement. Les modeles de ce
module ne contiennent ni valeurs Terraform brutes, ni attributs de securite, ni
credentials.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from security_policy_models import (
    PolicyDecisionStatus,
    PolicyReasonCode,
    SecurityPolicyProfile,
)


_APPROVAL_REQUEST_ID_PATTERN = re.compile(
    r"\Aapproval_\d{8}T\d{6}Z_[0-9a-f]{8}\Z"
)
_SAFE_IDENTIFIER_PATTERN = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:@/-]*\Z")
_SENSITIVE_MARKER_PATTERN = re.compile(
    r"password|token|private[ _-]?key|secret",
    re.IGNORECASE,
)


class ApprovalWorkflowError(ValueError):
    """Erreur metier racine du workflow d'approbation."""


class InvalidApprovalModelError(ApprovalWorkflowError):
    """Un modele d'approbation est invalide ou incoherent."""


class InvalidApprovalTransitionError(ApprovalWorkflowError):
    """La transition demandee n'est pas permise par la machine d'etats."""


class ApprovalNotAllowedError(InvalidApprovalTransitionError):
    """La decision policy interdit toute action humaine d'approbation."""


class ApprovalCorrelationError(ApprovalWorkflowError):
    """Les identifiants de policy, rapport ou request ne correspondent pas."""


class ApprovalStatus(str, Enum):
    NOT_REQUIRED = "NOT_REQUIRED"
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    NOT_ALLOWED = "NOT_ALLOWED"
    EXPIRED = "EXPIRED"


class AuthorizationStatus(str, Enum):
    AUTHORIZED = "AUTHORIZED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    REJECTED = "REJECTED"
    BLOCKED = "BLOCKED"
    EXPIRED = "EXPIRED"


class ApprovalAction(str, Enum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"


def _require_text(
    value: str,
    field_name: str,
    *,
    reject_sensitive_markers: bool = True,
) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidApprovalModelError(
            f"{field_name} doit etre une chaine non vide"
        )
    normalized = value.strip()
    if any(character in normalized for character in ("\r", "\n", "\x00")):
        raise InvalidApprovalModelError(f"{field_name} contient un controle interdit")
    if reject_sensitive_markers and _SENSITIVE_MARKER_PATTERN.search(normalized):
        raise InvalidApprovalModelError(
            f"{field_name} contient un marqueur sensible interdit"
        )
    return normalized


def _require_identifier(value: str, field_name: str) -> str:
    normalized = _require_text(value, field_name)
    if not _SAFE_IDENTIFIER_PATTERN.fullmatch(normalized):
        raise InvalidApprovalModelError(f"{field_name} invalide")
    return normalized


def _require_request_id(value: str) -> str:
    normalized = _require_text(value, "request_id")
    if not _APPROVAL_REQUEST_ID_PATTERN.fullmatch(normalized):
        raise InvalidApprovalModelError("request_id invalide")
    return normalized


def _optional_identifier(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_identifier(value, field_name)


def _require_utc(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise InvalidApprovalModelError(f"{field_name} doit etre un datetime")
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise InvalidApprovalModelError(f"{field_name} doit etre UTC-aware")
    if value.microsecond:
        raise InvalidApprovalModelError(
            f"{field_name} doit avoir une precision a la seconde"
        )
    return value.astimezone(timezone.utc)


def format_approval_timestamp(value: datetime) -> str:
    """Formate un datetime valide en UTC ISO-8601 stable."""

    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def validate_approval_timestamp(
    value: datetime,
    field_name: str = "timestamp",
) -> datetime:
    """Valide et normalise un timestamp de transition en UTC."""

    return _require_utc(value, field_name)


def _stable_safe_values(values: tuple[str, ...], field_name: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise InvalidApprovalModelError(f"{field_name} doit etre une collection")
    try:
        supplied = tuple(values)
    except TypeError as exc:
        raise InvalidApprovalModelError(
            f"{field_name} doit etre une collection"
        ) from exc
    normalized = tuple(_require_text(value, field_name) for value in supplied)
    return tuple(sorted(set(normalized)))


@dataclass(frozen=True)
class ApprovalScope:
    """Projection minimale permettant une revue sans recopier les findings."""

    clouds: tuple[str, ...] = ()
    triggered_rule_ids: tuple[str, ...] = ()
    resource_addresses: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        clouds = _stable_safe_values(self.clouds, "clouds")
        if any(cloud not in {"gcp", "oci"} for cloud in clouds):
            raise InvalidApprovalModelError("clouds contient un cloud non supporte")
        object.__setattr__(self, "clouds", clouds)
        object.__setattr__(
            self,
            "triggered_rule_ids",
            _stable_safe_values(self.triggered_rule_ids, "triggered_rule_ids"),
        )
        object.__setattr__(
            self,
            "resource_addresses",
            _stable_safe_values(self.resource_addresses, "resource_addresses"),
        )

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "clouds": list(self.clouds),
            "triggered_rule_ids": list(self.triggered_rule_ids),
            "resource_addresses": list(self.resource_addresses),
        }


@dataclass(frozen=True)
class ApprovalRequest:
    """Snapshot immutable d'une demande et de ses correlations sures."""

    request_id: str
    policy_report_run_id: str | None
    security_run_id: str | None
    terraform_run_id: str | None
    policy_id: str
    policy_version: str
    profile: SecurityPolicyProfile
    policy_decision: PolicyDecisionStatus
    reason_code: PolicyReasonCode
    status: ApprovalStatus
    created_at: datetime
    expires_at: datetime | None
    requested_by: str
    scope: ApprovalScope
    approval_required: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", _require_request_id(self.request_id))
        for field_name in (
            "policy_report_run_id",
            "security_run_id",
            "terraform_run_id",
        ):
            object.__setattr__(
                self,
                field_name,
                _optional_identifier(getattr(self, field_name), field_name),
            )
        object.__setattr__(self, "policy_id", _require_identifier(self.policy_id, "policy_id"))
        object.__setattr__(
            self,
            "policy_version",
            _require_identifier(self.policy_version, "policy_version"),
        )
        object.__setattr__(
            self,
            "requested_by",
            _require_identifier(self.requested_by, "requested_by"),
        )
        if not isinstance(self.profile, SecurityPolicyProfile):
            raise InvalidApprovalModelError("profile invalide")
        if not isinstance(self.policy_decision, PolicyDecisionStatus):
            raise InvalidApprovalModelError("policy_decision invalide")
        if not isinstance(self.reason_code, PolicyReasonCode):
            raise InvalidApprovalModelError("reason_code invalide")
        if not isinstance(self.status, ApprovalStatus):
            raise InvalidApprovalModelError("status invalide")
        if not isinstance(self.scope, ApprovalScope):
            raise InvalidApprovalModelError("scope doit etre un ApprovalScope")
        if not isinstance(self.approval_required, bool):
            raise InvalidApprovalModelError("approval_required doit etre un booleen")
        object.__setattr__(self, "created_at", _require_utc(self.created_at, "created_at"))
        if self.expires_at is not None:
            expires_at = _require_utc(self.expires_at, "expires_at")
            if expires_at <= self.created_at:
                raise InvalidApprovalModelError("expires_at doit suivre created_at")
            object.__setattr__(self, "expires_at", expires_at)

        allowed_statuses = {
            PolicyDecisionStatus.ALLOW: {ApprovalStatus.NOT_REQUIRED},
            PolicyDecisionStatus.REQUIRE_APPROVAL: {
                ApprovalStatus.PENDING,
                ApprovalStatus.APPROVED,
                ApprovalStatus.REJECTED,
                ApprovalStatus.EXPIRED,
            },
            PolicyDecisionStatus.BLOCK: {ApprovalStatus.NOT_ALLOWED},
        }[self.policy_decision]
        if self.status not in allowed_statuses:
            raise InvalidApprovalModelError(
                "status incoherent avec la decision policy"
            )
        expected_required = self.policy_decision is PolicyDecisionStatus.REQUIRE_APPROVAL
        if self.approval_required is not expected_required:
            raise InvalidApprovalModelError(
                "approval_required incoherent avec la decision policy"
            )
        if not expected_required and self.expires_at is not None:
            raise InvalidApprovalModelError(
                "expires_at est reserve aux demandes d'approbation"
            )
        if self.status is ApprovalStatus.EXPIRED and self.expires_at is None:
            raise InvalidApprovalModelError("une request EXPIRED requiert expires_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "policy_report_run_id": self.policy_report_run_id,
            "security_run_id": self.security_run_id,
            "terraform_run_id": self.terraform_run_id,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "profile": self.profile.value,
            "policy_decision": self.policy_decision.value,
            "reason_code": self.reason_code.value,
            "status": self.status.value,
            "created_at": format_approval_timestamp(self.created_at),
            "expires_at": (
                format_approval_timestamp(self.expires_at)
                if self.expires_at is not None
                else None
            ),
            "requested_by": self.requested_by,
            "scope": self.scope.to_dict(),
            "approval_required": self.approval_required,
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


@dataclass(frozen=True)
class ApprovalRecord:
    """Trace immutable d'une action humaine explicite."""

    request_id: str
    action: ApprovalAction
    approver_id: str
    reason: str
    decided_at: datetime
    previous_status: ApprovalStatus
    new_status: ApprovalStatus

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", _require_request_id(self.request_id))
        if not isinstance(self.action, ApprovalAction):
            raise InvalidApprovalModelError("action invalide")
        object.__setattr__(
            self,
            "approver_id",
            _require_identifier(self.approver_id, "approver_id"),
        )
        object.__setattr__(self, "reason", _require_text(self.reason, "reason"))
        object.__setattr__(self, "decided_at", _require_utc(self.decided_at, "decided_at"))
        if self.previous_status is not ApprovalStatus.PENDING:
            raise InvalidApprovalModelError("previous_status doit etre PENDING")
        expected_new_status = {
            ApprovalAction.APPROVE: ApprovalStatus.APPROVED,
            ApprovalAction.REJECT: ApprovalStatus.REJECTED,
        }[self.action]
        if self.new_status is not expected_new_status:
            raise InvalidApprovalModelError("new_status incoherent avec action")

    def to_dict(self) -> dict[str, str]:
        return {
            "request_id": self.request_id,
            "action": self.action.value,
            "approver_id": self.approver_id,
            "reason": self.reason,
            "decided_at": format_approval_timestamp(self.decided_at),
            "previous_status": self.previous_status.value,
            "new_status": self.new_status.value,
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


@dataclass(frozen=True)
class ControlledAuthorization:
    """Autorisation logique de gouvernance, sans effet d'execution."""

    authorization_status: AuthorizationStatus
    policy_decision: PolicyDecisionStatus
    approval_status: ApprovalStatus
    request_id: str
    policy_id: str
    policy_version: str
    policy_report_run_id: str | None
    authorized_at: datetime | None
    approver_id: str | None
    reason_code: PolicyReasonCode
    message: str
    execution_performed: bool = field(default=False, init=False)
    terraform_apply_executed: bool = field(default=False, init=False)
    terraform_destroy_executed: bool = field(default=False, init=False)
    cloud_write_executed: bool = field(default=False, init=False)
    auto_approval_executed: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.authorization_status, AuthorizationStatus):
            raise InvalidApprovalModelError("authorization_status invalide")
        if not isinstance(self.policy_decision, PolicyDecisionStatus):
            raise InvalidApprovalModelError("policy_decision invalide")
        if not isinstance(self.approval_status, ApprovalStatus):
            raise InvalidApprovalModelError("approval_status invalide")
        object.__setattr__(self, "request_id", _require_request_id(self.request_id))
        object.__setattr__(self, "policy_id", _require_identifier(self.policy_id, "policy_id"))
        object.__setattr__(
            self,
            "policy_version",
            _require_identifier(self.policy_version, "policy_version"),
        )
        object.__setattr__(
            self,
            "policy_report_run_id",
            _optional_identifier(self.policy_report_run_id, "policy_report_run_id"),
        )
        if not isinstance(self.reason_code, PolicyReasonCode):
            raise InvalidApprovalModelError("reason_code invalide")
        object.__setattr__(self, "message", _require_text(self.message, "message"))
        if self.authorized_at is not None:
            object.__setattr__(
                self,
                "authorized_at",
                _require_utc(self.authorized_at, "authorized_at"),
            )
        if self.approver_id is not None:
            object.__setattr__(
                self,
                "approver_id",
                _require_identifier(self.approver_id, "approver_id"),
            )

        expected_status = {
            (PolicyDecisionStatus.ALLOW, ApprovalStatus.NOT_REQUIRED): AuthorizationStatus.AUTHORIZED,
            (PolicyDecisionStatus.REQUIRE_APPROVAL, ApprovalStatus.PENDING): AuthorizationStatus.PENDING_APPROVAL,
            (PolicyDecisionStatus.REQUIRE_APPROVAL, ApprovalStatus.APPROVED): AuthorizationStatus.AUTHORIZED,
            (PolicyDecisionStatus.REQUIRE_APPROVAL, ApprovalStatus.REJECTED): AuthorizationStatus.REJECTED,
            (PolicyDecisionStatus.REQUIRE_APPROVAL, ApprovalStatus.EXPIRED): AuthorizationStatus.EXPIRED,
            (PolicyDecisionStatus.BLOCK, ApprovalStatus.NOT_ALLOWED): AuthorizationStatus.BLOCKED,
        }.get((self.policy_decision, self.approval_status))
        if self.authorization_status is not expected_status:
            raise InvalidApprovalModelError("authorization incoherente")
        human_approved = self.approval_status is ApprovalStatus.APPROVED
        if human_approved and (
            self.authorized_at is None or self.approver_id is None
        ):
            raise InvalidApprovalModelError(
                "une autorisation approuvee requiert date et approver_id"
            )
        if not human_approved and self.authorized_at is not None:
            raise InvalidApprovalModelError(
                "authorized_at est reserve a une approbation humaine"
            )
        if self.approval_status in {
            ApprovalStatus.PENDING,
            ApprovalStatus.NOT_REQUIRED,
            ApprovalStatus.NOT_ALLOWED,
            ApprovalStatus.EXPIRED,
        } and self.approver_id is not None:
            raise InvalidApprovalModelError("approver_id inattendu pour ce statut")

    @property
    def authorized(self) -> bool:
        return self.authorization_status is AuthorizationStatus.AUTHORIZED

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorization_status": self.authorization_status.value,
            "authorized": self.authorized,
            "policy_decision": self.policy_decision.value,
            "approval_status": self.approval_status.value,
            "request_id": self.request_id,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_report_run_id": self.policy_report_run_id,
            "authorized_at": (
                format_approval_timestamp(self.authorized_at)
                if self.authorized_at is not None
                else None
            ),
            "approver_id": self.approver_id,
            "reason_code": self.reason_code.value,
            "message": self.message,
            "safety": {
                "execution_performed": self.execution_performed,
                "terraform_apply_executed": self.terraform_apply_executed,
                "terraform_destroy_executed": self.terraform_destroy_executed,
                "cloud_write_executed": self.cloud_write_executed,
                "auto_approval_executed": self.auto_approval_executed,
            },
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)
