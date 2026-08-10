"""Transitions POLICY-5 pures, explicites et sans integration externe."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timezone
from uuid import UUID, uuid4

from security_approval_models import (
    ApprovalAction,
    ApprovalCorrelationError,
    ApprovalNotAllowedError,
    ApprovalRecord,
    ApprovalRequest,
    ApprovalScope,
    ApprovalStatus,
    AuthorizationStatus,
    ControlledAuthorization,
    InvalidApprovalModelError,
    InvalidApprovalTransitionError,
    format_approval_timestamp,
    validate_approval_timestamp,
)
from security_policy_models import PolicyDecision, PolicyDecisionStatus
from security_policy_report import PolicyDecisionReport


class HumanApprovalWorkflow:
    """Machine d'etats stateless consommant une PolicyDecision existante."""

    def __init__(
        self,
        *,
        now_factory: Callable[[], datetime] | None = None,
        uuid_factory: Callable[[], UUID] | None = None,
    ) -> None:
        if now_factory is not None and not callable(now_factory):
            raise TypeError("now_factory doit etre callable ou None")
        if uuid_factory is not None and not callable(uuid_factory):
            raise TypeError("uuid_factory doit etre callable ou None")
        self._now_factory = now_factory or (lambda: datetime.now(timezone.utc))
        self._uuid_factory = uuid_factory or uuid4

    def create_request(
        self,
        decision: PolicyDecision,
        *,
        policy_report: PolicyDecisionReport | None = None,
        requested_by: str = "policy-engine",
        expires_at: datetime | None = None,
        created_at: datetime | None = None,
    ) -> ApprovalRequest:
        """Cree une request sans declencher ni simuler une action humaine."""

        if not isinstance(decision, PolicyDecision):
            raise TypeError("decision doit etre une PolicyDecision")
        if policy_report is not None and not isinstance(
            policy_report,
            PolicyDecisionReport,
        ):
            raise TypeError("policy_report doit etre un PolicyDecisionReport ou None")
        if policy_report is not None:
            self._validate_report_correlation(decision, policy_report)

        creation_time = validate_approval_timestamp(
            created_at if created_at is not None else self._utc_now(),
            "created_at",
        )
        status = {
            PolicyDecisionStatus.ALLOW: ApprovalStatus.NOT_REQUIRED,
            PolicyDecisionStatus.REQUIRE_APPROVAL: ApprovalStatus.PENDING,
            PolicyDecisionStatus.BLOCK: ApprovalStatus.NOT_ALLOWED,
        }[decision.decision]
        request_id = self._build_request_id(creation_time, self._new_uuid())
        findings = decision.triggered_findings + decision.excepted_findings
        scope = ApprovalScope(
            clouds=tuple(finding.cloud for finding in findings),
            triggered_rule_ids=decision.triggered_rules
            + tuple(finding.rule_id for finding in findings),
            resource_addresses=tuple(
                finding.resource_address for finding in findings
            ),
        )
        return ApprovalRequest(
            request_id=request_id,
            policy_report_run_id=(
                policy_report.run_id if policy_report is not None else None
            ),
            security_run_id=(
                policy_report.security_context.security_run_id
                if policy_report is not None
                else None
            ),
            terraform_run_id=(
                policy_report.terraform_context.terraform_run_id
                if policy_report is not None
                and policy_report.terraform_context is not None
                else None
            ),
            policy_id=decision.policy_id,
            policy_version=decision.policy_version,
            profile=decision.profile,
            policy_decision=decision.decision,
            reason_code=decision.reason_code,
            status=status,
            created_at=creation_time,
            expires_at=expires_at,
            requested_by=requested_by,
            scope=scope,
            approval_required=decision.requires_human_approval,
        )

    def approve(
        self,
        request: ApprovalRequest,
        *,
        approver_id: str,
        reason: str,
        decided_at: datetime | None = None,
    ) -> tuple[ApprovalRequest, ApprovalRecord]:
        return self._record_decision(
            request,
            action=ApprovalAction.APPROVE,
            approver_id=approver_id,
            reason=reason,
            decided_at=decided_at,
        )

    def reject(
        self,
        request: ApprovalRequest,
        *,
        approver_id: str,
        reason: str,
        decided_at: datetime | None = None,
    ) -> tuple[ApprovalRequest, ApprovalRecord]:
        return self._record_decision(
            request,
            action=ApprovalAction.REJECT,
            approver_id=approver_id,
            reason=reason,
            decided_at=decided_at,
        )

    def check_expiration(
        self,
        request: ApprovalRequest,
        *,
        evaluated_at: datetime | None = None,
    ) -> ApprovalRequest:
        """Retourne une nouvelle request EXPIRED lorsque l'echeance est atteinte."""

        self._require_request(request)
        if request.status is not ApprovalStatus.PENDING or request.expires_at is None:
            return request
        evaluation_time = evaluated_at if evaluated_at is not None else self._utc_now()
        self._validate_transition_time(request, evaluation_time, "evaluated_at")
        if evaluation_time < request.expires_at:
            return request
        return replace(request, status=ApprovalStatus.EXPIRED)

    def build_authorization(
        self,
        request: ApprovalRequest,
        *,
        decision: PolicyDecision,
        approval_record: ApprovalRecord | None = None,
        evaluated_at: datetime | None = None,
    ) -> ControlledAuthorization:
        """Produit une autorisation logique sans executer la phase suivante."""

        self._require_request(request)
        self._validate_decision_correlation(request, decision)
        effective_request = self.check_expiration(
            request,
            evaluated_at=evaluated_at,
        )
        self._validate_record_correlation(effective_request, approval_record)
        authorization_status = {
            ApprovalStatus.NOT_REQUIRED: AuthorizationStatus.AUTHORIZED,
            ApprovalStatus.PENDING: AuthorizationStatus.PENDING_APPROVAL,
            ApprovalStatus.APPROVED: AuthorizationStatus.AUTHORIZED,
            ApprovalStatus.REJECTED: AuthorizationStatus.REJECTED,
            ApprovalStatus.NOT_ALLOWED: AuthorizationStatus.BLOCKED,
            ApprovalStatus.EXPIRED: AuthorizationStatus.EXPIRED,
        }[effective_request.status]
        messages = {
            AuthorizationStatus.AUTHORIZED: (
                "Governance permits a potential next phase; no execution performed."
            ),
            AuthorizationStatus.PENDING_APPROVAL: (
                "Explicit human approval is still required."
            ),
            AuthorizationStatus.REJECTED: "The explicit human review rejected the request.",
            AuthorizationStatus.BLOCKED: "The policy decision blocks authorization.",
            AuthorizationStatus.EXPIRED: "The approval request expired.",
        }
        human_approval = (
            approval_record
            if effective_request.status
            in {ApprovalStatus.APPROVED, ApprovalStatus.REJECTED}
            else None
        )
        return ControlledAuthorization(
            authorization_status=authorization_status,
            policy_decision=effective_request.policy_decision,
            approval_status=effective_request.status,
            request_id=effective_request.request_id,
            policy_id=effective_request.policy_id,
            policy_version=effective_request.policy_version,
            policy_report_run_id=effective_request.policy_report_run_id,
            authorized_at=(
                human_approval.decided_at
                if effective_request.status is ApprovalStatus.APPROVED
                and human_approval is not None
                else None
            ),
            approver_id=(
                human_approval.approver_id
                if human_approval is not None
                else None
            ),
            reason_code=effective_request.reason_code,
            message=messages[authorization_status],
        )

    def _record_decision(
        self,
        request: ApprovalRequest,
        *,
        action: ApprovalAction,
        approver_id: str,
        reason: str,
        decided_at: datetime | None,
    ) -> tuple[ApprovalRequest, ApprovalRecord]:
        self._require_request(request)
        if request.status in {
            ApprovalStatus.NOT_ALLOWED,
            ApprovalStatus.NOT_REQUIRED,
        }:
            raise ApprovalNotAllowedError(
                f"aucune action humaine permise depuis {request.status.value}"
            )
        if request.status is not ApprovalStatus.PENDING:
            raise InvalidApprovalTransitionError(
                f"transition impossible depuis {request.status.value}"
            )
        decision_time = decided_at if decided_at is not None else self._utc_now()
        self._validate_transition_time(request, decision_time, "decided_at")
        if request.expires_at is not None and decision_time >= request.expires_at:
            raise InvalidApprovalTransitionError(
                "la request est expiree et ne peut plus etre decidee"
            )
        new_status = {
            ApprovalAction.APPROVE: ApprovalStatus.APPROVED,
            ApprovalAction.REJECT: ApprovalStatus.REJECTED,
        }[action]
        record = ApprovalRecord(
            request_id=request.request_id,
            action=action,
            approver_id=approver_id,
            reason=reason,
            decided_at=decision_time,
            previous_status=request.status,
            new_status=new_status,
        )
        return replace(request, status=new_status), record

    @staticmethod
    def _require_request(request: ApprovalRequest) -> None:
        if not isinstance(request, ApprovalRequest):
            raise TypeError("request doit etre une ApprovalRequest")

    @staticmethod
    def _validate_transition_time(
        request: ApprovalRequest,
        value: datetime,
        field_name: str,
    ) -> None:
        try:
            normalized = validate_approval_timestamp(value, field_name)
        except InvalidApprovalModelError as exc:
            raise InvalidApprovalTransitionError(
                f"{field_name} invalide"
            ) from exc
        if normalized < request.created_at:
            raise InvalidApprovalTransitionError(
                f"{field_name} ne peut pas preceder created_at"
            )

    @staticmethod
    def _validate_report_correlation(
        decision: PolicyDecision,
        report: PolicyDecisionReport,
    ) -> None:
        checks = (
            (report.policy.get("policy_id"), decision.policy_id, "policy_id"),
            (
                report.policy.get("policy_version"),
                decision.policy_version,
                "policy_version",
            ),
            (report.policy.get("profile"), decision.profile.value, "profile"),
            (report.decision.get("status"), decision.decision.value, "decision"),
            (
                report.decision.get("reason_code"),
                decision.reason_code.value,
                "reason_code",
            ),
        )
        for actual, expected, field_name in checks:
            if actual != expected:
                raise ApprovalCorrelationError(
                    f"policy_report {field_name} incoherent"
                )

    @staticmethod
    def _validate_decision_correlation(
        request: ApprovalRequest,
        decision: PolicyDecision,
    ) -> None:
        if not isinstance(decision, PolicyDecision):
            raise TypeError("decision doit etre une PolicyDecision")
        checks = (
            (request.policy_id, decision.policy_id, "policy_id"),
            (request.policy_version, decision.policy_version, "policy_version"),
            (request.profile, decision.profile, "profile"),
            (request.policy_decision, decision.decision, "policy_decision"),
            (request.reason_code, decision.reason_code, "reason_code"),
        )
        for actual, expected, field_name in checks:
            if actual != expected:
                raise ApprovalCorrelationError(f"{field_name} incoherent")

    @staticmethod
    def _validate_record_correlation(
        request: ApprovalRequest,
        record: ApprovalRecord | None,
    ) -> None:
        record_required = request.status in {
            ApprovalStatus.APPROVED,
            ApprovalStatus.REJECTED,
        }
        if record_required and record is None:
            raise ApprovalCorrelationError(
                "un ApprovalRecord est requis pour ce statut"
            )
        if not record_required and record is not None:
            raise ApprovalCorrelationError(
                "ApprovalRecord inattendu pour ce statut"
            )
        if record is None:
            return
        if not isinstance(record, ApprovalRecord):
            raise TypeError("approval_record doit etre un ApprovalRecord ou None")
        if record.request_id != request.request_id:
            raise ApprovalCorrelationError("request_id du record incoherent")
        if record.new_status is not request.status:
            raise ApprovalCorrelationError("statut du record incoherent")

    def _utc_now(self) -> datetime:
        value = self._now_factory()
        if not isinstance(value, datetime):
            raise InvalidApprovalModelError("now_factory doit retourner un datetime")
        return value

    def _new_uuid(self) -> UUID:
        value = self._uuid_factory()
        if not isinstance(value, UUID):
            raise InvalidApprovalModelError("uuid_factory doit retourner un UUID")
        return value

    @staticmethod
    def _build_request_id(created_at: datetime, value: UUID) -> str:
        timestamp = format_approval_timestamp(created_at).replace("-", "").replace(":", "")
        return f"approval_{timestamp}_{value.hex[:8]}"
