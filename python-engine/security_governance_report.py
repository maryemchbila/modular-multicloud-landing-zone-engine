"""Rapport final POLICY-6, limite a des contextes de gouvernance surs."""

from __future__ import annotations

import json
import re
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any
from uuid import UUID, uuid4

from security_approval_models import (
    ApprovalRecord,
    ApprovalRequest,
    ApprovalStatus,
    ControlledAuthorization,
    format_approval_timestamp,
)
from security_policy_e2e import TerraformSecurityPolicyEndToEndResult


_GOVERNANCE_RUN_ID_PATTERN = re.compile(
    r"\Agovernance_\d{8}T\d{6}Z_[0-9a-f]{8}\Z"
)
_UTC_TIMESTAMP_PATTERN = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_SENSITIVE_MARKER_PATTERN = re.compile(
    r"password|token|private[ _-]?key|secret",
    re.IGNORECASE,
)


class InvalidGovernanceReportInputError(ValueError):
    """Les objets fournis ne permettent pas un audit coherent et sur."""


def _safe_context(
    value: Mapping[str, Any] | None,
    field_name: str,
) -> Mapping[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise InvalidGovernanceReportInputError(f"{field_name} doit etre un mapping")
    snapshot = dict(value)
    for key, item in snapshot.items():
        if not isinstance(key, str) or not key:
            raise InvalidGovernanceReportInputError(f"{field_name} contient une cle invalide")
        if not isinstance(item, (str, int, bool, type(None))):
            raise InvalidGovernanceReportInputError(
                f"{field_name}.{key} contient une valeur non sure"
            )
        if isinstance(item, str) and _SENSITIVE_MARKER_PATTERN.search(item):
            raise InvalidGovernanceReportInputError(
                f"{field_name}.{key} contient un marqueur sensible"
            )
    return MappingProxyType(snapshot)


def _require_keys(
    context: Mapping[str, Any] | None,
    field_name: str,
    required: set[str],
) -> None:
    if context is None or not required.issubset(context):
        raise InvalidGovernanceReportInputError(
            f"{field_name} ne contient pas les champs requis"
        )


@dataclass(frozen=True)
class GovernanceAuditReport:
    """Snapshot final sans donnees Terraform/Security brutes.

    ``AUTHORIZED`` signifie uniquement que la gouvernance permet une phase
    potentielle suivante. Ce rapport ne prouve et ne declenche aucun deployment.
    """

    schema_version: str
    run_id: str
    generated_at: str
    terraform: Mapping[str, Any] | None
    security: Mapping[str, Any] | None
    policy: Mapping[str, Any]
    approval: Mapping[str, Any]
    authorization: Mapping[str, Any]
    safety: Mapping[str, bool]

    def __post_init__(self) -> None:
        if self.schema_version != "1.0":
            raise InvalidGovernanceReportInputError("schema_version non supportee")
        if not isinstance(self.run_id, str) or not _GOVERNANCE_RUN_ID_PATTERN.fullmatch(self.run_id):
            raise InvalidGovernanceReportInputError("run_id governance invalide")
        if not isinstance(self.generated_at, str) or not _UTC_TIMESTAMP_PATTERN.fullmatch(self.generated_at):
            raise InvalidGovernanceReportInputError("generated_at doit etre UTC")
        object.__setattr__(self, "terraform", _safe_context(self.terraform, "terraform"))
        object.__setattr__(self, "security", _safe_context(self.security, "security"))
        object.__setattr__(self, "policy", _safe_context(self.policy, "policy"))
        object.__setattr__(self, "approval", _safe_context(self.approval, "approval"))
        object.__setattr__(self, "authorization", _safe_context(self.authorization, "authorization"))
        object.__setattr__(self, "safety", _safe_context(self.safety, "safety"))
        if self.terraform is not None:
            _require_keys(self.terraform, "terraform", {"run_id", "status", "plan_status"})
        if self.security is not None:
            _require_keys(
                self.security,
                "security",
                {"run_id", "status", "resources_total", "findings_total"},
            )
        _require_keys(
            self.policy,
            "policy",
            {"run_id", "policy_id", "policy_version", "profile", "decision", "reason_code"},
        )
        _require_keys(
            self.approval,
            "approval",
            {"request_id", "status", "human_action_required"},
        )
        _require_keys(
            self.authorization,
            "authorization",
            {"status", "authorized", "execution_performed"},
        )
        expected_safety = {
            "terraform_apply_executed": False,
            "terraform_destroy_executed": False,
            "cloud_write_executed": False,
            "auto_approval_executed": False,
        }
        if dict(self.safety) != expected_safety:
            raise InvalidGovernanceReportInputError("safety governance invalide")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "generated_at": self.generated_at,
            "terraform": dict(self.terraform) if self.terraform is not None else None,
            "security": dict(self.security) if self.security is not None else None,
            "policy": dict(self.policy),
            "approval": dict(self.approval),
            "authorization": dict(self.authorization),
            "safety": dict(self.safety),
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def render_text(self) -> str:
        separator = "=" * 70
        section = "-" * 70
        terraform = self.terraform
        security = self.security
        approval = self.approval
        lines = [
            separator,
            " FINAL GOVERNANCE AUDIT",
            separator,
            f"Governance Run : {self.run_id}",
            f"Generated      : {self.generated_at}",
            "",
            section,
            " TERRAFORM",
            section,
            f"Run ID         : {terraform['run_id'] if terraform else 'N/A'}",
            f"Status         : {terraform['status'] if terraform else 'N/A'}",
            f"Plan           : {terraform['plan_status'] if terraform else 'N/A'}",
            "",
            section,
            " SECURITY",
            section,
            f"Run ID         : {security['run_id'] if security and security['run_id'] else 'N/A'}",
            f"Status         : {security['status'] if security else 'N/A'}",
            f"Resources      : {security['resources_total'] if security else 'N/A'}",
            f"Findings       : {security['findings_total'] if security else 'N/A'}",
            "",
            section,
            " POLICY",
            section,
            f"Report Run     : {self.policy['run_id']}",
            f"Policy         : {self.policy['policy_id']}",
            f"Version        : {self.policy['policy_version']}",
            f"Profile        : {self.policy['profile']}",
            f"Decision       : {self.policy['decision']}",
            f"Reason         : {self.policy['reason_code']}",
            "",
            section,
            " HUMAN APPROVAL",
            section,
            f"Request ID     : {approval['request_id']}",
            f"Status         : {approval['status']}",
            "Human action required : " + self._yes_no(approval["human_action_required"]),
        ]
        if "approver_id" in approval:
            lines.extend(
                [
                    f"Action         : {approval['action']}",
                    f"Approver       : {approval['approver_id']}",
                    f"Reason         : {approval['reason']}",
                    f"Decided        : {approval['decided_at']}",
                ]
            )
        lines.extend(
            [
                "",
                section,
                " AUTHORIZATION",
                section,
                f"Status         : {self.authorization['status']}",
                "Execution      : NO",
                "Blocked by policy : "
                + self._yes_no(self.authorization["status"] == "BLOCKED"),
                "",
                section,
                " SAFETY",
                section,
                "Terraform Apply  : NO",
                "Terraform Destroy: NO",
                "Cloud Write      : NO",
                "Auto Approval    : NO",
                separator,
            ]
        )
        return "\n".join(lines)

    @staticmethod
    def _yes_no(value: bool) -> str:
        return "YES" if value else "NO"


class GovernanceAuditReportBuilder:
    """Construit et ecrit l'audit final sans recalculer aucune decision."""

    SCHEMA_VERSION = "1.0"
    DEFAULT_REPORT_DIRECTORY = Path("artifacts") / "governance" / "reports"

    def __init__(
        self,
        repository_root: Path | None = None,
        now_factory: Callable[[], datetime] | None = None,
        uuid_factory: Callable[[], UUID] | None = None,
    ) -> None:
        self.repository_root = (
            Path(repository_root).expanduser().resolve()
            if repository_root is not None
            else Path(__file__).resolve().parent.parent
        )
        self._now_factory = now_factory or (lambda: datetime.now(timezone.utc))
        self._uuid_factory = uuid_factory or uuid4

    def build(
        self,
        *,
        policy_pipeline_result: TerraformSecurityPolicyEndToEndResult,
        approval_request: ApprovalRequest,
        authorization: ControlledAuthorization,
        approval_record: ApprovalRecord | None = None,
    ) -> GovernanceAuditReport:
        self._validate_inputs(
            policy_pipeline_result,
            approval_request,
            authorization,
            approval_record,
        )
        generated_datetime = self._utc_now()
        policy_report = policy_pipeline_result.policy_report
        terraform_context = policy_report.terraform_context
        security_context = policy_report.security_context
        approval_context: dict[str, Any] = {
            "request_id": approval_request.request_id,
            "status": approval_request.status.value,
            "human_action_required": approval_request.status is ApprovalStatus.PENDING,
        }
        if approval_record is not None:
            approval_context.update(
                {
                    "action": approval_record.action.value,
                    "approver_id": approval_record.approver_id,
                    "reason": approval_record.reason,
                    "decided_at": format_approval_timestamp(approval_record.decided_at),
                }
            )
        return GovernanceAuditReport(
            schema_version=self.SCHEMA_VERSION,
            run_id=self._build_run_id(generated_datetime, self._new_uuid()),
            generated_at=self._format_utc(generated_datetime),
            terraform=(
                {
                    "run_id": terraform_context.terraform_run_id,
                    "status": terraform_context.terraform_final_status,
                    "plan_status": terraform_context.plan_status,
                }
                if terraform_context is not None
                else None
            ),
            security={
                "run_id": security_context.security_run_id,
                "status": security_context.security_evaluation_status,
                "resources_total": security_context.resources_total,
                "findings_total": security_context.findings_total,
            },
            policy={
                "run_id": policy_report.run_id,
                "policy_id": approval_request.policy_id,
                "policy_version": approval_request.policy_version,
                "profile": approval_request.profile.value,
                "decision": approval_request.policy_decision.value,
                "reason_code": approval_request.reason_code.value,
            },
            approval=approval_context,
            authorization={
                "status": authorization.authorization_status.value,
                "authorized": authorization.authorized,
                "execution_performed": authorization.execution_performed,
            },
            safety={
                "terraform_apply_executed": False,
                "terraform_destroy_executed": False,
                "cloud_write_executed": False,
                "auto_approval_executed": False,
            },
        )

    def write_report(
        self,
        report: GovernanceAuditReport,
        output_directory: Path | None = None,
    ) -> tuple[Path, Path]:
        if not isinstance(report, GovernanceAuditReport):
            raise TypeError("report doit etre un GovernanceAuditReport")
        report_directory = (
            Path(output_directory).expanduser().resolve()
            if output_directory is not None
            else (self.repository_root / self.DEFAULT_REPORT_DIRECTORY).resolve()
        )
        report_directory.mkdir(parents=True, exist_ok=True)
        json_path = report_directory / f"{report.run_id}.json"
        text_path = report_directory / f"{report.run_id}.txt"
        self._write_atomic(json_path, report.to_json() + "\n")
        self._write_atomic(text_path, report.render_text() + "\n")
        return json_path, text_path

    @staticmethod
    def _validate_inputs(
        policy_result: TerraformSecurityPolicyEndToEndResult,
        request: ApprovalRequest,
        authorization: ControlledAuthorization,
        record: ApprovalRecord | None,
    ) -> None:
        if not isinstance(policy_result, TerraformSecurityPolicyEndToEndResult):
            raise TypeError("policy_pipeline_result invalide")
        if not isinstance(request, ApprovalRequest):
            raise TypeError("approval_request invalide")
        if not isinstance(authorization, ControlledAuthorization):
            raise TypeError("authorization invalide")
        if record is not None and not isinstance(record, ApprovalRecord):
            raise TypeError("approval_record invalide")
        decision = policy_result.policy_decision
        report = policy_result.policy_report
        if decision is None or report is None:
            raise InvalidGovernanceReportInputError(
                "decision et policy report sont requis"
            )
        checks = (
            (request.policy_id, decision.policy_id, "policy_id"),
            (request.policy_version, decision.policy_version, "policy_version"),
            (request.policy_decision, decision.decision, "policy_decision"),
            (request.policy_report_run_id, report.run_id, "policy_report_run_id"),
            (authorization.request_id, request.request_id, "request_id"),
            (authorization.policy_id, request.policy_id, "authorization policy_id"),
            (authorization.policy_version, request.policy_version, "authorization policy_version"),
            (authorization.approval_status, request.status, "approval_status"),
            (authorization.policy_report_run_id, request.policy_report_run_id, "authorization policy run"),
        )
        for actual, expected, field_name in checks:
            if actual != expected:
                raise InvalidGovernanceReportInputError(f"{field_name} incoherent")
        record_required = request.status in {ApprovalStatus.APPROVED, ApprovalStatus.REJECTED}
        if record_required and record is None:
            raise InvalidGovernanceReportInputError("approval_record requis")
        if not record_required and record is not None:
            raise InvalidGovernanceReportInputError("approval_record inattendu")
        if record is not None and (
            record.request_id != request.request_id
            or record.new_status is not request.status
        ):
            raise InvalidGovernanceReportInputError("approval_record incoherent")
        if request.security_run_id != report.security_context.security_run_id:
            raise InvalidGovernanceReportInputError("security_run_id incoherent")
        terraform_run_id = (
            report.terraform_context.terraform_run_id
            if report.terraform_context is not None
            else None
        )
        if request.terraform_run_id != terraform_run_id:
            raise InvalidGovernanceReportInputError("terraform_run_id incoherent")

    def _utc_now(self) -> datetime:
        value = self._now_factory()
        if not isinstance(value, datetime):
            raise InvalidGovernanceReportInputError(
                "now_factory doit retourner un datetime"
            )
        if value.tzinfo is None or value.utcoffset() is None:
            raise InvalidGovernanceReportInputError("clock doit etre UTC-aware")
        return value.astimezone(timezone.utc).replace(microsecond=0)

    def _new_uuid(self) -> UUID:
        value = self._uuid_factory()
        if not isinstance(value, UUID):
            raise InvalidGovernanceReportInputError(
                "uuid_factory doit retourner un UUID"
            )
        return value

    @staticmethod
    def _format_utc(value: datetime) -> str:
        return value.isoformat(timespec="seconds").replace("+00:00", "Z")

    @staticmethod
    def _build_run_id(generated_at: datetime, value: UUID) -> str:
        return f"governance_{generated_at.strftime('%Y%m%dT%H%M%SZ')}_{value.hex[:8]}"

    @staticmethod
    def _write_atomic(path: Path, content: str) -> None:
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                newline="\n",
                dir=path.parent,
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary_file:
                temporary_file.write(content)
                temporary_path = Path(temporary_file.name)
            temporary_path.replace(path)
        finally:
            if temporary_path is not None and temporary_path.exists():
                temporary_path.unlink()
