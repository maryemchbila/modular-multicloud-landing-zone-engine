"""Reporting auditable d'une decision existante du Security Policy Gate."""

from __future__ import annotations

import json
import re
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any
from uuid import UUID, uuid4

from security_evaluation import SECURITY_CLOUD_ORDER, MultiCloudSecurityEvaluationResult
from security_models import SecuritySeverity
from security_policy_models import (
    PolicyDecision,
    PolicyTriggeredFinding,
    SecurityPolicy,
    SecurityPolicyException,
)
from security_report import SecurityComplianceReport
from terraform_report import TerraformExecutionReport


_POLICY_RUN_ID_PATTERN = re.compile(
    r"\Apolicy_\d{8}T\d{6}Z_[0-9a-f]{8}\Z"
)
_UTC_TIMESTAMP_PATTERN = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_SAFE_IDENTIFIER_PATTERN = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:-]*\Z")
_SAFE_STATUS_PATTERN = re.compile(r"\A[A-Z][A-Z0-9_]*\Z")


class InvalidPolicyReportInputError(ValueError):
    """Les objets sources ne permettent pas un rapport coherent et sur."""


def _require_text(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidPolicyReportInputError(
            f"{field_name} doit etre une chaine non vide"
        )
    return value.strip()


def _non_negative(value: int, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise InvalidPolicyReportInputError(
            f"{field_name} doit etre un entier positif ou nul"
        )
    return value


@dataclass(frozen=True)
class PolicySecurityContext:
    """Correlation legere avec une evaluation et son rapport securite."""

    security_evaluation_status: str
    clouds_evaluated: tuple[str, ...]
    resources_total: int
    findings_total: int
    critical_count: int
    high_count: int
    medium_count: int
    security_run_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.security_evaluation_status, str) or not (
            _SAFE_STATUS_PATTERN.fullmatch(self.security_evaluation_status)
        ):
            raise InvalidPolicyReportInputError(
                "security_evaluation_status invalide"
            )
        supplied_clouds = tuple(self.clouds_evaluated)
        if any(cloud not in SECURITY_CLOUD_ORDER for cloud in supplied_clouds):
            raise InvalidPolicyReportInputError("clouds_evaluated invalide")
        stable_clouds = tuple(
            cloud for cloud in SECURITY_CLOUD_ORDER if cloud in supplied_clouds
        )
        if len(supplied_clouds) != len(set(supplied_clouds)):
            raise InvalidPolicyReportInputError(
                "clouds_evaluated contient des doublons"
            )
        object.__setattr__(self, "clouds_evaluated", stable_clouds)
        for field_name in (
            "resources_total",
            "findings_total",
            "critical_count",
            "high_count",
            "medium_count",
        ):
            object.__setattr__(
                self,
                field_name,
                _non_negative(getattr(self, field_name), field_name),
            )
        if self.security_run_id is not None:
            value = _require_text(self.security_run_id, "security_run_id")
            if not _SAFE_IDENTIFIER_PATTERN.fullmatch(value):
                raise InvalidPolicyReportInputError("security_run_id invalide")
            object.__setattr__(self, "security_run_id", value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "security_run_id": self.security_run_id,
            "security_evaluation_status": self.security_evaluation_status,
            "clouds_evaluated": list(self.clouds_evaluated),
            "resources_total": self.resources_total,
            "findings_total": self.findings_total,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
        }


@dataclass(frozen=True)
class PolicyTerraformContext:
    """Correlation Terraform limitee aux statuts deja sanitizes."""

    terraform_run_id: str
    terraform_final_status: str
    plan_status: str
    plan_exit_code: int | None

    def __post_init__(self) -> None:
        run_id = _require_text(self.terraform_run_id, "terraform_run_id")
        if not _SAFE_IDENTIFIER_PATTERN.fullmatch(run_id):
            raise InvalidPolicyReportInputError("terraform_run_id invalide")
        object.__setattr__(self, "terraform_run_id", run_id)
        for field_name in ("terraform_final_status", "plan_status"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not _SAFE_STATUS_PATTERN.fullmatch(value):
                raise InvalidPolicyReportInputError(f"{field_name} invalide")
        if self.plan_exit_code is not None and (
            not isinstance(self.plan_exit_code, int)
            or isinstance(self.plan_exit_code, bool)
        ):
            raise InvalidPolicyReportInputError(
                "plan_exit_code doit etre un entier ou None"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "terraform_run_id": self.terraform_run_id,
            "terraform_final_status": self.terraform_final_status,
            "plan_status": self.plan_status,
            "plan_exit_code": self.plan_exit_code,
        }


@dataclass(frozen=True)
class PolicyAppliedExceptionSnapshot:
    """Snapshot public d'une exception effectivement appliquee par le gate."""

    exception_id: str
    reason: str
    rule_ids: tuple[str, ...]
    clouds: tuple[str, ...]
    resource_addresses: tuple[str, ...]
    expires_at: str | None
    reference: str | None

    @classmethod
    def from_exception(
        cls,
        exception: SecurityPolicyException,
    ) -> PolicyAppliedExceptionSnapshot:
        payload = exception.to_dict()
        scope = payload["scope"]
        return cls(
            exception_id=payload["exception_id"],
            reason=payload["reason"],
            rule_ids=tuple(scope["rule_ids"]),
            clouds=tuple(scope["clouds"]),
            resource_addresses=tuple(scope["resource_addresses"]),
            expires_at=payload["expires_at"],
            reference=payload["reference"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "exception_id": self.exception_id,
            "reason": self.reason,
            "scope": {
                "rule_ids": list(self.rule_ids),
                "clouds": list(self.clouds),
                "resource_addresses": list(self.resource_addresses),
            },
            "expires_at": self.expires_at,
            "reference": self.reference,
        }


@dataclass(frozen=True)
class PolicyDecisionAudit:
    """Dates, provenance et compteurs necessaires a l'audit de decision."""

    decision_evaluated_at: str | None
    policy_report_generated_at: str
    decision_source: str
    profile: str
    exceptions_applied_count: int
    triggered_findings_count: int
    excepted_findings_count: int

    def __post_init__(self) -> None:
        if self.decision_evaluated_at is not None and not (
            _UTC_TIMESTAMP_PATTERN.fullmatch(self.decision_evaluated_at)
        ):
            raise InvalidPolicyReportInputError(
                "decision_evaluated_at doit etre un timestamp UTC ou None"
            )
        if not _UTC_TIMESTAMP_PATTERN.fullmatch(self.policy_report_generated_at):
            raise InvalidPolicyReportInputError(
                "policy_report_generated_at doit etre un timestamp UTC"
            )
        if self.decision_source != "SecurityPolicyGate":
            raise InvalidPolicyReportInputError("decision_source invalide")
        for field_name in (
            "exceptions_applied_count",
            "triggered_findings_count",
            "excepted_findings_count",
        ):
            object.__setattr__(
                self,
                field_name,
                _non_negative(getattr(self, field_name), field_name),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_evaluated_at": self.decision_evaluated_at,
            "policy_report_generated_at": self.policy_report_generated_at,
            "decision_source": self.decision_source,
            "profile": self.profile,
            "exceptions_applied_count": self.exceptions_applied_count,
            "triggered_findings_count": self.triggered_findings_count,
            "excepted_findings_count": self.excepted_findings_count,
        }


@dataclass(frozen=True)
class PolicyDecisionReport:
    """Rapport POLICY-3 immutable construit sans recalculer la decision."""

    schema_version: str
    run_id: str
    generated_at: str
    policy: Mapping[str, Any]
    decision: Mapping[str, Any]
    thresholds: Mapping[str, int]
    security_context: PolicySecurityContext
    terraform_context: PolicyTerraformContext | None
    triggered_findings: tuple[PolicyTriggeredFinding, ...]
    applied_exception_ids: tuple[str, ...]
    applied_exceptions: tuple[PolicyAppliedExceptionSnapshot, ...]
    excepted_findings: tuple[PolicyTriggeredFinding, ...]
    audit: PolicyDecisionAudit
    safety: Mapping[str, bool] = field(init=False)

    def __post_init__(self) -> None:
        if self.schema_version != "1.0":
            raise InvalidPolicyReportInputError(
                "schema_version policy non supportee"
            )
        if not _POLICY_RUN_ID_PATTERN.fullmatch(self.run_id):
            raise InvalidPolicyReportInputError("run_id policy invalide")
        if not _UTC_TIMESTAMP_PATTERN.fullmatch(self.generated_at):
            raise InvalidPolicyReportInputError(
                "generated_at doit etre un timestamp UTC"
            )
        object.__setattr__(self, "policy", MappingProxyType(dict(self.policy)))
        decision_snapshot = dict(self.decision)
        decision_snapshot["triggered_rules"] = tuple(
            decision_snapshot.get("triggered_rules", ())
        )
        object.__setattr__(
            self,
            "decision",
            MappingProxyType(decision_snapshot),
        )
        object.__setattr__(
            self,
            "thresholds",
            MappingProxyType(dict(self.thresholds)),
        )
        object.__setattr__(self, "triggered_findings", tuple(self.triggered_findings))
        object.__setattr__(
            self,
            "applied_exception_ids",
            tuple(sorted(self.applied_exception_ids)),
        )
        object.__setattr__(
            self,
            "applied_exceptions",
            tuple(
                sorted(
                    self.applied_exceptions,
                    key=lambda exception: exception.exception_id,
                )
            ),
        )
        object.__setattr__(self, "excepted_findings", tuple(self.excepted_findings))
        object.__setattr__(
            self,
            "safety",
            MappingProxyType(
                {
                    "terraform_apply_executed": False,
                    "terraform_destroy_executed": False,
                    "cloud_write_operation_executed": False,
                    "auto_approval_executed": False,
                    "credentials_included": False,
                    "raw_security_attributes_included": False,
                    "raw_terraform_values_included": False,
                }
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        decision = dict(self.decision)
        decision["triggered_rules"] = list(decision["triggered_rules"])
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "generated_at": self.generated_at,
            "policy": dict(self.policy),
            "decision": decision,
            "thresholds": dict(self.thresholds),
            "security_context": self.security_context.to_dict(),
            "terraform_context": (
                self.terraform_context.to_dict()
                if self.terraform_context is not None
                else None
            ),
            "triggered_findings": [
                finding.to_dict() for finding in self.triggered_findings
            ],
            "exceptions": {
                "applied_exception_ids": list(self.applied_exception_ids),
                "applied": [
                    exception.to_dict() for exception in self.applied_exceptions
                ],
                "excepted_findings": [
                    finding.to_dict() for finding in self.excepted_findings
                ],
            },
            "audit": self.audit.to_dict(),
            "safety": dict(self.safety),
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def render_text(self) -> str:
        separator = "=" * 70
        section = "-" * 70
        lines = [
            separator,
            " POLICY DECISION REPORT",
            separator,
            f"Run ID        : {self.run_id}",
            f"Generated     : {self.generated_at}",
            f"Policy        : {self.policy['policy_id']}",
            f"Version       : {self.policy['policy_version']}",
            f"Profile       : {self.policy['profile']}",
            "",
            f"Decision      : {self.decision['status']}",
            f"Reason Code   : {self.decision['reason_code']}",
            f"Message       : {self.decision['message']}",
            "",
            "Human Approval Required : "
            f"{self._yes_no(self.decision['requires_human_approval'])}",
            "Deployment Allowed       : "
            f"{self._yes_no(self.decision['deployment_allowed'])}",
            "",
            section,
            " SECURITY CONTEXT",
            section,
            f"Security Run  : {self.security_context.security_run_id or 'N/A'}",
            "Clouds        : "
            f"{', '.join(cloud.upper() for cloud in self.security_context.clouds_evaluated) or 'NONE'}",
            f"Status        : {self.security_context.security_evaluation_status}",
            f"Resources     : {self.security_context.resources_total}",
            f"Findings      : {self.security_context.findings_total}",
            f"Critical      : {self.security_context.critical_count}",
            f"High          : {self.security_context.high_count}",
            f"Medium        : {self.security_context.medium_count}",
            "",
            section,
            " TERRAFORM CONTEXT",
            section,
        ]
        if self.terraform_context is None:
            lines.append("None")
        else:
            lines.extend(
                (
                    f"Terraform Run : {self.terraform_context.terraform_run_id}",
                    f"Final Status  : {self.terraform_context.terraform_final_status}",
                    f"Plan Status   : {self.terraform_context.plan_status}",
                    f"Plan Exit Code: {self.terraform_context.plan_exit_code}",
                )
            )
        lines.extend(("", section, " POLICY THRESHOLDS", section))
        lines.extend(
            f"{name:<30}: {value}" for name, value in self.thresholds.items()
        )
        lines.extend(("", section, " TRIGGERED FINDINGS", section))
        lines.extend(self._render_findings(self.triggered_findings))
        lines.extend(("", section, " APPLIED EXCEPTIONS", section))
        if not self.applied_exceptions:
            lines.append("None")
        for exception in self.applied_exceptions:
            lines.extend(
                (
                    "",
                    f"Exception ID : {exception.exception_id}",
                    f"Reason       : {exception.reason}",
                    f"Expires      : {exception.expires_at or 'None'}",
                    f"Reference    : {exception.reference or 'None'}",
                )
            )
        lines.extend(("", section, " EXCEPTED FINDINGS", section))
        lines.extend(self._render_findings(self.excepted_findings))
        lines.extend(
            (
                "",
                section,
                " AUDIT",
                section,
                "Decision evaluated : "
                f"{self.audit.decision_evaluated_at or 'Not provided'}",
                f"Report generated    : {self.audit.policy_report_generated_at}",
                f"Decision source     : {self.audit.decision_source}",
                f"Exceptions applied  : {self.audit.exceptions_applied_count}",
                "",
                section,
                " SAFETY",
                section,
                "Terraform apply     : NO",
                "Terraform destroy   : NO",
                "Cloud write         : NO",
                "Automatic approval  : NO",
                separator,
            )
        )
        return "\n".join(lines)

    @staticmethod
    def _render_findings(
        findings: tuple[PolicyTriggeredFinding, ...],
    ) -> list[str]:
        if not findings:
            return ["None"]
        lines: list[str] = []
        for finding in findings:
            lines.extend(
                (
                    "",
                    f"[{finding.severity.value}][{finding.status.value}]",
                    f"Rule       : {finding.rule_id}",
                    f"Cloud      : {finding.cloud.upper()}",
                    f"Resource   : {finding.resource_address}",
                    f"Title      : {finding.title}",
                )
            )
        return lines

    @staticmethod
    def _yes_no(value: bool) -> str:
        return "YES" if value else "NO"


class PolicyDecisionReportBuilder:
    """Contextualise et ecrit une PolicyDecision sans la recalculer."""

    SCHEMA_VERSION = "1.0"
    DEFAULT_REPORT_DIRECTORY = Path("artifacts") / "policy" / "reports"

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
        policy: SecurityPolicy,
        decision: PolicyDecision,
        evaluation_result: MultiCloudSecurityEvaluationResult,
        security_report: SecurityComplianceReport | None = None,
        terraform_report: TerraformExecutionReport | None = None,
    ) -> PolicyDecisionReport:
        """Construit un snapshot d'audit sans reevaluation ni effet de bord."""

        self._validate_inputs(
            policy,
            decision,
            evaluation_result,
            security_report,
            terraform_report,
        )
        generated_datetime = self._utc_now()
        generated_at = self._iso_utc(generated_datetime)
        exception_snapshots = self._applied_exceptions(policy, decision)
        return PolicyDecisionReport(
            schema_version=self.SCHEMA_VERSION,
            run_id=self._build_run_id(generated_datetime, self._uuid_factory()),
            generated_at=generated_at,
            policy={
                "policy_id": policy.policy_id,
                "policy_version": policy.policy_version,
                "profile": policy.profile.value,
                "enabled": policy.enabled,
                "name": policy.name,
                "description": policy.description,
            },
            decision={
                "status": decision.decision.value,
                "reason_code": decision.reason_code.value,
                "message": decision.message,
                "requires_human_approval": decision.requires_human_approval,
                "deployment_allowed": decision.deployment_allowed,
                "triggered_rules": list(decision.triggered_rules),
            },
            thresholds=policy.effective_thresholds.to_dict(),
            security_context=self._security_context(
                evaluation_result,
                security_report,
            ),
            terraform_context=self._terraform_context(
                security_report,
                terraform_report,
            ),
            triggered_findings=tuple(decision.triggered_findings),
            applied_exception_ids=tuple(decision.applied_exception_ids),
            applied_exceptions=exception_snapshots,
            excepted_findings=tuple(decision.excepted_findings),
            audit=PolicyDecisionAudit(
                decision_evaluated_at=decision.evaluation_time,
                policy_report_generated_at=generated_at,
                decision_source="SecurityPolicyGate",
                profile=policy.profile.value,
                exceptions_applied_count=len(decision.applied_exception_ids),
                triggered_findings_count=len(decision.triggered_findings),
                excepted_findings_count=len(decision.excepted_findings),
            ),
        )

    def write_report(
        self,
        report: PolicyDecisionReport,
        output_directory: Path | None = None,
    ) -> tuple[Path, Path]:
        """Ecrit JSON et TXT via fichiers temporaires puis remplacement atomique."""

        if not isinstance(report, PolicyDecisionReport):
            raise TypeError("report doit etre un PolicyDecisionReport")
        if not _POLICY_RUN_ID_PATTERN.fullmatch(report.run_id):
            raise InvalidPolicyReportInputError(
                "run_id invalide pour un rapport policy"
            )
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

    def _validate_inputs(
        self,
        policy: SecurityPolicy,
        decision: PolicyDecision,
        evaluation_result: MultiCloudSecurityEvaluationResult,
        security_report: SecurityComplianceReport | None,
        terraform_report: TerraformExecutionReport | None,
    ) -> None:
        if not isinstance(policy, SecurityPolicy):
            raise TypeError("policy doit etre une SecurityPolicy")
        if not isinstance(decision, PolicyDecision):
            raise TypeError("decision doit etre une PolicyDecision")
        if not isinstance(evaluation_result, MultiCloudSecurityEvaluationResult):
            raise TypeError(
                "evaluation_result doit etre un MultiCloudSecurityEvaluationResult"
            )
        if security_report is not None and not isinstance(
            security_report,
            SecurityComplianceReport,
        ):
            raise TypeError("security_report doit etre un SecurityComplianceReport")
        if terraform_report is not None and not isinstance(
            terraform_report,
            TerraformExecutionReport,
        ):
            raise TypeError("terraform_report doit etre un TerraformExecutionReport")
        if decision.policy_id != policy.policy_id:
            raise InvalidPolicyReportInputError("policy_id incoherent")
        if decision.policy_version != policy.policy_version:
            raise InvalidPolicyReportInputError("policy_version incoherente")
        if decision.profile is not policy.profile:
            raise InvalidPolicyReportInputError("profile incoherent")
        if bool(decision.applied_exception_ids) != bool(
            decision.excepted_findings
        ):
            raise InvalidPolicyReportInputError(
                "La trace des exceptions appliquees est incoherente"
            )
        self._validate_security_report(evaluation_result, security_report)
        self._validate_terraform_correlation(security_report, terraform_report)

    @staticmethod
    def _validate_security_report(
        evaluation_result: MultiCloudSecurityEvaluationResult,
        security_report: SecurityComplianceReport | None,
    ) -> None:
        if security_report is None:
            return
        if (
            security_report.evaluation_status
            is not evaluation_result.evaluation_status
            or security_report.clouds_evaluated
            != evaluation_result.clouds_evaluated
            or security_report.resources_total != evaluation_result.resources_total
            or security_report.findings_total != evaluation_result.findings_total
        ):
            raise InvalidPolicyReportInputError(
                "security_report ne correspond pas a evaluation_result"
            )

    @staticmethod
    def _validate_terraform_correlation(
        security_report: SecurityComplianceReport | None,
        terraform_report: TerraformExecutionReport | None,
    ) -> None:
        if (
            security_report is None
            or security_report.terraform_context is None
            or terraform_report is None
        ):
            return
        if (
            security_report.terraform_context.terraform_run_id
            != terraform_report.run_id
        ):
            raise InvalidPolicyReportInputError("terraform_run_id incoherent")

    @staticmethod
    def _applied_exceptions(
        policy: SecurityPolicy,
        decision: PolicyDecision,
    ) -> tuple[PolicyAppliedExceptionSnapshot, ...]:
        exceptions_by_id = {
            exception.exception_id: exception for exception in policy.exceptions
        }
        missing_ids = tuple(
            exception_id
            for exception_id in decision.applied_exception_ids
            if exception_id not in exceptions_by_id
        )
        if missing_ids:
            raise InvalidPolicyReportInputError(
                "Une exception appliquee est absente de la policy"
            )
        return tuple(
            PolicyAppliedExceptionSnapshot.from_exception(
                exceptions_by_id[exception_id]
            )
            for exception_id in decision.applied_exception_ids
        )

    @staticmethod
    def _security_context(
        evaluation_result: MultiCloudSecurityEvaluationResult,
        security_report: SecurityComplianceReport | None,
    ) -> PolicySecurityContext:
        return PolicySecurityContext(
            security_run_id=(
                security_report.run_id if security_report is not None else None
            ),
            security_evaluation_status=evaluation_result.evaluation_status.value,
            clouds_evaluated=evaluation_result.clouds_evaluated,
            resources_total=evaluation_result.resources_total,
            findings_total=evaluation_result.findings_total,
            critical_count=evaluation_result.severity_counts.get(
                SecuritySeverity.CRITICAL,
                0,
            ),
            high_count=evaluation_result.severity_counts.get(
                SecuritySeverity.HIGH,
                0,
            ),
            medium_count=evaluation_result.severity_counts.get(
                SecuritySeverity.MEDIUM,
                0,
            ),
        )

    @staticmethod
    def _terraform_context(
        security_report: SecurityComplianceReport | None,
        terraform_report: TerraformExecutionReport | None,
    ) -> PolicyTerraformContext | None:
        if terraform_report is not None:
            return PolicyTerraformContext(
                terraform_run_id=terraform_report.run_id,
                terraform_final_status=terraform_report.final_status,
                plan_status=terraform_report.plan_status,
                plan_exit_code=terraform_report.plan_exit_code,
            )
        if security_report is None or security_report.terraform_context is None:
            return None
        context = security_report.terraform_context
        return PolicyTerraformContext(
            terraform_run_id=context.terraform_run_id,
            terraform_final_status=context.terraform_final_status,
            plan_status=context.plan_status,
            plan_exit_code=context.plan_exit_code,
        )

    def _utc_now(self) -> datetime:
        value = self._now_factory()
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise InvalidPolicyReportInputError(
                "now_factory doit retourner un datetime avec fuseau"
            )
        return value.astimezone(timezone.utc)

    @staticmethod
    def _iso_utc(value: datetime) -> str:
        return value.isoformat(timespec="seconds").replace("+00:00", "Z")

    @staticmethod
    def _build_run_id(generated_at: datetime, value: UUID) -> str:
        if not isinstance(value, UUID):
            raise InvalidPolicyReportInputError("uuid_factory doit retourner un UUID")
        timestamp = generated_at.strftime("%Y%m%dT%H%M%SZ")
        return f"policy_{timestamp}_{value.hex[:8]}"

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
