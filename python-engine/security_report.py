"""Reporting structure et sur des evaluations de securite multi-cloud."""

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

from security_catalog import SecurityRuleCatalog
from security_evaluation import (
    SECURITY_CLOUD_ORDER,
    MultiCloudSecurityEvaluationResult,
    build_default_multicloud_security_engine,
)
from security_models import (
    SecurityFinding,
    SecurityScanResult,
    SecurityScanStatus,
    SecuritySeverity,
)
from security_terraform_adapter import TerraformSecurityAdaptationResult
from terraform_report import TerraformExecutionReport


_SECURITY_RUN_ID_PATTERN = re.compile(
    r"\Asecurity_(?:gcp|oci|multicloud|none)_"
    r"\d{8}T\d{6}Z_[0-9a-f]{8}\Z"
)
_TERRAFORM_RUN_ID_PATTERN = re.compile(
    r"\Atfplan_[a-z0-9_-]+_\d{8}T\d{6}Z_[0-9a-f]{8}\Z"
)
_UTC_TIMESTAMP_PATTERN = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_SAFE_STATUS_PATTERN = re.compile(r"\A[A-Z][A-Z0-9_]*\Z")


@dataclass(frozen=True)
class SecurityTerraformContext:
    """Reference Terraform legere n'exposant ni sorties ni chemins locaux."""

    terraform_run_id: str
    cloud: str
    terraform_final_status: str
    failed_step: str | None
    plan_status: str
    plan_exit_code: int | None
    add_count: int | None
    change_count: int | None
    destroy_count: int | None

    def __post_init__(self) -> None:
        if not _TERRAFORM_RUN_ID_PATTERN.fullmatch(self.terraform_run_id):
            raise ValueError("terraform_run_id invalide")
        if self.cloud not in SECURITY_CLOUD_ORDER:
            raise ValueError("cloud Terraform invalide")
        for field_name in ("terraform_final_status", "plan_status"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not _SAFE_STATUS_PATTERN.fullmatch(value):
                raise ValueError(f"{field_name} invalide")
        if self.failed_step not in {None, "fmt", "init", "validate", "plan"}:
            raise ValueError("failed_step Terraform invalide")
        for field_name in (
            "plan_exit_code",
            "add_count",
            "change_count",
            "destroy_count",
        ):
            value = getattr(self, field_name)
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool)
            ):
                raise TypeError(f"{field_name} doit etre un entier ou None")

    def to_dict(self) -> dict[str, Any]:
        return {
            "terraform_run_id": self.terraform_run_id,
            "cloud": self.cloud,
            "terraform_final_status": self.terraform_final_status,
            "failed_step": self.failed_step,
            "plan_status": self.plan_status,
            "plan_exit_code": self.plan_exit_code,
            "changes": {
                "add": self.add_count,
                "change": self.change_count,
                "destroy": self.destroy_count,
            },
        }


@dataclass(frozen=True)
class SecurityComplianceReport:
    """Rapport securite serialisable construit depuis des resultats existants."""

    schema_version: str
    run_id: str
    generated_at: str
    framework: str
    framework_versions: Mapping[str, str]
    evaluation_status: SecurityScanStatus
    clouds_evaluated: tuple[str, ...]
    resources_seen: int
    resources_adapted: int
    resources_skipped: int
    unsupported_resource_types: tuple[str, ...]
    adaptation_warnings: tuple[str, ...]
    resources_total: int
    findings_total: int
    passed: int
    failed: int
    warnings: int
    skipped: int
    not_applicable: int
    severity_counts: Mapping[SecuritySeverity, int]
    cloud_results: Mapping[str, SecurityScanResult]
    resources_by_cloud: Mapping[str, int]
    findings: tuple[SecurityFinding, ...]
    rules_available_by_cloud: Mapping[str, int]
    rules_evaluated_by_cloud: Mapping[str, int]
    terraform_context: SecurityTerraformContext | None = None
    safety: Mapping[str, bool] = field(init=False)

    def __post_init__(self) -> None:
        if self.schema_version != "1.0":
            raise ValueError("schema_version securite non supportee")
        if not _SECURITY_RUN_ID_PATTERN.fullmatch(self.run_id):
            raise ValueError("run_id securite invalide")
        if not _UTC_TIMESTAMP_PATTERN.fullmatch(self.generated_at):
            raise ValueError("generated_at doit etre un timestamp UTC")
        if not isinstance(self.evaluation_status, SecurityScanStatus):
            raise TypeError("evaluation_status doit etre un SecurityScanStatus")

        object.__setattr__(
            self,
            "framework_versions",
            self._ordered_mapping(self.framework_versions),
        )
        object.__setattr__(
            self,
            "severity_counts",
            MappingProxyType(
                {
                    severity: self.severity_counts.get(severity, 0)
                    for severity in SecuritySeverity
                }
            ),
        )
        object.__setattr__(
            self,
            "cloud_results",
            self._ordered_mapping(self.cloud_results),
        )
        object.__setattr__(
            self,
            "resources_by_cloud",
            self._ordered_mapping(self.resources_by_cloud),
        )
        object.__setattr__(
            self,
            "rules_available_by_cloud",
            self._ordered_mapping(self.rules_available_by_cloud),
        )
        object.__setattr__(
            self,
            "rules_evaluated_by_cloud",
            self._ordered_mapping(self.rules_evaluated_by_cloud),
        )
        object.__setattr__(self, "findings", tuple(self.findings))
        object.__setattr__(
            self,
            "safety",
            MappingProxyType(
                {
                    "terraform_apply_executed": False,
                    "terraform_destroy_executed": False,
                    "cloud_write_operation_executed": False,
                    "credentials_included": False,
                    "raw_terraform_values_included": False,
                    "tfstate_included": False,
                }
            ),
        )

    @property
    def rules_available_total(self) -> int:
        return sum(self.rules_available_by_cloud.values())

    @property
    def rules_evaluated_total(self) -> int:
        return sum(self.rules_evaluated_by_cloud.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "generated_at": self.generated_at,
            "framework": self.framework,
            "framework_versions": dict(self.framework_versions),
            "evaluation_status": self.evaluation_status.value,
            "clouds_evaluated": list(self.clouds_evaluated),
            "adaptation": {
                "resources_seen": self.resources_seen,
                "resources_adapted": self.resources_adapted,
                "resources_skipped": self.resources_skipped,
                "unsupported_resource_types": list(
                    self.unsupported_resource_types
                ),
                "diagnostics": list(self.adaptation_warnings),
            },
            "summary": {
                "resources_total": self.resources_total,
                "findings_total": self.findings_total,
                "passed": self.passed,
                "failed": self.failed,
                "warnings": self.warnings,
                "skipped": self.skipped,
                "not_applicable": self.not_applicable,
            },
            "rule_inventory": {
                "rules_available_total": self.rules_available_total,
                "rules_evaluated_total": self.rules_evaluated_total,
                "available_by_cloud": dict(self.rules_available_by_cloud),
                "evaluated_by_cloud": dict(self.rules_evaluated_by_cloud),
            },
            "severity_counts": {
                severity.value: self.severity_counts.get(severity, 0)
                for severity in SecuritySeverity
            },
            "cloud_results": {
                cloud: self._cloud_result_to_dict(cloud, result)
                for cloud, result in self.cloud_results.items()
            },
            "findings": [finding.to_dict() for finding in self.findings],
            "terraform_context": (
                self.terraform_context.to_dict()
                if self.terraform_context is not None
                else None
            ),
            "safety": dict(self.safety),
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def render_text(self) -> str:
        separator = "=" * 70
        section = "-" * 70
        lines = [
            separator,
            " SECURITY COMPLIANCE REPORT",
            separator,
            f"Run ID       : {self.run_id}",
            f"Generated    : {self.generated_at}",
            f"Framework    : {self.framework}",
            f"Status       : {self.evaluation_status.value}",
            "",
            section,
            " TERRAFORM ADAPTATION",
            section,
            f"Resources seen      : {self.resources_seen}",
            f"Resources adapted   : {self.resources_adapted}",
            f"Resources skipped   : {self.resources_skipped}",
        ]
        lines.extend(self._render_list("Unsupported", self.unsupported_resource_types))
        lines.extend(self._render_list("Diagnostics", self.adaptation_warnings))
        lines.extend(
            (
                "",
                section,
                " RULE INVENTORY",
                section,
                f"Rules available     : {self.rules_available_total}",
                f"Rules evaluated     : {self.rules_evaluated_total}",
                "",
                section,
                " SUMMARY",
                section,
                f"Findings            : {self.findings_total}",
                f"PASS                : {self.passed}",
                f"FAIL                : {self.failed}",
                f"WARNING             : {self.warnings}",
                f"SKIPPED             : {self.skipped}",
                f"NOT APPLICABLE      : {self.not_applicable}",
                "",
                "Severity:",
            )
        )
        lines.extend(
            f"{severity.value:<20}: {self.severity_counts.get(severity, 0)}"
            for severity in SecuritySeverity
        )
        for cloud, result in self.cloud_results.items():
            lines.extend(
                (
                    "",
                    section,
                    f" {cloud.upper()}",
                    section,
                    f"Resources           : {self.resources_by_cloud.get(cloud, 0)}",
                    f"Findings            : {result.total_rules_evaluated}",
                    f"Status              : {result.scan_status.value}",
                    f"PASS                : {result.passed}",
                    f"FAIL                : {result.failed}",
                    f"WARNING             : {result.warnings}",
                    f"SKIPPED             : {result.skipped}",
                )
            )
        lines.extend(("", section, " FINDINGS", section))
        if not self.findings:
            lines.append("None")
        for finding in self.findings:
            lines.extend(
                (
                    "",
                    f"[{finding.severity.value}][{finding.status.value}]",
                    f"Rule       : {finding.rule_id}",
                    f"Cloud      : {finding.cloud.upper()}",
                    f"Resource   : {finding.resource_address}",
                    f"Title      : {finding.title}",
                    f"Message    : {finding.message}",
                    f"Recommend  : {finding.recommendation}",
                )
            )
        if self.terraform_context is not None:
            context = self.terraform_context
            lines.extend(
                (
                    "",
                    section,
                    " TERRAFORM CONTEXT",
                    section,
                    f"Run ID              : {context.terraform_run_id}",
                    f"Cloud               : {context.cloud.upper()}",
                    f"Final status        : {context.terraform_final_status}",
                    f"Plan status         : {context.plan_status}",
                    f"Plan exit code      : {context.plan_exit_code}",
                )
            )
        lines.extend(
            (
                "",
                section,
                " SAFETY",
                section,
                "Terraform apply executed       : NO",
                "Terraform destroy executed     : NO",
                "Cloud write operation executed : NO",
                "Credentials included           : NO",
                "Raw Terraform values included  : NO",
                "Terraform state included       : NO",
                separator,
            )
        )
        return "\n".join(lines)

    def _cloud_result_to_dict(
        self,
        cloud: str,
        result: SecurityScanResult,
    ) -> dict[str, Any]:
        return {
            "resources": self.resources_by_cloud.get(cloud, 0),
            "findings_total": result.total_rules_evaluated,
            "passed": result.passed,
            "failed": result.failed,
            "warnings": result.warnings,
            "skipped": result.skipped,
            "not_applicable": result.not_applicable,
            "severity_counts": {
                severity.value: result.severity_counts.get(severity, 0)
                for severity in SecuritySeverity
            },
            "scan_status": result.scan_status.value,
        }

    @staticmethod
    def _render_list(label: str, values: tuple[str, ...]) -> list[str]:
        lines = ["", f"{label}:"]
        lines.extend(f"- {value}" for value in values)
        if not values:
            lines.append("- None")
        return lines

    @staticmethod
    def _ordered_mapping(values: Mapping[str, Any]) -> Mapping[str, Any]:
        return MappingProxyType(
            {cloud: values[cloud] for cloud in SECURITY_CLOUD_ORDER if cloud in values}
        )


class SecurityComplianceReportBuilder:
    """Construit et ecrit un rapport sans reexecuter les regles ou Terraform."""

    SCHEMA_VERSION = "1.0"
    DEFAULT_REPORT_DIRECTORY = Path("artifacts") / "security" / "reports"

    def __init__(
        self,
        repository_root: Path | None = None,
        now_factory: Callable[[], datetime] | None = None,
        uuid_factory: Callable[[], UUID] | None = None,
        catalog: SecurityRuleCatalog | None = None,
    ) -> None:
        self.repository_root = (
            Path(repository_root).expanduser().resolve()
            if repository_root is not None
            else Path(__file__).resolve().parent.parent
        )
        self._now_factory = now_factory or (lambda: datetime.now(timezone.utc))
        self._uuid_factory = uuid_factory or uuid4
        self.catalog = catalog or build_default_multicloud_security_engine().catalog
        if not isinstance(self.catalog, SecurityRuleCatalog):
            raise TypeError("catalog doit etre un SecurityRuleCatalog")

    def build(
        self,
        *,
        adaptation_result: TerraformSecurityAdaptationResult,
        evaluation_result: MultiCloudSecurityEvaluationResult,
        terraform_report: TerraformExecutionReport | None = None,
    ) -> SecurityComplianceReport:
        """Extrait uniquement les donnees sures des trois resultats sources."""

        self._validate_inputs(
            adaptation_result,
            evaluation_result,
            terraform_report,
        )
        generated_datetime = self._utc_now()
        cloud_label = self._cloud_label(evaluation_result.clouds_evaluated)
        findings = self._sorted_findings(evaluation_result)
        cloud_results = {
            cloud: evaluation_result.cloud_results[cloud]
            for cloud in SECURITY_CLOUD_ORDER
            if cloud in evaluation_result.cloud_results
        }
        resources_by_cloud = {
            cloud: sum(
                resource.cloud == cloud for resource in adaptation_result.resources
            )
            for cloud in evaluation_result.clouds_evaluated
        }
        available_by_cloud = {
            cloud: len(self.catalog.select(cloud=cloud, enabled_only=False))
            for cloud in SECURITY_CLOUD_ORDER
        }
        evaluated_by_cloud = {
            cloud: len(
                {
                    finding.rule_id
                    for finding in evaluation_result.cloud_results[cloud].findings
                }
            )
            for cloud in evaluation_result.clouds_evaluated
        }
        return SecurityComplianceReport(
            schema_version=self.SCHEMA_VERSION,
            run_id=self._build_run_id(
                cloud_label,
                generated_datetime,
                self._uuid_factory(),
            ),
            generated_at=self._iso_utc(generated_datetime),
            framework=self._framework(),
            framework_versions=self._framework_versions(
                evaluation_result.clouds_evaluated
            ),
            evaluation_status=evaluation_result.evaluation_status,
            clouds_evaluated=evaluation_result.clouds_evaluated,
            resources_seen=adaptation_result.resources_seen,
            resources_adapted=adaptation_result.resources_adapted,
            resources_skipped=adaptation_result.resources_skipped,
            unsupported_resource_types=(
                adaptation_result.unsupported_resource_types
            ),
            adaptation_warnings=adaptation_result.warnings,
            resources_total=evaluation_result.resources_total,
            findings_total=evaluation_result.findings_total,
            passed=evaluation_result.passed,
            failed=evaluation_result.failed,
            warnings=evaluation_result.warnings,
            skipped=evaluation_result.skipped,
            not_applicable=evaluation_result.not_applicable,
            severity_counts=evaluation_result.severity_counts,
            cloud_results=cloud_results,
            resources_by_cloud=resources_by_cloud,
            findings=findings,
            rules_available_by_cloud=available_by_cloud,
            rules_evaluated_by_cloud=evaluated_by_cloud,
            terraform_context=self._terraform_context(terraform_report),
        )

    def write_report(
        self,
        report: SecurityComplianceReport,
        output_directory: Path | None = None,
    ) -> tuple[Path, Path]:
        """Ecrit explicitement JSON et TXT avec le patron atomique PLAN-5."""

        if not isinstance(report, SecurityComplianceReport):
            raise TypeError("report doit etre un SecurityComplianceReport")
        if not _SECURITY_RUN_ID_PATTERN.fullmatch(report.run_id):
            raise ValueError("run_id invalide pour un nom de rapport securite")
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
        adaptation_result: TerraformSecurityAdaptationResult,
        evaluation_result: MultiCloudSecurityEvaluationResult,
        terraform_report: TerraformExecutionReport | None,
    ) -> None:
        if not isinstance(adaptation_result, TerraformSecurityAdaptationResult):
            raise TypeError(
                "adaptation_result doit etre un TerraformSecurityAdaptationResult"
            )
        if not isinstance(evaluation_result, MultiCloudSecurityEvaluationResult):
            raise TypeError(
                "evaluation_result doit etre un MultiCloudSecurityEvaluationResult"
            )
        if terraform_report is not None and not isinstance(
            terraform_report,
            TerraformExecutionReport,
        ):
            raise TypeError("terraform_report doit etre un TerraformExecutionReport")
        if evaluation_result.resources_total != len(adaptation_result.resources):
            raise ValueError(
                "Les resultats d'adaptation et d'evaluation ne correspondent pas"
            )

    def _framework(self) -> str:
        frameworks = {
            rule.metadata.framework
            for rule in self.catalog.rules
            if rule.metadata.framework is not None
        }
        if len(frameworks) != 1:
            raise ValueError("Le catalogue doit exposer un framework unique")
        return frameworks.pop()

    def _framework_versions(
        self,
        clouds: tuple[str, ...],
    ) -> Mapping[str, str]:
        versions: dict[str, str] = {}
        for cloud in clouds:
            cloud_versions = {
                rule.metadata.framework_version
                for rule in self.catalog.select(cloud=cloud)
                if rule.metadata.framework_version is not None
            }
            if len(cloud_versions) != 1:
                raise ValueError(
                    f"Le catalogue doit exposer une version unique pour {cloud}"
                )
            versions[cloud] = cloud_versions.pop()
        return versions

    @staticmethod
    def _terraform_context(
        report: TerraformExecutionReport | None,
    ) -> SecurityTerraformContext | None:
        if report is None:
            return None
        return SecurityTerraformContext(
            terraform_run_id=report.run_id,
            cloud=report.cloud,
            terraform_final_status=report.final_status,
            failed_step=report.failed_step,
            plan_status=report.plan_status,
            plan_exit_code=report.plan_exit_code,
            add_count=report.add_count,
            change_count=report.change_count,
            destroy_count=report.destroy_count,
        )

    @staticmethod
    def _sorted_findings(
        evaluation_result: MultiCloudSecurityEvaluationResult,
    ) -> tuple[SecurityFinding, ...]:
        return tuple(
            sorted(
                (
                    finding
                    for cloud in evaluation_result.clouds_evaluated
                    for finding in evaluation_result.cloud_results[cloud].findings
                ),
                key=lambda finding: (
                    -finding.severity.priority,
                    finding.cloud,
                    finding.rule_id,
                    finding.resource_address,
                    finding.resource_name,
                ),
            )
        )

    def _utc_now(self) -> datetime:
        generated_datetime = self._now_factory()
        if generated_datetime.tzinfo is None:
            raise ValueError("now_factory doit retourner un datetime avec fuseau")
        return generated_datetime.astimezone(timezone.utc)

    @staticmethod
    def _iso_utc(value: datetime) -> str:
        return value.isoformat(timespec="seconds").replace("+00:00", "Z")

    @staticmethod
    def _cloud_label(clouds: tuple[str, ...]) -> str:
        if not clouds:
            return "none"
        if len(clouds) == 1:
            return clouds[0]
        return "multicloud"

    @staticmethod
    def _build_run_id(
        cloud_label: str,
        generated_at: datetime,
        value: UUID,
    ) -> str:
        timestamp = generated_at.strftime("%Y%m%dT%H%M%SZ")
        return f"security_{cloud_label}_{timestamp}_{value.hex[:8]}"

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
