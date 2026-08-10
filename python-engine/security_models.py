"""Modeles generiques et serialisables du scanner de securite CIS-1."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any


SUPPORTED_SECURITY_CLOUDS = frozenset({"gcp", "oci"})


class UnknownSecurityCloudError(ValueError):
    """Le cloud demande n'est pas pris en charge par le scanner."""


def normalise_security_cloud(cloud: str) -> str:
    """Valide et normalise le cloud utilise par tous les modeles CIS-1."""

    if not isinstance(cloud, str):
        raise UnknownSecurityCloudError(
            "Le cloud de securite doit etre 'gcp' ou 'oci'."
        )
    normalised_cloud = cloud.strip().casefold()
    if normalised_cloud not in SUPPORTED_SECURITY_CLOUDS:
        raise UnknownSecurityCloudError(
            f"Cloud de securite inconnu : {cloud!r}. "
            "Valeurs autorisees : gcp, oci."
        )
    return normalised_cloud


class SecuritySeverity(str, Enum):
    """Niveaux de severite stables, du plus au moins important."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def priority(self) -> int:
        """Retourne une priorite numerique utile au tri des findings."""

        return {
            SecuritySeverity.CRITICAL: 5,
            SecuritySeverity.HIGH: 4,
            SecuritySeverity.MEDIUM: 3,
            SecuritySeverity.LOW: 2,
            SecuritySeverity.INFO: 1,
        }[self]


class RuleStatus(str, Enum):
    """Resultat fonctionnel d'une evaluation de regle."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    SKIPPED = "SKIPPED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class SecurityScanStatus(str, Enum):
    """Resume du scan, sans decision de deploiement."""

    PASS = "PASS"
    PASS_WITH_WARNINGS = "PASS_WITH_WARNINGS"
    FAIL = "FAIL"


def _require_non_empty(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} doit etre une chaine non vide")
    return value.strip()


@dataclass(frozen=True)
class SecurityRuleMetadata:
    """Perimetre et informations stables d'une regle de securite."""

    rule_id: str
    cloud: str
    service: str
    resource_type: str
    title: str
    description: str
    severity: SecuritySeverity
    recommendation: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "rule_id", _require_non_empty(self.rule_id, "rule_id"))
        object.__setattr__(self, "cloud", normalise_security_cloud(self.cloud))
        object.__setattr__(
            self,
            "service",
            _require_non_empty(self.service, "service").casefold(),
        )
        object.__setattr__(
            self,
            "resource_type",
            _require_non_empty(self.resource_type, "resource_type"),
        )
        object.__setattr__(self, "title", _require_non_empty(self.title, "title"))
        object.__setattr__(
            self,
            "description",
            _require_non_empty(self.description, "description"),
        )
        object.__setattr__(
            self,
            "recommendation",
            _require_non_empty(self.recommendation, "recommendation"),
        )
        if not isinstance(self.severity, SecuritySeverity):
            raise TypeError("severity doit etre un SecuritySeverity")

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "cloud": self.cloud,
            "service": self.service,
            "resource_type": self.resource_type,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "recommendation": self.recommendation,
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


@dataclass(frozen=True)
class SecurityResource:
    """Vue legere d'une ressource a evaluer, sans dependance Terraform ou Cloud."""

    cloud: str
    resource_type: str
    resource_name: str
    resource_address: str
    attributes: Mapping[str, Any]
    service: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "cloud", normalise_security_cloud(self.cloud))
        object.__setattr__(
            self,
            "resource_type",
            _require_non_empty(self.resource_type, "resource_type"),
        )
        object.__setattr__(
            self,
            "resource_name",
            _require_non_empty(self.resource_name, "resource_name"),
        )
        object.__setattr__(
            self,
            "resource_address",
            _require_non_empty(self.resource_address, "resource_address"),
        )
        if not isinstance(self.attributes, Mapping):
            raise TypeError("attributes doit etre un mapping")
        object.__setattr__(self, "attributes", dict(self.attributes))
        if self.service is not None:
            object.__setattr__(
                self,
                "service",
                _require_non_empty(self.service, "service").casefold(),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "cloud": self.cloud,
            "service": self.service,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "resource_address": self.resource_address,
            "attributes": dict(self.attributes),
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


@dataclass(frozen=True)
class SecurityFinding:
    """Resultat sur d'une regle pour une ressource, sans preuve sensible."""

    rule_id: str
    cloud: str
    resource_type: str
    resource_name: str
    resource_address: str
    status: RuleStatus
    severity: SecuritySeverity
    title: str
    message: str
    recommendation: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "rule_id", _require_non_empty(self.rule_id, "rule_id"))
        object.__setattr__(self, "cloud", normalise_security_cloud(self.cloud))
        for field_name in (
            "resource_type",
            "resource_name",
            "resource_address",
            "title",
            "message",
            "recommendation",
        ):
            object.__setattr__(
                self,
                field_name,
                _require_non_empty(getattr(self, field_name), field_name),
            )
        if not isinstance(self.status, RuleStatus):
            raise TypeError("status doit etre un RuleStatus")
        if not isinstance(self.severity, SecuritySeverity):
            raise TypeError("severity doit etre un SecuritySeverity")

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "cloud": self.cloud,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "resource_address": self.resource_address,
            "status": self.status.value,
            "severity": self.severity.value,
            "title": self.title,
            "message": self.message,
            "recommendation": self.recommendation,
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


@dataclass(frozen=True)
class SecurityScanResult:
    """Agregat deterministe d'un scan de securite en memoire."""

    cloud: str
    findings: tuple[SecurityFinding, ...]
    total_rules_evaluated: int
    passed: int
    failed: int
    warnings: int
    skipped: int
    not_applicable: int
    severity_counts: Mapping[SecuritySeverity, int]
    scan_status: SecurityScanStatus

    @classmethod
    def build(
        cls,
        cloud: str,
        findings: Sequence[SecurityFinding],
    ) -> SecurityScanResult:
        """Construit tous les compteurs depuis les findings tries du scanner."""

        normalised_cloud = normalise_security_cloud(cloud)
        stable_findings = tuple(findings)
        for finding in stable_findings:
            if not isinstance(finding, SecurityFinding):
                raise TypeError("findings doit contenir des SecurityFinding")
            if finding.cloud != normalised_cloud:
                raise ValueError("Un finding ne correspond pas au cloud du scan")

        status_counts = {
            status: sum(finding.status is status for finding in stable_findings)
            for status in RuleStatus
        }
        severity_counts = {
            severity: sum(
                finding.severity is severity
                and finding.status in {RuleStatus.FAIL, RuleStatus.WARNING}
                for finding in stable_findings
            )
            for severity in SecuritySeverity
        }
        failed = status_counts[RuleStatus.FAIL]
        warnings = status_counts[RuleStatus.WARNING]
        skipped = status_counts[RuleStatus.SKIPPED]
        if failed:
            scan_status = SecurityScanStatus.FAIL
        elif warnings or skipped:
            scan_status = SecurityScanStatus.PASS_WITH_WARNINGS
        else:
            scan_status = SecurityScanStatus.PASS

        return cls(
            cloud=normalised_cloud,
            findings=stable_findings,
            total_rules_evaluated=len(stable_findings),
            passed=status_counts[RuleStatus.PASS],
            failed=failed,
            warnings=warnings,
            skipped=skipped,
            not_applicable=status_counts[RuleStatus.NOT_APPLICABLE],
            severity_counts=severity_counts,
            scan_status=scan_status,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "cloud": self.cloud,
            "findings": [finding.to_dict() for finding in self.findings],
            "total_rules_evaluated": self.total_rules_evaluated,
            "passed": self.passed,
            "failed": self.failed,
            "warnings": self.warnings,
            "skipped": self.skipped,
            "not_applicable": self.not_applicable,
            "severity_counts": {
                severity.value: self.severity_counts.get(severity, 0)
                for severity in SecuritySeverity
            },
            "scan_status": self.scan_status.value,
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)
