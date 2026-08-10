"""Modeles immuables et serialisables du Security Policy Gate.

``deployment_allowed`` est uniquement une indication logique. Aucun modele de ce
module ne lance Terraform, un deploiement, un scanner ou un appel cloud.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any

from security_models import RuleStatus, SecuritySeverity


INTERNAL_SECURITY_POLICY_ID = "INTERNAL_SECURITY_POLICY_BASELINE"
INTERNAL_SECURITY_POLICY_VERSION = "1.0"
INTERNAL_SECURITY_POLICY_PROFILE = "INTERNAL_SECURITY_BASELINE"


class InvalidSecurityPolicyError(ValueError):
    """La configuration d'une politique de securite est invalide."""


class SecurityPolicyDisabledError(InvalidSecurityPolicyError):
    """Une politique desactivee ne peut pas produire de decision sure."""


class PolicyDecisionStatus(str, Enum):
    """Decisions stables du gate, de la moins a la plus restrictive."""

    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"

    @property
    def priority(self) -> int:
        """Retourne l'ordre stable BLOCK > REQUIRE_APPROVAL > ALLOW."""

        return {
            PolicyDecisionStatus.ALLOW: 1,
            PolicyDecisionStatus.REQUIRE_APPROVAL: 2,
            PolicyDecisionStatus.BLOCK: 3,
        }[self]


class PolicyReasonCode(str, Enum):
    """Identifiants metier deterministes, distincts des messages humains."""

    ALLOW_BASELINE_MET = "POLICY_ALLOW_BASELINE_MET"
    APPROVAL_REQUIRED = "POLICY_APPROVAL_REQUIRED"
    BLOCK_CRITICAL_FINDING = "POLICY_BLOCK_CRITICAL_FINDING"
    BLOCK_THRESHOLD_EXCEEDED = "POLICY_BLOCK_THRESHOLD_EXCEEDED"
    INSUFFICIENT_SECURITY_DATA = "POLICY_INSUFFICIENT_SECURITY_DATA"


def _required_text(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidSecurityPolicyError(
            f"{field_name} doit etre une chaine non vide"
        )
    return value.strip()


def _threshold(value: int, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise InvalidSecurityPolicyError(
            f"{field_name} doit etre un entier positif ou nul"
        )
    return value


@dataclass(frozen=True)
class SecurityPolicy:
    """Configuration explicite du gate, sans DSL ni effet de bord.

    Un seuil strictement positif est le nombre minimal de findings ``FAIL`` de
    la severite concernee qui declenche l'action. La valeur zero desactive ce
    seuil. Les warnings ne sont jamais assimiles a des failures.
    """

    policy_id: str
    policy_version: str
    name: str
    description: str
    enabled: bool
    profile: str
    framework: str
    critical_fail_threshold: int
    high_fail_threshold: int
    medium_fail_threshold: int
    approval_on_high: bool
    block_on_critical: bool
    minimum_resources_required: int
    require_complete_security_evaluation: bool

    def __post_init__(self) -> None:
        for field_name in (
            "policy_id",
            "policy_version",
            "name",
            "description",
            "profile",
            "framework",
        ):
            object.__setattr__(
                self,
                field_name,
                _required_text(getattr(self, field_name), field_name),
            )
        for field_name in (
            "critical_fail_threshold",
            "high_fail_threshold",
            "medium_fail_threshold",
            "minimum_resources_required",
        ):
            object.__setattr__(
                self,
                field_name,
                _threshold(getattr(self, field_name), field_name),
            )
        for field_name in (
            "enabled",
            "approval_on_high",
            "block_on_critical",
            "require_complete_security_evaluation",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise InvalidSecurityPolicyError(
                    f"{field_name} doit etre un booleen"
                )


@dataclass(frozen=True)
class PolicyTriggeredFinding:
    """Projection sure d'un finding ayant contribue a une decision."""

    rule_id: str
    cloud: str
    resource_address: str
    severity: SecuritySeverity
    status: RuleStatus
    title: str

    def __post_init__(self) -> None:
        for field_name in ("rule_id", "cloud", "resource_address", "title"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} doit etre une chaine non vide")
            object.__setattr__(self, field_name, value.strip())
        if not isinstance(self.severity, SecuritySeverity):
            raise TypeError("severity doit etre un SecuritySeverity")
        if not isinstance(self.status, RuleStatus):
            raise TypeError("status doit etre un RuleStatus")

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "cloud": self.cloud,
            "resource_address": self.resource_address,
            "severity": self.severity.value,
            "status": self.status.value,
            "title": self.title,
        }


@dataclass(frozen=True)
class PolicyDecision:
    """Decision pure du gate et informations minimales qui la justifient.

    ``ALLOW`` indique seulement l'absence de condition bloquante pour cette
    politique. ``REQUIRE_APPROVAL`` refuse une autorisation automatique et
    demande une intervention externe non implementee ici. ``BLOCK`` recommande
    de ne pas poursuivre. Aucune de ces valeurs n'execute un deploiement.
    """

    decision: PolicyDecisionStatus
    policy_id: str
    policy_version: str
    reason_code: PolicyReasonCode
    message: str
    triggered_rules: tuple[str, ...]
    triggered_findings: tuple[PolicyTriggeredFinding, ...]
    severity_summary: Mapping[str, int]
    requires_human_approval: bool
    deployment_allowed: bool

    def __post_init__(self) -> None:
        if not isinstance(self.decision, PolicyDecisionStatus):
            raise TypeError("decision doit etre un PolicyDecisionStatus")
        if not isinstance(self.reason_code, PolicyReasonCode):
            raise TypeError("reason_code doit etre un PolicyReasonCode")
        for field_name in ("policy_id", "policy_version", "message"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} doit etre une chaine non vide")
            object.__setattr__(self, field_name, value.strip())

        rules = tuple(self.triggered_rules)
        if any(not isinstance(rule_id, str) or not rule_id for rule_id in rules):
            raise ValueError("triggered_rules doit contenir des identifiants non vides")
        if len(rules) != len(set(rules)):
            raise ValueError("triggered_rules ne doit pas contenir de doublons")
        object.__setattr__(self, "triggered_rules", rules)

        findings = tuple(self.triggered_findings)
        if any(not isinstance(item, PolicyTriggeredFinding) for item in findings):
            raise TypeError(
                "triggered_findings doit contenir des PolicyTriggeredFinding"
            )
        object.__setattr__(self, "triggered_findings", findings)

        supplied_summary = dict(self.severity_summary)
        expected_keys = tuple(severity.value for severity in SecuritySeverity)
        if set(supplied_summary) != set(expected_keys):
            raise ValueError(
                "severity_summary doit contenir CRITICAL, HIGH, MEDIUM, LOW, INFO"
            )
        if any(
            not isinstance(count, int) or isinstance(count, bool) or count < 0
            for count in supplied_summary.values()
        ):
            raise ValueError("severity_summary doit contenir des entiers positifs")
        object.__setattr__(
            self,
            "severity_summary",
            MappingProxyType(
                {severity: supplied_summary[severity] for severity in expected_keys}
            ),
        )

        if not isinstance(self.requires_human_approval, bool):
            raise TypeError("requires_human_approval doit etre un booleen")
        if not isinstance(self.deployment_allowed, bool):
            raise TypeError("deployment_allowed doit etre un booleen")
        expected_flags = {
            PolicyDecisionStatus.ALLOW: (False, True),
            PolicyDecisionStatus.REQUIRE_APPROVAL: (True, False),
            PolicyDecisionStatus.BLOCK: (False, False),
        }[self.decision]
        if (
            self.requires_human_approval,
            self.deployment_allowed,
        ) != expected_flags:
            raise ValueError("Les indicateurs sont incoherents avec la decision")

    def to_dict(self) -> dict[str, Any]:
        """Retourne une representation stable sans details bruts ni secrets."""

        return {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "decision": self.decision.value,
            "reason_code": self.reason_code.value,
            "message": self.message,
            "triggered_rules": list(self.triggered_rules),
            "triggered_findings": [
                finding.to_dict() for finding in self.triggered_findings
            ],
            "severity_summary": dict(self.severity_summary),
            "requires_human_approval": self.requires_human_approval,
            "deployment_allowed": self.deployment_allowed,
        }

    def to_json(self, indent: int | None = 2) -> str:
        """Serialise la decision de facon deterministe et sans timestamp."""

        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


def build_default_security_policy() -> SecurityPolicy:
    """Construit la baseline interne de demonstration, non officielle."""

    return SecurityPolicy(
        policy_id=INTERNAL_SECURITY_POLICY_ID,
        policy_version=INTERNAL_SECURITY_POLICY_VERSION,
        name="Internal security policy baseline",
        description="Internal demonstration policy; no official compliance claim.",
        enabled=True,
        profile=INTERNAL_SECURITY_POLICY_PROFILE,
        framework=INTERNAL_SECURITY_POLICY_PROFILE,
        critical_fail_threshold=1,
        high_fail_threshold=1,
        medium_fail_threshold=1,
        approval_on_high=True,
        block_on_critical=True,
        minimum_resources_required=1,
        require_complete_security_evaluation=False,
    )
