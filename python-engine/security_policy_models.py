"""Modeles immuables et serialisables du Security Policy Gate.

``deployment_allowed`` est uniquement une indication logique. Aucun modele de ce
module ne lance Terraform, un deploiement, un scanner ou un appel cloud.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any

from security_models import (
    RuleStatus,
    SecurityFinding,
    SecuritySeverity,
    normalise_security_cloud,
)


INTERNAL_SECURITY_POLICY_ID = "INTERNAL_SECURITY_POLICY_BASELINE"
INTERNAL_SECURITY_POLICY_VERSION = "1.0"
INTERNAL_SECURITY_POLICY_PROFILE = "BASELINE"


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


class SecurityPolicyProfile(str, Enum):
    """Profils de politique internes, sans revendication CIS officielle."""

    BASELINE = "BASELINE"
    STRICT = "STRICT"
    CUSTOM = "CUSTOM"


class PolicyReasonCode(str, Enum):
    """Identifiants metier deterministes, distincts des messages humains."""

    ALLOW_BASELINE_MET = "POLICY_ALLOW_BASELINE_MET"
    APPROVAL_REQUIRED = "POLICY_APPROVAL_REQUIRED"
    BLOCK_CRITICAL_FINDING = "POLICY_BLOCK_CRITICAL_FINDING"
    BLOCK_THRESHOLD_EXCEEDED = "POLICY_BLOCK_THRESHOLD_EXCEEDED"
    INSUFFICIENT_SECURITY_DATA = "POLICY_INSUFFICIENT_SECURITY_DATA"
    APPROVAL_EXCEPTION_APPLIED = "POLICY_APPROVAL_EXCEPTION_APPLIED"


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


def _normalise_profile(
    value: SecurityPolicyProfile | str,
) -> SecurityPolicyProfile:
    if isinstance(value, SecurityPolicyProfile):
        return value
    if not isinstance(value, str) or not value.strip():
        raise InvalidSecurityPolicyError("profile doit etre un profil non vide")
    normalised = value.strip().upper()
    if normalised == "INTERNAL_SECURITY_BASELINE":
        normalised = SecurityPolicyProfile.BASELINE.value
    try:
        return SecurityPolicyProfile(normalised)
    except ValueError as exc:
        raise InvalidSecurityPolicyError(
            f"Profil de securite inconnu : {value!r}"
        ) from exc


def _normalise_scope(values: Iterable[str], field_name: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise InvalidSecurityPolicyError(
            f"{field_name} doit etre une collection de chaines"
        )
    try:
        collected = tuple(values)
    except TypeError as exc:
        raise InvalidSecurityPolicyError(
            f"{field_name} doit etre une collection de chaines"
        ) from exc
    return tuple(sorted({_required_text(value, field_name) for value in collected}))


def _reject_sensitive_text(value: str, field_name: str) -> str:
    normalised = _required_text(value, field_name)
    folded = normalised.casefold().replace("-", "_")
    sensitive_markers = (
        "password",
        "token",
        "private_key",
        "private key",
        "credential",
        "secret",
    )
    if any(marker in folded for marker in sensitive_markers):
        raise InvalidSecurityPolicyError(
            f"{field_name} ne doit contenir aucune donnee sensible"
        )
    return normalised


@dataclass(frozen=True)
class SecurityPolicyThresholds:
    """Seuils de decision; zero desactive une condition non critique.

    La protection ``CRITICAL FAIL`` est un invariant du moteur et doit rester a
    un finding. Les autres seuils acceptent zero pour desactiver la condition.
    """

    block_fail_critical: int
    block_fail_high: int
    approval_fail_high: int
    approval_fail_medium: int
    approval_warning_high: int
    approval_warning_medium: int

    def __post_init__(self) -> None:
        for field_name in (
            "block_fail_critical",
            "block_fail_high",
            "approval_fail_high",
            "approval_fail_medium",
            "approval_warning_high",
            "approval_warning_medium",
        ):
            object.__setattr__(
                self,
                field_name,
                _threshold(getattr(self, field_name), field_name),
            )
        if self.block_fail_critical != 1:
            raise InvalidSecurityPolicyError(
                "block_fail_critical doit rester egal a 1"
            )

    def to_dict(self) -> dict[str, int]:
        return {
            "block_fail_critical": self.block_fail_critical,
            "block_fail_high": self.block_fail_high,
            "approval_fail_high": self.approval_fail_high,
            "approval_fail_medium": self.approval_fail_medium,
            "approval_warning_high": self.approval_warning_high,
            "approval_warning_medium": self.approval_warning_medium,
        }


@dataclass(frozen=True)
class SecurityPolicyException:
    """Exception explicite, limitee, immutable et serialisable sans metadata."""

    exception_id: str
    reason: str
    enabled: bool = True
    rule_ids: tuple[str, ...] = ()
    clouds: tuple[str, ...] = ()
    resource_addresses: tuple[str, ...] = ()
    expires_at: datetime | None = None
    reference: str | None = None
    metadata: Mapping[str, Any] = field(
        default_factory=dict,
        compare=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "exception_id",
            _reject_sensitive_text(self.exception_id, "exception_id"),
        )
        object.__setattr__(
            self,
            "reason",
            _reject_sensitive_text(self.reason, "reason"),
        )
        if not isinstance(self.enabled, bool):
            raise InvalidSecurityPolicyError("enabled doit etre un booleen")
        object.__setattr__(
            self,
            "rule_ids",
            _normalise_scope(self.rule_ids, "rule_ids"),
        )
        try:
            normalised_clouds = tuple(
                sorted(
                    {
                        normalise_security_cloud(cloud)
                        for cloud in _normalise_scope(self.clouds, "clouds")
                    }
                )
            )
        except (TypeError, ValueError) as exc:
            raise InvalidSecurityPolicyError(
                "clouds contient un cloud non supporte"
            ) from exc
        object.__setattr__(self, "clouds", normalised_clouds)
        object.__setattr__(
            self,
            "resource_addresses",
            _normalise_scope(self.resource_addresses, "resource_addresses"),
        )
        if not (self.rule_ids or self.clouds or self.resource_addresses):
            raise InvalidSecurityPolicyError(
                "Une exception doit definir au moins un scope"
            )
        if self.expires_at is not None:
            if (
                not isinstance(self.expires_at, datetime)
                or self.expires_at.tzinfo is None
                or self.expires_at.utcoffset() is None
            ):
                raise InvalidSecurityPolicyError(
                    "expires_at doit etre un datetime avec fuseau"
                )
            object.__setattr__(
                self,
                "expires_at",
                self.expires_at.astimezone(timezone.utc),
            )
        if self.reference is not None:
            object.__setattr__(
                self,
                "reference",
                _reject_sensitive_text(self.reference, "reference"),
            )
        if not isinstance(self.metadata, Mapping):
            raise InvalidSecurityPolicyError("metadata doit etre un mapping")
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    def matches(self, finding: SecurityFinding) -> bool:
        """Applique AND entre dimensions et membership dans chaque dimension."""

        if not isinstance(finding, SecurityFinding):
            raise TypeError("finding doit etre un SecurityFinding")
        return (
            (not self.rule_ids or finding.rule_id in self.rule_ids)
            and (not self.clouds or finding.cloud in self.clouds)
            and (
                not self.resource_addresses
                or finding.resource_address in self.resource_addresses
            )
        )

    def is_active_at(self, evaluated_at: datetime | None) -> bool:
        if not self.enabled:
            return False
        if self.expires_at is None:
            return True
        if evaluated_at is None:
            raise ValueError(
                "evaluated_at est requis pour une exception avec expiration"
            )
        return evaluated_at < self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "exception_id": self.exception_id,
            "reason": self.reason,
            "enabled": self.enabled,
            "scope": {
                "rule_ids": list(self.rule_ids),
                "clouds": list(self.clouds),
                "resource_addresses": list(self.resource_addresses),
            },
            "expires_at": (
                self.expires_at.isoformat(timespec="seconds").replace("+00:00", "Z")
                if self.expires_at is not None
                else None
            ),
            "reference": self.reference,
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


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
    profile: SecurityPolicyProfile | str
    framework: str
    critical_fail_threshold: int
    high_fail_threshold: int
    medium_fail_threshold: int
    approval_on_high: bool
    block_on_critical: bool
    minimum_resources_required: int
    require_complete_security_evaluation: bool
    thresholds: SecurityPolicyThresholds | None = None
    exceptions: tuple[SecurityPolicyException, ...] = ()

    def __post_init__(self) -> None:
        for field_name in (
            "policy_id",
            "policy_version",
            "name",
            "description",
            "framework",
        ):
            object.__setattr__(
                self,
                field_name,
                _required_text(getattr(self, field_name), field_name),
            )
        object.__setattr__(self, "profile", _normalise_profile(self.profile))
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

        if self.critical_fail_threshold != 1 or not self.block_on_critical:
            raise InvalidSecurityPolicyError(
                "La protection CRITICAL FAIL doit rester active au seuil 1"
            )
        if self.thresholds is not None and not isinstance(
            self.thresholds,
            SecurityPolicyThresholds,
        ):
            raise InvalidSecurityPolicyError(
                "thresholds doit etre un SecurityPolicyThresholds"
            )
        if self.profile is SecurityPolicyProfile.CUSTOM and self.thresholds is None:
            raise InvalidSecurityPolicyError(
                "Une policy CUSTOM doit fournir des thresholds explicites"
            )
        if (
            self.profile is SecurityPolicyProfile.CUSTOM
            and self.thresholds is not None
            and not any(
                value > 0
                for field_name, value in self.thresholds.to_dict().items()
                if field_name != "block_fail_critical"
            )
        ):
            raise InvalidSecurityPolicyError(
                "Une policy CUSTOM doit activer une protection non critique"
            )

        exceptions = tuple(self.exceptions)
        if any(
            not isinstance(exception, SecurityPolicyException)
            for exception in exceptions
        ):
            raise InvalidSecurityPolicyError(
                "exceptions doit contenir des SecurityPolicyException"
            )
        stable_exceptions = tuple(
            sorted(exceptions, key=lambda exception: exception.exception_id)
        )
        exception_ids = tuple(
            exception.exception_id for exception in stable_exceptions
        )
        if len(exception_ids) != len(set(exception_ids)):
            raise InvalidSecurityPolicyError(
                "Les exception_id doivent etre uniques dans une policy"
            )
        object.__setattr__(self, "exceptions", stable_exceptions)

    @property
    def effective_thresholds(self) -> SecurityPolicyThresholds:
        """Retourne le modele explicite ou adapte les champs POLICY-1."""

        if self.thresholds is not None:
            return self.thresholds
        return SecurityPolicyThresholds(
            block_fail_critical=self.critical_fail_threshold,
            block_fail_high=(
                self.high_fail_threshold if not self.approval_on_high else 0
            ),
            approval_fail_high=(
                self.high_fail_threshold if self.approval_on_high else 0
            ),
            approval_fail_medium=self.medium_fail_threshold,
            approval_warning_high=0,
            approval_warning_medium=0,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialise la configuration publique sans metadata d'exception."""

        return {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "profile": self.profile.value,
            "framework": self.framework,
            "thresholds": self.effective_thresholds.to_dict(),
            "minimum_resources_required": self.minimum_resources_required,
            "require_complete_security_evaluation": (
                self.require_complete_security_evaluation
            ),
            "exceptions": [exception.to_dict() for exception in self.exceptions],
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


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
    profile: SecurityPolicyProfile = SecurityPolicyProfile.BASELINE
    applied_exception_ids: tuple[str, ...] = ()
    excepted_findings: tuple[PolicyTriggeredFinding, ...] = ()
    evaluation_time: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.decision, PolicyDecisionStatus):
            raise TypeError("decision doit etre un PolicyDecisionStatus")
        if not isinstance(self.reason_code, PolicyReasonCode):
            raise TypeError("reason_code doit etre un PolicyReasonCode")
        object.__setattr__(self, "profile", _normalise_profile(self.profile))
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

        exception_ids = tuple(sorted(self.applied_exception_ids))
        if any(
            not isinstance(exception_id, str) or not exception_id
            for exception_id in exception_ids
        ):
            raise ValueError(
                "applied_exception_ids doit contenir des identifiants non vides"
            )
        if len(exception_ids) != len(set(exception_ids)):
            raise ValueError("applied_exception_ids ne doit pas contenir de doublons")
        object.__setattr__(self, "applied_exception_ids", exception_ids)

        excepted_findings = tuple(self.excepted_findings)
        if any(
            not isinstance(item, PolicyTriggeredFinding)
            for item in excepted_findings
        ):
            raise TypeError(
                "excepted_findings doit contenir des PolicyTriggeredFinding"
            )
        object.__setattr__(self, "excepted_findings", excepted_findings)
        if self.evaluation_time is not None and (
            not isinstance(self.evaluation_time, str)
            or not self.evaluation_time.strip()
        ):
            raise ValueError("evaluation_time doit etre une chaine non vide ou None")

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
            "profile": self.profile.value,
            "decision": self.decision.value,
            "reason_code": self.reason_code.value,
            "message": self.message,
            "triggered_rules": list(self.triggered_rules),
            "triggered_findings": [
                finding.to_dict() for finding in self.triggered_findings
            ],
            "applied_exception_ids": list(self.applied_exception_ids),
            "excepted_findings": [
                finding.to_dict() for finding in self.excepted_findings
            ],
            "severity_summary": dict(self.severity_summary),
            "requires_human_approval": self.requires_human_approval,
            "deployment_allowed": self.deployment_allowed,
            "evaluation_time": self.evaluation_time,
        }

    def to_json(self, indent: int | None = 2) -> str:
        """Serialise la decision de facon deterministe et sans timestamp."""

        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


def build_baseline_security_policy(
    *,
    exceptions: Iterable[SecurityPolicyException] = (),
) -> SecurityPolicy:
    """Construit la baseline POLICY-1 interne et non officielle."""

    return SecurityPolicy(
        policy_id=INTERNAL_SECURITY_POLICY_ID,
        policy_version=INTERNAL_SECURITY_POLICY_VERSION,
        name="Internal security policy baseline",
        description="Internal demonstration policy; no official compliance claim.",
        enabled=True,
        profile=SecurityPolicyProfile.BASELINE,
        framework="INTERNAL_SECURITY_BASELINE",
        critical_fail_threshold=1,
        high_fail_threshold=1,
        medium_fail_threshold=1,
        approval_on_high=True,
        block_on_critical=True,
        minimum_resources_required=1,
        require_complete_security_evaluation=False,
        exceptions=tuple(exceptions),
    )


def build_default_security_policy() -> SecurityPolicy:
    """Alias logique retrocompatible vers la baseline POLICY-1."""

    return build_baseline_security_policy()


def build_strict_security_policy(
    *,
    exceptions: Iterable[SecurityPolicyException] = (),
) -> SecurityPolicy:
    """Construit le profil interne STRICT, plus conservateur."""

    thresholds = SecurityPolicyThresholds(
        block_fail_critical=1,
        block_fail_high=1,
        approval_fail_high=0,
        approval_fail_medium=1,
        approval_warning_high=1,
        approval_warning_medium=1,
    )
    return SecurityPolicy(
        policy_id="INTERNAL_SECURITY_POLICY_STRICT",
        policy_version="1.0",
        name="Internal strict security policy",
        description="Conservative internal policy; no official compliance claim.",
        enabled=True,
        profile=SecurityPolicyProfile.STRICT,
        framework="INTERNAL_SECURITY_BASELINE",
        critical_fail_threshold=1,
        high_fail_threshold=1,
        medium_fail_threshold=1,
        approval_on_high=False,
        block_on_critical=True,
        minimum_resources_required=1,
        require_complete_security_evaluation=False,
        thresholds=thresholds,
        exceptions=tuple(exceptions),
    )


def build_custom_security_policy(
    *,
    policy_id: str,
    policy_version: str,
    name: str,
    description: str,
    thresholds: SecurityPolicyThresholds,
    exceptions: Iterable[SecurityPolicyException] = (),
    enabled: bool = True,
    minimum_resources_required: int = 1,
    require_complete_security_evaluation: bool = False,
) -> SecurityPolicy:
    """Construit une policy CUSTOM explicite avec defaults fail-closed."""

    if not isinstance(thresholds, SecurityPolicyThresholds):
        raise InvalidSecurityPolicyError(
            "Une policy CUSTOM doit fournir des thresholds explicites"
        )
    return SecurityPolicy(
        policy_id=policy_id,
        policy_version=policy_version,
        name=name,
        description=description,
        enabled=enabled,
        profile=SecurityPolicyProfile.CUSTOM,
        framework="INTERNAL_SECURITY_BASELINE",
        critical_fail_threshold=1,
        high_fail_threshold=max(
            thresholds.block_fail_high,
            thresholds.approval_fail_high,
        ),
        medium_fail_threshold=thresholds.approval_fail_medium,
        approval_on_high=thresholds.approval_fail_high > 0,
        block_on_critical=True,
        minimum_resources_required=minimum_resources_required,
        require_complete_security_evaluation=require_complete_security_evaluation,
        thresholds=thresholds,
        exceptions=tuple(exceptions),
    )


def build_security_policy_for_profile(
    profile: SecurityPolicyProfile | str,
) -> SecurityPolicy:
    """Selectionne explicitement BASELINE ou STRICT; CUSTOM reste explicite."""

    normalised_profile = _normalise_profile(profile)
    if normalised_profile is SecurityPolicyProfile.BASELINE:
        return build_baseline_security_policy()
    if normalised_profile is SecurityPolicyProfile.STRICT:
        return build_strict_security_policy()
    raise InvalidSecurityPolicyError(
        "Le profil CUSTOM exige build_custom_security_policy"
    )
