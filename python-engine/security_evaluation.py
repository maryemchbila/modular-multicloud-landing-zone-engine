"""Orchestration deterministe des evaluations de securite multi-cloud."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from security_catalog import SecurityRuleCatalog
from security_gcp_pack import build_gcp_security_rule_pack
from security_models import (
    SecurityResource,
    SecurityScanResult,
    SecurityScanStatus,
    SecuritySeverity,
)
from security_oci_pack import build_oci_security_rule_pack
from security_rule import SecurityRule
from security_scanner import SecurityComplianceScanner


SECURITY_CLOUD_ORDER = ("gcp", "oci")


@dataclass(frozen=True)
class MultiCloudSecurityEvaluationResult:
    """Agrege des resultats de scan existants sans dupliquer leurs findings."""

    cloud_results: Mapping[str, SecurityScanResult]
    resources_total: int
    clouds_evaluated: tuple[str, ...] = field(init=False)
    findings_total: int = field(init=False)
    passed: int = field(init=False)
    failed: int = field(init=False)
    warnings: int = field(init=False)
    skipped: int = field(init=False)
    not_applicable: int = field(init=False)
    severity_counts: Mapping[SecuritySeverity, int] = field(init=False)
    evaluation_status: SecurityScanStatus = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.cloud_results, Mapping):
            raise TypeError("cloud_results doit etre un mapping")
        if (
            not isinstance(self.resources_total, int)
            or isinstance(self.resources_total, bool)
            or self.resources_total < 0
        ):
            raise ValueError("resources_total doit etre un entier positif ou nul")

        supplied_results = dict(self.cloud_results)
        unknown_clouds = tuple(
            sorted(set(supplied_results).difference(SECURITY_CLOUD_ORDER))
        )
        if unknown_clouds:
            raise ValueError(
                f"cloud_results contient un cloud non supporte : {unknown_clouds[0]!r}"
            )

        stable_results: dict[str, SecurityScanResult] = {}
        for cloud in SECURITY_CLOUD_ORDER:
            if cloud not in supplied_results:
                continue
            scan_result = supplied_results[cloud]
            if not isinstance(scan_result, SecurityScanResult):
                raise TypeError(
                    "cloud_results doit contenir des SecurityScanResult"
                )
            if scan_result.cloud != cloud:
                raise ValueError(
                    "La cle cloud_results ne correspond pas au cloud du scan"
                )
            stable_results[cloud] = scan_result

        object.__setattr__(
            self,
            "cloud_results",
            MappingProxyType(stable_results),
        )
        object.__setattr__(self, "clouds_evaluated", tuple(stable_results))
        object.__setattr__(
            self,
            "findings_total",
            sum(result.total_rules_evaluated for result in stable_results.values()),
        )
        for attribute in (
            "passed",
            "failed",
            "warnings",
            "skipped",
            "not_applicable",
        ):
            object.__setattr__(
                self,
                attribute,
                sum(getattr(result, attribute) for result in stable_results.values()),
            )

        severity_counts = {
            severity: sum(
                result.severity_counts.get(severity, 0)
                for result in stable_results.values()
            )
            for severity in SecuritySeverity
        }
        object.__setattr__(
            self,
            "severity_counts",
            MappingProxyType(severity_counts),
        )
        object.__setattr__(
            self,
            "evaluation_status",
            self._aggregate_status(stable_results.values()),
        )

    @staticmethod
    def _aggregate_status(
        scan_results: Iterable[SecurityScanResult],
    ) -> SecurityScanStatus:
        statuses = tuple(result.scan_status for result in scan_results)
        if SecurityScanStatus.FAIL in statuses:
            return SecurityScanStatus.FAIL
        if SecurityScanStatus.PASS_WITH_WARNINGS in statuses:
            return SecurityScanStatus.PASS_WITH_WARNINGS
        return SecurityScanStatus.PASS

    def to_dict(self) -> dict[str, Any]:
        """Serialise uniquement les resultats securises produits par les scanners."""

        return {
            "evaluation_status": self.evaluation_status.value,
            "resources_total": self.resources_total,
            "findings_total": self.findings_total,
            "clouds_evaluated": list(self.clouds_evaluated),
            "summary": {
                "passed": self.passed,
                "failed": self.failed,
                "warnings": self.warnings,
                "skipped": self.skipped,
                "not_applicable": self.not_applicable,
            },
            "severity_counts": {
                severity.value: self.severity_counts.get(severity, 0)
                for severity in SecuritySeverity
            },
            "cloud_results": {
                cloud: result.to_dict()
                for cloud, result in self.cloud_results.items()
            },
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


class MultiCloudSecurityEvaluationEngine:
    """Orchestre un scan distinct par cloud avec les composants existants."""

    def __init__(self, catalog: SecurityRuleCatalog) -> None:
        if not isinstance(catalog, SecurityRuleCatalog):
            raise TypeError("catalog doit etre un SecurityRuleCatalog")
        self._catalog = catalog

    @property
    def catalog(self) -> SecurityRuleCatalog:
        return self._catalog

    def evaluate(
        self,
        resources: Sequence[SecurityResource],
        *,
        profile: str | None = "baseline",
        services: Iterable[str] | None = None,
        tags: Iterable[str] | None = None,
        tag_match: str = "all",
        enabled_only: bool = True,
    ) -> MultiCloudSecurityEvaluationResult:
        """Groupe, selectionne puis scanne les ressources dans un ordre stable."""

        collected_resources = self._collect_resources(resources)
        normalised_profile = self._normalise_optional_text(profile, "profile")
        normalised_services = self._normalise_filters(services, "services")
        normalised_tags = self._normalise_filters(tags, "tags") or ()
        normalised_tag_match = self._normalise_tag_match(tag_match)
        if not isinstance(enabled_only, bool):
            raise TypeError("enabled_only doit etre un booleen")

        grouped_resources = {
            cloud: tuple(
                resource
                for resource in collected_resources
                if resource.cloud == cloud
            )
            for cloud in SECURITY_CLOUD_ORDER
        }
        cloud_results: dict[str, SecurityScanResult] = {}
        for cloud in SECURITY_CLOUD_ORDER:
            cloud_resources = grouped_resources[cloud]
            if not cloud_resources:
                continue
            selected_rules = self._select_rules(
                cloud=cloud,
                profile=normalised_profile,
                services=normalised_services,
                tags=normalised_tags,
                tag_match=normalised_tag_match,
                enabled_only=enabled_only,
            )
            cloud_results[cloud] = SecurityComplianceScanner(
                selected_rules
            ).scan(cloud, cloud_resources)

        return MultiCloudSecurityEvaluationResult(
            cloud_results=cloud_results,
            resources_total=len(collected_resources),
        )

    def _select_rules(
        self,
        *,
        cloud: str,
        profile: str | None,
        services: tuple[str, ...] | None,
        tags: tuple[str, ...],
        tag_match: str,
        enabled_only: bool,
    ) -> tuple[SecurityRule, ...]:
        selection_arguments = {
            "cloud": cloud,
            "profile": profile,
            "tags": tags,
            "tag_match": tag_match,
            "enabled_only": enabled_only,
        }
        if services is None:
            return self.catalog.select(**selection_arguments)

        selected_by_id: dict[str, SecurityRule] = {}
        for service in services:
            for rule in self.catalog.select(
                service=service,
                **selection_arguments,
            ):
                selected_by_id[rule.metadata.rule_id] = rule
        return tuple(
            sorted(selected_by_id.values(), key=self._rule_sort_key)
        )

    @staticmethod
    def _collect_resources(
        resources: Sequence[SecurityResource],
    ) -> tuple[SecurityResource, ...]:
        if isinstance(resources, (str, bytes)):
            raise TypeError(
                "resources doit etre une sequence de SecurityResource"
            )
        try:
            collected_resources = tuple(resources)
        except TypeError as exc:
            raise TypeError(
                "resources doit etre une sequence de SecurityResource"
            ) from exc
        if any(
            not isinstance(resource, SecurityResource)
            for resource in collected_resources
        ):
            raise TypeError(
                "resources doit contenir uniquement des SecurityResource"
            )
        return collected_resources

    @staticmethod
    def _normalise_optional_text(
        value: str | None,
        field_name: str,
    ) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field_name} doit etre une chaine non vide ou None")
        return value.strip().casefold()

    @classmethod
    def _normalise_filters(
        cls,
        values: Iterable[str] | None,
        field_name: str,
    ) -> tuple[str, ...] | None:
        if values is None:
            return None
        if isinstance(values, (str, bytes)):
            raise TypeError(f"{field_name} doit etre une collection de chaines")
        try:
            collected_values = tuple(values)
        except TypeError as exc:
            raise TypeError(
                f"{field_name} doit etre une collection de chaines"
            ) from exc
        return tuple(
            sorted(
                {
                    cls._normalise_required_text(value, field_name)
                    for value in collected_values
                }
            )
        )

    @staticmethod
    def _normalise_required_text(value: str, field_name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field_name} doit contenir des chaines non vides")
        return value.strip().casefold()

    @staticmethod
    def _normalise_tag_match(tag_match: str) -> str:
        if not isinstance(tag_match, str) or not tag_match.strip():
            raise ValueError("tag_match doit etre 'all' ou 'any'")
        normalised_tag_match = tag_match.strip().casefold()
        if normalised_tag_match not in SecurityRuleCatalog.TAG_MATCH_VALUES:
            raise ValueError("tag_match doit etre 'all' ou 'any'")
        return normalised_tag_match

    @staticmethod
    def _rule_sort_key(rule: SecurityRule) -> tuple[str, ...]:
        metadata = rule.metadata
        return (
            metadata.cloud,
            metadata.service,
            metadata.resource_type,
            metadata.rule_id,
        )


def build_default_multicloud_security_engine(
) -> MultiCloudSecurityEvaluationEngine:
    """Construit le catalogue interne GCP + OCI et son orchestrateur."""

    catalog = SecurityRuleCatalog(
        catalog_name="multi-cloud-internal-security-baseline",
        catalog_version="1.0",
        description="Internal deterministic GCP and OCI security rule catalog.",
    )
    catalog.register_many(
        build_gcp_security_rule_pack() + build_oci_security_rule_pack()
    )
    return MultiCloudSecurityEvaluationEngine(catalog)
