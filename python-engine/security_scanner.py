"""Moteur generique d'execution des regles de securite CIS-1."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence

from security_models import (
    RuleStatus,
    SecurityFinding,
    SecurityResource,
    SecurityScanResult,
    normalise_security_cloud,
)
from security_rule import SecurityRule


LOGGER = logging.getLogger(__name__)


class SecurityComplianceScanner:
    """Filtre et execute des regles injectees sur des ressources synthetiques."""

    RULE_EVALUATION_FAILED_MESSAGE = "Rule evaluation failed."
    _SENSITIVE_KEY_MARKERS = (
        "credential",
        "password",
        "privatekey",
        "secret",
        "tfstate",
        "tfvars",
        "token",
    )

    def __init__(self, rules: Iterable[SecurityRule]) -> None:
        try:
            collected_rules = tuple(rules)
        except TypeError as exc:
            raise TypeError("rules doit etre un iterable de SecurityRule") from exc
        if any(not isinstance(rule, SecurityRule) for rule in collected_rules):
            raise TypeError("rules doit contenir uniquement des SecurityRule")
        self.rules = tuple(sorted(collected_rules, key=self._rule_sort_key))

    def scan(
        self,
        cloud: str,
        resources: Iterable[SecurityResource],
    ) -> SecurityScanResult:
        """Execute chaque couple regle/ressource applicable une seule fois."""

        normalised_cloud = normalise_security_cloud(cloud)
        try:
            collected_resources = tuple(resources)
        except TypeError as exc:
            raise TypeError(
                "resources doit etre un iterable de SecurityResource"
            ) from exc
        if any(
            not isinstance(resource, SecurityResource)
            for resource in collected_resources
        ):
            raise TypeError(
                "resources doit contenir uniquement des SecurityResource"
            )

        cloud_resources = tuple(
            sorted(
                (
                    resource
                    for resource in collected_resources
                    if resource.cloud == normalised_cloud
                ),
                key=self._resource_sort_key,
            )
        )
        findings: list[SecurityFinding] = []
        for rule in self.rules:
            if rule.metadata.cloud != normalised_cloud:
                continue
            for resource in cloud_resources:
                if not self._scope_matches(rule, resource):
                    continue
                findings.append(self._evaluate_safely(rule, resource))

        findings.sort(key=self._finding_sort_key)
        return SecurityScanResult.build(normalised_cloud, findings)

    @staticmethod
    def _scope_matches(rule: SecurityRule, resource: SecurityResource) -> bool:
        metadata = rule.metadata
        if metadata.resource_type != resource.resource_type:
            return False
        if resource.service is not None and metadata.service != resource.service:
            return False
        return True

    def _evaluate_safely(
        self,
        rule: SecurityRule,
        resource: SecurityResource,
    ) -> SecurityFinding:
        try:
            finding = rule.evaluate(resource)
            self._validate_finding_context(rule, resource, finding)
            return finding
        except Exception:
            LOGGER.warning(
                "[security] cloud=%s rule_id=%s resource=%s status=SKIPPED",
                resource.cloud,
                rule.metadata.rule_id,
                resource.resource_address,
            )
            return SecurityFinding(
                rule_id=rule.metadata.rule_id,
                cloud=resource.cloud,
                resource_type=resource.resource_type,
                resource_name=resource.resource_name,
                resource_address=resource.resource_address,
                status=RuleStatus.SKIPPED,
                severity=rule.metadata.severity,
                title=rule.metadata.title,
                message=self.RULE_EVALUATION_FAILED_MESSAGE,
                recommendation=rule.metadata.recommendation,
            )

    @staticmethod
    def _validate_finding_context(
        rule: SecurityRule,
        resource: SecurityResource,
        finding: SecurityFinding,
    ) -> None:
        if not isinstance(finding, SecurityFinding):
            raise TypeError("evaluate doit retourner un SecurityFinding")
        expected_context = (
            rule.metadata.rule_id,
            resource.cloud,
            resource.resource_type,
            resource.resource_name,
            resource.resource_address,
        )
        actual_context = (
            finding.rule_id,
            finding.cloud,
            finding.resource_type,
            finding.resource_name,
            finding.resource_address,
        )
        if actual_context != expected_context:
            raise ValueError("Le finding ne correspond pas a son contexte")
        output_text = "\n".join(
            (
                finding.rule_id,
                finding.resource_type,
                finding.resource_name,
                finding.resource_address,
                finding.title,
                finding.message,
                finding.recommendation,
            )
        )
        if any(
            sensitive_value in output_text
            for sensitive_value in SecurityComplianceScanner._sensitive_values(
                resource.attributes
            )
        ):
            raise ValueError("Le finding contient une valeur sensible")

    @classmethod
    def _sensitive_values(cls, attributes: Mapping[str, object]) -> tuple[str, ...]:
        """Extrait sans journalisation les chaines placees sous une cle sensible."""

        values: set[str] = set()
        visited: set[int] = set()

        def visit(value: object, sensitive_context: bool = False) -> None:
            if isinstance(value, str):
                if sensitive_context and value:
                    values.add(value)
                return
            value_id = id(value)
            if value_id in visited:
                return
            if isinstance(value, Mapping):
                visited.add(value_id)
                for key, nested_value in value.items():
                    normalised_key = "".join(
                        character
                        for character in str(key).casefold()
                        if character.isalnum()
                    )
                    key_is_sensitive = any(
                        marker in normalised_key
                        for marker in cls._SENSITIVE_KEY_MARKERS
                    )
                    visit(nested_value, sensitive_context or key_is_sensitive)
                return
            if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
                visited.add(value_id)
                for nested_value in value:
                    visit(nested_value, sensitive_context)

        visit(attributes)
        return tuple(sorted(values))

    @staticmethod
    def _rule_sort_key(rule: SecurityRule) -> tuple[str, ...]:
        metadata = rule.metadata
        return (
            metadata.cloud,
            metadata.service,
            metadata.resource_type,
            metadata.rule_id,
        )

    @staticmethod
    def _resource_sort_key(resource: SecurityResource) -> tuple[str, ...]:
        return (
            resource.resource_address,
            resource.resource_type,
            resource.resource_name,
        )

    @staticmethod
    def _finding_sort_key(finding: SecurityFinding) -> tuple[int, str, str, str]:
        return (
            -finding.severity.priority,
            finding.rule_id,
            finding.resource_address,
            finding.resource_name,
        )
