"""Catalogue deterministe de regles et metadonnees de conformite CIS-2."""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from security_models import normalise_security_cloud
from security_rule import SecurityRule


class SecurityCatalogError(ValueError):
    """Erreur metier commune aux operations du catalogue."""


class DuplicateSecurityRuleError(SecurityCatalogError):
    """Un rule_id est deja enregistre dans le catalogue."""


class SecurityRuleNotFoundError(SecurityCatalogError):
    """Aucune regle ne correspond au rule_id demande."""


class SecurityRuleCatalog:
    """Enregistre et selectionne des regles sans executer leur logique."""

    DEFAULT_NAME = "security-rule-catalog"
    DEFAULT_VERSION = "1.0"
    TAG_MATCH_VALUES = frozenset({"all", "any"})

    def __init__(
        self,
        catalog_name: str = DEFAULT_NAME,
        catalog_version: str = DEFAULT_VERSION,
        description: str | None = None,
    ) -> None:
        self.catalog_name = self._normalise_required_text(
            catalog_name,
            "catalog_name",
        )
        self.catalog_version = self._normalise_required_text(
            catalog_version,
            "catalog_version",
        )
        self.description = self._normalise_optional_text(
            description,
            "description",
        )
        self._rules_by_id: dict[str, SecurityRule] = {}

    @property
    def rules(self) -> tuple[SecurityRule, ...]:
        """Retourne toutes les regles dans un ordre stable."""

        return tuple(sorted(self._rules_by_id.values(), key=self._rule_sort_key))

    def register(self, rule: SecurityRule) -> None:
        """Enregistre une regle sans jamais remplacer un rule_id existant."""

        self.register_many((rule,))

    def register_many(self, rules: Iterable[SecurityRule]) -> None:
        """Valide puis enregistre un lot entier de facon atomique."""

        try:
            collected_rules = tuple(rules)
        except TypeError as exc:
            raise TypeError("rules doit etre un iterable de SecurityRule") from exc
        if any(not isinstance(rule, SecurityRule) for rule in collected_rules):
            raise TypeError("rules doit contenir uniquement des SecurityRule")

        known_ids = set(self._rules_by_id)
        for rule in collected_rules:
            rule_id = rule.metadata.rule_id
            if rule_id in known_ids:
                raise DuplicateSecurityRuleError(
                    f"Security rule deja enregistree : {rule_id}"
                )
            known_ids.add(rule_id)

        self._rules_by_id.update(
            (rule.metadata.rule_id, rule) for rule in collected_rules
        )

    def get(self, rule_id: str) -> SecurityRule:
        """Retourne une regle ou leve une erreur metier explicite."""

        normalised_rule_id = self._normalise_required_text(rule_id, "rule_id")
        try:
            return self._rules_by_id[normalised_rule_id]
        except KeyError as exc:
            raise SecurityRuleNotFoundError(
                f"Security rule introuvable : {normalised_rule_id}"
            ) from exc

    def select(
        self,
        *,
        cloud: str | None = None,
        service: str | None = None,
        resource_type: str | None = None,
        profile: str | None = None,
        tags: Iterable[str] | None = None,
        tag_match: str = "all",
        enabled_only: bool = True,
    ) -> tuple[SecurityRule, ...]:
        """Selectionne des regles; plusieurs tags utilisent ALL par defaut."""

        normalised_cloud = (
            normalise_security_cloud(cloud) if cloud is not None else None
        )
        normalised_service = self._normalise_optional_filter(service, "service")
        normalised_resource_type = self._normalise_optional_filter(
            resource_type,
            "resource_type",
            casefold=False,
        )
        normalised_profile = self._normalise_optional_filter(profile, "profile")
        normalised_tags = self._normalise_filter_tags(tags)
        normalised_tag_match = self._normalise_tag_match(tag_match)
        if not isinstance(enabled_only, bool):
            raise TypeError("enabled_only doit etre un booleen")

        return tuple(
            rule
            for rule in self.rules
            if self._matches(
                rule,
                cloud=normalised_cloud,
                service=normalised_service,
                resource_type=normalised_resource_type,
                profile=normalised_profile,
                tags=normalised_tags,
                tag_match=normalised_tag_match,
                enabled_only=enabled_only,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialise uniquement l'inventaire stable des metadonnees."""

        rules = self.rules
        return {
            "catalog_name": self.catalog_name,
            "catalog_version": self.catalog_version,
            "description": self.description,
            "rules_total": len(rules),
            "rules_enabled": sum(rule.metadata.enabled for rule in rules),
            "rules_disabled": sum(not rule.metadata.enabled for rule in rules),
            "clouds": {
                cloud: sum(rule.metadata.cloud == cloud for rule in rules)
                for cloud in ("gcp", "oci")
            },
            "rules": [rule.metadata.to_dict() for rule in rules],
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    @staticmethod
    def _matches(
        rule: SecurityRule,
        *,
        cloud: str | None,
        service: str | None,
        resource_type: str | None,
        profile: str | None,
        tags: tuple[str, ...],
        tag_match: str,
        enabled_only: bool,
    ) -> bool:
        metadata = rule.metadata
        if enabled_only and not metadata.enabled:
            return False
        if cloud is not None and metadata.cloud != cloud:
            return False
        if service is not None and metadata.service != service:
            return False
        if resource_type is not None and metadata.resource_type != resource_type:
            return False
        if profile is not None and profile not in metadata.profiles:
            return False
        if not tags:
            return True
        metadata_tags = set(metadata.tags)
        requested_tags = set(tags)
        if tag_match == "all":
            return requested_tags.issubset(metadata_tags)
        return bool(requested_tags.intersection(metadata_tags))

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
    def _normalise_required_text(value: str, field_name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field_name} doit etre une chaine non vide")
        return value.strip()

    @staticmethod
    def _normalise_optional_text(
        value: str | None,
        field_name: str,
    ) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError(f"{field_name} doit etre une chaine ou None")
        return value.strip() or None

    @classmethod
    def _normalise_optional_filter(
        cls,
        value: str | None,
        field_name: str,
        *,
        casefold: bool = True,
    ) -> str | None:
        if value is None:
            return None
        normalised_value = cls._normalise_required_text(value, field_name)
        return normalised_value.casefold() if casefold else normalised_value

    @classmethod
    def _normalise_filter_tags(
        cls,
        tags: Iterable[str] | None,
    ) -> tuple[str, ...]:
        if tags is None:
            return ()
        if isinstance(tags, (str, bytes)):
            raise TypeError("tags doit etre une collection de chaines")
        try:
            return tuple(
                sorted(
                    {
                        cls._normalise_required_text(tag, "tags").casefold()
                        for tag in tags
                    }
                )
            )
        except TypeError as exc:
            raise TypeError("tags doit etre une collection de chaines") from exc

    @classmethod
    def _normalise_tag_match(cls, tag_match: str) -> str:
        normalised_value = cls._normalise_required_text(
            tag_match,
            "tag_match",
        ).casefold()
        if normalised_value not in cls.TAG_MATCH_VALUES:
            raise ValueError("tag_match doit etre 'all' ou 'any'")
        return normalised_value
