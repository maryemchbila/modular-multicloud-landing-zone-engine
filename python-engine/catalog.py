"""Catalogue versionne et strict de templates d'infrastructure non sensibles."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

try:
    import yaml
except ImportError as exc:  # pragma: no cover - verifie par le demarrage convivial
    yaml = None
    _YAML_IMPORT_ERROR = exc
else:
    _YAML_IMPORT_ERROR = None


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CATALOG_ROOT = (PROJECT_ROOT / "catalog").resolve()
_IDENTIFIER = re.compile(r"\A[a-z0-9]+(?:[a-z0-9_-]*[a-z0-9])?\Z")
_TEMPLATE_ID = re.compile(r"\A(?:gcp|oci)-[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_PARAMETER_PREFIX = re.compile(r"\A[a-z][a-z0-9_]*_\Z")
_PROVIDERS = frozenset({"gcp", "oci"})
_MODULES = frozenset({"compute", "network", "storage", "iam", "landing-zone"})
_FIELDS = frozenset(
    {
        "template_id",
        "provider",
        "module",
        "name",
        "description",
        "defaults",
        "required_parameters",
        "optional_parameters",
        "security_defaults",
        "components",
    }
)


class CatalogError(ValueError):
    pass


@dataclass(frozen=True)
class CatalogComponent:
    template_id: str
    parameter_prefix: str


@dataclass(frozen=True)
class InfrastructureTemplate:
    template_id: str
    provider: str
    module: str
    name: str
    description: str
    defaults: Mapping[str, Any]
    required_parameters: tuple[str, ...]
    optional_parameters: tuple[str, ...]
    security_defaults: Mapping[str, Any]
    components: tuple[CatalogComponent, ...] = ()

    @property
    def parameter_names(self) -> tuple[str, ...]:
        return self.required_parameters + self.optional_parameters


class CatalogLoader:
    """Charge uniquement des IDs indexes sous ``<PROJECT_ROOT>/catalog``."""

    def __init__(self, catalog_root: Path = CATALOG_ROOT) -> None:
        self.catalog_root = Path(catalog_root).resolve()
        if yaml is None:
            raise CatalogError(
                "PyYAML est requis pour le catalogue. Installez requirements.txt."
            ) from _YAML_IMPORT_ERROR
        self._ensure_under_catalog(self.catalog_root, allow_root=True)

    def list_templates(self, provider: str | None = None) -> tuple[InfrastructureTemplate, ...]:
        if provider is not None and provider not in _PROVIDERS:
            raise CatalogError("CATALOG_PROVIDER_INVALID")
        providers = (provider,) if provider else tuple(sorted(_PROVIDERS))
        templates: list[InfrastructureTemplate] = []
        for selected_provider in providers:
            directory = self._ensure_under_catalog(
                self.catalog_root / selected_provider,
                allow_root=False,
            )
            if not directory.is_dir():
                continue
            for path in sorted(directory.glob("*.yaml")):
                templates.append(self._load_path(path, selected_provider))
        return tuple(templates)

    def get(self, template_id: str) -> InfrastructureTemplate:
        if not isinstance(template_id, str) or not _TEMPLATE_ID.fullmatch(template_id):
            raise CatalogError("CATALOG_TEMPLATE_ID_INVALID")
        provider = template_id.split("-", 1)[0]
        expected_prefix = f"{provider}-"
        filename = template_id.removeprefix(expected_prefix) + ".yaml"
        path = self._ensure_under_catalog(
            self.catalog_root / provider / filename,
            allow_root=False,
        )
        if not path.is_file():
            raise CatalogError("CATALOG_TEMPLATE_NOT_FOUND")
        return self._load_path(path, provider)

    def _load_path(self, path: Path, expected_provider: str) -> InfrastructureTemplate:
        safe_path = self._ensure_under_catalog(path, allow_root=False)
        try:
            raw = yaml.safe_load(safe_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise CatalogError("CATALOG_TEMPLATE_NOT_READABLE") from exc
        if not isinstance(raw, dict) or set(raw) != _FIELDS:
            raise CatalogError("CATALOG_SCHEMA_INVALID")
        template_id = self._text(raw["template_id"], "template_id")
        provider = self._text(raw["provider"], "provider")
        module = self._text(raw["module"], "module")
        if not _TEMPLATE_ID.fullmatch(template_id):
            raise CatalogError("CATALOG_TEMPLATE_ID_INVALID")
        if provider != expected_provider or provider not in _PROVIDERS:
            raise CatalogError("CATALOG_PROVIDER_INVALID")
        expected_id = f"{provider}-{safe_path.stem}"
        if template_id != expected_id:
            raise CatalogError("CATALOG_TEMPLATE_FILENAME_MISMATCH")
        if module not in _MODULES:
            raise CatalogError("CATALOG_MODULE_INVALID")
        required = self._parameters(raw["required_parameters"], "required_parameters")
        optional = self._parameters(raw["optional_parameters"], "optional_parameters")
        if set(required) & set(optional):
            raise CatalogError("CATALOG_PARAMETER_OVERLAP")
        defaults = self._mapping(raw["defaults"], "defaults")
        security_defaults = self._mapping(raw["security_defaults"], "security_defaults")
        allowed_parameters = set(required) | set(optional)
        if set(defaults) - allowed_parameters or set(security_defaults) - allowed_parameters:
            raise CatalogError("CATALOG_DEFAULT_PARAMETER_UNKNOWN")
        if not set(optional) <= set(defaults):
            raise CatalogError("CATALOG_OPTIONAL_DEFAULT_MISSING")
        components = self._components(raw["components"], provider)
        if (module == "landing-zone") != bool(components):
            raise CatalogError("CATALOG_COMPONENTS_INVALID")
        return InfrastructureTemplate(
            template_id=template_id,
            provider=provider,
            module=module,
            name=self._text(raw["name"], "name"),
            description=self._text(raw["description"], "description"),
            defaults=MappingProxyType(defaults),
            required_parameters=required,
            optional_parameters=optional,
            security_defaults=MappingProxyType(security_defaults),
            components=components,
        )

    def _components(self, value: object, provider: str) -> tuple[CatalogComponent, ...]:
        if not isinstance(value, list):
            raise CatalogError("CATALOG_COMPONENTS_INVALID")
        result: list[CatalogComponent] = []
        for item in value:
            if not isinstance(item, dict) or set(item) != {"template_id", "parameter_prefix"}:
                raise CatalogError("CATALOG_COMPONENT_INVALID")
            template_id = self._text(item["template_id"], "component.template_id")
            prefix = self._text(item["parameter_prefix"], "component.parameter_prefix")
            if not _TEMPLATE_ID.fullmatch(template_id) or not template_id.startswith(f"{provider}-"):
                raise CatalogError("CATALOG_COMPONENT_PROVIDER_INVALID")
            if not _PARAMETER_PREFIX.fullmatch(prefix):
                raise CatalogError("CATALOG_COMPONENT_PREFIX_INVALID")
            result.append(CatalogComponent(template_id, prefix))
        return tuple(result)

    @staticmethod
    def _text(value: object, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise CatalogError(f"CATALOG_{field.upper()}_INVALID")
        return value.strip()

    @staticmethod
    def _mapping(value: object, field: str) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise CatalogError(f"CATALOG_{field.upper()}_INVALID")
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not _IDENTIFIER.fullmatch(key):
                raise CatalogError("CATALOG_PARAMETER_NAME_INVALID")
            if not isinstance(item, (str, bool, int, float)) or isinstance(item, bytes):
                raise CatalogError("CATALOG_DEFAULT_VALUE_INVALID")
            result[key] = item
        return result

    @staticmethod
    def _parameters(value: object, field: str) -> tuple[str, ...]:
        if not isinstance(value, list) or any(
            not isinstance(item, str) or not _IDENTIFIER.fullmatch(item)
            for item in value
        ):
            raise CatalogError(f"CATALOG_{field.upper()}_INVALID")
        result = tuple(value)
        if len(set(result)) != len(result):
            raise CatalogError("CATALOG_PARAMETER_DUPLICATE")
        return result

    def _ensure_under_catalog(self, candidate: Path, *, allow_root: bool) -> Path:
        resolved = candidate.resolve()
        try:
            relative = resolved.relative_to(self.catalog_root)
        except ValueError as exc:
            raise CatalogError("CATALOG_PATH_OUTSIDE_ROOT") from exc
        if not allow_root and not relative.parts:
            raise CatalogError("CATALOG_PATH_ROOT_FORBIDDEN")
        return resolved
