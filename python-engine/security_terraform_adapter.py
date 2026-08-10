"""Adaptation pure d'un plan Terraform structure vers SecurityResource."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from security_models import SecurityResource


SUPPORTED_GCP_RESOURCE_TYPES = frozenset(
    {
        "google_compute_firewall",
        "google_compute_instance",
        "google_project_iam_member",
        "google_storage_bucket",
    }
)
SUPPORTED_OCI_RESOURCE_TYPES = frozenset(
    {
        "oci_core_instance",
        "oci_core_security_list",
        "oci_identity_policy",
        "oci_objectstorage_bucket",
    }
)
SUPPORTED_TERRAFORM_RESOURCE_TYPES = (
    SUPPORTED_GCP_RESOURCE_TYPES | SUPPORTED_OCI_RESOURCE_TYPES
)

_RESOURCE_CONTEXT = MappingProxyType(
    {
        "google_compute_firewall": ("gcp", "network"),
        "google_compute_instance": ("gcp", "compute"),
        "google_project_iam_member": ("gcp", "iam"),
        "google_storage_bucket": ("gcp", "storage"),
        "oci_core_instance": ("oci", "compute"),
        "oci_core_security_list": ("oci", "network"),
        "oci_identity_policy": ("oci", "iam"),
        "oci_objectstorage_bucket": ("oci", "storage"),
    }
)
_VALID_RESOURCE_TYPE = re.compile(r"\A[a-z][a-z0-9_]*\Z")
_PORT_RANGE = re.compile(r"\A(\d+)-(\d+)\Z")
_MISSING = object()


@dataclass(frozen=True)
class TerraformSecurityAdaptationResult:
    """Resultat stable contenant seulement ressources normalisees et diagnostics."""

    resources: tuple[SecurityResource, ...]
    resources_seen: int
    resources_adapted: int
    unsupported_resource_types: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    resources_skipped: int = field(init=False)

    def __post_init__(self) -> None:
        stable_resources = tuple(sorted(self.resources, key=self._resource_sort_key))
        if any(
            not isinstance(resource, SecurityResource)
            for resource in stable_resources
        ):
            raise TypeError("resources doit contenir des SecurityResource")
        for field_name in ("resources_seen", "resources_adapted"):
            value = getattr(self, field_name)
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                raise ValueError(f"{field_name} doit etre un entier positif ou nul")
        if self.resources_adapted > self.resources_seen:
            raise ValueError("resources_adapted ne peut pas depasser resources_seen")

        object.__setattr__(self, "resources", stable_resources)
        object.__setattr__(
            self,
            "unsupported_resource_types",
            self._normalise_labels(
                self.unsupported_resource_types,
                "unsupported_resource_types",
            ),
        )
        object.__setattr__(
            self,
            "warnings",
            self._normalise_labels(self.warnings, "warnings"),
        )
        object.__setattr__(
            self,
            "resources_skipped",
            self.resources_seen - self.resources_adapted,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "resources_seen": self.resources_seen,
            "resources_adapted": self.resources_adapted,
            "resources_skipped": self.resources_skipped,
            "unsupported_resource_types": list(self.unsupported_resource_types),
            "warnings": list(self.warnings),
            "resources": [resource.to_dict() for resource in self.resources],
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    @staticmethod
    def _normalise_labels(
        values: Sequence[str],
        field_name: str,
    ) -> tuple[str, ...]:
        if isinstance(values, (str, bytes)):
            raise TypeError(f"{field_name} doit etre une collection de chaines")
        if any(not isinstance(value, str) or not value for value in values):
            raise ValueError(f"{field_name} contient une valeur invalide")
        return tuple(sorted(set(values)))

    @staticmethod
    def _resource_sort_key(resource: SecurityResource) -> tuple[str, ...]:
        return (
            resource.cloud,
            resource.resource_type,
            resource.resource_address,
            resource.resource_name,
        )


class TerraformSecurityResourceAdapter:
    """Transforme uniquement les types Terraform explicitement supportes."""

    PLANNED_VALUES_MISSING = "PLANNED_VALUES_MISSING"
    PLANNED_VALUES_INVALID = "PLANNED_VALUES_INVALID"
    ROOT_MODULE_MISSING = "ROOT_MODULE_MISSING"
    ROOT_MODULE_INVALID = "ROOT_MODULE_INVALID"
    MODULE_RESOURCES_INVALID = "MODULE_RESOURCES_INVALID"
    CHILD_MODULES_INVALID = "CHILD_MODULES_INVALID"
    MODULE_CYCLE_SKIPPED = "MODULE_CYCLE_SKIPPED"
    RESOURCE_ENTRY_INVALID = "RESOURCE_ENTRY_INVALID"
    RESOURCE_VALUES_INVALID = "RESOURCE_VALUES_INVALID"
    NON_MANAGED_RESOURCE_SKIPPED = "NON_MANAGED_RESOURCE_SKIPPED"

    def from_plan_dict(
        self,
        plan_data: Mapping[str, Any],
    ) -> TerraformSecurityAdaptationResult:
        """Adapte planned_values sans executer Terraform ni muter l'entree."""

        if not isinstance(plan_data, Mapping):
            raise TypeError("plan_data doit etre un mapping")

        entries, warnings = self._collect_plan_resources(plan_data)
        resources: list[SecurityResource] = []
        unsupported_types: list[str] = []
        resources_adapted = 0
        for entry in entries:
            adapted, unsupported_type, warning = self._adapt_entry(entry)
            if warning is not None:
                warnings.append(warning)
            if unsupported_type is not None:
                unsupported_types.append(unsupported_type)
            if adapted:
                resources_adapted += 1
                resources.extend(adapted)

        return TerraformSecurityAdaptationResult(
            resources=tuple(resources),
            resources_seen=len(entries),
            resources_adapted=resources_adapted,
            unsupported_resource_types=tuple(unsupported_types),
            warnings=tuple(warnings),
        )

    def _collect_plan_resources(
        self,
        plan_data: Mapping[str, Any],
    ) -> tuple[list[object], list[str]]:
        planned_values = plan_data.get("planned_values", _MISSING)
        if planned_values is _MISSING:
            return [], [self.PLANNED_VALUES_MISSING]
        if not isinstance(planned_values, Mapping):
            return [], [self.PLANNED_VALUES_INVALID]

        root_module = planned_values.get("root_module", _MISSING)
        if root_module is _MISSING:
            return [], [self.ROOT_MODULE_MISSING]
        if not isinstance(root_module, Mapping):
            return [], [self.ROOT_MODULE_INVALID]

        resources: list[object] = []
        warnings: list[str] = []
        self._walk_module(
            root_module,
            resources=resources,
            warnings=warnings,
            visited=set(),
        )
        return resources, warnings

    def _walk_module(
        self,
        module: Mapping[str, Any],
        *,
        resources: list[object],
        warnings: list[str],
        visited: set[int],
    ) -> None:
        module_id = id(module)
        if module_id in visited:
            warnings.append(self.MODULE_CYCLE_SKIPPED)
            return
        visited.add(module_id)

        module_resources = module.get("resources", ())
        if self._is_sequence(module_resources):
            resources.extend(module_resources)
        else:
            warnings.append(self.MODULE_RESOURCES_INVALID)

        child_modules = module.get("child_modules", ())
        if not self._is_sequence(child_modules):
            warnings.append(self.CHILD_MODULES_INVALID)
            return
        valid_children = [
            child for child in child_modules if isinstance(child, Mapping)
        ]
        if len(valid_children) != len(child_modules):
            warnings.append(self.CHILD_MODULES_INVALID)
        for child in sorted(valid_children, key=self._module_sort_key):
            self._walk_module(
                child,
                resources=resources,
                warnings=warnings,
                visited=visited,
            )

    def _adapt_entry(
        self,
        entry: object,
    ) -> tuple[tuple[SecurityResource, ...], str | None, str | None]:
        if not isinstance(entry, Mapping):
            return (), None, self.RESOURCE_ENTRY_INVALID

        resource_type = self._required_text(entry.get("type"))
        if resource_type is None or not _VALID_RESOURCE_TYPE.fullmatch(resource_type):
            return (), None, self.RESOURCE_ENTRY_INVALID
        if resource_type not in SUPPORTED_TERRAFORM_RESOURCE_TYPES:
            return (), resource_type, None

        mode = entry.get("mode")
        if mode is not None and self._required_text(mode) != "managed":
            return (), None, self.NON_MANAGED_RESOURCE_SKIPPED

        resource_name = self._required_text(entry.get("name"))
        if resource_name is None:
            return (), None, self.RESOURCE_ENTRY_INVALID
        resource_address = self._required_text(entry.get("address"))
        if resource_address is None:
            resource_address = f"{resource_type}.{resource_name}"

        values = entry.get("values", {})
        if values is None:
            values = {}
        if not isinstance(values, Mapping):
            return (), None, self.RESOURCE_VALUES_INVALID

        resources = self._map_supported_resource(
            resource_type=resource_type,
            resource_name=resource_name,
            resource_address=resource_address,
            values=values,
        )
        return resources, None, None

    def _map_supported_resource(
        self,
        *,
        resource_type: str,
        resource_name: str,
        resource_address: str,
        values: Mapping[str, Any],
    ) -> tuple[SecurityResource, ...]:
        if resource_type == "google_compute_instance":
            attribute_sets = (self._gcp_compute_attributes(values),)
        elif resource_type == "google_compute_firewall":
            attribute_sets = self._gcp_firewall_attributes(values)
        elif resource_type == "google_storage_bucket":
            attribute_sets = (self._gcp_storage_attributes(values),)
        elif resource_type == "google_project_iam_member":
            attribute_sets = (self._gcp_iam_attributes(values),)
        elif resource_type == "oci_core_instance":
            attribute_sets = (self._oci_compute_attributes(values),)
        elif resource_type == "oci_core_security_list":
            attribute_sets = self._oci_security_list_attributes(values)
        elif resource_type == "oci_objectstorage_bucket":
            attribute_sets = (self._oci_storage_attributes(values),)
        else:
            attribute_sets = (self._oci_iam_attributes(values),)

        cloud, service = _RESOURCE_CONTEXT[resource_type]
        multiple = len(attribute_sets) > 1
        return tuple(
            SecurityResource(
                cloud=cloud,
                service=service,
                resource_type=resource_type,
                resource_name=resource_name,
                resource_address=(
                    f"{resource_address}#rule[{index:03d}]"
                    if multiple
                    else resource_address
                ),
                attributes=attributes,
            )
            for index, attributes in enumerate(attribute_sets)
        )

    def _gcp_compute_attributes(
        self,
        values: Mapping[str, Any],
    ) -> dict[str, Any]:
        attributes: dict[str, Any] = {}
        interfaces = self._mapping_sequence(values.get("network_interface"))
        if interfaces:
            exposure_states: list[bool] = []
            for interface in interfaces:
                access_config = interface.get("access_config", ())
                if not self._is_sequence(access_config):
                    exposure_states = []
                    break
                exposure_states.append(bool(access_config))
            if exposure_states:
                attributes["public_ip"] = any(exposure_states)

        shielded_config = self._first_mapping(
            values.get("shielded_instance_config")
        )
        if shielded_config is not None:
            self._copy_bool(
                shielded_config,
                "enable_secure_boot",
                attributes,
                "shielded_vm",
            )
        self._copy_bool(
            values,
            "deletion_protection",
            attributes,
            "deletion_protection",
        )
        return attributes

    def _gcp_firewall_attributes(
        self,
        values: Mapping[str, Any],
    ) -> tuple[dict[str, Any], ...]:
        common: dict[str, Any] = {}
        direction = self._required_text(values.get("direction"))
        if direction is not None:
            common["direction"] = direction
        sources = self._string_sequence(values.get("source_ranges"))
        if sources is not None:
            common["source_ranges"] = sources

        allow_blocks = self._mapping_sequence(values.get("allow"))
        if not allow_blocks:
            return (common,)
        return tuple(
            self._gcp_allow_attributes(common, block)
            for block in sorted(allow_blocks, key=self._network_block_sort_key)
        )

    def _gcp_allow_attributes(
        self,
        common: Mapping[str, Any],
        block: Mapping[str, Any],
    ) -> dict[str, Any]:
        attributes = dict(common)
        protocol = self._normalise_protocol(block.get("protocol"))
        if protocol is not None:
            attributes["protocol"] = protocol

        raw_ports = block.get("ports", _MISSING)
        if raw_ports is not _MISSING and raw_ports is not None:
            ports = self._normalise_ports(raw_ports)
            if ports is not None:
                attributes["allowed_ports"] = ports
                attributes["all_ports"] = not bool(raw_ports)
        elif raw_ports is _MISSING and protocol in {"all", "tcp", "udp"}:
            attributes["allowed_ports"] = ()
            attributes["all_ports"] = True
        if protocol == "all":
            attributes["all_ports"] = True
        return attributes

    def _gcp_storage_attributes(
        self,
        values: Mapping[str, Any],
    ) -> dict[str, Any]:
        attributes: dict[str, Any] = {}
        prevention = self._required_text(values.get("public_access_prevention"))
        if prevention == "enforced":
            attributes["public_access"] = False
        self._copy_bool(
            values,
            "uniform_bucket_level_access",
            attributes,
            "uniform_bucket_level_access",
        )
        versioning = self._first_mapping(values.get("versioning"))
        if versioning is not None:
            self._copy_bool(
                versioning,
                "enabled",
                attributes,
                "versioning_enabled",
            )
        return attributes

    def _gcp_iam_attributes(
        self,
        values: Mapping[str, Any],
    ) -> dict[str, Any]:
        attributes: dict[str, Any] = {}
        role = self._required_text(values.get("role"), casefold=False)
        if role is not None:
            attributes["roles"] = (role,)
        members: list[str] = []
        member = self._required_text(values.get("member"), casefold=False)
        if member is not None:
            members.append(member)
        multiple_members = self._string_sequence(values.get("members"))
        if multiple_members is not None:
            members.extend(multiple_members)
        if members:
            attributes["members"] = tuple(sorted(set(members)))
        return attributes

    def _oci_compute_attributes(
        self,
        values: Mapping[str, Any],
    ) -> dict[str, Any]:
        attributes: dict[str, Any] = {}
        vnic = self._first_mapping(values.get("create_vnic_details"))
        if vnic is not None:
            self._copy_bool(
                vnic,
                "assign_public_ip",
                attributes,
                "public_ip",
            )
        platform = self._first_mapping(values.get("platform_config"))
        if platform is not None:
            self._copy_bool(
                platform,
                "is_secure_boot_enabled",
                attributes,
                "secure_boot",
            )
        launch_options = self._first_mapping(values.get("launch_options"))
        if launch_options is not None:
            self._copy_bool(
                launch_options,
                "is_pv_encryption_in_transit_enabled",
                attributes,
                "in_transit_encryption",
            )
        return attributes

    def _oci_security_list_attributes(
        self,
        values: Mapping[str, Any],
    ) -> tuple[dict[str, Any], ...]:
        normalised_rules: list[dict[str, Any]] = []
        for source_key, direction in (
            ("ingress_security_rules", "ingress"),
            ("egress_security_rules", "egress"),
        ):
            rules = self._mapping_sequence(values.get(source_key))
            if not rules:
                continue
            for rule in sorted(rules, key=self._network_block_sort_key):
                normalised_rules.append(
                    self._oci_security_rule_attributes(rule, direction)
                )
        return tuple(normalised_rules) or ({},)

    def _oci_security_rule_attributes(
        self,
        rule: Mapping[str, Any],
        direction: str,
    ) -> dict[str, Any]:
        attributes: dict[str, Any] = {"direction": direction}
        source_key = "source" if direction == "ingress" else "destination"
        source = self._required_text(rule.get(source_key), casefold=False)
        if source is not None:
            attributes["source_ranges"] = (source,)
        protocol = self._normalise_protocol(rule.get("protocol"))
        if protocol is not None:
            attributes["protocol"] = protocol

        options_key = "tcp_options" if protocol == "tcp" else "udp_options"
        raw_options = rule.get(options_key, _MISSING)
        port_range = (
            self._oci_port_range(raw_options)
            if raw_options is not _MISSING
            else None
        )
        if protocol == "all":
            attributes["allowed_ports"] = ()
            attributes["all_ports"] = True
        elif protocol in {"tcp", "udp"} and raw_options is _MISSING:
            attributes["allowed_ports"] = ()
            attributes["all_ports"] = True
        elif port_range is not None:
            minimum, maximum = port_range
            attributes["allowed_ports"] = self._relevant_range_ports(
                minimum,
                maximum,
            )
            attributes["all_ports"] = minimum <= 1 and maximum == 65535
        return attributes

    def _oci_storage_attributes(
        self,
        values: Mapping[str, Any],
    ) -> dict[str, Any]:
        attributes: dict[str, Any] = {}
        access_type = self._required_text(values.get("access_type"))
        if access_type == "nopublicaccess":
            attributes["public_access"] = False
        elif access_type in {"objectread", "objectreadwithoutlist"}:
            attributes["public_access"] = True

        versioning = values.get("versioning", _MISSING)
        if isinstance(versioning, bool):
            attributes["versioning_enabled"] = versioning
        elif isinstance(versioning, str):
            normalised_versioning = versioning.strip().casefold()
            if normalised_versioning in {"enabled", "disabled"}:
                attributes["versioning_enabled"] = (
                    normalised_versioning == "enabled"
                )

        key_id = values.get("kms_key_id", _MISSING)
        if key_id is None:
            attributes["customer_managed_key"] = False
        elif isinstance(key_id, str):
            attributes["customer_managed_key"] = bool(key_id.strip())
        return attributes

    def _oci_iam_attributes(
        self,
        values: Mapping[str, Any],
    ) -> dict[str, Any]:
        attributes: dict[str, Any] = {}
        statements = self._string_sequence(values.get("statements"))
        if statements is not None:
            attributes["statements"] = statements
        return attributes

    def _oci_port_range(self, value: object) -> tuple[int, int] | None:
        options = self._first_mapping(value)
        if options is None:
            return None
        destination = self._first_mapping(
            options.get("destination_port_range")
        )
        if destination is None:
            destination = options
        minimum = destination.get("min")
        maximum = destination.get("max")
        if (
            isinstance(minimum, bool)
            or not isinstance(minimum, int)
            or isinstance(maximum, bool)
            or not isinstance(maximum, int)
            or not 0 <= minimum <= maximum <= 65535
        ):
            return None
        return minimum, maximum

    @classmethod
    def _normalise_ports(cls, value: object) -> tuple[int, ...] | None:
        if not cls._is_sequence(value):
            return None
        ports: set[int] = set()
        for item in value:
            if isinstance(item, bool):
                return None
            if isinstance(item, int):
                if not 0 <= item <= 65535:
                    return None
                ports.add(item)
                continue
            if not isinstance(item, str):
                return None
            token = item.strip()
            if token.isdigit():
                port = int(token)
                if not 0 <= port <= 65535:
                    return None
                ports.add(port)
                continue
            match = _PORT_RANGE.fullmatch(token)
            if match is None:
                return None
            minimum, maximum = (int(part) for part in match.groups())
            if not 0 <= minimum <= maximum <= 65535:
                return None
            ports.update(cls._relevant_range_ports(minimum, maximum))
        return tuple(sorted(ports))

    @staticmethod
    def _relevant_range_ports(minimum: int, maximum: int) -> tuple[int, ...]:
        if minimum == maximum:
            return (minimum,)
        return tuple(port for port in (22, 3389) if minimum <= port <= maximum)

    @staticmethod
    def _copy_bool(
        source: Mapping[str, Any],
        source_key: str,
        target: dict[str, Any],
        target_key: str,
    ) -> None:
        value = source.get(source_key)
        if isinstance(value, bool):
            target[target_key] = value

    @classmethod
    def _first_mapping(cls, value: object) -> Mapping[str, Any] | None:
        if isinstance(value, Mapping):
            return value
        mappings = cls._mapping_sequence(value)
        return mappings[0] if mappings else None

    @classmethod
    def _mapping_sequence(
        cls,
        value: object,
    ) -> tuple[Mapping[str, Any], ...] | None:
        if not cls._is_sequence(value):
            return None
        if any(not isinstance(item, Mapping) for item in value):
            return None
        return tuple(value)

    @classmethod
    def _string_sequence(cls, value: object) -> tuple[str, ...] | None:
        if not cls._is_sequence(value):
            return None
        if any(not isinstance(item, str) or not item.strip() for item in value):
            return None
        return tuple(sorted({item.strip() for item in value}))

    @staticmethod
    def _normalise_protocol(value: object) -> str | None:
        protocol = TerraformSecurityResourceAdapter._required_text(value)
        if protocol is None:
            return None
        return {"6": "tcp", "17": "udp"}.get(protocol, protocol)

    @staticmethod
    def _required_text(
        value: object,
        *,
        casefold: bool = True,
    ) -> str | None:
        if not isinstance(value, str) or not value.strip():
            return None
        normalised = value.strip()
        return normalised.casefold() if casefold else normalised

    @staticmethod
    def _is_sequence(value: object) -> bool:
        return isinstance(value, Sequence) and not isinstance(
            value,
            (str, bytes, bytearray),
        )

    @classmethod
    def _network_block_sort_key(
        cls,
        block: Mapping[str, Any],
    ) -> tuple[str, str, str]:
        protocol = cls._required_text(block.get("protocol")) or ""
        source = cls._required_text(
            block.get("source", block.get("destination")),
            casefold=False,
        ) or ""
        ports = block.get("ports", ())
        safe_ports = (
            ",".join(str(port) for port in ports)
            if cls._is_sequence(ports)
            else ""
        )
        return protocol, source, safe_ports

    @staticmethod
    def _module_sort_key(module: Mapping[str, Any]) -> str:
        address = module.get("address")
        return address.strip() if isinstance(address, str) else ""
