"""Regles OCI internes basees sur le contrat d'attributs normalise CIS-4.

Ces controles appartiennent a ``INTERNAL_SECURITY_BASELINE``. Ils ne sont pas
des controles CIS officiels et ne lisent ni HCL, ni API OCI, ni environnement.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from security_models import (
    RuleStatus,
    SecurityFinding,
    SecurityResource,
    SecurityRuleMetadata,
    SecuritySeverity,
)
from security_rule import SecurityRule


OCI_INTERNAL_FRAMEWORK = "INTERNAL_SECURITY_BASELINE"
OCI_INTERNAL_FRAMEWORK_VERSION = "oci-v1"
OCI_COMPUTE_RESOURCE_TYPE = "oci_core_instance"
OCI_NETWORK_RESOURCE_TYPE = "oci_core_security_list"
OCI_STORAGE_RESOURCE_TYPE = "oci_objectstorage_bucket"
OCI_IAM_RESOURCE_TYPE = "oci_identity_policy"


def _metadata(
    *,
    rule_id: str,
    service: str,
    resource_type: str,
    title: str,
    description: str,
    severity: SecuritySeverity,
    recommendation: str,
    tags: tuple[str, ...],
    control_family: str,
    rationale: str,
) -> SecurityRuleMetadata:
    return SecurityRuleMetadata(
        rule_id=rule_id,
        cloud="oci",
        service=service,
        resource_type=resource_type,
        title=title,
        description=description,
        severity=severity,
        recommendation=recommendation,
        enabled=True,
        tags=tags,
        profiles=("baseline",),
        framework=OCI_INTERNAL_FRAMEWORK,
        framework_version=OCI_INTERNAL_FRAMEWORK_VERSION,
        reference_id=None,
        reference_url=None,
        control_family=control_family,
        rationale=rationale,
    )


class _OciInternalRule(SecurityRule):
    """Helpers purs communs aux regles du pack OCI interne."""

    MISSING_ATTRIBUTE_MESSAGE = "Required security attribute is unavailable."

    def _finding(
        self,
        resource: SecurityResource,
        status: RuleStatus,
        message: str,
    ) -> SecurityFinding:
        return SecurityFinding(
            rule_id=self.metadata.rule_id,
            cloud=resource.cloud,
            resource_type=resource.resource_type,
            resource_name=resource.resource_name,
            resource_address=resource.resource_address,
            status=status,
            severity=self.metadata.severity,
            title=self.metadata.title,
            message=message,
            recommendation=self.metadata.recommendation,
        )

    def _missing(self, resource: SecurityResource) -> SecurityFinding:
        return self._finding(
            resource,
            RuleStatus.SKIPPED,
            self.MISSING_ATTRIBUTE_MESSAGE,
        )

    @staticmethod
    def _required_bool(attributes: Mapping[str, Any], key: str) -> bool | None:
        value = attributes.get(key)
        return value if isinstance(value, bool) else None

    @staticmethod
    def _required_text(attributes: Mapping[str, Any], key: str) -> str | None:
        value = attributes.get(key)
        if not isinstance(value, str) or not value.strip():
            return None
        return value.strip().casefold()

    @staticmethod
    def _required_strings(
        attributes: Mapping[str, Any],
        key: str,
    ) -> tuple[str, ...] | None:
        value = attributes.get(key)
        if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
            return None
        if any(not isinstance(item, str) or not item.strip() for item in value):
            return None
        return tuple(item.strip() for item in value)

    @staticmethod
    def _required_ports(
        attributes: Mapping[str, Any],
        key: str,
    ) -> tuple[int, ...] | None:
        value = attributes.get(key)
        if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
            return None
        if any(
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 0 <= port <= 65535
            for port in value
        ):
            return None
        return tuple(value)

    def _evaluate_boolean(
        self,
        resource: SecurityResource,
        *,
        attribute: str,
        secure_value: bool,
        insecure_status: RuleStatus,
        pass_message: str,
        insecure_message: str,
    ) -> SecurityFinding:
        value = self._required_bool(resource.attributes, attribute)
        if value is None:
            return self._missing(resource)
        if value is secure_value:
            return self._finding(resource, RuleStatus.PASS, pass_message)
        return self._finding(resource, insecure_status, insecure_message)

    def _evaluate_unrestricted_port(
        self,
        resource: SecurityResource,
        *,
        port: int,
        pass_message: str,
        fail_message: str,
    ) -> SecurityFinding:
        direction = self._required_text(resource.attributes, "direction")
        if direction is None:
            return self._missing(resource)
        if direction != "ingress":
            return self._finding(resource, RuleStatus.PASS, pass_message)

        source_ranges = self._required_strings(
            resource.attributes,
            "source_ranges",
        )
        if source_ranges is None:
            return self._missing(resource)
        if "0.0.0.0/0" not in source_ranges:
            return self._finding(resource, RuleStatus.PASS, pass_message)

        protocol = self._required_text(resource.attributes, "protocol")
        if protocol is None:
            return self._missing(resource)
        if protocol != "tcp":
            return self._finding(resource, RuleStatus.PASS, pass_message)

        allowed_ports = self._required_ports(
            resource.attributes,
            "allowed_ports",
        )
        if allowed_ports is None:
            return self._missing(resource)
        if port in allowed_ports:
            return self._finding(resource, RuleStatus.FAIL, fail_message)
        return self._finding(resource, RuleStatus.PASS, pass_message)


class OciPublicIpExposureRule(_OciInternalRule):
    """Signale une instance dont le contrat normalise expose une IP publique."""

    def __init__(self) -> None:
        super().__init__(
            _metadata(
                rule_id="OCI_INTERNAL_COMPUTE_001",
                service="compute",
                resource_type=OCI_COMPUTE_RESOURCE_TYPE,
                title="Public IP exposure",
                description="Checks whether an OCI instance exposes a public IP.",
                severity=SecuritySeverity.HIGH,
                recommendation=(
                    "Prefer private connectivity unless Internet exposure is "
                    "explicitly required."
                ),
                tags=("compute", "network-exposure", "public-ip"),
                control_family="compute-network-exposure",
                rationale=(
                    "Public addressing increases the instance's reachable attack "
                    "surface."
                ),
            )
        )

    def evaluate(self, resource: SecurityResource) -> SecurityFinding:
        return self._evaluate_boolean(
            resource,
            attribute="public_ip",
            secure_value=False,
            insecure_status=RuleStatus.FAIL,
            pass_message="The OCI instance does not expose a public IP.",
            insecure_message="The OCI instance exposes a public IP.",
        )


class OciSecureBootRule(_OciInternalRule):
    """Avertit lorsque le secure boot normalise est desactive."""

    def __init__(self) -> None:
        super().__init__(
            _metadata(
                rule_id="OCI_INTERNAL_COMPUTE_002",
                service="compute",
                resource_type=OCI_COMPUTE_RESOURCE_TYPE,
                title="Secure boot protection",
                description="Checks the normalized secure boot flag.",
                severity=SecuritySeverity.MEDIUM,
                recommendation="Enable secure boot when supported by the workload.",
                tags=("compute", "hardening", "secure-boot"),
                control_family="compute-hardening",
                rationale="Secure boot can strengthen instance boot integrity.",
            )
        )

    def evaluate(self, resource: SecurityResource) -> SecurityFinding:
        return self._evaluate_boolean(
            resource,
            attribute="secure_boot",
            secure_value=True,
            insecure_status=RuleStatus.WARNING,
            pass_message="Secure boot is enabled.",
            insecure_message="Secure boot is disabled.",
        )


class OciInTransitEncryptionRule(_OciInternalRule):
    """Avertit lorsque le chiffrement en transit normalise est desactive."""

    def __init__(self) -> None:
        super().__init__(
            _metadata(
                rule_id="OCI_INTERNAL_COMPUTE_003",
                service="compute",
                resource_type=OCI_COMPUTE_RESOURCE_TYPE,
                title="In-transit encryption",
                description="Checks the normalized in-transit encryption flag.",
                severity=SecuritySeverity.MEDIUM,
                recommendation="Enable in-transit encryption where supported.",
                tags=("compute", "encryption", "in-transit"),
                control_family="data-protection",
                rationale=(
                    "Encryption in transit can reduce exposure of data between "
                    "components."
                ),
            )
        )

    def evaluate(self, resource: SecurityResource) -> SecurityFinding:
        return self._evaluate_boolean(
            resource,
            attribute="in_transit_encryption",
            secure_value=True,
            insecure_status=RuleStatus.WARNING,
            pass_message="In-transit encryption is enabled.",
            insecure_message="In-transit encryption is disabled.",
        )


class OciUnrestrictedSshIngressRule(_OciInternalRule):
    """Detecte SSH/TCP ouvert a la source IPv4 non restreinte."""

    def __init__(self) -> None:
        super().__init__(
            _metadata(
                rule_id="OCI_INTERNAL_NETWORK_001",
                service="network",
                resource_type=OCI_NETWORK_RESOURCE_TYPE,
                title="Unrestricted SSH ingress",
                description="Checks normalized ingress sources and TCP port 22.",
                severity=SecuritySeverity.HIGH,
                recommendation=(
                    "Restrict SSH ingress to approved administrative CIDR ranges."
                ),
                tags=("ingress", "network", "ssh"),
                control_family="network-ingress",
                rationale="Unrestricted SSH exposes an administrative service.",
            )
        )

    def evaluate(self, resource: SecurityResource) -> SecurityFinding:
        return self._evaluate_unrestricted_port(
            resource,
            port=22,
            pass_message="SSH ingress is not open to an unrestricted IPv4 source.",
            fail_message="SSH ingress is open to an unrestricted IPv4 source.",
        )


class OciUnrestrictedRdpIngressRule(_OciInternalRule):
    """Detecte RDP/TCP ouvert a la source IPv4 non restreinte."""

    def __init__(self) -> None:
        super().__init__(
            _metadata(
                rule_id="OCI_INTERNAL_NETWORK_002",
                service="network",
                resource_type=OCI_NETWORK_RESOURCE_TYPE,
                title="Unrestricted RDP ingress",
                description="Checks normalized ingress sources and TCP port 3389.",
                severity=SecuritySeverity.HIGH,
                recommendation=(
                    "Restrict RDP ingress to approved administrative CIDR ranges."
                ),
                tags=("ingress", "network", "rdp"),
                control_family="network-ingress",
                rationale="Unrestricted RDP exposes an administrative service.",
            )
        )

    def evaluate(self, resource: SecurityResource) -> SecurityFinding:
        return self._evaluate_unrestricted_port(
            resource,
            port=3389,
            pass_message="RDP ingress is not open to an unrestricted IPv4 source.",
            fail_message="RDP ingress is open to an unrestricted IPv4 source.",
        )


class OciUnrestrictedAllPortsIngressRule(_OciInternalRule):
    """Detecte tous les ports ouverts a la source IPv4 non restreinte."""

    def __init__(self) -> None:
        super().__init__(
            _metadata(
                rule_id="OCI_INTERNAL_NETWORK_003",
                service="network",
                resource_type=OCI_NETWORK_RESOURCE_TYPE,
                title="Unrestricted all-port ingress",
                description="Checks the normalized all_ports ingress exposure flag.",
                severity=SecuritySeverity.HIGH,
                recommendation=(
                    "Limit ingress to required protocols, ports, and approved sources."
                ),
                tags=("all-ports", "ingress", "network"),
                control_family="network-ingress",
                rationale=(
                    "All-port ingress creates a broad exposure; HIGH is used for this "
                    "conservative initial baseline."
                ),
            )
        )

    def evaluate(self, resource: SecurityResource) -> SecurityFinding:
        direction = self._required_text(resource.attributes, "direction")
        if direction is None:
            return self._missing(resource)
        pass_message = (
            "All-port ingress is not open to an unrestricted IPv4 source."
        )
        if direction != "ingress":
            return self._finding(resource, RuleStatus.PASS, pass_message)

        source_ranges = self._required_strings(
            resource.attributes,
            "source_ranges",
        )
        if source_ranges is None:
            return self._missing(resource)
        if "0.0.0.0/0" not in source_ranges:
            return self._finding(resource, RuleStatus.PASS, pass_message)

        all_ports = self._required_bool(resource.attributes, "all_ports")
        if all_ports is None:
            return self._missing(resource)
        if all_ports:
            return self._finding(
                resource,
                RuleStatus.FAIL,
                "All-port ingress is open to an unrestricted IPv4 source.",
            )
        return self._finding(resource, RuleStatus.PASS, pass_message)


class OciPublicObjectStorageRule(_OciInternalRule):
    """Detecte l'acces public declare dans le contrat de bucket normalise."""

    def __init__(self) -> None:
        super().__init__(
            _metadata(
                rule_id="OCI_INTERNAL_STORAGE_001",
                service="storage",
                resource_type=OCI_STORAGE_RESOURCE_TYPE,
                title="Public object storage access",
                description="Checks the normalized public object storage access flag.",
                severity=SecuritySeverity.HIGH,
                recommendation=(
                    "Keep bucket access private unless public distribution is "
                    "explicitly required."
                ),
                tags=("public-access", "storage"),
                control_family="storage-access",
                rationale="Public bucket access can expose stored data.",
            )
        )

    def evaluate(self, resource: SecurityResource) -> SecurityFinding:
        return self._evaluate_boolean(
            resource,
            attribute="public_access",
            secure_value=False,
            insecure_status=RuleStatus.FAIL,
            pass_message="Public object storage access is disabled.",
            insecure_message="Public object storage access is enabled.",
        )


class OciObjectVersioningRule(_OciInternalRule):
    """Avertit lorsque le versioning du bucket est desactive."""

    def __init__(self) -> None:
        super().__init__(
            _metadata(
                rule_id="OCI_INTERNAL_STORAGE_002",
                service="storage",
                resource_type=OCI_STORAGE_RESOURCE_TYPE,
                title="Object storage versioning",
                description="Checks the normalized object versioning flag.",
                severity=SecuritySeverity.MEDIUM,
                recommendation=(
                    "Enable object versioning when recovery from overwrite or deletion "
                    "is required."
                ),
                tags=("resilience", "storage", "versioning"),
                control_family="storage-resilience",
                rationale="Versioning can improve recovery from object changes.",
            )
        )

    def evaluate(self, resource: SecurityResource) -> SecurityFinding:
        return self._evaluate_boolean(
            resource,
            attribute="versioning_enabled",
            secure_value=True,
            insecure_status=RuleStatus.WARNING,
            pass_message="Object storage versioning is enabled.",
            insecure_message="Object storage versioning is disabled.",
        )


class OciCustomerManagedKeyRule(_OciInternalRule):
    """Avertit lorsque le contrat n'indique pas une cle geree par le client."""

    def __init__(self) -> None:
        super().__init__(
            _metadata(
                rule_id="OCI_INTERNAL_STORAGE_003",
                service="storage",
                resource_type=OCI_STORAGE_RESOURCE_TYPE,
                title="Customer-managed encryption key",
                description="Checks the normalized customer-managed key flag.",
                severity=SecuritySeverity.MEDIUM,
                recommendation=(
                    "Use a customer-managed encryption key when required by the "
                    "workload's internal policy."
                ),
                tags=("customer-managed-key", "encryption", "storage"),
                control_family="storage-encryption",
                rationale=(
                    "This internal baseline reports key ownership as a non-blocking "
                    "signal and does not claim an official requirement."
                ),
            )
        )

    def evaluate(self, resource: SecurityResource) -> SecurityFinding:
        return self._evaluate_boolean(
            resource,
            attribute="customer_managed_key",
            secure_value=True,
            insecure_status=RuleStatus.WARNING,
            pass_message="A customer-managed encryption key is configured.",
            insecure_message="A customer-managed encryption key is not configured.",
        )


class OciManageAllResourcesStatementRule(_OciInternalRule):
    """Detecte uniquement le token canonique exact 'manage all-resources'."""

    CANONICAL_BROAD_STATEMENT = "manage all-resources"

    def __init__(self) -> None:
        super().__init__(
            _metadata(
                rule_id="OCI_INTERNAL_IAM_001",
                service="iam",
                resource_type=OCI_IAM_RESOURCE_TYPE,
                title="Overly broad manage-all statement",
                description=(
                    "Checks normalized statements for the exact canonical token "
                    "'manage all-resources'; it is not a policy-language parser."
                ),
                severity=SecuritySeverity.HIGH,
                recommendation=(
                    "Replace broad manage-all access with narrowly scoped policy "
                    "statements."
                ),
                tags=("broad-policy", "iam", "least-privilege"),
                control_family="iam-least-privilege",
                rationale="Manage-all access grants a broad capability scope.",
            )
        )

    def evaluate(self, resource: SecurityResource) -> SecurityFinding:
        statements = self._required_strings(resource.attributes, "statements")
        if statements is None:
            return self._missing(resource)
        normalised_statements = tuple(
            statement.casefold() for statement in statements
        )
        if self.CANONICAL_BROAD_STATEMENT in normalised_statements:
            return self._finding(
                resource,
                RuleStatus.FAIL,
                "The canonical manage all-resources statement is present.",
            )
        return self._finding(
            resource,
            RuleStatus.PASS,
            "The canonical manage all-resources statement is not present.",
        )


class OciWildcardPermissionRule(_OciInternalRule):
    """Detecte la permission exacte '*' dans la liste normalisee."""

    def __init__(self) -> None:
        super().__init__(
            _metadata(
                rule_id="OCI_INTERNAL_IAM_002",
                service="iam",
                resource_type=OCI_IAM_RESOURCE_TYPE,
                title="Wildcard permission detected",
                description="Checks normalized permissions for the exact wildcard '*'.",
                severity=SecuritySeverity.HIGH,
                recommendation="Replace wildcard permissions with explicit permissions.",
                tags=("iam", "least-privilege", "wildcard"),
                control_family="iam-least-privilege",
                rationale="Wildcard permissions exceed narrowly scoped access.",
            )
        )

    def evaluate(self, resource: SecurityResource) -> SecurityFinding:
        permissions = self._required_strings(resource.attributes, "permissions")
        if permissions is None:
            return self._missing(resource)
        if "*" in permissions:
            return self._finding(
                resource,
                RuleStatus.FAIL,
                "An exact wildcard permission is present.",
            )
        return self._finding(
            resource,
            RuleStatus.PASS,
            "No exact wildcard permission is present.",
        )


class OciBroadSubjectAssignmentRule(_OciInternalRule):
    """Avertit uniquement sur le booleen normalise broad_subject."""

    def __init__(self) -> None:
        super().__init__(
            _metadata(
                rule_id="OCI_INTERNAL_IAM_003",
                service="iam",
                resource_type=OCI_IAM_RESOURCE_TYPE,
                title="Broad subject assignment",
                description="Checks the explicit normalized broad_subject flag.",
                severity=SecuritySeverity.MEDIUM,
                recommendation=(
                    "Restrict policy assignment to explicitly approved subjects."
                ),
                tags=("broad-subject", "iam", "least-privilege"),
                control_family="iam-least-privilege",
                rationale=(
                    "The explicit broad-subject signal identifies a potentially wide "
                    "assignment without interpreting OCI policy syntax."
                ),
            )
        )

    def evaluate(self, resource: SecurityResource) -> SecurityFinding:
        return self._evaluate_boolean(
            resource,
            attribute="broad_subject",
            secure_value=False,
            insecure_status=RuleStatus.WARNING,
            pass_message="No broad subject assignment is declared.",
            insecure_message="A broad subject assignment is declared.",
        )
