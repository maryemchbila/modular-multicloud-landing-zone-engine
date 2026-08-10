"""Regles GCP internes basees sur le contrat d'attributs normalise CIS-3.

Ces controles appartiennent a ``INTERNAL_SECURITY_BASELINE``. Ils ne sont pas
des controles CIS officiels et ne lisent ni HCL, ni API GCP, ni environnement.
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


GCP_INTERNAL_FRAMEWORK = "INTERNAL_SECURITY_BASELINE"
GCP_INTERNAL_FRAMEWORK_VERSION = "gcp-v1"
GCP_COMPUTE_RESOURCE_TYPE = "google_compute_instance"
GCP_NETWORK_RESOURCE_TYPE = "google_compute_firewall"
GCP_STORAGE_RESOURCE_TYPE = "google_storage_bucket"
GCP_IAM_RESOURCE_TYPE = "google_project_iam_member"


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
        cloud="gcp",
        service=service,
        resource_type=resource_type,
        title=title,
        description=description,
        severity=severity,
        recommendation=recommendation,
        enabled=True,
        tags=tags,
        profiles=("baseline",),
        framework=GCP_INTERNAL_FRAMEWORK,
        framework_version=GCP_INTERNAL_FRAMEWORK_VERSION,
        reference_id=None,
        reference_url=None,
        control_family=control_family,
        rationale=rationale,
    )


class _GcpInternalRule(SecurityRule):
    """Helpers purs communs aux regles du pack GCP interne."""

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


class GcpPublicIpExposureRule(_GcpInternalRule):
    """Signale une VM dont le contrat normalise expose une IP publique."""

    def __init__(self) -> None:
        super().__init__(
            _metadata(
                rule_id="GCP_INTERNAL_COMPUTE_001",
                service="compute",
                resource_type=GCP_COMPUTE_RESOURCE_TYPE,
                title="Public IP exposure",
                description="Checks whether a compute instance exposes a public IP.",
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
            pass_message="The compute instance does not expose a public IP.",
            insecure_message="The compute instance exposes a public IP.",
        )


class GcpShieldedVmRule(_GcpInternalRule):
    """Avertit lorsque la protection Shielded VM normalisee est desactivee."""

    def __init__(self) -> None:
        super().__init__(
            _metadata(
                rule_id="GCP_INTERNAL_COMPUTE_002",
                service="compute",
                resource_type=GCP_COMPUTE_RESOURCE_TYPE,
                title="Shielded VM protection",
                description="Checks the normalized Shielded VM protection flag.",
                severity=SecuritySeverity.MEDIUM,
                recommendation=(
                    "Enable Shielded VM protections when supported by the workload."
                ),
                tags=("compute", "hardening", "shielded-vm"),
                control_family="compute-hardening",
                rationale=(
                    "Shielded VM features can strengthen boot integrity and runtime "
                    "protection."
                ),
            )
        )

    def evaluate(self, resource: SecurityResource) -> SecurityFinding:
        return self._evaluate_boolean(
            resource,
            attribute="shielded_vm",
            secure_value=True,
            insecure_status=RuleStatus.WARNING,
            pass_message="Shielded VM protection is enabled.",
            insecure_message="Shielded VM protection is disabled.",
        )


class GcpDeletionProtectionRule(_GcpInternalRule):
    """Avertit lorsque la protection de suppression normalisee est absente."""

    def __init__(self) -> None:
        super().__init__(
            _metadata(
                rule_id="GCP_INTERNAL_COMPUTE_003",
                service="compute",
                resource_type=GCP_COMPUTE_RESOURCE_TYPE,
                title="Compute deletion protection",
                description="Checks the normalized deletion protection flag.",
                severity=SecuritySeverity.MEDIUM,
                recommendation=(
                    "Enable deletion protection for workloads that require safeguards "
                    "against accidental removal."
                ),
                tags=("compute", "deletion-protection", "operations"),
                control_family="operational-protection",
                rationale=(
                    "Deletion protection reduces accidental workload removal risk."
                ),
            )
        )

    def evaluate(self, resource: SecurityResource) -> SecurityFinding:
        return self._evaluate_boolean(
            resource,
            attribute="deletion_protection",
            secure_value=True,
            insecure_status=RuleStatus.WARNING,
            pass_message="Compute deletion protection is enabled.",
            insecure_message="Compute deletion protection is disabled.",
        )


class GcpUnrestrictedSshIngressRule(_GcpInternalRule):
    """Detecte SSH/TCP ouvert a la source IPv4 non restreinte."""

    def __init__(self) -> None:
        super().__init__(
            _metadata(
                rule_id="GCP_INTERNAL_NETWORK_001",
                service="network",
                resource_type=GCP_NETWORK_RESOURCE_TYPE,
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


class GcpUnrestrictedRdpIngressRule(_GcpInternalRule):
    """Detecte RDP/TCP ouvert a la source IPv4 non restreinte."""

    def __init__(self) -> None:
        super().__init__(
            _metadata(
                rule_id="GCP_INTERNAL_NETWORK_002",
                service="network",
                resource_type=GCP_NETWORK_RESOURCE_TYPE,
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


class GcpUnrestrictedAllPortsIngressRule(_GcpInternalRule):
    """Detecte tous les ports ouverts a la source IPv4 non restreinte."""

    def __init__(self) -> None:
        super().__init__(
            _metadata(
                rule_id="GCP_INTERNAL_NETWORK_003",
                service="network",
                resource_type=GCP_NETWORK_RESOURCE_TYPE,
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
        return self._finding(
            resource,
            RuleStatus.PASS,
            pass_message,
        )


class GcpPublicBucketAccessRule(_GcpInternalRule):
    """Detecte l'acces public declare dans le contrat de bucket normalise."""

    def __init__(self) -> None:
        super().__init__(
            _metadata(
                rule_id="GCP_INTERNAL_STORAGE_001",
                service="storage",
                resource_type=GCP_STORAGE_RESOURCE_TYPE,
                title="Public bucket access",
                description="Checks the normalized public bucket access flag.",
                severity=SecuritySeverity.HIGH,
                recommendation=(
                    "Keep bucket access private unless public distribution is "
                    "explicitly required."
                ),
                tags=("public-access", "storage"),
                control_family="storage-access",
                rationale=(
                    "Public bucket access can expose stored data; HIGH is used for "
                    "this generic initial baseline."
                ),
            )
        )

    def evaluate(self, resource: SecurityResource) -> SecurityFinding:
        return self._evaluate_boolean(
            resource,
            attribute="public_access",
            secure_value=False,
            insecure_status=RuleStatus.FAIL,
            pass_message="Public bucket access is disabled.",
            insecure_message="Public bucket access is enabled.",
        )


class GcpUniformBucketAccessRule(_GcpInternalRule):
    """Avertit lorsque l'acces uniforme au bucket est desactive."""

    def __init__(self) -> None:
        super().__init__(
            _metadata(
                rule_id="GCP_INTERNAL_STORAGE_002",
                service="storage",
                resource_type=GCP_STORAGE_RESOURCE_TYPE,
                title="Uniform bucket-level access",
                description="Checks the normalized uniform bucket access flag.",
                severity=SecuritySeverity.MEDIUM,
                recommendation="Enable uniform bucket-level access where appropriate.",
                tags=("access-control", "storage", "uniform-access"),
                control_family="storage-access",
                rationale=(
                    "Uniform access simplifies and centralizes bucket authorization."
                ),
            )
        )

    def evaluate(self, resource: SecurityResource) -> SecurityFinding:
        return self._evaluate_boolean(
            resource,
            attribute="uniform_bucket_level_access",
            secure_value=True,
            insecure_status=RuleStatus.WARNING,
            pass_message="Uniform bucket-level access is enabled.",
            insecure_message="Uniform bucket-level access is disabled.",
        )


class GcpBucketVersioningRule(_GcpInternalRule):
    """Avertit lorsque le versioning du bucket est desactive."""

    def __init__(self) -> None:
        super().__init__(
            _metadata(
                rule_id="GCP_INTERNAL_STORAGE_003",
                service="storage",
                resource_type=GCP_STORAGE_RESOURCE_TYPE,
                title="Bucket object versioning",
                description="Checks the normalized bucket versioning flag.",
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
            pass_message="Bucket object versioning is enabled.",
            insecure_message="Bucket object versioning is disabled.",
        )


class GcpPrimitiveOwnerRoleRule(_GcpInternalRule):
    """Detecte le role primitif owner dans la liste normalisee."""

    def __init__(self) -> None:
        super().__init__(
            _metadata(
                rule_id="GCP_INTERNAL_IAM_001",
                service="iam",
                resource_type=GCP_IAM_RESOURCE_TYPE,
                title="Primitive Owner role detected",
                description="Checks normalized IAM roles for roles/owner.",
                severity=SecuritySeverity.HIGH,
                recommendation=(
                    "Replace primitive Owner access with narrowly scoped roles."
                ),
                tags=("iam", "least-privilege", "owner-role"),
                control_family="iam-least-privilege",
                rationale="Primitive Owner access grants broad administrative control.",
            )
        )

    def evaluate(self, resource: SecurityResource) -> SecurityFinding:
        roles = self._required_strings(resource.attributes, "roles")
        if roles is None:
            return self._missing(resource)
        if "roles/owner" in roles:
            return self._finding(
                resource,
                RuleStatus.FAIL,
                "The primitive roles/owner role is assigned.",
            )
        return self._finding(
            resource,
            RuleStatus.PASS,
            "The primitive roles/owner role is not assigned.",
        )


class GcpPrimitiveEditorRoleRule(_GcpInternalRule):
    """Avertit sur le role primitif editor dans la liste normalisee."""

    def __init__(self) -> None:
        super().__init__(
            _metadata(
                rule_id="GCP_INTERNAL_IAM_002",
                service="iam",
                resource_type=GCP_IAM_RESOURCE_TYPE,
                title="Primitive Editor role detected",
                description="Checks normalized IAM roles for roles/editor.",
                severity=SecuritySeverity.MEDIUM,
                recommendation=(
                    "Replace primitive Editor access with narrowly scoped roles."
                ),
                tags=("editor-role", "iam", "least-privilege"),
                control_family="iam-least-privilege",
                rationale=(
                    "Primitive Editor access is broad; this initial baseline reports a "
                    "non-blocking MEDIUM warning."
                ),
            )
        )

    def evaluate(self, resource: SecurityResource) -> SecurityFinding:
        roles = self._required_strings(resource.attributes, "roles")
        if roles is None:
            return self._missing(resource)
        if "roles/editor" in roles:
            return self._finding(
                resource,
                RuleStatus.WARNING,
                "The primitive roles/editor role is assigned.",
            )
        return self._finding(
            resource,
            RuleStatus.PASS,
            "The primitive roles/editor role is not assigned.",
        )


class GcpWildcardPermissionRule(_GcpInternalRule):
    """Detecte la permission exacte '*' dans la liste normalisee."""

    def __init__(self) -> None:
        super().__init__(
            _metadata(
                rule_id="GCP_INTERNAL_IAM_003",
                service="iam",
                resource_type=GCP_IAM_RESOURCE_TYPE,
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
