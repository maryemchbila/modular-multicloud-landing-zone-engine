"""Modeles de donnees partages par le moteur Python."""

from dataclasses import asdict, dataclass
from typing import Any, Dict, List


@dataclass(frozen=True)
class GCPContext:
    project_id: str


@dataclass(frozen=True, kw_only=True)
class ClientContext:
    client_id: str = ""
    environment: str = ""

    def context_dict(self) -> Dict[str, str]:
        return {
            "client_id": self.client_id,
            "environment": self.environment,
        }


@dataclass(frozen=True)
class VMResource:
    resource_name: str
    name: str
    machine_type: str
    zone: str
    image: str
    network: str


@dataclass(frozen=True)
class CreateVMRequest(ClientContext):
    module_path: str
    resource: VMResource
    project_id: str
    action: str = "create"
    provider: str = "gcp"
    module: str = "compute"

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le contrat JSON attendu par le programme Go."""
        return {
            **self.context_dict(),
            "action": self.action,
            "provider": self.provider,
            "module": self.module,
            "module_path": self.module_path,
            "project_id": self.project_id,
            "resource": asdict(self.resource),
        }


@dataclass(frozen=True)
class OCIComputeResource:
    resource_name: str
    display_name: str
    availability_domain: str
    compartment_id: str
    shape: str
    subnet_id: str
    image_id: str
    assign_public_ip: bool


@dataclass(frozen=True)
class CreateOCIComputeRequest(ClientContext):
    module_path: str
    resource: OCIComputeResource
    action: str = "create"
    provider: str = "oci"
    module: str = "compute"

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le contrat JSON OCI Compute Create attendu par Go."""
        return {
            **self.context_dict(),
            "action": self.action,
            "provider": self.provider,
            "module": self.module,
            "module_path": self.module_path,
            "resource": asdict(self.resource),
        }


@dataclass(frozen=True)
class OCINetworkResource:
    resource_name: str
    display_name: str
    compartment_id: str
    vcn_cidr: str
    dns_label: str
    subnet_resource_name: str
    subnet_display_name: str
    subnet_cidr: str
    subnet_dns_label: str
    availability_domain: str
    prohibit_public_ip_on_vnic: bool
    internet_gateway_resource_name: str
    internet_gateway_display_name: str
    route_table_resource_name: str
    route_table_display_name: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "dns_label", self.dns_label.strip().lower())
        object.__setattr__(
            self,
            "subnet_dns_label",
            self.subnet_dns_label.strip().lower(),
        )


@dataclass(frozen=True)
class CreateOCINetworkRequest(ClientContext):
    module_path: str
    resource: OCINetworkResource
    action: str = "create"
    provider: str = "oci"
    module: str = "network"

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le contrat JSON OCI Network Create attendu par Go."""
        return {
            **self.context_dict(),
            "action": self.action,
            "provider": self.provider,
            "module": self.module,
            "module_path": self.module_path,
            "resource": asdict(self.resource),
        }


@dataclass(frozen=True)
class OCIStorageResource:
    resource_name: str
    compartment_id: str
    namespace: str
    name: str
    access_type: str
    storage_tier: str
    versioning: str
    object_events_enabled: bool

    def __post_init__(self) -> None:
        canonical_values = {
            "access_type": {
                "nopublicaccess": "NoPublicAccess",
                "objectread": "ObjectRead",
                "objectreadwithoutlist": "ObjectReadWithoutList",
            },
            "storage_tier": {
                "standard": "Standard",
                "archive": "Archive",
            },
            "versioning": {
                "enabled": "Enabled",
                "disabled": "Disabled",
            },
        }
        for field, values in canonical_values.items():
            value = getattr(self, field).strip()
            object.__setattr__(
                self,
                field,
                values.get(value.casefold(), value),
            )


@dataclass(frozen=True)
class CreateOCIStorageRequest(ClientContext):
    module_path: str
    resource: OCIStorageResource
    action: str = "create"
    provider: str = "oci"
    module: str = "storage"

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le contrat JSON OCI Storage Create attendu par Go."""
        return {
            **self.context_dict(),
            "action": self.action,
            "provider": self.provider,
            "module": self.module,
            "module_path": self.module_path,
            "resource": asdict(self.resource),
        }


@dataclass(frozen=True)
class UpdateOCIStorageRequest(ClientContext):
    module_path: str
    resource: OCIStorageResource
    action: str = "update"
    provider: str = "oci"
    module: str = "storage"

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le contrat JSON OCI Storage Update attendu par Go."""
        return {
            **self.context_dict(),
            "action": self.action,
            "provider": self.provider,
            "module": self.module,
            "module_path": self.module_path,
            "resource": asdict(self.resource),
        }


@dataclass(frozen=True)
class OCIStorageDeleteResource:
    resource_name: str


@dataclass(frozen=True)
class DeleteOCIStorageRequest(ClientContext):
    module_path: str
    resource: OCIStorageDeleteResource
    action: str = "delete"
    provider: str = "oci"
    module: str = "storage"

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le contrat JSON minimal OCI Storage Delete attendu par Go."""
        return {
            **self.context_dict(),
            "action": self.action,
            "provider": self.provider,
            "module": self.module,
            "module_path": self.module_path,
            "resource": asdict(self.resource),
        }


@dataclass(frozen=True)
class OCIIAMResource:
    tenancy_ocid: str
    user_resource_name: str
    user_name: str
    user_description: str
    group_resource_name: str
    group_name: str
    group_description: str
    membership_resource_name: str
    policy_resource_name: str
    policy_name: str
    policy_description: str
    policy_compartment_id: str
    policy_statements: List[str]

    def __post_init__(self) -> None:
        for field in (
            "tenancy_ocid",
            "user_resource_name",
            "user_name",
            "user_description",
            "group_resource_name",
            "group_name",
            "group_description",
            "membership_resource_name",
            "policy_resource_name",
            "policy_name",
            "policy_description",
            "policy_compartment_id",
        ):
            value = getattr(self, field)
            if isinstance(value, str):
                object.__setattr__(self, field, value.strip())
        if isinstance(self.policy_statements, list):
            object.__setattr__(
                self,
                "policy_statements",
                [
                    statement.strip()
                    if isinstance(statement, str)
                    else statement
                    for statement in self.policy_statements
                ],
            )


@dataclass(frozen=True)
class CreateOCIIAMRequest(ClientContext):
    module_path: str
    resource: OCIIAMResource
    action: str = "create"
    provider: str = "oci"
    module: str = "iam"

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le contrat JSON OCI IAM Create attendu par Go."""
        return {
            **self.context_dict(),
            "action": self.action,
            "provider": self.provider,
            "module": self.module,
            "module_path": self.module_path,
            "resource": asdict(self.resource),
        }


@dataclass(frozen=True)
class UpdateOCIIAMRequest(ClientContext):
    module_path: str
    resource: OCIIAMResource
    action: str = "update"
    provider: str = "oci"
    module: str = "iam"

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le contrat JSON OCI IAM Update attendu par Go."""
        return {
            **self.context_dict(),
            "action": self.action,
            "provider": self.provider,
            "module": self.module,
            "module_path": self.module_path,
            "resource": asdict(self.resource),
        }


@dataclass(frozen=True)
class OCIIAMDeleteResource:
    user_resource_name: str
    group_resource_name: str
    membership_resource_name: str
    policy_resource_name: str

    def __post_init__(self) -> None:
        for field in (
            "user_resource_name",
            "group_resource_name",
            "membership_resource_name",
            "policy_resource_name",
        ):
            value = getattr(self, field)
            if isinstance(value, str):
                object.__setattr__(self, field, value.strip())


@dataclass(frozen=True)
class DeleteOCIIAMRequest(ClientContext):
    module_path: str
    resource: OCIIAMDeleteResource
    action: str = "delete"
    provider: str = "oci"
    module: str = "iam"

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le contrat JSON minimal OCI IAM Delete attendu par Go."""
        return {
            **self.context_dict(),
            "action": self.action,
            "provider": self.provider,
            "module": self.module,
            "module_path": self.module_path,
            "resource": asdict(self.resource),
        }


@dataclass(frozen=True)
class UpdateOCINetworkRequest(ClientContext):
    module_path: str
    resource: OCINetworkResource
    action: str = "update"
    provider: str = "oci"
    module: str = "network"

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le contrat JSON OCI Network Update attendu par Go."""
        return {
            **self.context_dict(),
            "action": self.action,
            "provider": self.provider,
            "module": self.module,
            "module_path": self.module_path,
            "resource": asdict(self.resource),
        }


@dataclass(frozen=True)
class OCINetworkDeleteResource:
    resource_name: str
    subnet_resource_name: str
    internet_gateway_resource_name: str
    route_table_resource_name: str


@dataclass(frozen=True)
class DeleteOCINetworkRequest(ClientContext):
    module_path: str
    resource: OCINetworkDeleteResource
    action: str = "delete"
    provider: str = "oci"
    module: str = "network"

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le contrat JSON minimal OCI Network Delete attendu par Go."""
        return {
            **self.context_dict(),
            "action": self.action,
            "provider": self.provider,
            "module": self.module,
            "module_path": self.module_path,
            "resource": asdict(self.resource),
        }


@dataclass(frozen=True)
class UpdateOCIComputeRequest(ClientContext):
    module_path: str
    resource: OCIComputeResource
    action: str = "update"
    provider: str = "oci"
    module: str = "compute"

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le contrat JSON OCI Compute Update attendu par Go."""
        return {
            **self.context_dict(),
            "action": self.action,
            "provider": self.provider,
            "module": self.module,
            "module_path": self.module_path,
            "resource": asdict(self.resource),
        }


@dataclass(frozen=True)
class OCIComputeDeleteResource:
    resource_name: str


@dataclass(frozen=True)
class DeleteOCIComputeRequest(ClientContext):
    module_path: str
    resource: OCIComputeDeleteResource
    action: str = "delete"
    provider: str = "oci"
    module: str = "compute"

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le contrat JSON minimal OCI Compute Delete attendu par Go."""
        return {
            **self.context_dict(),
            "action": self.action,
            "provider": self.provider,
            "module": self.module,
            "module_path": self.module_path,
            "resource": asdict(self.resource),
        }


@dataclass(frozen=True)
class UpdateVMRequest(ClientContext):
    module_path: str
    resource: VMResource
    project_id: str
    action: str = "update"
    provider: str = "gcp"
    module: str = "compute"

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le contrat JSON Compute Update attendu par le programme Go."""
        return {
            **self.context_dict(),
            "action": self.action,
            "provider": self.provider,
            "module": self.module,
            "module_path": self.module_path,
            "project_id": self.project_id,
            "resource": asdict(self.resource),
        }


@dataclass(frozen=True)
class ComputeDeleteResource:
    resource_name: str


@dataclass(frozen=True)
class DeleteVMRequest(ClientContext):
    module_path: str
    resource: ComputeDeleteResource
    project_id: str = ""
    action: str = "delete"
    provider: str = "gcp"
    module: str = "compute"

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le contrat JSON minimal Compute Delete attendu par Go."""
        return {
            **self.context_dict(),
            "action": self.action,
            "provider": self.provider,
            "module": self.module,
            "module_path": self.module_path,
            "project_id": self.project_id,
            "resource": asdict(self.resource),
        }


@dataclass(frozen=True)
class NetworkResource:
    resource_name: str
    name: str
    subnet_resource_name: str
    subnet_name: str
    cidr: str
    region: str


@dataclass(frozen=True)
class CreateNetworkRequest(ClientContext):
    module_path: str
    resource: NetworkResource
    project_id: str = ""
    action: str = "create"
    provider: str = "gcp"
    module: str = "network"

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le contrat JSON Network attendu par le programme Go."""
        return {
            **self.context_dict(),
            "action": self.action,
            "provider": self.provider,
            "module": self.module,
            "module_path": self.module_path,
            "project_id": self.project_id,
            "resource": asdict(self.resource),
        }


@dataclass(frozen=True)
class UpdateNetworkRequest(ClientContext):
    module_path: str
    resource: NetworkResource
    project_id: str = ""
    action: str = "update"
    provider: str = "gcp"
    module: str = "network"

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le contrat JSON Network Update attendu par Go."""
        return {
            **self.context_dict(),
            "action": self.action,
            "provider": self.provider,
            "module": self.module,
            "module_path": self.module_path,
            "project_id": self.project_id,
            "resource": asdict(self.resource),
        }


@dataclass(frozen=True)
class NetworkDeleteResource:
    resource_name: str
    subnet_resource_name: str


@dataclass(frozen=True)
class DeleteNetworkRequest(ClientContext):
    module_path: str
    resource: NetworkDeleteResource
    project_id: str = ""
    action: str = "delete"
    provider: str = "gcp"
    module: str = "network"

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le contrat JSON minimal Network Delete attendu par Go."""
        return {
            **self.context_dict(),
            "action": self.action,
            "provider": self.provider,
            "module": self.module,
            "module_path": self.module_path,
            "project_id": self.project_id,
            "resource": asdict(self.resource),
        }


@dataclass(frozen=True)
class StorageResource:
    resource_name: str
    name: str
    location: str
    storage_class: str
    uniform_bucket_level_access: bool

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "storage_class",
            self.storage_class.strip().upper(),
        )


@dataclass(frozen=True)
class CreateStorageRequest(ClientContext):
    module_path: str
    resource: StorageResource
    project_id: str = ""
    action: str = "create"
    provider: str = "gcp"
    module: str = "storage"

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le contrat JSON Storage attendu par le programme Go."""
        return {
            **self.context_dict(),
            "action": self.action,
            "provider": self.provider,
            "module": self.module,
            "module_path": self.module_path,
            "project_id": self.project_id,
            "resource": asdict(self.resource),
        }


@dataclass(frozen=True)
class UpdateStorageRequest(ClientContext):
    module_path: str
    resource: StorageResource
    project_id: str = ""
    action: str = "update"
    provider: str = "gcp"
    module: str = "storage"

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le contrat JSON Storage Update attendu par Go."""
        return {
            **self.context_dict(),
            "action": self.action,
            "provider": self.provider,
            "module": self.module,
            "module_path": self.module_path,
            "project_id": self.project_id,
            "resource": asdict(self.resource),
        }


@dataclass(frozen=True)
class StorageDeleteResource:
    resource_name: str


@dataclass(frozen=True)
class DeleteStorageRequest(ClientContext):
    module_path: str
    resource: StorageDeleteResource
    project_id: str = ""
    action: str = "delete"
    provider: str = "gcp"
    module: str = "storage"

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le contrat JSON minimal Storage Delete attendu par Go."""
        return {
            **self.context_dict(),
            "action": self.action,
            "provider": self.provider,
            "module": self.module,
            "module_path": self.module_path,
            "project_id": self.project_id,
            "resource": asdict(self.resource),
        }


@dataclass(frozen=True)
class IAMResource:
    resource_name: str
    account_id: str
    display_name: str
    description: str
    project_id: str
    role: str


@dataclass(frozen=True)
class CreateIAMRequest(ClientContext):
    module_path: str
    resource: IAMResource
    project_id: str = ""
    action: str = "create"
    provider: str = "gcp"
    module: str = "iam"

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le contrat JSON IAM Create attendu par Go."""
        return {
            **self.context_dict(),
            "action": self.action,
            "provider": self.provider,
            "module": self.module,
            "module_path": self.module_path,
            "project_id": self.project_id,
            "resource": asdict(self.resource),
        }


@dataclass(frozen=True)
class UpdateIAMRequest(ClientContext):
    module_path: str
    resource: IAMResource
    project_id: str = ""
    action: str = "update"
    provider: str = "gcp"
    module: str = "iam"

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le contrat JSON IAM Update attendu par Go."""
        return {
            **self.context_dict(),
            "action": self.action,
            "provider": self.provider,
            "module": self.module,
            "module_path": self.module_path,
            "project_id": self.project_id,
            "resource": asdict(self.resource),
        }


@dataclass(frozen=True)
class IAMDeleteResource:
    resource_name: str


@dataclass(frozen=True)
class DeleteIAMRequest(ClientContext):
    module_path: str
    resource: IAMDeleteResource
    project_id: str = ""
    action: str = "delete"
    provider: str = "gcp"
    module: str = "iam"

    def to_dict(self) -> Dict[str, Any]:
        """Retourne le contrat JSON minimal IAM Delete attendu par Go."""
        return {
            **self.context_dict(),
            "action": self.action,
            "provider": self.provider,
            "module": self.module,
            "module_path": self.module_path,
            "project_id": self.project_id,
            "resource": asdict(self.resource),
        }
