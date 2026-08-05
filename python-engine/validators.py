"""Validation locale du contrat avant son envoi au generateur Go."""

import ipaddress
import re
from pathlib import Path
from typing import List, Union

from models import (
    CreateIAMRequest,
    CreateNetworkRequest,
    CreateOCIComputeRequest,
    CreateOCINetworkRequest,
    CreateOCIStorageRequest,
    CreateOCIIAMRequest,
    CreateStorageRequest,
    CreateVMRequest,
    DeleteIAMRequest,
    DeleteNetworkRequest,
    DeleteOCIComputeRequest,
    DeleteOCIIAMRequest,
    DeleteOCINetworkRequest,
    DeleteOCIStorageRequest,
    DeleteStorageRequest,
    DeleteVMRequest,
    UpdateIAMRequest,
    UpdateNetworkRequest,
    UpdateOCIComputeRequest,
    UpdateOCIIAMRequest,
    UpdateOCINetworkRequest,
    UpdateOCIStorageRequest,
    UpdateStorageRequest,
    UpdateVMRequest,
)


class ValidationError(ValueError):
    pass


_RESOURCE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
_OCI_IAM_RESOURCE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_OCI_DNS_LABEL = re.compile(r"^[a-z][a-z0-9]{0,14}$")
_STORAGE_CLASSES = {"STANDARD", "NEARLINE", "COLDLINE", "ARCHIVE"}
_FORBIDDEN_IAM_ROLES = {"roles/owner", "roles/editor"}
_GENERATED_ROOT = (
    Path(__file__).resolve().parent.parent / "hcl-generator" / "generated"
)
_GCP_OUTPUTS = {
    "compute": _GENERATED_ROOT / "gcp" / "compute",
    "network": _GENERATED_ROOT / "gcp" / "network",
    "storage": _GENERATED_ROOT / "gcp" / "storage",
    "iam": _GENERATED_ROOT / "gcp" / "iam",
}
_OCI_COMPUTE_OUTPUT = _GENERATED_ROOT / "oci" / "compute"
_OCI_NETWORK_OUTPUT = _GENERATED_ROOT / "oci" / "network"
_OCI_STORAGE_OUTPUT = _GENERATED_ROOT / "oci" / "storage"
_OCI_IAM_OUTPUT = _GENERATED_ROOT / "oci" / "iam"
_OCI_STORAGE_ACCESS_TYPES = {
    "NoPublicAccess",
    "ObjectRead",
    "ObjectReadWithoutList",
}
_OCI_STORAGE_TIERS = {"Standard", "Archive"}
_OCI_STORAGE_VERSIONING = {"Enabled", "Disabled"}


def _validate_oci_iam_policy_statements(resource, errors: List[str]) -> None:
    statements = resource.policy_statements
    if not isinstance(statements, list):
        errors.append("resource.policy_statements doit etre une liste")
        return
    if not statements:
        errors.append(
            "OCI IAM policy statements cannot be empty; must contain at "
            "least one value."
        )
        return

    seen = set()
    for statement in statements:
        if not isinstance(statement, str) or not statement.strip():
            errors.append(
                "OCI IAM policy statements cannot contain empty values."
            )
            continue
        statement = statement.strip()
        if statement in seen:
            errors.append(
                "OCI IAM policy statements cannot contain duplicates: "
                f"{statement}"
            )
            continue
        seen.add(statement)

        words = statement.split()
        if not words or words[0].casefold() != "allow":
            errors.append(
                "OCI IAM policy statement must start with 'Allow': "
                f"{statement}"
            )
            continue
        normalized = " ".join(words).casefold()
        if normalized == "allow any-user" or normalized.startswith(
            "allow any-user "
        ):
            errors.append(
                "OCI IAM policy using any-user is not allowed in the "
                "current security profile."
            )
            continue
        if (
            "manage all-resources" in normalized
            and "in tenancy" in normalized
        ):
            errors.append(
                "OCI IAM policy is too permissive and is blocked by the "
                f"security policy: {statement}"
            )
            continue
        if (
            len(words) < 3
            or words[1].casefold() != "group"
            or words[2] != resource.group_name
        ):
            errors.append(
                "OCI IAM policy statement does not target the configured "
                f"group: {resource.group_name}"
            )


def validate_request(
    request: Union[
        CreateVMRequest,
        CreateOCIComputeRequest,
        CreateOCINetworkRequest,
        CreateOCIStorageRequest,
        CreateOCIIAMRequest,
        UpdateOCIIAMRequest,
        UpdateOCINetworkRequest,
        UpdateOCIStorageRequest,
        UpdateOCIComputeRequest,
        DeleteOCIComputeRequest,
        DeleteOCIIAMRequest,
        DeleteOCINetworkRequest,
        DeleteOCIStorageRequest,
        CreateIAMRequest,
        UpdateIAMRequest,
        UpdateVMRequest,
        DeleteVMRequest,
        DeleteIAMRequest,
        DeleteNetworkRequest,
        DeleteStorageRequest,
        CreateNetworkRequest,
        UpdateNetworkRequest,
        CreateStorageRequest,
        UpdateStorageRequest,
    ],
) -> None:
    errors: List[str] = []

    if isinstance(
        request,
        (
            DeleteVMRequest,
            DeleteNetworkRequest,
            DeleteStorageRequest,
            DeleteIAMRequest,
            DeleteOCIComputeRequest,
            DeleteOCIIAMRequest,
            DeleteOCINetworkRequest,
            DeleteOCIStorageRequest,
        ),
    ):
        expected_action = "delete"
    elif isinstance(
        request,
        (
            UpdateVMRequest,
            UpdateNetworkRequest,
            UpdateOCIComputeRequest,
            UpdateOCIIAMRequest,
            UpdateOCINetworkRequest,
            UpdateOCIStorageRequest,
            UpdateStorageRequest,
            UpdateIAMRequest,
        ),
    ):
        expected_action = "update"
    else:
        expected_action = "create"
    if request.action != expected_action:
        errors.append(f"action doit valoir '{expected_action}'")
    expected_provider = (
        "oci"
        if isinstance(
            request,
            (
                CreateOCIComputeRequest,
                CreateOCINetworkRequest,
                CreateOCIStorageRequest,
                CreateOCIIAMRequest,
                UpdateOCIIAMRequest,
                UpdateOCIComputeRequest,
                UpdateOCINetworkRequest,
                UpdateOCIStorageRequest,
                DeleteOCIComputeRequest,
                DeleteOCIIAMRequest,
                DeleteOCINetworkRequest,
                DeleteOCIStorageRequest,
            ),
        )
        else "gcp"
    )
    if request.provider != expected_provider:
        errors.append(f"provider doit valoir '{expected_provider}'")
    fields = {"module_path": request.module_path}

    if isinstance(request, DeleteOCIIAMRequest):
        if request.module != "iam":
            errors.append("module doit valoir 'iam'")
        identifiers = (
            (
                "resource.user_resource_name",
                request.resource.user_resource_name,
            ),
            (
                "resource.group_resource_name",
                request.resource.group_resource_name,
            ),
            (
                "resource.membership_resource_name",
                request.resource.membership_resource_name,
            ),
            (
                "resource.policy_resource_name",
                request.resource.policy_resource_name,
            ),
        )
        seen_identifiers = {}
        for field, value in identifiers:
            fields[field] = value
            if value and not _OCI_IAM_RESOURCE_NAME.fullmatch(value):
                errors.append(
                    f"{field} doit etre un identifiant Terraform OCI IAM "
                    "valide (lettres, chiffres ou '_', sans chiffre initial)"
                )
            if value in seen_identifiers:
                errors.append(
                    f"{seen_identifiers[value]} et {field} doivent etre "
                    "differents"
                )
            else:
                seen_identifiers[value] = field
    elif isinstance(request, DeleteOCIComputeRequest):
        if request.module != "compute":
            errors.append("module doit valoir 'compute'")
        fields.update(
            {
                "resource.resource_name": request.resource.resource_name,
            }
        )
    elif isinstance(request, DeleteOCINetworkRequest):
        if request.module != "network":
            errors.append("module doit valoir 'network'")
        fields.update(
            {
                "resource.resource_name": request.resource.resource_name,
                "resource.subnet_resource_name": (
                    request.resource.subnet_resource_name
                ),
                "resource.internet_gateway_resource_name": (
                    request.resource.internet_gateway_resource_name
                ),
                "resource.route_table_resource_name": (
                    request.resource.route_table_resource_name
                ),
            }
        )
    elif isinstance(request, DeleteOCIStorageRequest):
        if request.module != "storage":
            errors.append("module doit valoir 'storage'")
        fields.update(
            {
                "resource.resource_name": request.resource.resource_name,
            }
        )
    elif isinstance(request, (CreateOCIIAMRequest, UpdateOCIIAMRequest)):
        if request.module != "iam":
            errors.append("module doit valoir 'iam'")
        resource = request.resource
        fields.update(
            {
                "resource.tenancy_ocid": resource.tenancy_ocid,
                "resource.user_resource_name": (
                    resource.user_resource_name
                ),
                "resource.user_name": resource.user_name,
                "resource.user_description": resource.user_description,
                "resource.group_resource_name": (
                    resource.group_resource_name
                ),
                "resource.group_name": resource.group_name,
                "resource.group_description": resource.group_description,
                "resource.membership_resource_name": (
                    resource.membership_resource_name
                ),
                "resource.policy_resource_name": (
                    resource.policy_resource_name
                ),
                "resource.policy_name": resource.policy_name,
                "resource.policy_description": (
                    resource.policy_description
                ),
                "resource.policy_compartment_id": (
                    resource.policy_compartment_id
                ),
            }
        )
        identifiers = (
            (
                "resource.user_resource_name",
                resource.user_resource_name,
            ),
            (
                "resource.group_resource_name",
                resource.group_resource_name,
            ),
            (
                "resource.membership_resource_name",
                resource.membership_resource_name,
            ),
            (
                "resource.policy_resource_name",
                resource.policy_resource_name,
            ),
        )
        seen_identifiers = {}
        for field, value in identifiers:
            if value and not _OCI_IAM_RESOURCE_NAME.fullmatch(value):
                errors.append(
                    f"{field} doit etre un identifiant Terraform OCI IAM "
                    "valide (lettres, chiffres ou '_', sans chiffre initial)"
                )
            if value in seen_identifiers:
                errors.append(
                    f"{seen_identifiers[value]} et {field} doivent etre "
                    "differents"
                )
            else:
                seen_identifiers[value] = field
        if not resource.tenancy_ocid.startswith("ocid1.tenancy."):
            errors.append(
                "Le Tenancy OCID doit commencer par ocid1.tenancy."
            )
        if not resource.policy_compartment_id.startswith(
            ("ocid1.tenancy.", "ocid1.compartment.")
        ):
            errors.append(
                "resource.policy_compartment_id doit commencer par "
                "ocid1.tenancy. ou ocid1.compartment."
            )
        _validate_oci_iam_policy_statements(resource, errors)
    elif isinstance(
        request,
        (CreateOCIComputeRequest, UpdateOCIComputeRequest),
    ):
        if request.module != "compute":
            errors.append("module doit valoir 'compute'")
        fields.update(
            {
                "resource.resource_name": request.resource.resource_name,
                "resource.display_name": request.resource.display_name,
                "resource.availability_domain": (
                    request.resource.availability_domain
                ),
                "resource.compartment_id": request.resource.compartment_id,
                "resource.shape": request.resource.shape,
                "resource.subnet_id": request.resource.subnet_id,
                "resource.image_id": request.resource.image_id,
            }
        )
        if not request.resource.compartment_id.startswith(
            "ocid1.compartment."
        ):
            errors.append(
                "resource.compartment_id doit commencer par "
                "ocid1.compartment."
            )
        if not request.resource.subnet_id.startswith("ocid1.subnet."):
            errors.append(
                "resource.subnet_id doit commencer par ocid1.subnet."
            )
        if not request.resource.image_id.startswith("ocid1.image."):
            errors.append(
                "resource.image_id doit commencer par ocid1.image."
            )
        if not isinstance(request.resource.assign_public_ip, bool):
            errors.append(
                "resource.assign_public_ip doit etre un booleen"
            )
    elif isinstance(
        request,
        (
            CreateOCINetworkRequest,
            UpdateOCINetworkRequest,
        ),
    ):
        if request.module != "network":
            errors.append("module doit valoir 'network'")
        fields.update(
            {
                "resource.resource_name": request.resource.resource_name,
                "resource.display_name": request.resource.display_name,
                "resource.compartment_id": request.resource.compartment_id,
                "resource.vcn_cidr": request.resource.vcn_cidr,
                "resource.dns_label": request.resource.dns_label,
                "resource.subnet_resource_name": (
                    request.resource.subnet_resource_name
                ),
                "resource.subnet_display_name": (
                    request.resource.subnet_display_name
                ),
                "resource.subnet_cidr": request.resource.subnet_cidr,
                "resource.subnet_dns_label": (
                    request.resource.subnet_dns_label
                ),
                "resource.availability_domain": (
                    request.resource.availability_domain
                ),
                "resource.internet_gateway_resource_name": (
                    request.resource.internet_gateway_resource_name
                ),
                "resource.internet_gateway_display_name": (
                    request.resource.internet_gateway_display_name
                ),
                "resource.route_table_resource_name": (
                    request.resource.route_table_resource_name
                ),
                "resource.route_table_display_name": (
                    request.resource.route_table_display_name
                ),
            }
        )
        if not request.resource.compartment_id.startswith(
            "ocid1.compartment."
        ):
            errors.append(
                "resource.compartment_id doit commencer par "
                "ocid1.compartment."
            )
        if not isinstance(
            request.resource.prohibit_public_ip_on_vnic,
            bool,
        ):
            errors.append(
                "resource.prohibit_public_ip_on_vnic doit etre un booleen"
            )
        for field, value in (
            ("resource.dns_label", request.resource.dns_label),
            (
                "resource.subnet_dns_label",
                request.resource.subnet_dns_label,
            ),
        ):
            if value and not _OCI_DNS_LABEL.fullmatch(value):
                errors.append(
                    f"{field} doit commencer par une lettre, contenir "
                    "uniquement des lettres minuscules et des chiffres, "
                    "et avoir au plus 15 caracteres"
                )
    elif isinstance(
        request,
        (
            CreateOCIStorageRequest,
            UpdateOCIStorageRequest,
        ),
    ):
        if request.module != "storage":
            errors.append("module doit valoir 'storage'")
        fields.update(
            {
                "resource.resource_name": request.resource.resource_name,
                "resource.compartment_id": request.resource.compartment_id,
                "resource.namespace": request.resource.namespace,
                "resource.name": request.resource.name,
                "resource.access_type": request.resource.access_type,
                "resource.storage_tier": request.resource.storage_tier,
                "resource.versioning": request.resource.versioning,
            }
        )
        if not request.resource.compartment_id.startswith(
            "ocid1.compartment."
        ):
            errors.append(
                "resource.compartment_id doit commencer par "
                "ocid1.compartment."
            )
        if request.resource.access_type not in _OCI_STORAGE_ACCESS_TYPES:
            errors.append(
                "resource.access_type doit valoir NoPublicAccess, "
                "ObjectRead ou ObjectReadWithoutList"
            )
        if request.resource.storage_tier not in _OCI_STORAGE_TIERS:
            errors.append(
                "resource.storage_tier doit valoir Standard ou Archive"
            )
        if request.resource.versioning not in _OCI_STORAGE_VERSIONING:
            errors.append(
                "resource.versioning doit valoir Enabled ou Disabled"
            )
        if not isinstance(request.resource.object_events_enabled, bool):
            errors.append(
                "resource.object_events_enabled doit etre un booleen"
            )
    elif isinstance(request, DeleteVMRequest):
        if request.module != "compute":
            errors.append("module doit valoir 'compute'")
        fields.update(
            {
                "resource.resource_name": request.resource.resource_name,
            }
        )
    elif isinstance(request, DeleteNetworkRequest):
        if request.module != "network":
            errors.append("module doit valoir 'network'")
        fields.update(
            {
                "resource.resource_name": request.resource.resource_name,
                "resource.subnet_resource_name": (
                    request.resource.subnet_resource_name
                ),
            }
        )
    elif isinstance(request, DeleteStorageRequest):
        if request.module != "storage":
            errors.append("module doit valoir 'storage'")
        fields.update(
            {
                "resource.resource_name": request.resource.resource_name,
            }
        )
    elif isinstance(request, DeleteIAMRequest):
        if request.module != "iam":
            errors.append("module doit valoir 'iam'")
        fields.update(
            {
                "resource.resource_name": request.resource.resource_name,
            }
        )
    elif isinstance(request, (CreateIAMRequest, UpdateIAMRequest)):
        if request.module != "iam":
            errors.append("module doit valoir 'iam'")
        fields.update(
            {
                "resource.resource_name": request.resource.resource_name,
                "resource.account_id": request.resource.account_id,
                "resource.display_name": request.resource.display_name,
                "resource.description": request.resource.description,
                "resource.project_id": request.resource.project_id,
                "resource.role": request.resource.role,
            }
        )
        if request.resource.role and not request.resource.role.startswith(
            "roles/"
        ):
            errors.append("Le rôle IAM doit commencer par roles/")
        if request.resource.role in _FORBIDDEN_IAM_ROLES:
            errors.append(
                "Rôle IAM trop permissif interdit par la politique de "
                f"sécurité : {request.resource.role}"
            )
    elif isinstance(request, (CreateVMRequest, UpdateVMRequest)):
        if request.module != "compute":
            errors.append("module doit valoir 'compute'")
        fields.update(
            {
                "resource.resource_name": request.resource.resource_name,
                "resource.name": request.resource.name,
                "resource.machine_type": request.resource.machine_type,
                "resource.zone": request.resource.zone,
                "resource.image": request.resource.image,
                "resource.network": request.resource.network,
            }
        )
    elif isinstance(request, (CreateNetworkRequest, UpdateNetworkRequest)):
        if request.module != "network":
            errors.append("module doit valoir 'network'")
        fields.update(
            {
                "resource.resource_name": request.resource.resource_name,
                "resource.name": request.resource.name,
                "resource.subnet_resource_name": (
                    request.resource.subnet_resource_name
                ),
                "resource.subnet_name": request.resource.subnet_name,
                "resource.cidr": request.resource.cidr,
                "resource.region": request.resource.region,
            }
        )
    elif isinstance(request, (CreateStorageRequest, UpdateStorageRequest)):
        if request.module != "storage":
            errors.append("module doit valoir 'storage'")
        fields.update(
            {
                "resource.resource_name": request.resource.resource_name,
                "resource.name": request.resource.name,
                "resource.location": request.resource.location,
                "resource.storage_class": request.resource.storage_class,
            }
        )
        if not isinstance(request.resource.uniform_bucket_level_access, bool):
            errors.append(
                "resource.uniform_bucket_level_access doit etre un booleen"
            )
        if request.resource.storage_class not in _STORAGE_CLASSES:
            errors.append(
                "resource.storage_class doit valoir STANDARD, NEARLINE, "
                "COLDLINE ou ARCHIVE"
            )
    for name, value in fields.items():
        if not value.strip():
            errors.append(f"{name} est obligatoire")

    if isinstance(
        request,
        (
            CreateOCIIAMRequest,
            UpdateOCIIAMRequest,
            DeleteOCIIAMRequest,
        ),
    ):
        expected_output = _OCI_IAM_OUTPUT
    elif isinstance(
        request,
        (
            CreateOCIStorageRequest,
            UpdateOCIStorageRequest,
            DeleteOCIStorageRequest,
        ),
    ):
        expected_output = _OCI_STORAGE_OUTPUT
    elif isinstance(
        request,
        (
            CreateOCINetworkRequest,
            UpdateOCINetworkRequest,
            DeleteOCINetworkRequest,
        ),
    ):
        expected_output = _OCI_NETWORK_OUTPUT
    elif isinstance(
        request,
        (
            CreateOCIComputeRequest,
            UpdateOCIComputeRequest,
            DeleteOCIComputeRequest,
        ),
    ):
        expected_output = _OCI_COMPUTE_OUTPUT
    else:
        expected_output = _GCP_OUTPUTS.get(request.module)
    if (
        expected_output is not None
        and Path(request.module_path).resolve() != expected_output.resolve()
    ):
        errors.append(
            f"module_path {expected_provider}/{request.module} doit cibler "
            f"hcl-generator/generated/{expected_provider}/{request.module}"
        )

    resource_name = getattr(request.resource, "resource_name", "")
    if resource_name.strip() and not _RESOURCE_NAME.fullmatch(resource_name):
        errors.append(
            "resource.resource_name doit etre un identifiant Terraform valide "
            "(lettres, chiffres, '_' ou '-', sans chiffre initial)"
        )

    if isinstance(
        request,
        (CreateNetworkRequest, UpdateNetworkRequest, DeleteNetworkRequest),
    ):
        subnet_resource_name = request.resource.subnet_resource_name.strip()
        if subnet_resource_name and not _RESOURCE_NAME.fullmatch(
            subnet_resource_name
        ):
            errors.append(
                "resource.subnet_resource_name doit etre un identifiant "
                "Terraform valide (lettres, chiffres, '_' ou '-', sans "
                "chiffre initial)"
            )
        if request.resource.resource_name == request.resource.subnet_resource_name:
            errors.append(
                "resource.resource_name et resource.subnet_resource_name "
                "doivent etre differents"
            )
        if isinstance(request, (CreateNetworkRequest, UpdateNetworkRequest)):
            try:
                network = ipaddress.ip_network(request.resource.cidr, strict=True)
                if network.version != 4:
                    errors.append("resource.cidr doit etre un CIDR IPv4 valide")
            except ValueError:
                errors.append("resource.cidr doit etre un CIDR IPv4 valide")

    if isinstance(
        request,
        (
            CreateOCINetworkRequest,
            UpdateOCINetworkRequest,
            DeleteOCINetworkRequest,
        ),
    ):
        identifiers = {
            "resource.resource_name": request.resource.resource_name,
            "resource.subnet_resource_name": (
                request.resource.subnet_resource_name
            ),
            "resource.internet_gateway_resource_name": (
                request.resource.internet_gateway_resource_name
            ),
            "resource.route_table_resource_name": (
                request.resource.route_table_resource_name
            ),
        }
        seen_identifiers = {}
        for field, value in identifiers.items():
            if value.strip() and not _RESOURCE_NAME.fullmatch(value):
                errors.append(
                    f"{field} doit etre un identifiant Terraform valide "
                    "(lettres, chiffres, '_' ou '-', sans chiffre initial)"
                )
            if value in seen_identifiers:
                errors.append(
                    f"{seen_identifiers[value]} et {field} "
                    "doivent etre differents"
                )
            else:
                seen_identifiers[value] = field

        if not isinstance(request, DeleteOCINetworkRequest):
            vcn_network = None
            subnet_network = None
            try:
                vcn_network = ipaddress.ip_network(
                    request.resource.vcn_cidr,
                    strict=True,
                )
                if vcn_network.version != 4:
                    errors.append(
                        "resource.vcn_cidr doit etre un CIDR IPv4 valide"
                    )
                    vcn_network = None
            except ValueError:
                errors.append(
                    "resource.vcn_cidr doit etre un CIDR IPv4 valide"
                )
            try:
                subnet_network = ipaddress.ip_network(
                    request.resource.subnet_cidr,
                    strict=True,
                )
                if subnet_network.version != 4:
                    errors.append(
                        "resource.subnet_cidr doit etre un CIDR IPv4 valide"
                    )
                    subnet_network = None
            except ValueError:
                errors.append(
                    "resource.subnet_cidr doit etre un CIDR IPv4 valide"
                )

            if vcn_network is not None and subnet_network is not None:
                if not subnet_network.subnet_of(vcn_network):
                    errors.append(
                        "Le CIDR du subnet doit appartenir au CIDR du VCN."
                    )
                elif subnet_network.prefixlen <= vcn_network.prefixlen:
                    errors.append(
                        "resource.subnet_cidr doit etre plus specifique "
                        "que resource.vcn_cidr"
                    )

    if errors:
        raise ValidationError("\n".join(f"- {error}" for error in errors))
