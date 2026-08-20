"""Collecte interactive et construction des demandes multi-cloud."""

from pathlib import Path
from typing import Callable

from models import (
    ComputeDeleteResource,
    CreateIAMRequest,
    CreateNetworkRequest,
    CreateOCIComputeRequest,
    CreateOCINetworkRequest,
    CreateOCIStorageRequest,
    CreateOCIIAMRequest,
    CreateStorageRequest,
    CreateVMRequest,
    DeleteNetworkRequest,
    DeleteIAMRequest,
    DeleteOCIComputeRequest,
    DeleteOCIIAMRequest,
    DeleteOCINetworkRequest,
    DeleteOCIStorageRequest,
    DeleteStorageRequest,
    DeleteVMRequest,
    GCPContext,
    IAMResource,
    IAMDeleteResource,
    NetworkResource,
    NetworkDeleteResource,
    OCIComputeDeleteResource,
    OCIComputeResource,
    OCIIAMDeleteResource,
    OCINetworkResource,
    OCINetworkDeleteResource,
    OCIStorageResource,
    OCIStorageDeleteResource,
    OCIIAMResource,
    StorageResource,
    StorageDeleteResource,
    UpdateIAMRequest,
    UpdateNetworkRequest,
    UpdateOCIComputeRequest,
    UpdateOCIIAMRequest,
    UpdateOCINetworkRequest,
    UpdateOCIStorageRequest,
    UpdateStorageRequest,
    UpdateVMRequest,
    VMResource,
)


InputFunction = Callable[[str], str]

PROJECT_ROOT = Path(__file__).resolve().parent.parent
GENERATED_ROOT = PROJECT_ROOT / "hcl-generator" / "generated"
GCP_ROOT = GENERATED_ROOT / "gcp"
GCP_MODULES_ROOT = GCP_ROOT / "modules"
GCP_COMPUTE_OUTPUT = GCP_MODULES_ROOT / "compute"
GCP_NETWORK_OUTPUT = GCP_MODULES_ROOT / "network"
GCP_STORAGE_OUTPUT = GCP_MODULES_ROOT / "storage"
GCP_IAM_OUTPUT = GCP_MODULES_ROOT / "iam"
OCI_ROOT = GENERATED_ROOT / "oci"
OCI_MODULES_ROOT = OCI_ROOT / "modules"
OCI_COMPUTE_OUTPUT = OCI_MODULES_ROOT / "compute"
OCI_NETWORK_OUTPUT = OCI_MODULES_ROOT / "network"
OCI_STORAGE_OUTPUT = OCI_MODULES_ROOT / "storage"
OCI_IAM_OUTPUT = OCI_MODULES_ROOT / "iam"


def _ask(label: str, default: str, input_fn: InputFunction) -> str:
    value = input_fn(f"{label} [{default}] : ").strip()
    return value or default


def _ask_required(label: str, input_fn: InputFunction) -> str:
    return input_fn(f"{label} : ").strip()


def _ask_bool(label: str, default: bool, input_fn: InputFunction) -> bool:
    default_text = "true" if default else "false"
    value = input_fn(f"{label} [{default_text}] : ").strip().lower()
    if not value:
        return default
    if value in {"true", "yes", "y", "1"}:
        return True
    if value in {"false", "no", "n", "0"}:
        return False
    raise ValueError(
        f"{label} doit valoir true/false, yes/no, y/n ou 1/0"
    )


def ask_gcp_context(input_fn: InputFunction = input) -> GCPContext:
    project_id = _ask_required("Identifiant du projet GCP", input_fn)
    if not project_id:
        raise ValueError("Identifiant du projet GCP obligatoire")
    return GCPContext(project_id=project_id)


def _resolve_gcp_context(
    context: GCPContext | None,
    input_fn: InputFunction,
) -> GCPContext:
    if context is None:
        return ask_gcp_context(input_fn)
    if not isinstance(context, GCPContext):
        raise TypeError("context doit etre un GCPContext")
    return context


def build_request(
    input_fn: InputFunction = input,
    *,
    gcp_context: GCPContext | None = None,
    prompt_module_path: bool = True,
) -> CreateVMRequest:
    default_module_path = str(GCP_COMPUTE_OUTPUT.resolve())

    print("\nParametres de la VM GCP (Entree conserve la valeur proposee)\n")
    context = _resolve_gcp_context(gcp_context, input_fn)
    resource = VMResource(
        resource_name=_ask("Identifiant Terraform", "vm_web_01", input_fn),
        name=_ask("Nom de la VM GCP", "vm-web-01", input_fn),
        machine_type=_ask("Type de machine", "e2-medium", input_fn),
        zone=_ask("Zone GCP", "europe-west1-b", input_fn),
        image=_ask("Image", "debian-cloud/debian-12", input_fn),
        network=_ask("Reseau", "default", input_fn),
    )
    module_path = default_module_path
    if prompt_module_path:
        module_path = _ask("Dossier Terraform cible", default_module_path, input_fn)
    return CreateVMRequest(
        module_path=module_path,
        resource=resource,
        project_id=context.project_id,
    )


def ask_oci_compute_parameters(
    input_fn: InputFunction = input,
) -> CreateOCIComputeRequest:
    print(
        "\nParametres de l'instance OCI "
        "(Entree conserve la valeur proposee)\n"
    )
    resource = OCIComputeResource(
        resource_name=_ask(
            "Nom logique Terraform",
            "oci_vm_web_01",
            input_fn,
        ),
        display_name=_ask(
            "Display name",
            "oci-vm-web-01",
            input_fn,
        ),
        availability_domain=_ask(
            "Availability Domain",
            "Uocm:EU-FRANKFURT-1-AD-1",
            input_fn,
        ),
        compartment_id=_ask(
            "Compartment OCID",
            "ocid1.compartment.oc1..exampleuniqueID",
            input_fn,
        ),
        shape=_ask("Shape", "VM.Standard.E4.Flex", input_fn),
        subnet_id=_ask(
            "Subnet OCID",
            "ocid1.subnet.oc1.eu-frankfurt-1.exampleuniqueID",
            input_fn,
        ),
        image_id=_ask(
            "Image OCID",
            "ocid1.image.oc1.eu-frankfurt-1.exampleuniqueID",
            input_fn,
        ),
        assign_public_ip=_ask_bool(
            "Assign public IP",
            False,
            input_fn,
        ),
    )
    return CreateOCIComputeRequest(
        module_path=str(OCI_COMPUTE_OUTPUT.resolve()),
        resource=resource,
    )


def ask_oci_network_parameters(
    input_fn: InputFunction = input,
) -> CreateOCINetworkRequest:
    print(
        "\nParametres du reseau OCI "
        "(Entree conserve la valeur proposee)\n"
    )
    resource = OCINetworkResource(
        resource_name=_ask(
            "Nom logique Terraform du VCN",
            "oci_vcn_web_01",
            input_fn,
        ),
        display_name=_ask(
            "Nom affiche du VCN",
            "oci-vcn-web-01",
            input_fn,
        ),
        compartment_id=_ask(
            "Compartment OCID",
            "ocid1.compartment.oc1..exampleuniqueID",
            input_fn,
        ),
        vcn_cidr=_ask("CIDR du VCN", "10.20.0.0/16", input_fn),
        dns_label=_ask("DNS label du VCN", "vcnweb01", input_fn),
        subnet_resource_name=_ask(
            "Nom logique Terraform du subnet",
            "oci_subnet_web_01",
            input_fn,
        ),
        subnet_display_name=_ask(
            "Nom affiche du subnet",
            "oci-subnet-web-01",
            input_fn,
        ),
        subnet_cidr=_ask("CIDR du subnet", "10.20.1.0/24", input_fn),
        subnet_dns_label=_ask(
            "DNS label du subnet",
            "subweb01",
            input_fn,
        ),
        availability_domain=_ask(
            "Availability Domain",
            "Uocm:EU-FRANKFURT-1-AD-1",
            input_fn,
        ),
        prohibit_public_ip_on_vnic=_ask_bool(
            "Prohibit public IP on VNIC",
            False,
            input_fn,
        ),
        internet_gateway_resource_name=_ask(
            "Nom logique Terraform de l'Internet Gateway",
            "oci_igw_web_01",
            input_fn,
        ),
        internet_gateway_display_name=_ask(
            "Nom affiche de l'Internet Gateway",
            "oci-igw-web-01",
            input_fn,
        ),
        route_table_resource_name=_ask(
            "Nom logique Terraform de la route table",
            "oci_rt_web_01",
            input_fn,
        ),
        route_table_display_name=_ask(
            "Nom affiche de la route table",
            "oci-rt-web-01",
            input_fn,
        ),
    )
    return CreateOCINetworkRequest(
        module_path=str(OCI_NETWORK_OUTPUT.resolve()),
        resource=resource,
    )


def ask_oci_storage_parameters(
    input_fn: InputFunction = input,
) -> CreateOCIStorageRequest:
    print(
        "\nParametres du bucket OCI Object Storage "
        "(Entree conserve la valeur proposee)\n"
    )
    resource = OCIStorageResource(
        resource_name=_ask(
            "Nom logique Terraform du bucket",
            "oci_bucket_web_01",
            input_fn,
        ),
        compartment_id=_ask(
            "Compartment OCID",
            "ocid1.compartment.oc1..exampleuniqueID",
            input_fn,
        ),
        namespace=_ask(
            "Namespace OCI Object Storage",
            "exampletenancy",
            input_fn,
        ),
        name=_ask("Nom reel du bucket", "oci-bucket-web-01", input_fn),
        access_type=_ask(
            "Access type",
            "NoPublicAccess",
            input_fn,
        ),
        storage_tier=_ask("Storage tier", "Standard", input_fn),
        versioning=_ask("Versioning", "Enabled", input_fn),
        object_events_enabled=_ask_bool(
            "Object events enabled",
            True,
            input_fn,
        ),
    )
    return CreateOCIStorageRequest(
        module_path=str(OCI_STORAGE_OUTPUT.resolve()),
        resource=resource,
    )


def ask_oci_storage_update_parameters(
    input_fn: InputFunction = input,
) -> UpdateOCIStorageRequest:
    print("\nNouvelles valeurs finales du bucket OCI existant\n")
    resource = OCIStorageResource(
        resource_name=_ask(
            "Nom logique Terraform du bucket existant",
            "oci_bucket_test_01",
            input_fn,
        ),
        compartment_id=_ask(
            "Compartment OCID",
            "ocid1.compartment.oc1..exampleuniqueID",
            input_fn,
        ),
        namespace=_ask(
            "Namespace OCI Object Storage",
            "exampletenancynamespace",
            input_fn,
        ),
        name=_ask(
            "Nouveau nom reel du bucket",
            "stage2026-oci-bucket-production-01",
            input_fn,
        ),
        access_type=_ask(
            "Access type",
            "NoPublicAccess",
            input_fn,
        ),
        storage_tier=_ask("Storage tier", "Standard", input_fn),
        versioning=_ask("Versioning", "Enabled", input_fn),
        object_events_enabled=_ask_bool(
            "Object events enabled",
            True,
            input_fn,
        ),
    )
    return UpdateOCIStorageRequest(
        module_path=str(OCI_STORAGE_OUTPUT.resolve()),
        resource=resource,
    )


def ask_oci_storage_delete_parameters(
    input_fn: InputFunction = input,
) -> DeleteOCIStorageRequest:
    print("\nSuppression locale d'un bucket Terraform OCI\n")
    resource = OCIStorageDeleteResource(
        resource_name=_ask(
            "Nom logique Terraform du bucket OCI a supprimer",
            "oci_bucket_delete_test_01",
            input_fn,
        ),
    )
    return DeleteOCIStorageRequest(
        module_path=str(OCI_STORAGE_OUTPUT.resolve()),
        resource=resource,
    )


def ask_oci_iam_create_parameters(
    input_fn: InputFunction = input,
) -> CreateOCIIAMRequest:
    print(
        "\nParametres de l'ensemble OCI IAM "
        "(Entree conserve la valeur proposee)\n"
    )
    tenancy_ocid = _ask(
        "Tenancy OCID",
        "ocid1.tenancy.oc1..exampleuniqueID",
        input_fn,
    )
    user_resource_name = _ask(
        "Nom logique Terraform de l'utilisateur",
        "oci_user_observability_01",
        input_fn,
    )
    user_name = _ask(
        "Nom OCI de l'utilisateur",
        "stage2026-observability-user",
        input_fn,
    )
    user_description = _ask(
        "Description de l'utilisateur",
        "Utilisateur OCI pour les operations d'observabilite",
        input_fn,
    )
    group_resource_name = _ask(
        "Nom logique Terraform du groupe",
        "oci_group_observability_01",
        input_fn,
    )
    group_name = _ask(
        "Nom OCI du groupe",
        "stage2026-observability-group",
        input_fn,
    )
    group_description = _ask(
        "Description du groupe",
        "Groupe OCI pour les operations d'observabilite",
        input_fn,
    )
    membership_resource_name = _ask(
        "Nom logique Terraform de l'association utilisateur-groupe",
        "oci_membership_observability_01",
        input_fn,
    )
    policy_resource_name = _ask(
        "Nom logique Terraform de la politique",
        "oci_policy_observability_01",
        input_fn,
    )
    policy_name = _ask(
        "Nom OCI de la politique",
        "stage2026-observability-policy",
        input_fn,
    )
    policy_description = _ask(
        "Description de la politique",
        "Politique OCI minimale pour l'observabilite",
        input_fn,
    )
    policy_compartment_id = _ask(
        "OCID du tenancy ou compartiment contenant la politique",
        "ocid1.compartment.oc1..exampleuniqueID",
        input_fn,
    )
    statement_count_text = _ask(
        "Nombre de declarations IAM",
        "1",
        input_fn,
    )
    try:
        statement_count = int(statement_count_text)
    except ValueError as exc:
        raise ValueError(
            "Le nombre de declarations IAM doit etre un entier superieur "
            "ou egal a 1"
        ) from exc
    if statement_count < 1:
        raise ValueError(
            "Le nombre de declarations IAM doit etre superieur ou egal a 1"
        )
    default_statement = (
        f"Allow group {group_name} to read metrics in compartment stage2026"
    )
    statements = [
        _ask(
            f"Declaration IAM {index}",
            default_statement,
            input_fn,
        )
        for index in range(1, statement_count + 1)
    ]

    return CreateOCIIAMRequest(
        module_path=str(OCI_IAM_OUTPUT.resolve()),
        resource=OCIIAMResource(
            tenancy_ocid=tenancy_ocid,
            user_resource_name=user_resource_name,
            user_name=user_name,
            user_description=user_description,
            group_resource_name=group_resource_name,
            group_name=group_name,
            group_description=group_description,
            membership_resource_name=membership_resource_name,
            policy_resource_name=policy_resource_name,
            policy_name=policy_name,
            policy_description=policy_description,
            policy_compartment_id=policy_compartment_id,
            policy_statements=statements,
        ),
    )


def ask_oci_iam_update_parameters(
    input_fn: InputFunction = input,
) -> UpdateOCIIAMRequest:
    print(
        "\nValeurs finales de l'ensemble OCI IAM existant "
        "(Entree conserve la valeur proposee)\n"
    )
    tenancy_ocid = _ask(
        "Tenancy OCID final",
        "ocid1.tenancy.oc1..exampleuniqueID",
        input_fn,
    )
    user_resource_name = _ask(
        "Nom logique Terraform de l'utilisateur existant",
        "oci_user_observability_01",
        input_fn,
    )
    user_name = _ask(
        "Nom OCI final de l'utilisateur",
        "stage2026-observability-user",
        input_fn,
    )
    user_description = _ask(
        "Description finale de l'utilisateur",
        "Utilisateur OCI de production pour l'observabilite",
        input_fn,
    )
    group_resource_name = _ask(
        "Nom logique Terraform du groupe existant",
        "oci_group_observability_01",
        input_fn,
    )
    group_name = _ask(
        "Nom OCI final du groupe",
        "stage2026-observability-group",
        input_fn,
    )
    group_description = _ask(
        "Description finale du groupe",
        "Groupe OCI de production pour l'observabilite",
        input_fn,
    )
    membership_resource_name = _ask(
        "Nom logique Terraform de l'association existante",
        "oci_membership_observability_01",
        input_fn,
    )
    policy_resource_name = _ask(
        "Nom logique Terraform de la politique existante",
        "oci_policy_observability_01",
        input_fn,
    )
    policy_name = _ask(
        "Nom OCI final de la politique",
        "stage2026-observability-policy",
        input_fn,
    )
    policy_description = _ask(
        "Description finale de la politique",
        "Politique OCI minimale de production pour l'observabilite",
        input_fn,
    )
    policy_compartment_id = _ask(
        "OCID final du tenancy ou compartiment de la politique",
        "ocid1.compartment.oc1..exampleuniqueID",
        input_fn,
    )
    statement_count_text = _ask(
        "Nombre de policy statements",
        "1",
        input_fn,
    )
    try:
        statement_count = int(statement_count_text)
    except ValueError as exc:
        raise ValueError(
            "Le nombre de policy statements doit etre un entier superieur "
            "ou egal a 1"
        ) from exc
    if statement_count < 1:
        raise ValueError(
            "Le nombre de policy statements doit etre superieur ou egal a 1"
        )
    default_statement = (
        f"Allow group {group_name} to read metrics in compartment stage2026"
    )
    statements = [
        _ask(
            f"Policy statement {index}",
            default_statement,
            input_fn,
        )
        for index in range(1, statement_count + 1)
    ]

    return UpdateOCIIAMRequest(
        module_path=str(OCI_IAM_OUTPUT.resolve()),
        resource=OCIIAMResource(
            tenancy_ocid=tenancy_ocid,
            user_resource_name=user_resource_name,
            user_name=user_name,
            user_description=user_description,
            group_resource_name=group_resource_name,
            group_name=group_name,
            group_description=group_description,
            membership_resource_name=membership_resource_name,
            policy_resource_name=policy_resource_name,
            policy_name=policy_name,
            policy_description=policy_description,
            policy_compartment_id=policy_compartment_id,
            policy_statements=statements,
        ),
    )


def ask_oci_iam_delete_parameters(
    input_fn: InputFunction = input,
) -> DeleteOCIIAMRequest:
    print("\nSuppression locale d'un ensemble Terraform OCI IAM\n")
    resource = OCIIAMDeleteResource(
        user_resource_name=_ask(
            "Nom logique Terraform de l'utilisateur OCI a supprimer",
            "oci_user_delete_test_01",
            input_fn,
        ),
        group_resource_name=_ask(
            "Nom logique Terraform du groupe OCI a supprimer",
            "oci_group_delete_test_01",
            input_fn,
        ),
        membership_resource_name=_ask(
            "Nom logique Terraform de la Membership a supprimer",
            "oci_membership_delete_test_01",
            input_fn,
        ),
        policy_resource_name=_ask(
            "Nom logique Terraform de la Policy a supprimer",
            "oci_policy_delete_test_01",
            input_fn,
        ),
    )
    return DeleteOCIIAMRequest(
        module_path=str(OCI_IAM_OUTPUT.resolve()),
        resource=resource,
    )


def ask_oci_network_update_parameters(
    input_fn: InputFunction = input,
) -> UpdateOCINetworkRequest:
    print("\nNouvelles valeurs finales du reseau OCI existant\n")
    resource = OCINetworkResource(
        resource_name=_ask(
            "Nom logique Terraform du VCN existant",
            "oci_vcn_test_01",
            input_fn,
        ),
        display_name=_ask(
            "Nom affiche du VCN",
            "oci-vcn-production-01",
            input_fn,
        ),
        compartment_id=_ask(
            "Compartment OCID",
            "ocid1.compartment.oc1..exampleuniqueID",
            input_fn,
        ),
        vcn_cidr=_ask("CIDR du VCN", "10.30.0.0/16", input_fn),
        dns_label=_ask("DNS label du VCN", "vcnprod01", input_fn),
        subnet_resource_name=_ask(
            "Nom logique Terraform du subnet existant",
            "oci_subnet_test_01",
            input_fn,
        ),
        subnet_display_name=_ask(
            "Nom affiche du subnet",
            "oci-subnet-production-01",
            input_fn,
        ),
        subnet_cidr=_ask(
            "CIDR du subnet",
            "10.30.20.0/24",
            input_fn,
        ),
        subnet_dns_label=_ask(
            "DNS label du subnet",
            "subprod01",
            input_fn,
        ),
        availability_domain=_ask(
            "Availability Domain",
            "Uocm:EU-FRANKFURT-1-AD-1",
            input_fn,
        ),
        prohibit_public_ip_on_vnic=_ask_bool(
            "Prohibit public IP on VNIC",
            True,
            input_fn,
        ),
        internet_gateway_resource_name=_ask(
            "Nom logique Terraform de l'Internet Gateway existante",
            "oci_igw_test_01",
            input_fn,
        ),
        internet_gateway_display_name=_ask(
            "Nom affiche de l'Internet Gateway",
            "oci-igw-production-01",
            input_fn,
        ),
        route_table_resource_name=_ask(
            "Nom logique Terraform de la route table existante",
            "oci_rt_test_01",
            input_fn,
        ),
        route_table_display_name=_ask(
            "Nom affiche de la route table",
            "oci-rt-production-01",
            input_fn,
        ),
    )
    return UpdateOCINetworkRequest(
        module_path=str(OCI_NETWORK_OUTPUT.resolve()),
        resource=resource,
    )


def ask_oci_network_delete_parameters(
    input_fn: InputFunction = input,
) -> DeleteOCINetworkRequest:
    print("\nSuppression locale d'un reseau Terraform OCI\n")
    resource = OCINetworkDeleteResource(
        resource_name=_ask(
            "Nom logique Terraform du VCN a supprimer",
            "oci_vcn_delete_test_01",
            input_fn,
        ),
        subnet_resource_name=_ask(
            "Nom logique Terraform du subnet a supprimer",
            "oci_subnet_delete_test_01",
            input_fn,
        ),
        internet_gateway_resource_name=_ask(
            "Nom logique Terraform de l'Internet Gateway a supprimer",
            "oci_igw_delete_test_01",
            input_fn,
        ),
        route_table_resource_name=_ask(
            "Nom logique Terraform de la route table a supprimer",
            "oci_rt_delete_test_01",
            input_fn,
        ),
    )
    return DeleteOCINetworkRequest(
        module_path=str(OCI_NETWORK_OUTPUT.resolve()),
        resource=resource,
    )


def ask_oci_compute_update_parameters(
    input_fn: InputFunction = input,
) -> UpdateOCIComputeRequest:
    print("\nNouvelles valeurs finales de l'instance OCI existante\n")
    resource = OCIComputeResource(
        resource_name=_ask(
            "Nom logique Terraform de l'instance existante",
            "oci_vm_test_01",
            input_fn,
        ),
        display_name=_ask(
            "Display name",
            "oci-vm-test-01",
            input_fn,
        ),
        availability_domain=_ask(
            "Availability Domain",
            "Uocm:EU-FRANKFURT-1-AD-1",
            input_fn,
        ),
        compartment_id=_ask(
            "Compartment OCID",
            "ocid1.compartment.oc1..exampleuniqueID",
            input_fn,
        ),
        shape=_ask("Shape", "VM.Standard.E4.Flex", input_fn),
        subnet_id=_ask(
            "Subnet OCID",
            "ocid1.subnet.oc1.eu-frankfurt-1.exampleuniqueID",
            input_fn,
        ),
        image_id=_ask(
            "Image OCID",
            "ocid1.image.oc1.eu-frankfurt-1.exampleuniqueID",
            input_fn,
        ),
        assign_public_ip=_ask_bool(
            "Assign public IP",
            False,
            input_fn,
        ),
    )
    return UpdateOCIComputeRequest(
        module_path=str(OCI_COMPUTE_OUTPUT.resolve()),
        resource=resource,
    )


def ask_oci_compute_delete_parameters(
    input_fn: InputFunction = input,
) -> DeleteOCIComputeRequest:
    print("\nSuppression locale d'une instance Terraform OCI\n")
    resource = OCIComputeDeleteResource(
        resource_name=_ask(
            "Nom logique Terraform de l'instance OCI à supprimer",
            "oci_vm_test_01",
            input_fn,
        ),
    )
    return DeleteOCIComputeRequest(
        module_path=str(OCI_COMPUTE_OUTPUT.resolve()),
        resource=resource,
    )


def ask_gcp_compute_update_parameters(
    input_fn: InputFunction = input,
    *,
    gcp_context: GCPContext | None = None,
    prompt_module_path: bool = True,
) -> UpdateVMRequest:
    default_module_path = str(GCP_COMPUTE_OUTPUT.resolve())

    print("\nNouvelles valeurs finales de la VM GCP\n")
    context = _resolve_gcp_context(gcp_context, input_fn)
    resource = VMResource(
        resource_name=_ask(
            "Nom logique Terraform de la VM existante",
            "vm_clean_test_01",
            input_fn,
        ),
        name=_ask("Nom reel", "vm-clean-test-01", input_fn),
        machine_type=_ask("Machine type", "e2-standard-2", input_fn),
        zone=_ask("Zone", "europe-west1-b", input_fn),
        image=_ask("Image", "debian-cloud/debian-12", input_fn),
        network=_ask("Network", "default", input_fn),
    )
    module_path = default_module_path
    if prompt_module_path:
        module_path = _ask("Dossier Terraform cible", default_module_path, input_fn)
    return UpdateVMRequest(
        module_path=module_path,
        resource=resource,
        project_id=context.project_id,
    )


def ask_gcp_compute_delete_parameters(
    input_fn: InputFunction = input,
    *,
    gcp_context: GCPContext | None = None,
) -> DeleteVMRequest:
    print("\nSuppression d'une VM Terraform GCP\n")
    context = _resolve_gcp_context(gcp_context, input_fn)
    resource = ComputeDeleteResource(
        resource_name=_ask(
            "Nom logique Terraform de la VM a supprimer",
            "vm_delete_test_01",
            input_fn,
        ),
    )
    return DeleteVMRequest(
        module_path=str(GCP_COMPUTE_OUTPUT.resolve()),
        resource=resource,
        project_id=context.project_id,
    )


def ask_gcp_network_parameters(
    input_fn: InputFunction = input,
    *,
    gcp_context: GCPContext | None = None,
    prompt_module_path: bool = True,
) -> CreateNetworkRequest:
    default_module_path = str(GCP_NETWORK_OUTPUT.resolve())

    print("\nParametres du reseau GCP (Entree conserve la valeur proposee)\n")
    context = _resolve_gcp_context(gcp_context, input_fn)
    resource = NetworkResource(
        resource_name=_ask(
            "Nom logique Terraform du VPC", "vpc_prod", input_fn
        ),
        name=_ask("Nom reel du VPC", "vpc-prod", input_fn),
        subnet_resource_name=_ask(
            "Nom logique Terraform du subnet", "subnet_prod", input_fn
        ),
        subnet_name=_ask("Nom reel du subnet", "subnet-prod", input_fn),
        cidr=_ask("CIDR", "10.10.0.0/24", input_fn),
        region=_ask("Region", "europe-west1", input_fn),
    )
    module_path = default_module_path
    if prompt_module_path:
        module_path = _ask("Dossier Terraform cible", default_module_path, input_fn)
    return CreateNetworkRequest(
        module_path=module_path,
        resource=resource,
        project_id=context.project_id,
    )


def ask_gcp_network_update_parameters(
    input_fn: InputFunction = input,
    *,
    gcp_context: GCPContext | None = None,
    prompt_module_path: bool = True,
) -> UpdateNetworkRequest:
    default_module_path = str(GCP_NETWORK_OUTPUT.resolve())

    print("\nNouvelles valeurs finales du reseau GCP\n")
    context = _resolve_gcp_context(gcp_context, input_fn)
    resource = NetworkResource(
        resource_name=_ask(
            "Nom logique Terraform du VPC existant",
            "vpc_dev_01",
            input_fn,
        ),
        name=_ask("Nouveau nom reel du VPC", "vpc-dev-production", input_fn),
        subnet_resource_name=_ask(
            "Nom logique Terraform du subnet existant",
            "subnet_dev_01",
            input_fn,
        ),
        subnet_name=_ask(
            "Nouveau nom reel du subnet",
            "subnet-dev-production",
            input_fn,
        ),
        cidr=_ask("Nouveau CIDR", "10.81.0.0/24", input_fn),
        region=_ask("Region", "europe-west1", input_fn),
    )
    module_path = default_module_path
    if prompt_module_path:
        module_path = _ask("Dossier Terraform cible", default_module_path, input_fn)
    return UpdateNetworkRequest(
        module_path=module_path,
        resource=resource,
        project_id=context.project_id,
    )


def ask_gcp_network_delete_parameters(
    input_fn: InputFunction = input,
    *,
    gcp_context: GCPContext | None = None,
) -> DeleteNetworkRequest:
    print("\nSuppression d'un reseau Terraform GCP\n")
    context = _resolve_gcp_context(gcp_context, input_fn)
    resource = NetworkDeleteResource(
        resource_name=_ask(
            "Nom logique Terraform du VPC a supprimer",
            "vpc_delete_test_01",
            input_fn,
        ),
        subnet_resource_name=_ask(
            "Nom logique Terraform du subnet a supprimer",
            "subnet_delete_test_01",
            input_fn,
        ),
    )
    return DeleteNetworkRequest(
        module_path=str(GCP_NETWORK_OUTPUT.resolve()),
        resource=resource,
        project_id=context.project_id,
    )


def ask_gcp_storage_parameters(
    input_fn: InputFunction = input,
    *,
    gcp_context: GCPContext | None = None,
    prompt_module_path: bool = True,
) -> CreateStorageRequest:
    default_module_path = str(GCP_STORAGE_OUTPUT.resolve())

    print("\nParametres du bucket GCS (Entree conserve la valeur proposee)\n")
    context = _resolve_gcp_context(gcp_context, input_fn)
    resource = StorageResource(
        resource_name=_ask(
            "Nom logique Terraform du bucket", "bucket_backup_01", input_fn
        ),
        name=_ask("Nom reel du bucket", "stage2026-backup-01", input_fn),
        location=_ask("Location", "EU", input_fn),
        storage_class=_ask("Storage class", "STANDARD", input_fn),
        uniform_bucket_level_access=_ask_bool(
            "Uniform bucket level access", True, input_fn
        ),
    )
    module_path = default_module_path
    if prompt_module_path:
        module_path = _ask("Dossier Terraform cible", default_module_path, input_fn)
    return CreateStorageRequest(
        module_path=module_path,
        resource=resource,
        project_id=context.project_id,
    )


def ask_gcp_storage_update_parameters(
    input_fn: InputFunction = input,
    *,
    gcp_context: GCPContext | None = None,
    prompt_module_path: bool = True,
) -> UpdateStorageRequest:
    default_module_path = str(GCP_STORAGE_OUTPUT.resolve())

    print("\nNouvelles valeurs finales du bucket GCS\n")
    context = _resolve_gcp_context(gcp_context, input_fn)
    resource = StorageResource(
        resource_name=_ask(
            "Nom logique Terraform du bucket existant",
            "bucket_test_01",
            input_fn,
        ),
        name=_ask(
            "Nouveau nom reel du bucket",
            "stage2026-storage-production-01",
            input_fn,
        ),
        location=_ask("Nouvelle location", "EU", input_fn),
        storage_class=_ask("Nouvelle storage class", "NEARLINE", input_fn),
        uniform_bucket_level_access=_ask_bool(
            "Uniform bucket level access",
            True,
            input_fn,
        ),
    )
    module_path = default_module_path
    if prompt_module_path:
        module_path = _ask("Dossier Terraform cible", default_module_path, input_fn)
    return UpdateStorageRequest(
        module_path=module_path,
        resource=resource,
        project_id=context.project_id,
    )


def ask_gcp_storage_delete_parameters(
    input_fn: InputFunction = input,
    *,
    gcp_context: GCPContext | None = None,
) -> DeleteStorageRequest:
    print("\nSuppression d'un bucket Terraform GCP\n")
    context = _resolve_gcp_context(gcp_context, input_fn)
    resource = StorageDeleteResource(
        resource_name=_ask(
            "Nom logique Terraform du bucket a supprimer",
            "bucket_delete_test_01",
            input_fn,
        ),
    )
    return DeleteStorageRequest(
        module_path=str(GCP_STORAGE_OUTPUT.resolve()),
        resource=resource,
        project_id=context.project_id,
    )


def ask_gcp_iam_parameters(
    input_fn: InputFunction = input,
    *,
    gcp_context: GCPContext | None = None,
) -> CreateIAMRequest:
    print(
        "\nParametres du compte de service GCP "
        "(Entree conserve la valeur proposee)\n"
    )
    context = _resolve_gcp_context(gcp_context, input_fn)
    resource = IAMResource(
        resource_name=_ask(
            "Nom logique Terraform du compte de service",
            "sa_app_01",
            input_fn,
        ),
        account_id=_ask("Account ID", "sa-app-01", input_fn),
        display_name=_ask(
            "Display name",
            "Service Account Application 01",
            input_fn,
        ),
        description=_ask(
            "Description",
            "Compte de service pour l'application principale",
            input_fn,
        ),
        project_id=context.project_id,
        role=_ask("Role IAM", "roles/logging.logWriter", input_fn),
    )
    return CreateIAMRequest(
        module_path=str(GCP_IAM_OUTPUT.resolve()),
        resource=resource,
        project_id=context.project_id,
    )


def ask_gcp_iam_update_parameters(
    input_fn: InputFunction = input,
    *,
    gcp_context: GCPContext | None = None,
) -> UpdateIAMRequest:
    print("\nNouvelles valeurs finales du compte de service GCP\n")
    context = _resolve_gcp_context(gcp_context, input_fn)
    print(
        "Attention : modifier Account ID peut provoquer le remplacement du "
        "compte de service lors d'un futur terraform plan/apply.\n"
    )
    resource = IAMResource(
        resource_name=_ask(
            "Nom logique Terraform du compte de service existant",
            "sa_logging_01",
            input_fn,
        ),
        account_id=_ask(
            "Nouvel Account ID",
            "sa-logging-01",
            input_fn,
        ),
        display_name=_ask(
            "Nouveau Display name",
            "Service Account Logging Production",
            input_fn,
        ),
        description=_ask(
            "Nouvelle Description",
            "Compte de service de production pour les journaux",
            input_fn,
        ),
        project_id=context.project_id,
        role=_ask(
            "Nouveau rôle IAM",
            "roles/logging.logWriter",
            input_fn,
        ),
    )
    return UpdateIAMRequest(
        module_path=str(GCP_IAM_OUTPUT.resolve()),
        resource=resource,
        project_id=context.project_id,
    )


def ask_gcp_iam_delete_parameters(
    input_fn: InputFunction = input,
    *,
    gcp_context: GCPContext | None = None,
) -> DeleteIAMRequest:
    print("\nSuppression locale d'un compte de service Terraform GCP\n")
    context = _resolve_gcp_context(gcp_context, input_fn)
    resource = IAMDeleteResource(
        resource_name=_ask(
            "Nom logique Terraform du compte de service à supprimer",
            "sa_delete_test_01",
            input_fn,
        ),
    )
    return DeleteIAMRequest(
        module_path=str(GCP_IAM_OUTPUT.resolve()),
        resource=resource,
        project_id=context.project_id,
    )
