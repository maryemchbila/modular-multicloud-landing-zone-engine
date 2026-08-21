"""Point d'entree interactif du moteur Python."""

import sys
from collections.abc import Callable
from contextvars import ContextVar
from pathlib import Path

from app_governance import run_governance_after_generation
from client_context import ClientContextError, validate_client_context
from client_config import (
    ClientRuntimeSelection,
    discover_client_config,
    load_client_config,
    select_runtime_configuration,
)
from go_client import GoClientError, run_generator
from models import ClientContext, GCPContext
from request_builder import (
    ask_gcp_context,
    ask_gcp_compute_delete_parameters,
    ask_gcp_compute_update_parameters,
    ask_gcp_iam_parameters,
    ask_gcp_iam_delete_parameters,
    ask_gcp_iam_update_parameters,
    ask_gcp_network_delete_parameters,
    ask_gcp_network_parameters,
    ask_gcp_network_update_parameters,
    ask_gcp_storage_parameters,
    ask_gcp_storage_delete_parameters,
    ask_gcp_storage_update_parameters,
    ask_oci_compute_delete_parameters,
    ask_oci_compute_parameters,
    ask_oci_compute_update_parameters,
    ask_oci_iam_create_parameters,
    ask_oci_iam_delete_parameters,
    ask_oci_iam_update_parameters,
    ask_oci_network_parameters,
    ask_oci_network_delete_parameters,
    ask_oci_network_update_parameters,
    ask_oci_storage_parameters,
    ask_oci_storage_delete_parameters,
    ask_oci_storage_update_parameters,
    build_request,
)
from safe_data import redact_sensitive_data
from state_config import detect_terraform_version, write_backend_runtime_files
from validators import ValidationError, validate_request
from workflow import (
    REQUEST_DIRECTORY as SHARED_REQUEST_DIRECTORY,
    persist_request,
    generate_request,
    run_governed_workflow,
)


REQUEST_DIRECTORY = SHARED_REQUEST_DIRECTORY
ACTIVE_CLIENT_CONTEXT: ContextVar[ClientContext | None] = ContextVar(
    "active_client_context",
    default=None,
)


def _choose_option(prompt: str, options: dict[str, str], error_message: str) -> str:
    choice = input(prompt).strip()
    try:
        return options[choice]
    except KeyError as exc:
        raise ValueError(error_message) from exc


def choose_provider() -> str:
    print("Choisir un provider :")
    print("1 - GCP")
    print("2 - OCI")
    return _choose_option("Votre choix : ", {"1": "gcp", "2": "oci"}, "Choix provider invalide")


def ask_client_context() -> ClientContext:
    client_id = input("Client ID : ").strip()
    environment = input("Environment (dev/staging/prod) : ").strip()
    try:
        validate_client_context(client_id, environment)
    except ClientContextError as exc:
        raise ValueError(str(exc)) from exc
    return ClientContext(client_id=client_id, environment=environment)


def choose_module() -> str:
    print("\nChoisir un module :")
    print("1 - Compute")
    print("2 - Network")
    print("3 - Storage")
    print("4 - IAM")
    return _choose_option(
        "Votre choix : ",
        {"1": "compute", "2": "network", "3": "storage", "4": "iam"},
        "Choix module invalide",
    )


def choose_action() -> str:
    print("\nChoisir une action :")
    print("1 - Create")
    print("2 - Update")
    print("3 - Delete")
    return _choose_option(
        "Votre choix : ",
        {"1": "create", "2": "update", "3": "delete"},
        "Choix action invalide",
    )


def save_request(payload: dict) -> Path:
    """Compatibilite publique historique autour du persisteur partage."""

    return persist_request(payload, REQUEST_DIRECTORY)


def load_client_runtime(
    client_context: ClientContext,
    provider: str,
) -> ClientRuntimeSelection | None:
    """Charge une configuration si le client en possede une, sinon garde J1."""

    path = discover_client_config(client_context.client_id)
    if path is None:
        return None
    config = load_client_config(path, runtime_client_id=client_context.client_id)
    selection = select_runtime_configuration(
        config,
        client_context.environment,
        provider,
        terraform_version=detect_terraform_version(),
    )
    if not selection.backend.native_backend_available:
        raise ValueError(selection.backend.reason)
    write_backend_runtime_files(
        selection.backend,
        selection.client_id,
        selection.environment,
        selection.provider,
    )
    return selection


def print_client_runtime_summary(selection: ClientRuntimeSelection) -> None:
    """Affiche uniquement les identifiants et statuts non sensibles."""

    region = selection.cloud.get("default_region") or selection.cloud.get("region")
    target_field = (
        ("Project ID", selection.cloud.get("project_id"))
        if selection.provider == "gcp"
        else ("Compartment OCID", selection.cloud.get("compartment_ocid"))
    )
    fields = [
        ("Runtime Mode", "CONFIG_MODE"),
        ("Client", selection.client_id),
        ("Environment", selection.environment),
        ("Provider", selection.provider),
        target_field,
        ("Region", region),
        ("Credential Profile", selection.credential_profile.credential_id),
        ("Credential Mode", selection.credential_profile.auth_mode),
        ("Credential Status", selection.credential_status),
    ]
    if selection.credential_status != "VALID":
        fields.append(("Reason", selection.credential_reason_code))
    fields.extend(
        (
            ("State Mode", selection.state_mode),
            ("Backend Type", selection.backend.backend_type),
            ("State Identity", selection.state_identity),
        )
    )
    print("\n" + "=" * 60)
    print(" CLIENT CLOUD RUNTIME")
    print("=" * 60)
    for label, value in fields:
        safe = redact_sensitive_data({label: value})[label]
        print(f"{label:<23}: {safe}")
    print("=" * 60)


def _generate(payload: dict) -> bool:
    client_context = ACTIVE_CLIENT_CONTEXT.get()
    result = generate_request(
        payload,
        client_context=client_context,
        generator_fn=run_generator,
        save_fn=save_request,
    )
    print(f"\nRequete valide sauvegardee : {result.request_path}")
    print("Appel du generateur Go...")
    if result.generator_output:
        print(f"\n{result.generator_output}")
    return True


def create_gcp_compute(*, gcp_context: GCPContext | None = None) -> bool:
    request = build_request(
        gcp_context=gcp_context,
        prompt_module_path=ACTIVE_CLIENT_CONTEXT.get() is None,
    )
    validate_request(request)
    return _generate(request.to_dict())


def create_oci_compute() -> bool:
    request = ask_oci_compute_parameters()
    validate_request(request)
    if request.resource.assign_public_ip:
        print(
            "\nAvertissement sécurité : une adresse IP publique sera "
            "attribuée à l'instance OCI."
        )
    return _generate(request.to_dict())


def create_oci_iam() -> bool:
    request = ask_oci_iam_create_parameters()
    validate_request(request)
    return _generate(request.to_dict())


def update_oci_iam() -> bool:
    request = ask_oci_iam_update_parameters()
    validate_request(request)
    return _generate(request.to_dict())


def delete_oci_iam(input_fn=input) -> bool:
    request = ask_oci_iam_delete_parameters(input_fn)
    validate_request(request)
    resource = request.resource

    print("\nLes ressources Terraform locales suivantes seront supprimees :\n")
    print(
        "oci_identity_user_group_membership."
        f"{resource.membership_resource_name}"
    )
    print(f"oci_identity_policy.{resource.policy_resource_name}")
    print(f"oci_identity_user.{resource.user_resource_name}")
    print(f"oci_identity_group.{resource.group_resource_name}\n")
    print(
        "Les variables, tfvars et outputs associes seront egalement "
        "supprimes.\n"
    )
    print(
        "Aucune identite ou politique OCI reelle ne sera detruite "
        "automatiquement.\n"
    )
    confirmation = input_fn(
        "Confirmer la suppression de l'ensemble IAM complet ? [y/N] : "
    ).strip().lower()
    if confirmation not in {"y", "yes", "oui", "o"}:
        print("Suppression annulee.")
        return False

    _generate(request.to_dict())
    print(
        "\nTerraform OCI IAM code deleted locally. "
        "No OCI identity or policy was destroyed."
    )
    return True


def create_oci_network() -> bool:
    request = ask_oci_network_parameters()
    validate_request(request)
    if not request.resource.prohibit_public_ip_on_vnic:
        print(
            "\nAvertissement sécurité : le subnet autorise "
            "potentiellement des IP publiques sur les VNIC."
        )
    return _generate(request.to_dict())


def create_oci_storage() -> bool:
    request = ask_oci_storage_parameters()
    validate_request(request)
    if request.resource.access_type in {
        "ObjectRead",
        "ObjectReadWithoutList",
    }:
        print(
            "\nAvertissement sécurité : le bucket OCI autorise un accès "
            "public en lecture."
        )
    if request.resource.versioning == "Disabled":
        print(
            "\nAvertissement sécurité : le versioning du bucket OCI est "
            "désactivé."
        )
    return _generate(request.to_dict())


def update_oci_storage() -> bool:
    request = ask_oci_storage_update_parameters()
    validate_request(request)
    if request.resource.access_type in {
        "ObjectRead",
        "ObjectReadWithoutList",
    }:
        print(
            "\nAvertissement sécurité : le bucket OCI autorise un accès "
            "public en lecture."
        )
    if request.resource.versioning == "Disabled":
        print(
            "\nAvertissement sécurité : le versioning du bucket OCI est "
            "désactivé."
        )
    return _generate(request.to_dict())


def delete_oci_storage(input_fn=input) -> bool:
    request = ask_oci_storage_delete_parameters(input_fn)
    validate_request(request)

    resource_name = request.resource.resource_name
    print("\nLa ressource Terraform locale suivante sera supprimée :\n")
    print(f"oci_objectstorage_bucket.{resource_name}\n")
    print(
        "Les variables, tfvars et outputs associés seront également "
        "supprimés.\n"
    )
    print(
        "Aucun bucket OCI réel ne sera détruit automatiquement.\n"
    )
    confirmation = input_fn(
        "Confirmer la suppression ? [y/N] : "
    ).strip().lower()
    if confirmation not in {"y", "yes", "oui", "o"}:
        print("Suppression annulée.")
        return False

    _generate(request.to_dict())
    print(
        "\nTerraform OCI Storage code deleted locally. "
        "No OCI bucket was destroyed."
    )
    return True


def update_oci_network() -> bool:
    request = ask_oci_network_update_parameters()
    validate_request(request)
    if not request.resource.prohibit_public_ip_on_vnic:
        print(
            "\nAvertissement sécurité : le subnet autorise "
            "potentiellement des adresses IP publiques sur ses VNIC."
        )
    return _generate(request.to_dict())


def delete_oci_network(input_fn=input) -> bool:
    request = ask_oci_network_delete_parameters(input_fn)
    validate_request(request)

    resource = request.resource
    print("\nLes ressources Terraform locales suivantes seront supprimées :\n")
    print(f"oci_core_subnet.{resource.subnet_resource_name}")
    print(f"oci_core_route_table.{resource.route_table_resource_name}")
    print(
        "oci_core_internet_gateway."
        f"{resource.internet_gateway_resource_name}"
    )
    print(f"oci_core_vcn.{resource.resource_name}\n")
    print(
        "Aucune ressource OCI réelle ne sera détruite automatiquement.\n"
    )
    confirmation = input_fn(
        "Confirmer la suppression du réseau complet ? [y/N] : "
    ).strip().lower()
    if confirmation not in {"y", "yes", "oui", "o"}:
        print("Suppression annulée.")
        return False

    _generate(request.to_dict())
    print(
        "\nTerraform OCI Network code deleted locally. "
        "No OCI network resource was destroyed."
    )
    return True


def update_oci_compute() -> bool:
    request = ask_oci_compute_update_parameters()
    validate_request(request)
    if request.resource.assign_public_ip:
        print(
            "\nAvertissement sécurité : une adresse IP publique sera "
            "configurée sur l’instance OCI."
        )
    return _generate(request.to_dict())


def delete_oci_compute(input_fn=input) -> bool:
    request = ask_oci_compute_delete_parameters(input_fn)
    validate_request(request)

    resource_name = request.resource.resource_name
    print("\nLa ressource Terraform locale suivante sera supprimée :")
    print(f"\noci_core_instance.{resource_name}\n")
    print("Aucune instance OCI réelle ne sera détruite automatiquement.\n")
    confirmation = input_fn("Confirmer la suppression ? [y/N] : ").strip().lower()
    if confirmation not in {"y", "yes", "oui", "o"}:
        print("Suppression annulée.")
        return False

    _generate(request.to_dict())
    print(
        "\nTerraform OCI Compute code deleted locally. "
        "No cloud instance was destroyed."
    )
    return True


def create_gcp_network(*, gcp_context: GCPContext | None = None) -> bool:
    request = ask_gcp_network_parameters(
        gcp_context=gcp_context,
        prompt_module_path=ACTIVE_CLIENT_CONTEXT.get() is None,
    )
    validate_request(request)
    return _generate(request.to_dict())


def update_gcp_compute(*, gcp_context: GCPContext | None = None) -> bool:
    request = ask_gcp_compute_update_parameters(
        gcp_context=gcp_context,
        prompt_module_path=ACTIVE_CLIENT_CONTEXT.get() is None,
    )
    validate_request(request)
    return _generate(request.to_dict())


def delete_gcp_compute(
    input_fn=input,
    *,
    gcp_context: GCPContext | None = None,
) -> bool:
    request = ask_gcp_compute_delete_parameters(
        input_fn,
        gcp_context=gcp_context,
    )
    validate_request(request)

    resource_name = request.resource.resource_name
    print("\nLa ressource Terraform suivante sera supprimee :")
    print(f"\ngoogle_compute_instance.{resource_name}\n")
    confirmation = input_fn("Confirmer la suppression ? [y/N] : ").strip().lower()
    if confirmation not in {"y", "yes", "oui", "o"}:
        print("Suppression annulée.")
        return False

    return _generate(request.to_dict())


def update_gcp_network(*, gcp_context: GCPContext | None = None) -> bool:
    request = ask_gcp_network_update_parameters(
        gcp_context=gcp_context,
        prompt_module_path=ACTIVE_CLIENT_CONTEXT.get() is None,
    )
    validate_request(request)
    return _generate(request.to_dict())


def delete_gcp_network(
    input_fn=input,
    *,
    gcp_context: GCPContext | None = None,
) -> bool:
    request = ask_gcp_network_delete_parameters(
        input_fn,
        gcp_context=gcp_context,
    )
    validate_request(request)

    resource = request.resource
    print("\nLes ressources Terraform suivantes seront supprimees :")
    print(
        f"\ngoogle_compute_subnetwork.{resource.subnet_resource_name}"
        f"\ngoogle_compute_network.{resource.resource_name}\n"
    )
    confirmation = input_fn(
        "Confirmer la suppression du reseau complet ? [y/N] : "
    ).strip().lower()
    if confirmation not in {"y", "yes", "oui", "o"}:
        print("Suppression annulée.")
        return False

    return _generate(request.to_dict())


def create_gcp_storage(*, gcp_context: GCPContext | None = None) -> bool:
    request = ask_gcp_storage_parameters(
        gcp_context=gcp_context,
        prompt_module_path=ACTIVE_CLIENT_CONTEXT.get() is None,
    )
    validate_request(request)
    return _generate(request.to_dict())


def create_gcp_iam(*, gcp_context: GCPContext | None = None) -> bool:
    request = ask_gcp_iam_parameters(gcp_context=gcp_context)
    validate_request(request)
    return _generate(request.to_dict())


def update_gcp_iam(*, gcp_context: GCPContext | None = None) -> bool:
    request = ask_gcp_iam_update_parameters(gcp_context=gcp_context)
    validate_request(request)
    return _generate(request.to_dict())


def delete_gcp_iam(
    input_fn=input,
    *,
    gcp_context: GCPContext | None = None,
) -> bool:
    request = ask_gcp_iam_delete_parameters(
        input_fn,
        gcp_context=gcp_context,
    )
    validate_request(request)

    resource_name = request.resource.resource_name
    print("\nLes ressources Terraform locales suivantes seront supprimées :")
    print(f"\ngoogle_project_iam_member.{resource_name}_role")
    print(f"google_service_account.{resource_name}\n")
    print("Aucune ressource cloud ne sera supprimée automatiquement.\n")
    confirmation = input_fn("Confirmer la suppression ? [y/N] : ").strip().lower()
    if confirmation not in {"y", "yes", "oui", "o"}:
        print("Suppression annulée.")
        return False

    _generate(request.to_dict())
    print("\nTerraform IAM code deleted locally. No cloud identity was destroyed.")
    return True


def update_gcp_storage(*, gcp_context: GCPContext | None = None) -> bool:
    request = ask_gcp_storage_update_parameters(
        gcp_context=gcp_context,
        prompt_module_path=ACTIVE_CLIENT_CONTEXT.get() is None,
    )
    validate_request(request)
    return _generate(request.to_dict())


def delete_gcp_storage(
    input_fn=input,
    *,
    gcp_context: GCPContext | None = None,
) -> bool:
    request = ask_gcp_storage_delete_parameters(
        input_fn,
        gcp_context=gcp_context,
    )
    validate_request(request)

    resource_name = request.resource.resource_name
    print("\nLa ressource Terraform suivante sera supprimée localement :")
    print(f"\ngoogle_storage_bucket.{resource_name}\n")
    print("Aucune ressource cloud ne sera détruite automatiquement.\n")
    confirmation = input_fn("Confirmer la suppression ? [y/N] : ").strip().lower()
    if confirmation not in {"y", "yes", "oui", "o"}:
        print("Suppression annulée.")
        return False

    _generate(request.to_dict())
    print("\nTerraform code deleted locally. No cloud resource was destroyed.")
    return True


def dispatch(
    provider: str,
    module: str,
    action: str,
    *,
    gcp_context: GCPContext | None = None,
) -> bool:
    handlers: dict[tuple[str, str, str], Callable[..., bool]] = {
        ("oci", "compute", "create"): create_oci_compute,
        ("oci", "compute", "update"): update_oci_compute,
        ("oci", "compute", "delete"): delete_oci_compute,
        ("oci", "network", "create"): create_oci_network,
        ("oci", "network", "update"): update_oci_network,
        ("oci", "network", "delete"): delete_oci_network,
        ("oci", "storage", "create"): create_oci_storage,
        ("oci", "storage", "update"): update_oci_storage,
        ("oci", "storage", "delete"): delete_oci_storage,
        ("oci", "iam", "create"): create_oci_iam,
        ("oci", "iam", "update"): update_oci_iam,
        ("oci", "iam", "delete"): delete_oci_iam,
        ("gcp", "compute", "create"): create_gcp_compute,
        ("gcp", "compute", "update"): update_gcp_compute,
        ("gcp", "compute", "delete"): delete_gcp_compute,
        ("gcp", "network", "create"): create_gcp_network,
        ("gcp", "network", "update"): update_gcp_network,
        ("gcp", "network", "delete"): delete_gcp_network,
        ("gcp", "storage", "create"): create_gcp_storage,
        ("gcp", "storage", "update"): update_gcp_storage,
        ("gcp", "storage", "delete"): delete_gcp_storage,
        ("gcp", "iam", "create"): create_gcp_iam,
        ("gcp", "iam", "update"): update_gcp_iam,
        ("gcp", "iam", "delete"): delete_gcp_iam,
    }
    handler = handlers.get((provider, module, action))
    if handler is not None:
        if provider == "gcp" and gcp_context is not None:
            return handler(gcp_context=gcp_context)
        return handler()
    print(f"Fonctionnalité non encore implémentée : {provider} / {module} / {action}")
    return False


def main() -> int:
    try:
        print("===============================")
        print(" Multi-Cloud Automation Engine")
        print("===============================\n")
        provider = choose_provider()
        client_context = ask_client_context()
        client_runtime = load_client_runtime(client_context, provider)
        gcp_context = None
        if client_runtime is not None:
            if provider == "gcp":
                gcp_context = GCPContext(str(client_runtime.cloud["project_id"]))
            print_client_runtime_summary(client_runtime)
            if client_runtime.credential_status != "VALID":
                print(
                    "Credential validation failed: offline HCL generation remains "
                    "available; Terraform governance will not run."
                )
        else:
            print("\nRuntime Mode           : LEGACY_MANUAL_MODE")
            if provider == "gcp":
                gcp_context = ask_gcp_context()
        if provider == "gcp" and gcp_context is not None:
            print(f"\nProjet GCP cible : {gcp_context.project_id}")
        module = choose_module()
        action = choose_action()
        def generate_selected_request() -> bool:
            context_token = ACTIVE_CLIENT_CONTEXT.set(client_context)
            try:
                return dispatch(
                    provider,
                    module,
                    action,
                    gcp_context=gcp_context,
                )
            finally:
                ACTIVE_CLIENT_CONTEXT.reset(context_token)

        workflow_result = run_governed_workflow(
            provider,
            generate_selected_request,
            run_governance_after_generation,
            credential_valid=(
                client_runtime is None
                or client_runtime.credential_status == "VALID"
            ),
        )
        if not workflow_result.generation_succeeded:
            print("\nGeneration : NOT_RUN")
            print("Governance : NOT_RUN")
            return 0
        if workflow_result.governance_skipped_reason == "CREDENTIAL_INVALID":
            print("\nGovernance : NOT_RUN_CREDENTIAL_INVALID")
            return 0
        return 0
    except ValidationError as exc:
        print(f"\nParametres invalides :\n{exc}", file=sys.stderr)
    except ValueError as exc:
        print(f"\n{exc}", file=sys.stderr)
    except GoClientError as exc:
        print(f"\nErreur retournee par Go :\n{exc}", file=sys.stderr)
        print("Generation : FAIL", file=sys.stderr)
        print("Governance : NOT_RUN", file=sys.stderr)
    except (EOFError, KeyboardInterrupt):
        print("\nOperation annulee.", file=sys.stderr)
    except OSError as exc:
        print(f"\nErreur de fichier : {exc}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
