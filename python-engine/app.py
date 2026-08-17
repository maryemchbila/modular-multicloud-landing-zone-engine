"""Point d'entree interactif du moteur Python."""

import json
import sys
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from app_governance import run_governance_after_generation
from go_client import GoClientError, run_generator
from models import GCPContext
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
from validators import ValidationError, validate_request


REQUEST_DIRECTORY = Path(__file__).resolve().parent / "generated_requests"


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
    REQUEST_DIRECTORY.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    filename = (
        f"{payload['action']}_{payload['provider']}_{payload['module']}_{timestamp}.json"
    )
    path = REQUEST_DIRECTORY / filename
    with path.open("x", encoding="utf-8") as request_file:
        json.dump(payload, request_file, ensure_ascii=False, indent=2)
        request_file.write("\n")
    return path


def _generate(payload: dict) -> bool:
    request_path = save_request(payload)
    print(f"\nRequete valide sauvegardee : {request_path}")
    print("Appel du generateur Go...")
    output = run_generator(request_path)
    if output:
        print(f"\n{output}")
    return True


def create_gcp_compute(*, gcp_context: GCPContext | None = None) -> bool:
    request = build_request(gcp_context=gcp_context)
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
    request = ask_gcp_network_parameters(gcp_context=gcp_context)
    validate_request(request)
    return _generate(request.to_dict())


def update_gcp_compute(*, gcp_context: GCPContext | None = None) -> bool:
    request = ask_gcp_compute_update_parameters(gcp_context=gcp_context)
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
    request = ask_gcp_network_update_parameters(gcp_context=gcp_context)
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
    request = ask_gcp_storage_parameters(gcp_context=gcp_context)
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
    request = ask_gcp_storage_update_parameters(gcp_context=gcp_context)
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
        gcp_context = None
        if provider == "gcp":
            gcp_context = ask_gcp_context()
            print(f"\nProjet GCP cible : {gcp_context.project_id}")
        module = choose_module()
        action = choose_action()
        generation_succeeded = dispatch(
            provider,
            module,
            action,
            gcp_context=gcp_context,
        )
        if generation_succeeded is not True:
            print("\nGeneration : NOT_RUN")
            print("Governance : NOT_RUN")
            return 0
        run_governance_after_generation(provider)
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
