"""Resolution pure des chemins runtime client/environnement."""

from pathlib import Path

from client_context import validate_client_context


PROJECT_ROOT = Path(__file__).resolve().parent.parent
RUNTIME_CLIENTS_ROOT = (PROJECT_ROOT / "runtime" / "clients").resolve()
VALID_PROVIDERS = frozenset({"gcp", "oci"})
VALID_MODULES = frozenset({"compute", "network", "storage", "iam"})


class ClientPathError(ValueError):
    pass


def _validate_member(value: str, allowed: frozenset[str], field: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ClientPathError(f"{field} non supporte : {value!r}")
    return value


def _ensure_under_runtime(candidate: Path) -> Path:
    resolved = candidate.resolve()
    try:
        relative = resolved.relative_to(RUNTIME_CLIENTS_ROOT)
    except ValueError as exc:
        raise ClientPathError(
            f"chemin hors de {RUNTIME_CLIENTS_ROOT}"
        ) from exc
    if not relative.parts:
        raise ClientPathError("le chemin doit etre strictement sous runtime/clients")
    return resolved


def build_client_root(client_id: str, environment: str, provider: str) -> Path:
    validate_client_context(client_id, environment)
    provider = _validate_member(provider, VALID_PROVIDERS, "provider")
    return _ensure_under_runtime(
        RUNTIME_CLIENTS_ROOT / client_id / environment / provider
    )


def build_client_module_path(
    client_id: str,
    environment: str,
    provider: str,
    module: str,
) -> Path:
    module = _validate_member(module, VALID_MODULES, "module")
    return _ensure_under_runtime(
        build_client_root(client_id, environment, provider) / "modules" / module
    )
