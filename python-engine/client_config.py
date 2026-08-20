"""Chargement centralise des configurations client versionnables non sensibles."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from client_context import VALID_ENVIRONMENTS, validate_client_context, validate_client_id
from client_paths import VALID_PROVIDERS
from cloud_runtime_models import CredentialProfile, CredentialSourceType, StateProfile
from credential_resolver import validate_credentials
from safe_data import is_sensitive_key
from state_config import (
    BackendRuntimeConfiguration,
    build_backend_configuration,
    build_state_identity,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CLIENT_CONFIG_ROOT = PROJECT_ROOT / "config" / "clients"
_RAW_SECRET_KEYS = frozenset(
    {
        "password",
        "secret",
        "token",
        "token_value",
        "private_key",
        "private-key",
        "private_key_content",
        "credentials",
        "api_key",
        "client_secret",
        "service_account_json",
    }
)


class ClientConfigError(ValueError):
    pass


@dataclass(frozen=True)
class ClientConfiguration:
    client_id: str
    client_name: str
    environments: Mapping[str, Mapping[str, Any]]
    clouds: Mapping[str, Mapping[str, Any]]
    credential_profiles: Mapping[str, CredentialProfile]
    state_profiles: Mapping[str, StateProfile]
    state_mode: str
    backend_profiles: Mapping[str, str]
    security: Mapping[str, Any]
    governance: Mapping[str, Any]


@dataclass(frozen=True)
class ClientRuntimeSelection:
    client_id: str
    environment: str
    provider: str
    cloud: Mapping[str, Any]
    credential_profile: CredentialProfile
    credential_status: str
    credential_reason_code: str
    state_profile: StateProfile
    state_mode: str
    state_identity: str
    backend: BackendRuntimeConfiguration


def client_config_path(client_id: str) -> Path:
    validate_client_id(client_id)
    return CLIENT_CONFIG_ROOT / f"{client_id}.yaml"


def discover_client_config(client_id: str) -> Path | None:
    """Trouve un client uniquement dans les emplacements config autorises."""

    validate_client_id(client_id)
    canonical_candidates = [
        CLIENT_CONFIG_ROOT / f"{client_id}{suffix}"
        for suffix in (".yaml", ".yml", ".json")
    ]
    existing_canonical = [path for path in canonical_candidates if path.is_file()]
    if len(existing_canonical) > 1:
        raise ClientConfigError("CLIENT_CONFIG_AMBIGUOUS")
    if existing_canonical:
        path = existing_canonical[0]
        load_client_config(path, runtime_client_id=client_id)
        return path

    examples_root = CLIENT_CONFIG_ROOT / "examples"
    if not examples_root.is_dir():
        return None
    matches: list[Path] = []
    for path in sorted(examples_root.iterdir(), key=lambda item: item.name):
        if not path.is_file() or path.suffix.casefold() not in {".yaml", ".yml", ".json"}:
            continue
        config = load_client_config(path)
        if config.client_id == client_id:
            matches.append(path.resolve())
    if len(matches) > 1:
        raise ClientConfigError("CLIENT_CONFIG_AMBIGUOUS")
    return matches[0] if matches else None


def load_client_config(
    path: str | Path,
    *,
    runtime_client_id: str | None = None,
) -> ClientConfiguration:
    """Charge JSON ou le sous-ensemble YAML documente, sans interpolation."""

    config_path = Path(path).expanduser().resolve()
    try:
        raw_text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ClientConfigError(f"CLIENT_CONFIG_NOT_READABLE: {config_path}") from exc
    try:
        raw = json.loads(raw_text, object_pairs_hook=_reject_duplicate_json_keys)
    except json.JSONDecodeError:
        raw = _parse_simple_yaml(raw_text)
    return validate_client_config(raw, runtime_client_id=runtime_client_id)


def validate_client_config(
    raw: object,
    *,
    runtime_client_id: str | None = None,
) -> ClientConfiguration:
    """Valide les references croisees et rejette toute donnee sensible brute."""

    if not isinstance(raw, dict):
        raise ClientConfigError("CLIENT_CONFIG_ROOT_INVALID")
    _reject_sensitive_fields(raw)
    client = _mapping(raw.get("client"), "client")
    client_id = _string(client.get("id"), "client.id")
    try:
        validate_client_id(client_id)
    except ValueError as exc:
        raise ClientConfigError("CLIENT_ID_INVALID") from exc
    if runtime_client_id is not None and client_id != runtime_client_id:
        raise ClientConfigError("CLIENT_ID_RUNTIME_MISMATCH")

    environments = _mapping(raw.get("environments"), "environments")
    unknown_environments = set(environments) - VALID_ENVIRONMENTS
    if unknown_environments:
        raise ClientConfigError("UNKNOWN_ENVIRONMENT")
    if not environments:
        raise ClientConfigError("ENVIRONMENTS_MISSING")
    for name, value in environments.items():
        environment = _mapping(value, f"environments.{name}")
        if not isinstance(environment.get("enabled"), bool):
            raise ClientConfigError("ENVIRONMENT_ENABLED_INVALID")

    credentials_raw = _mapping(raw.get("credential_profiles"), "credential_profiles")
    credential_profiles = {
        credential_id: _build_credential_profile(credential_id, profile)
        for credential_id, profile in credentials_raw.items()
    }
    states_raw = _mapping(raw.get("state_profiles"), "state_profiles")
    state_profiles = {
        state_id: _build_state_profile(state_id, profile)
        for state_id, profile in states_raw.items()
    }

    clouds = _mapping(raw.get("clouds"), "clouds")
    unknown_providers = set(clouds) - VALID_PROVIDERS
    if unknown_providers:
        raise ClientConfigError("UNKNOWN_PROVIDER")
    if not clouds:
        raise ClientConfigError("CLOUDS_MISSING")
    for provider, value in clouds.items():
        cloud = _mapping(value, f"clouds.{provider}")
        if not isinstance(cloud.get("enabled"), bool):
            raise ClientConfigError("CLOUD_ENABLED_INVALID")
        credential_id = _string(
            cloud.get("credential_profile"),
            f"clouds.{provider}.credential_profile",
        )
        credential = credential_profiles.get(credential_id)
        if credential is None:
            raise ClientConfigError("CREDENTIAL_PROFILE_NOT_FOUND")
        if credential.provider != provider:
            raise ClientConfigError("CREDENTIAL_PROVIDER_MISMATCH")
        required = (
            ("project_id", "default_region")
            if provider == "gcp"
            else ("region", "compartment_ocid")
        )
        for field in required:
            _string(cloud.get(field), f"clouds.{provider}.{field}")

    state = _mapping(raw.get("state"), "state")
    state_mode = _string(state.get("mode"), "state.mode").casefold()
    if state_mode not in {"local", "remote"}:
        raise ClientConfigError("STATE_MODE_INVALID")
    backend_profiles = _backend_profile_mapping(state.get("backend_profile"), clouds)
    for provider, profile_id in backend_profiles.items():
        profile = state_profiles.get(profile_id)
        if profile is None:
            raise ClientConfigError("STATE_PROFILE_NOT_FOUND")
        if profile.provider != provider:
            raise ClientConfigError("STATE_PROVIDER_MISMATCH")
        expected_backend = "local" if state_mode == "local" else {"gcp": "gcs", "oci": "oci"}[provider]
        if profile.backend_type != expected_backend:
            raise ClientConfigError("STATE_MODE_BACKEND_MISMATCH")
        if profile.credential_profile:
            state_credential = credential_profiles.get(profile.credential_profile)
            if state_credential is None:
                raise ClientConfigError("CREDENTIAL_PROFILE_NOT_FOUND")
            if state_credential.provider != provider:
                raise ClientConfigError("CREDENTIAL_PROVIDER_MISMATCH")

    return ClientConfiguration(
        client_id=client_id,
        client_name=_string(client.get("name"), "client.name"),
        environments=environments,
        clouds=clouds,
        credential_profiles=credential_profiles,
        state_profiles=state_profiles,
        state_mode=state_mode,
        backend_profiles=backend_profiles,
        security=_mapping(raw.get("security"), "security"),
        governance=_mapping(raw.get("governance"), "governance"),
    )


def select_runtime_configuration(
    config: ClientConfiguration,
    environment: str,
    provider: str,
    *,
    terraform_version: str,
) -> ClientRuntimeSelection:
    """Selectionne cloud, credential et state sans demander de secret."""

    try:
        validate_client_context(config.client_id, environment)
    except ValueError as exc:
        raise ClientConfigError("CLIENT_CONTEXT_INVALID") from exc
    if provider not in VALID_PROVIDERS:
        raise ClientConfigError("UNKNOWN_PROVIDER")
    environment_config = config.environments.get(environment)
    if not environment_config or not environment_config.get("enabled"):
        raise ClientConfigError("ENVIRONMENT_DISABLED")
    cloud = config.clouds.get(provider)
    if not cloud or not cloud.get("enabled"):
        raise ClientConfigError("CLOUD_DISABLED")
    credential_id = str(cloud["credential_profile"])
    credential = config.credential_profiles[credential_id]
    credential_validation = validate_credentials(credential)
    state_profile = config.state_profiles[config.backend_profiles[provider]]
    backend = build_backend_configuration(
        state_profile,
        config.client_id,
        environment,
        provider,
        terraform_version=terraform_version,
    )
    return ClientRuntimeSelection(
        client_id=config.client_id,
        environment=environment,
        provider=provider,
        cloud=cloud,
        credential_profile=credential,
        credential_status=credential_validation.status.value,
        credential_reason_code=credential_validation.reason_code,
        state_profile=state_profile,
        state_mode=config.state_mode,
        state_identity=build_state_identity(config.client_id, environment, provider),
        backend=backend,
    )


def _build_credential_profile(identifier: str, raw: object) -> CredentialProfile:
    profile = _mapping(raw, f"credential_profiles.{identifier}")
    try:
        source_type = CredentialSourceType(
            _string(profile.get("source_type"), "credential source_type").upper()
        )
        return CredentialProfile(
            credential_id=identifier,
            provider=_string(profile.get("provider"), "credential provider").casefold(),
            auth_mode=_string(profile.get("auth_mode"), "credential auth_mode").upper(),
            source_type=source_type,
            reference=_string(profile.get("reference"), "credential reference", allow_empty=True),
            profile_name=_optional_string(profile.get("profile_name")),
            metadata=_mapping(profile.get("metadata", {}), "credential metadata"),
        )
    except ValueError as exc:
        raise ClientConfigError(str(exc)) from exc


def _build_state_profile(identifier: str, raw: object) -> StateProfile:
    profile = _mapping(raw, f"state_profiles.{identifier}")
    allowed_fields = {
        "provider",
        "backend_type",
        "bucket",
        "region",
        "namespace",
        "credential_profile",
        "locking_expected",
        "versioning_expected",
    }
    if set(profile) - allowed_fields:
        raise ClientConfigError("STATE_PROFILE_FIELD_UNSUPPORTED")
    try:
        return StateProfile(
            state_profile_id=identifier,
            provider=_string(profile.get("provider"), "state provider").casefold(),
            backend_type=_string(profile.get("backend_type"), "backend_type").casefold(),
            bucket=_optional_string(profile.get("bucket")),
            region=_optional_string(profile.get("region")),
            namespace=_optional_string(profile.get("namespace")),
            credential_profile=_optional_string(profile.get("credential_profile")),
            locking_expected=_boolean(profile.get("locking_expected", True), "locking_expected"),
            versioning_expected=_boolean(profile.get("versioning_expected", True), "versioning_expected"),
        )
    except ValueError as exc:
        raise ClientConfigError(str(exc)) from exc


def _backend_profile_mapping(value: object, clouds: Mapping[str, Any]) -> dict[str, str]:
    enabled = {provider for provider, raw in clouds.items() if isinstance(raw, dict) and raw.get("enabled")}
    if isinstance(value, str):
        if len(enabled) != 1:
            raise ClientConfigError("STATE_PROFILE_PROVIDER_MAPPING_REQUIRED")
        return {next(iter(enabled)): _string(value, "state.backend_profile")}
    mapping = _mapping(value, "state.backend_profile")
    if set(mapping) != enabled:
        raise ClientConfigError("STATE_PROFILE_PROVIDER_MAPPING_INVALID")
    return {provider: _string(profile_id, "state backend profile") for provider, profile_id in mapping.items()}


def _reject_sensitive_fields(value: object, path: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).strip().casefold()
            current = f"{path}.{key}" if path else str(key)
            if normalized in _RAW_SECRET_KEYS or (
                is_sensitive_key(normalized)
                and normalized not in {"credential_profile", "credential_profiles"}
            ):
                raise ClientConfigError(f"SENSITIVE_FIELD_FORBIDDEN: {current}")
            _reject_sensitive_fields(item, current)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_sensitive_fields(item, f"{path}[{index}]")


def _mapping(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ClientConfigError(f"{field} doit etre un objet")
    return value


def _string(value: object, field: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise ClientConfigError(f"{field} doit etre une chaine non vide")
    return value.strip()


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    return _string(value, "optional value")


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise ClientConfigError(f"{field} doit etre booleen")
    return value


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    """Parseur volontairement limite: mappings YAML, scalaires et listes JSON."""

    tokens: list[tuple[int, str, str, int]] = []
    for line_number, original in enumerate(text.splitlines(), start=1):
        if not original.strip() or original.lstrip().startswith("#"):
            continue
        indent = len(original) - len(original.lstrip(" "))
        if "\t" in original[:indent] or indent % 2:
            raise ClientConfigError(f"YAML_INDENT_INVALID line {line_number}")
        stripped = original.strip()
        if ":" not in stripped:
            raise ClientConfigError(f"YAML_MAPPING_INVALID line {line_number}")
        key, value = stripped.split(":", 1)
        if not key.strip():
            raise ClientConfigError(f"YAML_KEY_INVALID line {line_number}")
        tokens.append((indent, key.strip(), value.strip(), line_number))
    if not tokens:
        raise ClientConfigError("CLIENT_CONFIG_EMPTY")

    def parse_block(index: int, indent: int) -> tuple[dict[str, Any], int]:
        result: dict[str, Any] = {}
        while index < len(tokens):
            current_indent, key, scalar, line_number = tokens[index]
            if current_indent < indent:
                break
            if current_indent != indent:
                raise ClientConfigError(f"YAML_INDENT_INVALID line {line_number}")
            if key in result:
                raise ClientConfigError(f"YAML_DUPLICATE_KEY: {key}")
            index += 1
            if scalar:
                result[key] = _parse_scalar(scalar, line_number)
            else:
                if index >= len(tokens) or tokens[index][0] <= indent:
                    result[key] = {}
                else:
                    result[key], index = parse_block(index, indent + 2)
        return result, index

    parsed, final_index = parse_block(0, tokens[0][0])
    if final_index != len(tokens) or tokens[0][0] != 0:
        raise ClientConfigError("YAML_ROOT_INDENT_INVALID")
    return parsed


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ClientConfigError(f"JSON_DUPLICATE_KEY: {key}")
        result[key] = value
    return result


def _parse_scalar(value: str, line_number: int) -> Any:
    lowered = value.casefold()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if lowered in {"null", "~"}:
        return None
    if value.startswith(("[", "{", '"')):
        try:
            return json.loads(value)
        except json.JSONDecodeError as exc:
            raise ClientConfigError(f"YAML_SCALAR_INVALID line {line_number}") from exc
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1].replace("''", "'")
    return value
