"""Validation locale et resolution ephemere des references de credentials."""

from __future__ import annotations

import configparser
import os
from dataclasses import replace
from pathlib import Path
from typing import Mapping

from cloud_runtime_models import (
    CredentialProfile,
    CredentialSourceType,
    CredentialStatus,
    CredentialValidationResult,
)


def validate_credentials(
    profile: CredentialProfile,
    *,
    environ: Mapping[str, str] | None = None,
) -> CredentialValidationResult:
    """Valide une reference localement sans lire ni afficher un secret."""

    environment = os.environ if environ is None else environ
    if profile.source_type is CredentialSourceType.FILE_REFERENCE:
        return _validate_file_reference(profile.reference)
    if profile.source_type is CredentialSourceType.ENVIRONMENT:
        try:
            names = _environment_names(profile)
        except ValueError:
            return CredentialValidationResult(
                CredentialStatus.INVALID, "CRED_ENV_REFERENCE_INVALID"
            )
        missing = [name for name in names if not environment.get(name)]
        return CredentialValidationResult(
            CredentialStatus.MISSING if missing else CredentialStatus.VALID,
            "CRED_ENV_MISSING" if missing else "CRED_VALID",
        )
    if profile.source_type is CredentialSourceType.OS_PROFILE:
        if profile.auth_mode == "ADC" and profile.reference == "application-default":
            return CredentialValidationResult(CredentialStatus.VALID, "CRED_VALID")
        return _validate_os_profile(profile)
    if profile.source_type is CredentialSourceType.EPHEMERAL_SESSION:
        if profile.auth_mode == "INSTANCE_PRINCIPAL":
            return CredentialValidationResult(CredentialStatus.VALID, "CRED_VALID")
        return CredentialValidationResult(
            CredentialStatus.UNSUPPORTED, "CRED_AUTH_MODE_UNSUPPORTED"
        )
    return CredentialValidationResult(
        CredentialStatus.UNSUPPORTED, "CRED_SOURCE_UNSUPPORTED"
    )


def resolve_credentials(
    profile: CredentialProfile,
    runtime_context: object | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Construit uniquement les overrides destines au subprocess Terraform."""

    del runtime_context
    environment = os.environ if environ is None else environ
    validation = validate_credentials(profile, environ=environment)
    if validation.status is not CredentialStatus.VALID:
        raise ValueError(validation.reason_code)

    if profile.source_type is CredentialSourceType.ENVIRONMENT:
        return {name: environment[name] for name in _environment_names(profile)}
    if profile.provider == "gcp":
        if profile.auth_mode == "ADC":
            return {}
        if profile.auth_mode in {"SERVICE_ACCOUNT_FILE", "WIF_REFERENCE"}:
            return {"GOOGLE_APPLICATION_CREDENTIALS": profile.reference}
    elif profile.provider == "oci":
        if profile.auth_mode == "INSTANCE_PRINCIPAL":
            return {"OCI_AUTH": "InstancePrincipal"}
        if profile.auth_mode in {"API_KEY_PROFILE", "SECURITY_TOKEN_PROFILE"}:
            overrides = {"OCI_CONFIG_FILE": profile.reference}
            if profile.profile_name:
                overrides["OCI_CONFIG_PROFILE"] = profile.profile_name
            if profile.auth_mode == "SECURITY_TOKEN_PROFILE":
                overrides["OCI_AUTH"] = "SecurityToken"
            return overrides
    raise ValueError("CRED_AUTH_MODE_UNSUPPORTED")


def with_validation_status(
    profile: CredentialProfile,
    *,
    environ: Mapping[str, str] | None = None,
) -> CredentialProfile:
    result = validate_credentials(profile, environ=environ)
    return replace(profile, status=result.status)


def _validate_file_reference(reference: str) -> CredentialValidationResult:
    path = Path(reference).expanduser()
    if not path.is_absolute() or ".." in path.parts:
        return CredentialValidationResult(CredentialStatus.INVALID, "CRED_FILE_UNSAFE")
    if not path.is_file():
        return CredentialValidationResult(CredentialStatus.MISSING, "CRED_FILE_NOT_FOUND")
    try:
        with path.open("rb"):
            pass
    except OSError:
        return CredentialValidationResult(CredentialStatus.INVALID, "CRED_FILE_NOT_READABLE")
    return CredentialValidationResult(CredentialStatus.VALID, "CRED_VALID")


def _validate_os_profile(profile: CredentialProfile) -> CredentialValidationResult:
    path_result = _validate_file_reference(profile.reference)
    if path_result.status is not CredentialStatus.VALID:
        return CredentialValidationResult(
            path_result.status,
            "CRED_PROFILE_NOT_FOUND",
        )
    if not profile.profile_name:
        return CredentialValidationResult(CredentialStatus.MISSING, "CRED_PROFILE_NOT_FOUND")
    parser = configparser.ConfigParser()
    try:
        parser.read(profile.reference, encoding="utf-8")
    except (OSError, configparser.Error):
        return CredentialValidationResult(CredentialStatus.INVALID, "CRED_PROFILE_INVALID")
    if profile.profile_name not in parser.sections():
        return CredentialValidationResult(CredentialStatus.MISSING, "CRED_PROFILE_NOT_FOUND")
    return CredentialValidationResult(CredentialStatus.VALID, "CRED_VALID")


def _environment_names(profile: CredentialProfile) -> tuple[str, ...]:
    raw = profile.metadata.get("required_env_vars", ())
    if isinstance(raw, str):
        names = (raw,)
    else:
        names = tuple(raw) if isinstance(raw, (list, tuple)) else ()
    if not names and profile.reference:
        names = tuple(item.strip() for item in profile.reference.split(",") if item.strip())
    if not names or any(not name.replace("_", "").isalnum() for name in names):
        raise ValueError("CRED_ENV_REFERENCE_INVALID")
    return names
