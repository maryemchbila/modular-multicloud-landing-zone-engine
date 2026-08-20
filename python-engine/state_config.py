"""Isolation d'etat et generation sure de backend runtime."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Mapping

from client_context import validate_client_context
from client_paths import VALID_PROVIDERS, build_client_root
from cloud_runtime_models import StateProfile


@dataclass(frozen=True)
class BackendRuntimeConfiguration:
    backend_type: str
    state_identity: str
    backend_hcl: str
    values: Mapping[str, str]
    native_backend_available: bool = True
    reason: str = "AVAILABLE"


def build_state_identity(client_id: str, environment: str, provider: str) -> str:
    """Construit l'identite immuable client/environnement/provider."""

    validate_client_context(client_id, environment)
    if provider not in VALID_PROVIDERS:
        raise ValueError(f"provider non supporte : {provider!r}")
    return f"clients/{client_id}/{environment}/{provider}/terraform.tfstate"


def bind_state_identity(
    profile: StateProfile,
    client_id: str,
    environment: str,
    provider: str,
) -> StateProfile:
    identity = build_state_identity(client_id, environment, provider)
    prefix_key = identity.removesuffix("/terraform.tfstate") if provider == "gcp" else identity
    return replace(profile, prefix_key=prefix_key)


def supports_oci_native_backend(terraform_version: str) -> bool:
    match = re.search(r"(?:Terraform\s+v)?(\d+)\.(\d+)(?:\.\d+)?", terraform_version)
    if match is None:
        return False
    return (int(match.group(1)), int(match.group(2))) >= (1, 12)


def detect_terraform_version(terraform_binary: str = "terraform") -> str:
    """Detecte la version sans mise a niveau et sans initialiser de backend."""

    completed = subprocess.run(
        [terraform_binary, "version", "-json"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=15,
        shell=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("TERRAFORM_VERSION_UNAVAILABLE")
    try:
        return str(json.loads(completed.stdout)["terraform_version"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("TERRAFORM_VERSION_INVALID") from exc


def build_backend_configuration(
    profile: StateProfile,
    client_id: str,
    environment: str,
    provider: str,
    *,
    terraform_version: str,
) -> BackendRuntimeConfiguration:
    bound = bind_state_identity(profile, client_id, environment, provider)
    identity = build_state_identity(client_id, environment, provider)
    if profile.provider != provider:
        raise ValueError("STATE_PROVIDER_MISMATCH")
    if profile.backend_type == "local":
        return BackendRuntimeConfiguration(
            backend_type="local",
            state_identity=identity,
            backend_hcl='terraform {\n  backend "local" {}\n}\n',
            values={"path": "terraform.tfstate"},
        )
    if provider == "gcp":
        if profile.backend_type != "gcs" or not profile.bucket:
            raise ValueError("GCP_BACKEND_CONFIG_INVALID")
        return BackendRuntimeConfiguration(
            backend_type="gcs",
            state_identity=identity,
            backend_hcl='terraform {\n  backend "gcs" {}\n}\n',
            values={"bucket": profile.bucket, "prefix": bound.prefix_key or ""},
        )
    if not supports_oci_native_backend(terraform_version):
        return BackendRuntimeConfiguration(
            backend_type="oci",
            state_identity=identity,
            backend_hcl="",
            values={},
            native_backend_available=False,
            reason="TERRAFORM_VERSION_LT_1_12",
        )
    if profile.backend_type != "oci" or not all(
        (profile.bucket, profile.namespace, profile.region)
    ):
        raise ValueError("OCI_BACKEND_CONFIG_INVALID")
    return BackendRuntimeConfiguration(
        backend_type="oci",
        state_identity=identity,
        backend_hcl='terraform {\n  backend "oci" {}\n}\n',
        values={
            "bucket": profile.bucket or "",
            "namespace": profile.namespace or "",
            "region": profile.region or "",
            "key": bound.prefix_key or "",
        },
    )


def write_backend_runtime_files(
    configuration: BackendRuntimeConfiguration,
    client_id: str,
    environment: str,
    provider: str,
) -> tuple[Path, Path]:
    """Ecrit uniquement des parametres non sensibles dans la racine ignoree."""

    if not configuration.native_backend_available:
        raise RuntimeError(configuration.reason)
    root = build_client_root(client_id, environment, provider)
    root.mkdir(parents=True, exist_ok=True)
    backend_path = root / "backend.tf"
    runtime_path = root / "backend.runtime.tfbackend"
    backend_path.write_text(configuration.backend_hcl, encoding="utf-8", newline="\n")
    lines = [f'{key} = {json.dumps(value)}' for key, value in configuration.values.items()]
    runtime_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return backend_path, runtime_path
