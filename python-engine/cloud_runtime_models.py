"""Modeles non sensibles pour credentials et state multi-cloud."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class CredentialSourceType(str, Enum):
    ENVIRONMENT = "ENVIRONMENT"
    FILE_REFERENCE = "FILE_REFERENCE"
    OS_PROFILE = "OS_PROFILE"
    EPHEMERAL_SESSION = "EPHEMERAL_SESSION"


class CredentialStatus(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    MISSING = "MISSING"
    UNSUPPORTED = "UNSUPPORTED"


GCP_AUTH_MODES = frozenset({"ADC", "SERVICE_ACCOUNT_FILE", "WIF_REFERENCE"})
OCI_AUTH_MODES = frozenset(
    {"API_KEY_PROFILE", "INSTANCE_PRINCIPAL", "SECURITY_TOKEN_PROFILE"}
)


@dataclass(frozen=True)
class CredentialProfile:
    credential_id: str
    provider: str
    auth_mode: str
    source_type: CredentialSourceType
    reference: str
    profile_name: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    status: CredentialStatus = CredentialStatus.MISSING

    def __post_init__(self) -> None:
        if self.provider not in {"gcp", "oci"}:
            raise ValueError(f"credential provider non supporte : {self.provider!r}")
        if not self.credential_id or not isinstance(self.credential_id, str):
            raise ValueError("credential_id est obligatoire")
        allowed = GCP_AUTH_MODES if self.provider == "gcp" else OCI_AUTH_MODES
        if self.auth_mode not in allowed:
            raise ValueError("CRED_AUTH_MODE_UNSUPPORTED")
        if not isinstance(self.source_type, CredentialSourceType):
            raise ValueError("credential source_type non supporte")
        if not isinstance(self.reference, str):
            raise ValueError("credential reference doit etre une chaine")


@dataclass(frozen=True)
class CredentialValidationResult:
    status: CredentialStatus
    reason_code: str


@dataclass(frozen=True)
class StateProfile:
    state_profile_id: str
    provider: str
    backend_type: str
    bucket: str | None = None
    prefix_key: str | None = None
    region: str | None = None
    namespace: str | None = None
    credential_profile: str | None = None
    locking_expected: bool = True
    versioning_expected: bool = True

    def __post_init__(self) -> None:
        if self.provider not in {"gcp", "oci"}:
            raise ValueError(f"state provider non supporte : {self.provider!r}")
        allowed = {"gcp": {"gcs", "local"}, "oci": {"oci", "local"}}
        if self.backend_type not in allowed[self.provider]:
            raise ValueError(
                f"backend_type {self.backend_type!r} invalide pour {self.provider}"
            )
        if not self.state_profile_id:
            raise ValueError("state_profile_id est obligatoire")
