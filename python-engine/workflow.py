"""Orchestration partagee de generation locale et de gouvernance sans deploiement."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from client_paths import build_client_module_path
from models import ClientContext
from safe_data import redact_sensitive_data


REQUEST_DIRECTORY = Path(__file__).resolve().parent / "generated_requests"


@dataclass(frozen=True)
class GenerationResult:
    request_path: Path
    generator_output: str


@dataclass(frozen=True)
class GovernedWorkflowResult:
    generation_succeeded: bool
    governance_result: object | None
    governance_skipped_reason: str | None = None


def prepare_generation_payload(
    payload: Mapping[str, Any],
    client_context: ClientContext | None,
) -> dict[str, Any]:
    """Lie une requete validee au runtime canonique, sans chemin utilisateur."""

    prepared = dict(payload)
    if client_context is None:
        return prepared
    prepared.update(client_context.context_dict())
    prepared["module_path"] = str(
        build_client_module_path(
            client_context.client_id,
            client_context.environment,
            str(prepared["provider"]),
            str(prepared["module"]),
        )
    )
    return prepared


def persist_request(
    payload: Mapping[str, Any],
    request_directory: Path = REQUEST_DIRECTORY,
) -> Path:
    """Ecrit uniquement une projection redactee dans le dossier controle."""

    request_directory.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    filename = (
        f"{payload['action']}_{payload['provider']}_{payload['module']}_{timestamp}.json"
    )
    path = request_directory / filename
    with path.open("x", encoding="utf-8") as request_file:
        json.dump(
            redact_sensitive_data(dict(payload)),
            request_file,
            ensure_ascii=False,
            indent=2,
        )
        request_file.write("\n")
    return path


def generate_request(
    payload: Mapping[str, Any],
    *,
    client_context: ClientContext | None,
    generator_fn: Callable[[Path], str],
    save_fn: Callable[[Mapping[str, Any]], Path] = persist_request,
) -> GenerationResult:
    prepared = prepare_generation_payload(payload, client_context)
    request_path = save_fn(prepared)
    output = generator_fn(request_path)
    return GenerationResult(request_path=request_path, generator_output=output)


def run_governed_workflow(
    cloud: str,
    generation_fn: Callable[[], bool],
    governance_fn: Callable[[str], object],
    *,
    credential_valid: bool = True,
) -> GovernedWorkflowResult:
    """Sequence commune CLI/Web. Ne contient ni apply, ni destroy, ni approbation."""

    generated = generation_fn()
    if generated is not True:
        return GovernedWorkflowResult(False, None, "GENERATION_NOT_RUN")
    if not credential_valid:
        return GovernedWorkflowResult(True, None, "CREDENTIAL_INVALID")
    governance_result = governance_fn(cloud)
    return GovernedWorkflowResult(True, governance_result)
