"""Services minces entre les formulaires Web et le moteur existant."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from app_governance import run_governance_after_generation
from catalog import CatalogError, CatalogLoader, InfrastructureTemplate
from client_config import (
    ClientRuntimeSelection,
    discover_client_config,
    load_client_config,
    select_runtime_configuration,
)
from client_context import validate_client_context
from go_client import GoClientError, run_generator
from models import ClientContext
from request_builder import build_create_request_from_parameters, default_module_path
from safe_data import redact_sensitive_data
from state_config import detect_terraform_version, write_backend_runtime_files
from validators import validate_request
from workflow import generate_request, run_governed_workflow


PROJECT_ROOT = Path(__file__).resolve().parents[2]
_REPORT_ROOTS = {
    "security": (PROJECT_ROOT / "artifacts" / "security" / "reports").resolve(),
    "policy": (PROJECT_ROOT / "artifacts" / "policy" / "reports").resolve(),
    "governance": (PROJECT_ROOT / "artifacts" / "governance" / "reports").resolve(),
}
_REPORT_ID = re.compile(r"\A[a-z0-9_-]+\Z")
_SENSITIVE_TEXT = re.compile(
    r"(?:password|secret|token|private[_ -]?key|credentials|client[_ -]?secret)",
    re.IGNORECASE,
)


class WebServiceError(ValueError):
    pass


@dataclass(frozen=True)
class WebExecutionResult:
    view: Mapping[str, Any]


def _value(value: object | None, default: str = "SKIPPED") -> str:
    if value is None:
        return default
    return str(getattr(value, "value", value))


class WebOrchestrationService:
    def __init__(self, catalog_loader: CatalogLoader | None = None) -> None:
        self.catalog = catalog_loader or CatalogLoader()

    def load_runtime(
        self,
        client_id: str,
        environment: str,
        provider: str,
    ) -> ClientRuntimeSelection:
        validate_client_context(client_id, environment)
        if provider not in {"gcp", "oci"}:
            raise WebServiceError("Provider must be gcp or oci.")
        path = discover_client_config(client_id)
        if path is None:
            raise WebServiceError("Client configuration not found.")
        config = load_client_config(path, runtime_client_id=client_id)
        return select_runtime_configuration(
            config,
            environment,
            provider,
            terraform_version=detect_terraform_version(),
        )

    def safe_runtime_view(self, selection: ClientRuntimeSelection) -> dict[str, Any]:
        cloud_target = (
            selection.cloud.get("project_id")
            if selection.provider == "gcp"
            else selection.cloud.get("compartment_ocid")
        )
        target_label = "Project ID" if selection.provider == "gcp" else "Compartment OCID"
        safe = {
            "client_id": selection.client_id,
            "environment": selection.environment,
            "provider": selection.provider,
            "target_label": target_label,
            "cloud_target": cloud_target,
            "region": selection.cloud.get("default_region") or selection.cloud.get("region"),
            "zone": selection.cloud.get("default_zone"),
            "credential_profile_id": selection.credential_profile.credential_id,
            "credential_mode": selection.credential_profile.auth_mode,
            "credential_status": selection.credential_status,
            "credential_reason": selection.credential_reason_code,
            "state_profile_id": selection.state_profile.state_profile_id,
            "state_mode": selection.state_mode,
            "backend_type": selection.backend.backend_type,
            "state_identity": selection.state_identity,
        }
        return dict(redact_sensitive_data(safe))

    def validate_parameters(
        self,
        template: InfrastructureTemplate,
        submitted: Mapping[str, Any],
    ) -> dict[str, Any]:
        allowed = set(template.parameter_names)
        unknown = set(submitted) - allowed
        if unknown:
            raise WebServiceError("Unknown infrastructure parameter.")
        values = dict(template.defaults)
        values.update(template.security_defaults)
        for name in template.parameter_names:
            if name not in submitted:
                continue
            raw = submitted[name]
            if isinstance(values.get(name), bool):
                values[name] = self._boolean(raw, name)
            elif not isinstance(raw, str) or not raw.strip():
                raise WebServiceError(f"Parameter {name} is invalid.")
            else:
                values[name] = raw.strip()
        missing = [
            name
            for name in template.required_parameters
            if name not in values or not str(values[name]).strip()
        ]
        if missing:
            raise WebServiceError(f"Missing required parameters: {', '.join(missing)}")
        return values

    def execute(
        self,
        selection: ClientRuntimeSelection,
        template_id: str,
        submitted: Mapping[str, Any],
    ) -> WebExecutionResult:
        template = self.catalog.get(template_id)
        if template.provider != selection.provider:
            raise WebServiceError("Template provider does not match client provider.")
        parameters = self.validate_parameters(template, submitted)
        requests = self._build_requests(selection, template, parameters)
        for _, request_model in requests:
            validate_request(request_model)
        write_backend_runtime_files(
            selection.backend,
            selection.client_id,
            selection.environment,
            selection.provider,
        )
        component_views: list[dict[str, Any]] = []
        for component_template, request_model in requests:
            def generate() -> bool:
                generate_request(
                    request_model.to_dict(),
                    client_context=ClientContext(
                        client_id=selection.client_id,
                        environment=selection.environment,
                    ),
                    generator_fn=run_generator,
                )
                return True

            try:
                governed = run_governed_workflow(
                    selection.provider,
                    generate,
                    run_governance_after_generation,
                    credential_valid=selection.credential_status == "VALID",
                )
            except GoClientError as exc:
                raise WebServiceError(
                    "Generation failed: the existing Go generator rejected the request."
                ) from exc
            component_views.append(
                self._safe_result_view(
                    governed.governance_result,
                    component_template,
                    generation_succeeded=governed.generation_succeeded,
                    skipped_reason=governed.governance_skipped_reason,
                )
            )
        final = dict(component_views[-1])
        final.update(
            {
                "client": selection.client_id,
                "environment": selection.environment,
                "provider": selection.provider,
                "template": template.template_id,
                "components": component_views,
                "apply": "NOT EXECUTED",
                "destroy": "NOT EXECUTED",
            }
        )
        return WebExecutionResult(view=dict(redact_sensitive_data(final)))

    def _build_requests(
        self,
        selection: ClientRuntimeSelection,
        template: InfrastructureTemplate,
        parameters: Mapping[str, Any],
    ) -> list[tuple[InfrastructureTemplate, Any]]:
        targets: list[tuple[InfrastructureTemplate, Mapping[str, Any]]] = []
        if template.components:
            for component in template.components:
                component_template = self.catalog.get(component.template_id)
                component_values = {
                    key.removeprefix(component.parameter_prefix): value
                    for key, value in parameters.items()
                    if key.startswith(component.parameter_prefix)
                }
                targets.append((component_template, component_values))
        else:
            targets.append((template, parameters))
        requests = []
        for component_template, values in targets:
            validated = self.validate_parameters(component_template, values)
            module_path = default_module_path(
                selection.provider,
                component_template.module,
            )
            request_model = build_create_request_from_parameters(
                provider=selection.provider,
                module=component_template.module,
                parameters=validated,
                cloud=selection.cloud,
                client_id=selection.client_id,
                environment=selection.environment,
                module_path=module_path,
            )
            requests.append((component_template, request_model))
        return requests

    def _safe_result_view(
        self,
        result: object | None,
        template: InfrastructureTemplate,
        *,
        generation_succeeded: bool,
        skipped_reason: str | None,
    ) -> dict[str, Any]:
        policy = getattr(result, "policy_pipeline_result", None)
        security = getattr(policy, "security_pipeline_result", None)
        terraform = getattr(security, "terraform_result", None)
        terraform_report = getattr(terraform, "report", None)
        decision = getattr(policy, "policy_decision", None)
        security_report = getattr(security, "security_report", None)
        findings = []
        for finding in getattr(security_report, "findings", ()):
            findings.append(
                {
                    "severity": _value(getattr(finding, "severity", None)),
                    "status": _value(getattr(finding, "status", None)),
                    "resource": getattr(finding, "resource_address", "unknown"),
                    "explanation": getattr(finding, "message", "Unavailable"),
                }
            )
        governance_status = getattr(result, "governance_status", None)
        return {
            "template": template.template_id,
            "module": template.module,
            "generation": "PASS" if generation_succeeded else "ERROR",
            "terraform_status": _value(getattr(result, "terraform_final_status", None)),
            "fmt_status": _value(getattr(terraform_report, "fmt_status", None)),
            "init_status": _value(getattr(terraform_report, "init_status", None)),
            "validate_status": _value(getattr(terraform_report, "validate_status", None)),
            "plan_status": _value(getattr(terraform_report, "plan_status", None)),
            "add_count": getattr(terraform_report, "add_count", None),
            "change_count": getattr(terraform_report, "change_count", None),
            "destroy_count": getattr(terraform_report, "destroy_count", None),
            "security_status": _value(getattr(result, "security_evaluation_status", None)),
            "findings": findings,
            "policy_profile": _value(getattr(decision, "profile", None)),
            "policy_decision": _value(getattr(decision, "decision", None)),
            "policy_reason": _value(getattr(decision, "reason_code", None)),
            "approval_status": _value(getattr(result, "approval_status", None)),
            "authorization_status": _value(getattr(result, "authorization_status", None)),
            "governance_status": _value(governance_status),
            "skipped_reason": skipped_reason,
        }

    @staticmethod
    def _boolean(value: object, field: str) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.strip().casefold()
            if lowered in {"true", "1", "yes", "on"}:
                return True
            if lowered in {"false", "0", "no", "off"}:
                return False
        raise WebServiceError(f"Parameter {field} must be a boolean.")


class ReportService:
    def list_reports(self) -> list[dict[str, Any]]:
        reports: list[dict[str, Any]] = []
        for report_type, root in _REPORT_ROOTS.items():
            if not root.is_dir():
                continue
            for path in sorted(root.glob("*.json"), reverse=True):
                try:
                    raw = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                reports.append(
                    {
                        "id": path.stem,
                        "type": report_type,
                        "timestamp": raw.get("generated_at", "Unknown"),
                        "provider": raw.get("cloud", "Unknown"),
                        "status": self._status(raw, report_type),
                    }
                )
        return reports

    def read_report(self, report_type: str, report_id: str) -> Mapping[str, Any]:
        if report_type not in _REPORT_ROOTS or not _REPORT_ID.fullmatch(report_id):
            raise WebServiceError("Report identifier is invalid.")
        root = _REPORT_ROOTS[report_type]
        path = (root / f"{report_id}.json").resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise WebServiceError("Report path is outside the reports root.") from exc
        if not path.is_file():
            raise WebServiceError("Report not found.")
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise WebServiceError("Report is not readable.") from exc
        return self._sanitize_report(redact_sensitive_data(raw))

    def _sanitize_report(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: self._sanitize_report(item)
                for key, item in value.items()
                if key not in {"working_directory"}
                and not key.casefold().endswith("_path")
            }
        if isinstance(value, list):
            return [self._sanitize_report(item) for item in value]
        if isinstance(value, str) and _SENSITIVE_TEXT.search(value):
            return "********"
        return value

    @staticmethod
    def _status(raw: Mapping[str, Any], report_type: str) -> str:
        candidates = {
            "security": ("evaluation_status", "scan_status"),
            "policy": ("decision", "status"),
            "governance": ("governance_status", "authorization_status", "status"),
        }[report_type]
        for key in candidates:
            value = raw.get(key)
            if isinstance(value, str):
                return "********" if _SENSITIVE_TEXT.search(value) else value
            if isinstance(value, dict):
                for nested in ("decision", "status", "authorization_status"):
                    if isinstance(value.get(nested), str):
                        return value[nested]
        return "Unknown"
