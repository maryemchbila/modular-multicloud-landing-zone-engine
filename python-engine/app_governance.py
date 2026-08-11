"""Integration sure entre la generation applicative et la gouvernance E2E."""

from __future__ import annotations

from pathlib import Path

from security_governance_e2e import (
    FinalGovernanceResult,
    build_default_terraform_security_governance_engine,
)


DEFAULT_PROFILE = "baseline"


def normalize_cloud(cloud: str) -> str:
    """Normalise le provider applicatif avant toute execution Terraform."""

    if not isinstance(cloud, str):
        raise ValueError("cloud doit etre gcp ou oci")
    normalized = cloud.strip().casefold()
    if normalized not in {"gcp", "oci"}:
        raise ValueError("cloud doit etre gcp ou oci")
    return normalized


def run_governance_after_generation(cloud: str) -> FinalGovernanceResult:
    """Lance une fois le pipeline final apres une generation reussie."""

    normalized_cloud = normalize_cloud(cloud)
    pipeline = build_default_terraform_security_governance_engine(
        profile=DEFAULT_PROFILE
    )
    result = pipeline.run(
        cloud=normalized_cloud,
        write_security_report=True,
        write_policy_report=True,
        write_governance_report=True,
    )
    print_governance_summary(result)
    return result


def print_governance_summary(result: FinalGovernanceResult) -> None:
    """Affiche exclusivement des statuts et chemins de rapports sanitizes."""

    policy_result = result.policy_pipeline_result
    security_result = (
        policy_result.security_pipeline_result
        if policy_result is not None
        else None
    )
    terraform_result = (
        security_result.terraform_result
        if security_result is not None
        else None
    )
    terraform_report = (
        terraform_result.report if terraform_result is not None else None
    )
    decision = (
        policy_result.policy_decision if policy_result is not None else None
    )

    terraform_engine = (
        terraform_result.engine_status
        if terraform_result is not None
        else result.engine_status
    )
    policy_gate = (
        policy_result.policy_gate_status
        if policy_result is not None
        else None
    )
    plan_status = (
        terraform_report.plan_status if terraform_report is not None else None
    )

    print("=" * 60)
    print(" FINAL GOVERNANCE RESULT")
    print("=" * 60)
    _print_field("Cloud", result.cloud)
    _print_field("Generation", "PASS")
    print()
    _print_field("Terraform Engine", terraform_engine)
    _print_field("Terraform Status", result.terraform_final_status)
    _print_field("Plan Status", plan_status)
    print()
    _print_field("Security Status", result.security_evaluation_status)
    print()
    _print_field("Policy Gate Status", policy_gate)
    _print_field(
        "Policy Decision",
        decision.decision if decision is not None else None,
    )
    _print_field(
        "Policy Reason",
        decision.reason_code if decision is not None else None,
    )
    print()
    _print_field("Approval Status", result.approval_status)
    _print_field("Authorization Status", result.authorization_status)
    _print_field("Governance Status", result.governance_status)
    if _safe_value(
        decision.decision if decision is not None else None
    ) == "REQUIRE_APPROVAL":
        _print_field("Human action required", "YES")
    print()
    _print_field(
        "Security Report",
        _report_paths(
            security_result.security_json_path if security_result else None,
            security_result.security_text_path if security_result else None,
        ),
    )
    _print_field(
        "Policy Report",
        _report_paths(
            policy_result.policy_json_path if policy_result else None,
            policy_result.policy_text_path if policy_result else None,
        ),
    )
    _print_field(
        "Governance Report",
        _report_paths(
            result.governance_json_path,
            result.governance_text_path,
        ),
    )
    print()
    _print_field("Terraform Apply", "NOT EXECUTED")
    _print_field("Terraform Destroy", "NOT EXECUTED")
    print("=" * 60)


def _print_field(label: str, value: object | None) -> None:
    print(f"{label:<23}: {_safe_value(value)}")


def _safe_value(value: object | None) -> str:
    if value is None:
        return "SKIPPED"
    enum_value = getattr(value, "value", value)
    return str(enum_value)


def _report_paths(json_path: Path | None, text_path: Path | None) -> str:
    paths = [str(path) for path in (json_path, text_path) if path is not None]
    return ", ".join(paths) if paths else "NOT_WRITTEN"
