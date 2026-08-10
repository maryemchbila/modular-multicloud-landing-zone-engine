"""Composition CIS-8 vers decision et rapport policy, sans reexecution."""

from __future__ import annotations

import argparse
import json
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from security_policy_gate import SecurityPolicyGate, build_default_security_policy_gate
from security_policy_models import (
    PolicyDecision,
    SecurityPolicy,
    SecurityPolicyProfile,
    build_security_policy_for_profile,
)
from security_policy_report import PolicyDecisionReport, PolicyDecisionReportBuilder
from security_terraform_e2e import (
    TerraformSecurityEndToEndPipeline,
    TerraformSecurityEndToEndResult,
    build_default_terraform_security_engine,
)
from terraform_e2e import TerraformEngineStatus


class PolicyPipelineStageStatus(str, Enum):
    """Statut technique d'une etape POLICY-4, distinct de la decision."""

    PASS = "PASS"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


@dataclass(frozen=True)
class TerraformSecurityPolicyEndToEndResult:
    """Resultat structure sans raw plan, sorties Terraform ni credentials."""

    engine_status: TerraformEngineStatus
    cloud: str
    security_pipeline_result: TerraformSecurityEndToEndResult | None = field(
        repr=False
    )
    policy_gate_status: PolicyPipelineStageStatus
    policy_report_status: PolicyPipelineStageStatus
    policy_decision: PolicyDecision | None
    policy_report: PolicyDecisionReport | None = field(repr=False)
    policy_report_written: bool
    policy_json_path: Path | None
    policy_text_path: Path | None
    duration_seconds: float
    engine_error: str | None = None
    apply_executed: bool = field(default=False, init=False)
    destroy_executed: bool = field(default=False, init=False)
    cloud_write_executed: bool = field(default=False, init=False)
    auto_approval_executed: bool = field(default=False, init=False)

    @property
    def terraform_final_status(self) -> str | None:
        if self.security_pipeline_result is None:
            return None
        return self.security_pipeline_result.terraform_final_status

    @property
    def security_evaluation_status(self) -> str | None:
        if self.security_pipeline_result is None:
            return None
        return self.security_pipeline_result.security_evaluation_status.value

    def to_dict(self) -> dict[str, Any]:
        """Serialise uniquement des statuts, rapports sanitizes et chemins runtime."""

        security_result = self.security_pipeline_result
        decision = self.policy_decision
        return {
            "engine_status": self.engine_status.value,
            "cloud": self.cloud,
            "terraform_final_status": self.terraform_final_status,
            "security": (
                {
                    "engine_status": security_result.engine_status.value,
                    "show_status": security_result.show_status.value,
                    "adaptation_status": security_result.adaptation_status.value,
                    "evaluation_status": (
                        security_result.security_evaluation_status.value
                    ),
                    "security_report_written": (
                        security_result.security_report_written
                    ),
                    "security_json_path": (
                        str(security_result.security_json_path)
                        if security_result.security_json_path is not None
                        else None
                    ),
                    "security_text_path": (
                        str(security_result.security_text_path)
                        if security_result.security_text_path is not None
                        else None
                    ),
                }
                if security_result is not None
                else None
            ),
            "policy_gate_status": self.policy_gate_status.value,
            "policy_report_status": self.policy_report_status.value,
            "policy_decision": decision.to_dict() if decision is not None else None,
            "policy_report": (
                self.policy_report.to_dict()
                if self.policy_report is not None
                else None
            ),
            "policy_report_written": self.policy_report_written,
            "policy_json_path": (
                str(self.policy_json_path)
                if self.policy_json_path is not None
                else None
            ),
            "policy_text_path": (
                str(self.policy_text_path)
                if self.policy_text_path is not None
                else None
            ),
            "duration_seconds": self.duration_seconds,
            "engine_error": self.engine_error,
            "safety": {
                "apply_executed": self.apply_executed,
                "destroy_executed": self.destroy_executed,
                "cloud_write_executed": self.cloud_write_executed,
                "auto_approval_executed": self.auto_approval_executed,
            },
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


class TerraformSecurityPolicyEndToEndPipeline:
    """Orchestre une fois CIS-8, le gate, puis le reporting POLICY-3."""

    SECURITY_PIPELINE_ERROR = "Terraform security pipeline failed internally."
    POLICY_GATE_ERROR = "Security policy gate evaluation failed."
    POLICY_REPORT_ERROR = "Policy decision report processing failed."

    def __init__(
        self,
        terraform_security_pipeline: TerraformSecurityEndToEndPipeline,
        policy_gate: SecurityPolicyGate,
        policy_report_builder: PolicyDecisionReportBuilder,
    ) -> None:
        if not callable(getattr(terraform_security_pipeline, "run", None)):
            raise TypeError("terraform_security_pipeline doit exposer run")
        if not callable(getattr(policy_gate, "evaluate", None)) or not isinstance(
            getattr(policy_gate, "policy", None),
            SecurityPolicy,
        ):
            raise TypeError("policy_gate doit exposer une SecurityPolicy")
        if not callable(getattr(policy_report_builder, "build", None)) or not (
            callable(getattr(policy_report_builder, "write_report", None))
        ):
            raise TypeError(
                "policy_report_builder doit exposer build et write_report"
            )
        self.terraform_security_pipeline = terraform_security_pipeline
        self.policy_gate = policy_gate
        self.policy_report_builder = policy_report_builder

    @property
    def policy(self) -> SecurityPolicy:
        return self.policy_gate.policy

    def run(
        self,
        cloud: str,
        *,
        write_security_report: bool = False,
        write_policy_report: bool = False,
        evaluated_at: datetime | None = None,
    ) -> TerraformSecurityPolicyEndToEndResult:
        """Execute chaque composant au plus une fois dans l'ordre valide."""

        normalised_cloud = self._normalise_cloud(cloud)
        if not isinstance(write_security_report, bool):
            raise TypeError("write_security_report doit etre un booleen")
        if not isinstance(write_policy_report, bool):
            raise TypeError("write_policy_report doit etre un booleen")
        started_at = time.perf_counter()
        try:
            security_result = self.terraform_security_pipeline.run(
                cloud=normalised_cloud,
                write_report=write_security_report,
            )
        except Exception:
            return self._result(
                started_at=started_at,
                cloud=normalised_cloud,
                engine_status=TerraformEngineStatus.FAIL,
                engine_error=self.SECURITY_PIPELINE_ERROR,
            )

        if not isinstance(security_result, TerraformSecurityEndToEndResult):
            return self._result(
                started_at=started_at,
                cloud=normalised_cloud,
                engine_status=TerraformEngineStatus.FAIL,
                engine_error=self.SECURITY_PIPELINE_ERROR,
            )

        engine_status = security_result.engine_status
        evaluation_result = security_result.security_evaluation_result
        if engine_status is TerraformEngineStatus.FAIL or evaluation_result is None:
            return self._result(
                started_at=started_at,
                cloud=normalised_cloud,
                engine_status=engine_status,
                security_result=security_result,
            )

        try:
            decision = self.policy_gate.evaluate(
                evaluation_result,
                evaluated_at=evaluated_at,
            )
        except Exception:
            return self._result(
                started_at=started_at,
                cloud=normalised_cloud,
                engine_status=TerraformEngineStatus.FAIL,
                security_result=security_result,
                policy_gate_status=PolicyPipelineStageStatus.ERROR,
                engine_error=self.POLICY_GATE_ERROR,
            )

        terraform_report = (
            security_result.terraform_result.report
            if security_result.terraform_result is not None
            else None
        )
        try:
            policy_report = self.policy_report_builder.build(
                policy=self.policy,
                decision=decision,
                evaluation_result=evaluation_result,
                security_report=security_result.security_report,
                terraform_report=terraform_report,
            )
        except Exception:
            return self._result(
                started_at=started_at,
                cloud=normalised_cloud,
                engine_status=TerraformEngineStatus.FAIL,
                security_result=security_result,
                policy_gate_status=PolicyPipelineStageStatus.PASS,
                policy_report_status=PolicyPipelineStageStatus.ERROR,
                decision=decision,
                engine_error=self.POLICY_REPORT_ERROR,
            )

        json_path: Path | None = None
        text_path: Path | None = None
        if write_policy_report:
            try:
                json_path, text_path = self.policy_report_builder.write_report(
                    policy_report
                )
            except Exception:
                return self._result(
                    started_at=started_at,
                    cloud=normalised_cloud,
                    engine_status=TerraformEngineStatus.FAIL,
                    security_result=security_result,
                    policy_gate_status=PolicyPipelineStageStatus.PASS,
                    policy_report_status=PolicyPipelineStageStatus.ERROR,
                    decision=decision,
                    policy_report=policy_report,
                    engine_error=self.POLICY_REPORT_ERROR,
                )

        return self._result(
            started_at=started_at,
            cloud=normalised_cloud,
            engine_status=engine_status,
            security_result=security_result,
            policy_gate_status=PolicyPipelineStageStatus.PASS,
            policy_report_status=PolicyPipelineStageStatus.PASS,
            decision=decision,
            policy_report=policy_report,
            policy_report_written=write_policy_report,
            json_path=json_path,
            text_path=text_path,
        )

    @staticmethod
    def _normalise_cloud(cloud: str) -> str:
        if not isinstance(cloud, str):
            raise ValueError("cloud doit etre gcp ou oci")
        normalised = cloud.strip().casefold()
        if normalised not in {"gcp", "oci"}:
            raise ValueError("cloud doit etre gcp ou oci")
        return normalised

    @staticmethod
    def _result(
        *,
        started_at: float,
        cloud: str,
        engine_status: TerraformEngineStatus,
        security_result: TerraformSecurityEndToEndResult | None = None,
        policy_gate_status: PolicyPipelineStageStatus = (
            PolicyPipelineStageStatus.SKIPPED
        ),
        policy_report_status: PolicyPipelineStageStatus = (
            PolicyPipelineStageStatus.SKIPPED
        ),
        decision: PolicyDecision | None = None,
        policy_report: PolicyDecisionReport | None = None,
        policy_report_written: bool = False,
        json_path: Path | None = None,
        text_path: Path | None = None,
        engine_error: str | None = None,
    ) -> TerraformSecurityPolicyEndToEndResult:
        return TerraformSecurityPolicyEndToEndResult(
            engine_status=engine_status,
            cloud=cloud,
            security_pipeline_result=security_result,
            policy_gate_status=policy_gate_status,
            policy_report_status=policy_report_status,
            policy_decision=decision,
            policy_report=policy_report,
            policy_report_written=policy_report_written,
            policy_json_path=json_path,
            policy_text_path=text_path,
            duration_seconds=round(time.perf_counter() - started_at, 6),
            engine_error=engine_error,
        )


def build_default_terraform_security_policy_engine(
    repository_root: Path | None = None,
    *,
    profile: SecurityPolicyProfile | str = SecurityPolicyProfile.BASELINE,
    policy: SecurityPolicy | None = None,
) -> TerraformSecurityPolicyEndToEndPipeline:
    """Compose CIS-8, une policy interne et le builder POLICY-3."""

    if policy is not None and not isinstance(policy, SecurityPolicy):
        raise TypeError("policy doit etre une SecurityPolicy ou None")
    if policy is None:
        if (
            isinstance(profile, SecurityPolicyProfile)
            and profile is SecurityPolicyProfile.BASELINE
        ) or (isinstance(profile, str) and profile.strip().casefold() == "baseline"):
            gate = build_default_security_policy_gate()
        else:
            selected_policy = build_security_policy_for_profile(profile)
            gate = SecurityPolicyGate(selected_policy)
    else:
        gate = SecurityPolicyGate(policy)
    return TerraformSecurityPolicyEndToEndPipeline(
        terraform_security_pipeline=build_default_terraform_security_engine(
            repository_root
        ),
        policy_gate=gate,
        policy_report_builder=PolicyDecisionReportBuilder(
            repository_root=repository_root
        ),
    )


def _display_value(value: object | None) -> str:
    return str(value) if value is not None else "NONE"


def _print_safe_summary(result: TerraformSecurityPolicyEndToEndResult) -> None:
    """Affiche uniquement les statuts, la decision et les chemins de rapports."""

    decision = result.policy_decision
    security_result = result.security_pipeline_result
    values = {
        "engine_status": result.engine_status.value,
        "cloud": result.cloud,
        "terraform_final_status": result.terraform_final_status,
        "security_evaluation_status": result.security_evaluation_status,
        "policy_gate_status": result.policy_gate_status.value,
        "policy_report_status": result.policy_report_status.value,
        "policy_decision": decision.decision.value if decision is not None else None,
        "policy_reason_code": (
            decision.reason_code.value if decision is not None else None
        ),
        "requires_human_approval": (
            decision.requires_human_approval if decision is not None else None
        ),
        "deployment_allowed": (
            decision.deployment_allowed if decision is not None else None
        ),
        "security_report_json": (
            security_result.security_json_path
            if security_result is not None
            else None
        ),
        "security_report_text": (
            security_result.security_text_path
            if security_result is not None
            else None
        ),
        "policy_report_json": result.policy_json_path,
        "policy_report_text": result.policy_text_path,
    }
    for key, value in values.items():
        print(f"{key}={_display_value(value)}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run Terraform security evaluation and policy reporting safely."
    )
    parser.add_argument("--cloud", required=True, choices=("gcp", "oci"))
    parser.add_argument(
        "--profile",
        choices=("baseline", "strict"),
        default="baseline",
    )
    parser.add_argument("--write-security-report", action="store_true")
    parser.add_argument("--write-policy-report", action="store_true")
    arguments = parser.parse_args(argv)

    result = build_default_terraform_security_policy_engine(
        profile=arguments.profile
    ).run(
        cloud=arguments.cloud,
        write_security_report=arguments.write_security_report,
        write_policy_report=arguments.write_policy_report,
    )
    _print_safe_summary(result)
    return 0 if result.engine_status is TerraformEngineStatus.PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
