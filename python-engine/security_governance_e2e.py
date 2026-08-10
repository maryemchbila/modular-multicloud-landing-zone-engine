"""Pipeline final POLICY-6 : Policy E2E vers gouvernance, sans deploiement."""

from __future__ import annotations

import argparse
import json
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from security_approval_models import (
    ApprovalRecord,
    ApprovalRequest,
    ApprovalStatus,
    AuthorizationStatus,
    ControlledAuthorization,
)
from security_approval_workflow import HumanApprovalWorkflow
from security_governance_report import (
    GovernanceAuditReport,
    GovernanceAuditReportBuilder,
)
from security_policy_e2e import (
    PolicyPipelineStageStatus,
    TerraformSecurityPolicyEndToEndPipeline,
    TerraformSecurityPolicyEndToEndResult,
    build_default_terraform_security_policy_engine,
)
from security_policy_models import SecurityPolicy, SecurityPolicyProfile
from terraform_e2e import TerraformEngineStatus


class GovernanceStageStatus(str, Enum):
    PASS = "PASS"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


@dataclass(frozen=True)
class FinalGovernanceResult:
    """Projection finale sure; AUTHORIZED n'implique aucune execution."""

    engine_status: TerraformEngineStatus
    cloud: str
    policy_pipeline_result: TerraformSecurityPolicyEndToEndResult | None = field(
        repr=False
    )
    approval_stage_status: GovernanceStageStatus
    governance_report_status: GovernanceStageStatus
    approval_request: ApprovalRequest | None
    approval_record: ApprovalRecord | None
    authorization: ControlledAuthorization | None
    governance_report: GovernanceAuditReport | None = field(repr=False)
    governance_report_written: bool
    governance_json_path: Path | None
    governance_text_path: Path | None
    duration_seconds: float
    engine_error: str | None = None
    apply_executed: bool = field(default=False, init=False)
    destroy_executed: bool = field(default=False, init=False)
    cloud_write_executed: bool = field(default=False, init=False)
    auto_approval_executed: bool = field(default=False, init=False)

    @property
    def approval_status(self) -> str | None:
        return (
            self.approval_request.status.value
            if self.approval_request is not None
            else None
        )

    @property
    def authorization_status(self) -> str | None:
        return (
            self.authorization.authorization_status.value
            if self.authorization is not None
            else None
        )

    @property
    def governance_status(self) -> str:
        if self.authorization is not None:
            return self.authorization.authorization_status.value
        return self.approval_stage_status.value

    @property
    def terraform_final_status(self) -> str | None:
        if self.policy_pipeline_result is None:
            return None
        return self.policy_pipeline_result.terraform_final_status

    @property
    def security_evaluation_status(self) -> str | None:
        if self.policy_pipeline_result is None:
            return None
        return self.policy_pipeline_result.security_evaluation_status

    def to_dict(self) -> dict[str, Any]:
        policy_result = self.policy_pipeline_result
        policy_decision = (
            policy_result.policy_decision if policy_result is not None else None
        )
        return {
            "engine_status": self.engine_status.value,
            "cloud": self.cloud,
            "terraform_final_status": self.terraform_final_status,
            "security_evaluation_status": self.security_evaluation_status,
            "policy": (
                {
                    "gate_status": policy_result.policy_gate_status.value,
                    "report_status": policy_result.policy_report_status.value,
                    "decision": policy_decision.decision.value,
                    "reason_code": policy_decision.reason_code.value,
                    "policy_id": policy_decision.policy_id,
                    "policy_version": policy_decision.policy_version,
                    "profile": policy_decision.profile.value,
                    "policy_report_run_id": (
                        policy_result.policy_report.run_id
                        if policy_result.policy_report is not None
                        else None
                    ),
                }
                if policy_result is not None and policy_decision is not None
                else None
            ),
            "approval_stage_status": self.approval_stage_status.value,
            "approval": (
                self.approval_request.to_dict()
                if self.approval_request is not None
                else None
            ),
            "approval_record": (
                self.approval_record.to_dict()
                if self.approval_record is not None
                else None
            ),
            "authorization": (
                self.authorization.to_dict()
                if self.authorization is not None
                else None
            ),
            "governance_status": self.governance_status,
            "governance_report_status": self.governance_report_status.value,
            "governance_report": (
                self.governance_report.to_dict()
                if self.governance_report is not None
                else None
            ),
            "governance_report_written": self.governance_report_written,
            "governance_json_path": (
                str(self.governance_json_path)
                if self.governance_json_path is not None
                else None
            ),
            "governance_text_path": (
                str(self.governance_text_path)
                if self.governance_text_path is not None
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


class TerraformSecurityGovernanceEndToEndPipeline:
    """Compose exactement une execution POLICY-4 et le workflow POLICY-5."""

    POLICY_PIPELINE_ERROR = "Terraform security policy pipeline failed internally."
    APPROVAL_WORKFLOW_ERROR = "Human approval workflow processing failed."
    GOVERNANCE_REPORT_ERROR = "Governance audit report processing failed."

    def __init__(
        self,
        policy_pipeline: TerraformSecurityPolicyEndToEndPipeline,
        approval_workflow: HumanApprovalWorkflow,
        governance_report_builder: GovernanceAuditReportBuilder,
    ) -> None:
        if not callable(getattr(policy_pipeline, "run", None)):
            raise TypeError("policy_pipeline doit exposer run")
        if not callable(getattr(approval_workflow, "create_request", None)) or not callable(
            getattr(approval_workflow, "build_authorization", None)
        ):
            raise TypeError("approval_workflow incomplet")
        if not callable(getattr(governance_report_builder, "build", None)) or not callable(
            getattr(governance_report_builder, "write_report", None)
        ):
            raise TypeError("governance_report_builder incomplet")
        self.policy_pipeline = policy_pipeline
        self.approval_workflow = approval_workflow
        self.governance_report_builder = governance_report_builder

    def run(
        self,
        cloud: str,
        *,
        write_security_report: bool = False,
        write_policy_report: bool = False,
        write_governance_report: bool = False,
        evaluated_at: datetime | None = None,
        approval_expires_at: datetime | None = None,
    ) -> FinalGovernanceResult:
        normalised_cloud = self._normalise_cloud(cloud)
        for value, field_name in (
            (write_security_report, "write_security_report"),
            (write_policy_report, "write_policy_report"),
            (write_governance_report, "write_governance_report"),
        ):
            if not isinstance(value, bool):
                raise TypeError(f"{field_name} doit etre un booleen")
        started_at = time.perf_counter()
        try:
            policy_result = self.policy_pipeline.run(
                cloud=normalised_cloud,
                write_security_report=write_security_report,
                write_policy_report=write_policy_report,
                evaluated_at=evaluated_at,
            )
        except Exception:
            return self._result(
                started_at=started_at,
                cloud=normalised_cloud,
                engine_status=TerraformEngineStatus.FAIL,
                engine_error=self.POLICY_PIPELINE_ERROR,
            )
        if not isinstance(policy_result, TerraformSecurityPolicyEndToEndResult):
            return self._result(
                started_at=started_at,
                cloud=normalised_cloud,
                engine_status=TerraformEngineStatus.FAIL,
                engine_error=self.POLICY_PIPELINE_ERROR,
            )
        policy_stage_error = (
            policy_result.policy_gate_status is PolicyPipelineStageStatus.ERROR
            or policy_result.policy_report_status is PolicyPipelineStageStatus.ERROR
        )
        if policy_result.engine_status is TerraformEngineStatus.FAIL or policy_stage_error:
            return self._result(
                started_at=started_at,
                cloud=normalised_cloud,
                engine_status=TerraformEngineStatus.FAIL,
                policy_result=policy_result,
            )
        if (
            policy_result.policy_decision is None
            or policy_result.policy_gate_status is not PolicyPipelineStageStatus.PASS
        ):
            return self._result(
                started_at=started_at,
                cloud=normalised_cloud,
                engine_status=policy_result.engine_status,
                policy_result=policy_result,
            )

        try:
            approval_request = self.approval_workflow.create_request(
                policy_result.policy_decision,
                policy_report=policy_result.policy_report,
                expires_at=(
                    approval_expires_at
                    if policy_result.policy_decision.requires_human_approval
                    else None
                ),
            )
            authorization = self.approval_workflow.build_authorization(
                approval_request,
                decision=policy_result.policy_decision,
            )
        except Exception:
            return self._result(
                started_at=started_at,
                cloud=normalised_cloud,
                engine_status=TerraformEngineStatus.FAIL,
                policy_result=policy_result,
                approval_stage_status=GovernanceStageStatus.ERROR,
                engine_error=self.APPROVAL_WORKFLOW_ERROR,
            )

        try:
            governance_report = self.governance_report_builder.build(
                policy_pipeline_result=policy_result,
                approval_request=approval_request,
                authorization=authorization,
                approval_record=None,
            )
        except Exception:
            return self._result(
                started_at=started_at,
                cloud=normalised_cloud,
                engine_status=TerraformEngineStatus.FAIL,
                policy_result=policy_result,
                approval_stage_status=GovernanceStageStatus.PASS,
                approval_request=approval_request,
                authorization=authorization,
                governance_report_status=GovernanceStageStatus.ERROR,
                engine_error=self.GOVERNANCE_REPORT_ERROR,
            )

        json_path: Path | None = None
        text_path: Path | None = None
        if write_governance_report:
            try:
                json_path, text_path = self.governance_report_builder.write_report(
                    governance_report
                )
            except Exception:
                return self._result(
                    started_at=started_at,
                    cloud=normalised_cloud,
                    engine_status=TerraformEngineStatus.FAIL,
                    policy_result=policy_result,
                    approval_stage_status=GovernanceStageStatus.PASS,
                    approval_request=approval_request,
                    authorization=authorization,
                    governance_report_status=GovernanceStageStatus.ERROR,
                    governance_report=governance_report,
                    engine_error=self.GOVERNANCE_REPORT_ERROR,
                )

        return self._result(
            started_at=started_at,
            cloud=normalised_cloud,
            engine_status=policy_result.engine_status,
            policy_result=policy_result,
            approval_stage_status=GovernanceStageStatus.PASS,
            approval_request=approval_request,
            authorization=authorization,
            governance_report_status=GovernanceStageStatus.PASS,
            governance_report=governance_report,
            governance_report_written=write_governance_report,
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
        policy_result: TerraformSecurityPolicyEndToEndResult | None = None,
        approval_stage_status: GovernanceStageStatus = GovernanceStageStatus.SKIPPED,
        governance_report_status: GovernanceStageStatus = GovernanceStageStatus.SKIPPED,
        approval_request: ApprovalRequest | None = None,
        approval_record: ApprovalRecord | None = None,
        authorization: ControlledAuthorization | None = None,
        governance_report: GovernanceAuditReport | None = None,
        governance_report_written: bool = False,
        json_path: Path | None = None,
        text_path: Path | None = None,
        engine_error: str | None = None,
    ) -> FinalGovernanceResult:
        return FinalGovernanceResult(
            engine_status=engine_status,
            cloud=cloud,
            policy_pipeline_result=policy_result,
            approval_stage_status=approval_stage_status,
            governance_report_status=governance_report_status,
            approval_request=approval_request,
            approval_record=approval_record,
            authorization=authorization,
            governance_report=governance_report,
            governance_report_written=governance_report_written,
            governance_json_path=json_path,
            governance_text_path=text_path,
            duration_seconds=round(time.perf_counter() - started_at, 6),
            engine_error=engine_error,
        )


def build_default_terraform_security_governance_engine(
    repository_root: Path | None = None,
    *,
    profile: SecurityPolicyProfile | str = SecurityPolicyProfile.BASELINE,
    policy: SecurityPolicy | None = None,
) -> TerraformSecurityGovernanceEndToEndPipeline:
    return TerraformSecurityGovernanceEndToEndPipeline(
        policy_pipeline=build_default_terraform_security_policy_engine(
            repository_root,
            profile=profile,
            policy=policy,
        ),
        approval_workflow=HumanApprovalWorkflow(
            now_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0)
        ),
        governance_report_builder=GovernanceAuditReportBuilder(
            repository_root=repository_root
        ),
    )


def _display_value(value: object | None) -> str:
    return str(value) if value is not None else "NONE"


def _print_safe_summary(result: FinalGovernanceResult) -> None:
    policy_result = result.policy_pipeline_result
    decision = policy_result.policy_decision if policy_result is not None else None
    values = {
        "engine_status": result.engine_status.value,
        "cloud": result.cloud,
        "terraform_final_status": result.terraform_final_status,
        "security_evaluation_status": result.security_evaluation_status,
        "policy_decision": decision.decision.value if decision is not None else None,
        "approval_status": result.approval_status,
        "authorization_status": result.authorization_status,
        "policy_report_run_id": (
            policy_result.policy_report.run_id
            if policy_result is not None and policy_result.policy_report is not None
            else None
        ),
        "approval_request_id": (
            result.approval_request.request_id
            if result.approval_request is not None
            else None
        ),
        "governance_run_id": (
            result.governance_report.run_id
            if result.governance_report is not None
            else None
        ),
        "governance_report_json": result.governance_json_path,
        "governance_report_text": result.governance_text_path,
    }
    for key, value in values.items():
        print(f"{key}={_display_value(value)}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run final Terraform security governance without deployment."
    )
    parser.add_argument("--cloud", required=True, choices=("gcp", "oci"))
    parser.add_argument("--profile", choices=("baseline", "strict"), default="baseline")
    parser.add_argument("--write-security-report", action="store_true")
    parser.add_argument("--write-policy-report", action="store_true")
    parser.add_argument("--write-governance-report", action="store_true")
    arguments = parser.parse_args(argv)
    result = build_default_terraform_security_governance_engine(
        profile=arguments.profile
    ).run(
        cloud=arguments.cloud,
        write_security_report=arguments.write_security_report,
        write_policy_report=arguments.write_policy_report,
        write_governance_report=arguments.write_governance_report,
    )
    _print_safe_summary(result)
    return 0 if result.engine_status is TerraformEngineStatus.PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
