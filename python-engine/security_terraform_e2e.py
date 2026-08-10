"""Pipeline Terraform vers rapport de securite, sans operation destructive."""

from __future__ import annotations

import argparse
import json
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from security_evaluation import (
    MultiCloudSecurityEvaluationEngine,
    MultiCloudSecurityEvaluationResult,
    build_default_multicloud_security_engine,
)
from security_report import SecurityComplianceReport, SecurityComplianceReportBuilder
from security_terraform_adapter import (
    TerraformSecurityAdaptationResult,
    TerraformSecurityResourceAdapter,
)
from terraform_e2e import (
    TerraformEndToEndPipeline,
    TerraformEndToEndResult,
    TerraformEngineStatus,
)
from terraform_error_classifier import TerraformErrorClassifier
from terraform_models import TerraformErrorClassification, TerraformPlanStatus
from terraform_pipeline import TerraformValidationPipeline
from terraform_plan import TerraformPlanPipeline
from terraform_report import TerraformReportBuilder
from terraform_runner import TerraformRunner


class TerraformSecurityStageStatus(str, Enum):
    """Statut d'une etape CIS-8, distinct du statut du moteur Python."""

    PASS = "PASS"
    PASS_WITH_WARNINGS = "PASS_WITH_WARNINGS"
    FAIL = "FAIL"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


@dataclass(frozen=True)
class TerraformSecurityEndToEndResult:
    """Resultat CIS-8 ne conservant aucune sortie brute de ``terraform show``."""

    engine_status: TerraformEngineStatus
    cloud: str
    terraform_result: TerraformEndToEndResult | None = field(repr=False)
    show_status: TerraformSecurityStageStatus
    show_error_classification: TerraformErrorClassification | None
    adaptation_status: TerraformSecurityStageStatus
    adaptation_result: TerraformSecurityAdaptationResult | None = field(repr=False)
    security_evaluation_status: TerraformSecurityStageStatus
    security_evaluation_result: MultiCloudSecurityEvaluationResult | None = field(
        repr=False
    )
    security_report: SecurityComplianceReport | None = field(repr=False)
    security_report_written: bool
    security_json_path: Path | None
    security_text_path: Path | None
    duration_seconds: float
    temporary_plan_created: bool
    temporary_plan_cleaned: bool
    engine_error: str | None = None
    apply_executed: bool = field(default=False, init=False)
    destroy_executed: bool = field(default=False, init=False)

    @property
    def terraform_final_status(self) -> str | None:
        if self.terraform_result is None:
            return None
        return self.terraform_result.terraform_final_status

    def to_dict(self) -> dict[str, Any]:
        """Expose uniquement des champs synthetiques et des rapports sanitizes."""

        terraform_report = (
            self.terraform_result.report
            if self.terraform_result is not None
            else None
        )
        adaptation = self.adaptation_result
        evaluation = self.security_evaluation_result
        return {
            "engine_status": self.engine_status.value,
            "cloud": self.cloud,
            "terraform": (
                terraform_report.to_dict() if terraform_report is not None else None
            ),
            "show_status": self.show_status.value,
            "show_error_classification": (
                self.show_error_classification.to_dict()
                if self.show_error_classification is not None
                else None
            ),
            "adaptation_status": self.adaptation_status.value,
            "adaptation": (
                {
                    "resources_seen": adaptation.resources_seen,
                    "resources_adapted": adaptation.resources_adapted,
                    "resources_skipped": adaptation.resources_skipped,
                    "unsupported_resource_types": list(
                        adaptation.unsupported_resource_types
                    ),
                    "diagnostics": list(adaptation.warnings),
                }
                if adaptation is not None
                else None
            ),
            "security_evaluation_status": self.security_evaluation_status.value,
            "security_evaluation": (
                {
                    "resources_total": evaluation.resources_total,
                    "findings_total": evaluation.findings_total,
                    "passed": evaluation.passed,
                    "failed": evaluation.failed,
                    "warnings": evaluation.warnings,
                    "skipped": evaluation.skipped,
                    "not_applicable": evaluation.not_applicable,
                }
                if evaluation is not None
                else None
            ),
            "security_report": (
                self.security_report.to_dict()
                if self.security_report is not None
                else None
            ),
            "security_report_written": self.security_report_written,
            "security_json_path": (
                str(self.security_json_path)
                if self.security_json_path is not None
                else None
            ),
            "security_text_path": (
                str(self.security_text_path)
                if self.security_text_path is not None
                else None
            ),
            "duration_seconds": self.duration_seconds,
            "temporary_plan_created": self.temporary_plan_created,
            "temporary_plan_cleaned": self.temporary_plan_cleaned,
            "engine_error": self.engine_error,
            "safety": {
                "apply_executed": self.apply_executed,
                "destroy_executed": self.destroy_executed,
            },
        }


class TerraformSecurityEndToEndPipeline:
    """Compose PLAN-6, show, CIS-6, CIS-5 et CIS-7 dans un run unique."""

    TEMP_PLAN_FILENAME = "security_plan.tfplan"
    INTERNAL_ERROR_MESSAGE = "Internal Terraform security engine error."
    INVALID_SHOW_JSON_MESSAGE = "Terraform show returned invalid JSON."
    SAVED_PLAN_UNAVAILABLE_MESSAGE = "Terraform saved plan is unavailable."
    CLEANUP_ERROR_MESSAGE = "Terraform temporary saved plan cleanup failed."
    SUCCESSFUL_PLAN_STATUSES = frozenset(
        {TerraformPlanStatus.NO_CHANGES, TerraformPlanStatus.CHANGES_DETECTED}
    )

    def __init__(
        self,
        terraform_pipeline: TerraformEndToEndPipeline,
        runner: TerraformRunner,
        error_classifier: TerraformErrorClassifier,
        adapter: TerraformSecurityResourceAdapter,
        evaluation_engine: MultiCloudSecurityEvaluationEngine,
        report_builder: SecurityComplianceReportBuilder,
        show_timeout: float = 60.0,
    ) -> None:
        self.terraform_pipeline = terraform_pipeline
        self.runner = runner
        self.error_classifier = error_classifier
        self.adapter = adapter
        self.evaluation_engine = evaluation_engine
        self.report_builder = report_builder
        self.show_timeout = self._validate_timeout(show_timeout)

    def run(
        self,
        cloud: str,
        write_report: bool = False,
    ) -> TerraformSecurityEndToEndResult:
        """Execute un plan capture une fois, l'analyse, puis nettoie le plan."""

        normalised_cloud = TerraformValidationPipeline._normalise_cloud(cloud)
        started_at = time.perf_counter()
        state = self._initial_state()
        temporary_directory: tempfile.TemporaryDirectory[str] | None = None
        plan_path: Path | None = None
        temporary_plan_created = False
        temporary_plan_cleaned = True

        try:
            temporary_directory = tempfile.TemporaryDirectory(
                prefix="terraform-security-cis8-"
            )
            plan_path = (
                Path(temporary_directory.name).resolve() / self.TEMP_PLAN_FILENAME
            )
            state = self._execute(
                cloud=normalised_cloud,
                plan_path=plan_path,
                write_report=write_report,
            )
        except Exception:
            state["engine_status"] = TerraformEngineStatus.FAIL
            state["engine_error"] = self.INTERNAL_ERROR_MESSAGE
        finally:
            if plan_path is not None:
                temporary_plan_created = plan_path.is_file()
            if temporary_directory is not None:
                try:
                    temporary_directory.cleanup()
                    temporary_plan_cleaned = (
                        plan_path is None or not plan_path.exists()
                    )
                except Exception:
                    temporary_plan_cleaned = False
                    state["engine_status"] = TerraformEngineStatus.FAIL
                    state["engine_error"] = self.CLEANUP_ERROR_MESSAGE

        return TerraformSecurityEndToEndResult(
            cloud=normalised_cloud,
            duration_seconds=round(time.perf_counter() - started_at, 6),
            temporary_plan_created=temporary_plan_created,
            temporary_plan_cleaned=temporary_plan_cleaned,
            **state,
        )

    def _execute(
        self,
        *,
        cloud: str,
        plan_path: Path,
        write_report: bool,
    ) -> dict[str, Any]:
        state = self._initial_state()
        terraform_result = self.terraform_pipeline.run(
            cloud=cloud,
            write_report=write_report,
            plan_output_path=plan_path,
        )
        state["terraform_result"] = terraform_result
        if terraform_result.engine_status is TerraformEngineStatus.FAIL:
            state["engine_status"] = TerraformEngineStatus.FAIL
            state["engine_error"] = self.INTERNAL_ERROR_MESSAGE
            return state

        plan_result = terraform_result.plan_pipeline_result
        if plan_result is None:
            state["engine_status"] = TerraformEngineStatus.FAIL
            state["engine_error"] = self.INTERNAL_ERROR_MESSAGE
            return state
        if plan_result.plan_status not in self.SUCCESSFUL_PLAN_STATUSES:
            return state
        if not plan_path.is_file():
            state["engine_status"] = TerraformEngineStatus.FAIL
            state["engine_error"] = self.SAVED_PLAN_UNAVAILABLE_MESSAGE
            return state

        try:
            show_result = self.runner.run(
                ["show", "-json", str(plan_path)],
                cwd=Path(plan_result.working_directory),
                timeout=self.show_timeout,
            )
        except Exception:
            state["engine_status"] = TerraformEngineStatus.FAIL
            state["show_status"] = TerraformSecurityStageStatus.ERROR
            state["engine_error"] = self.INTERNAL_ERROR_MESSAGE
            return state

        if show_result.timed_out or show_result.exit_code != 0:
            state["show_status"] = TerraformSecurityStageStatus.ERROR
            state["show_error_classification"] = self.error_classifier.classify(
                "show", show_result
            )
            return state

        try:
            raw_show_json = show_result.stdout
            plan_data = json.loads(raw_show_json)
            del raw_show_json
            if not isinstance(plan_data, Mapping):
                raise ValueError(self.INVALID_SHOW_JSON_MESSAGE)
        except (json.JSONDecodeError, TypeError, ValueError):
            state["engine_status"] = TerraformEngineStatus.FAIL
            state["show_status"] = TerraformSecurityStageStatus.ERROR
            state["engine_error"] = self.INVALID_SHOW_JSON_MESSAGE
            return state
        state["show_status"] = TerraformSecurityStageStatus.PASS

        try:
            adaptation_result = self.adapter.from_plan_dict(plan_data)
        except Exception:
            state["engine_status"] = TerraformEngineStatus.FAIL
            state["adaptation_status"] = TerraformSecurityStageStatus.ERROR
            state["engine_error"] = self.INTERNAL_ERROR_MESSAGE
            return state
        finally:
            plan_data = None
        state["adaptation_result"] = adaptation_result
        state["adaptation_status"] = TerraformSecurityStageStatus.PASS

        try:
            evaluation_result = self.evaluation_engine.evaluate(
                resources=adaptation_result.resources
            )
        except Exception:
            state["engine_status"] = TerraformEngineStatus.FAIL
            state["security_evaluation_status"] = (
                TerraformSecurityStageStatus.ERROR
            )
            state["engine_error"] = self.INTERNAL_ERROR_MESSAGE
            return state
        state["security_evaluation_result"] = evaluation_result
        state["security_evaluation_status"] = TerraformSecurityStageStatus(
            evaluation_result.evaluation_status.value
        )

        try:
            security_report = self.report_builder.build(
                adaptation_result=adaptation_result,
                evaluation_result=evaluation_result,
                terraform_report=terraform_result.report,
            )
        except Exception:
            state["engine_status"] = TerraformEngineStatus.FAIL
            state["engine_error"] = self.INTERNAL_ERROR_MESSAGE
            return state
        state["security_report"] = security_report

        if write_report:
            try:
                json_path, text_path = self.report_builder.write_report(
                    security_report
                )
            except Exception:
                state["engine_status"] = TerraformEngineStatus.FAIL
                state["engine_error"] = self.INTERNAL_ERROR_MESSAGE
                return state
            state["security_report_written"] = True
            state["security_json_path"] = json_path
            state["security_text_path"] = text_path
        return state

    @staticmethod
    def _initial_state() -> dict[str, Any]:
        return {
            "engine_status": TerraformEngineStatus.PASS,
            "terraform_result": None,
            "show_status": TerraformSecurityStageStatus.SKIPPED,
            "show_error_classification": None,
            "adaptation_status": TerraformSecurityStageStatus.SKIPPED,
            "adaptation_result": None,
            "security_evaluation_status": TerraformSecurityStageStatus.SKIPPED,
            "security_evaluation_result": None,
            "security_report": None,
            "security_report_written": False,
            "security_json_path": None,
            "security_text_path": None,
            "engine_error": None,
        }

    @staticmethod
    def _validate_timeout(timeout: float) -> float:
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or timeout <= 0
        ):
            raise ValueError("Le timeout Terraform pour show doit etre positif.")
        return float(timeout)


def build_default_terraform_security_engine(
    repository_root: Path | None = None,
) -> TerraformSecurityEndToEndPipeline:
    """Assemble les composants existants autour d'un runner Terraform unique."""

    runner = TerraformRunner()
    error_classifier = TerraformErrorClassifier()
    validation_pipeline = TerraformValidationPipeline(
        runner,
        repository_root=repository_root,
        error_classifier=error_classifier,
    )
    plan_pipeline = TerraformPlanPipeline(
        runner,
        validation_pipeline=validation_pipeline,
        error_classifier=error_classifier,
    )
    terraform_pipeline = TerraformEndToEndPipeline(
        plan_pipeline,
        TerraformReportBuilder(repository_root=repository_root),
    )
    evaluation_engine = build_default_multicloud_security_engine()
    return TerraformSecurityEndToEndPipeline(
        terraform_pipeline=terraform_pipeline,
        runner=runner,
        error_classifier=error_classifier,
        adapter=TerraformSecurityResourceAdapter(),
        evaluation_engine=evaluation_engine,
        report_builder=SecurityComplianceReportBuilder(
            repository_root=repository_root,
            catalog=evaluation_engine.catalog,
        ),
    )


def _display_value(value: object | None) -> str:
    return str(value) if value is not None else "NONE"


def _print_safe_summary(result: TerraformSecurityEndToEndResult) -> None:
    """Affiche uniquement les compteurs, statuts et chemins de rapports surs."""

    terraform_report = (
        result.terraform_result.report
        if result.terraform_result is not None
        else None
    )
    adaptation = result.adaptation_result
    evaluation = result.security_evaluation_result
    values = {
        "engine_status": result.engine_status.value,
        "cloud": result.cloud,
        "terraform_engine_status": (
            result.terraform_result.engine_status.value
            if result.terraform_result is not None
            else None
        ),
        "terraform_final_status": result.terraform_final_status,
        "plan_status": (
            terraform_report.plan_status if terraform_report is not None else None
        ),
        "plan_exit_code": (
            terraform_report.plan_exit_code if terraform_report is not None else None
        ),
        "show_status": result.show_status.value,
        "resources_seen": (
            adaptation.resources_seen if adaptation is not None else None
        ),
        "resources_adapted": (
            adaptation.resources_adapted if adaptation is not None else None
        ),
        "security_evaluation_status": result.security_evaluation_status.value,
        "security_findings_total": (
            evaluation.findings_total if evaluation is not None else None
        ),
        "security_failed": evaluation.failed if evaluation is not None else None,
        "security_warnings": (
            evaluation.warnings if evaluation is not None else None
        ),
        "security_report_json": result.security_json_path,
        "security_report_text": result.security_text_path,
        "temp_plan_cleaned": result.temporary_plan_cleaned,
    }
    for key, value in values.items():
        print(f"{key}={_display_value(value)}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the safe Terraform-to-security reporting pipeline."
    )
    parser.add_argument("--cloud", required=True, choices=("gcp", "oci"))
    parser.add_argument("--write-report", action="store_true")
    arguments = parser.parse_args(argv)

    result = build_default_terraform_security_engine().run(
        cloud=arguments.cloud,
        write_report=arguments.write_report,
    )
    _print_safe_summary(result)
    return 0 if result.engine_status is TerraformEngineStatus.PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
