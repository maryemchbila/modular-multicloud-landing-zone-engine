"""Orchestration end-to-end du plan Terraform jusqu'au rapport PLAN-6."""

from __future__ import annotations

import argparse
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Sequence

from terraform_models import TerraformPlanPipelineResult
from terraform_pipeline import TerraformValidationPipeline
from terraform_plan import TerraformPlanPipeline
from terraform_report import TerraformExecutionReport, TerraformReportBuilder
from terraform_runner import TerraformRunner


class TerraformEngineStatus(str, Enum):
    """Statut du moteur, distinct du resultat fonctionnel de Terraform."""

    PASS = "PASS"
    FAIL = "FAIL"


@dataclass(frozen=True)
class TerraformEndToEndResult:
    """Resultat E2E conservant les objets PLAN-3 et PLAN-5 sans duplication."""

    cloud: str
    engine_status: TerraformEngineStatus
    plan_pipeline_result: TerraformPlanPipelineResult | None
    report: TerraformExecutionReport | None
    report_written: bool
    json_path: Path | None
    text_path: Path | None
    duration_seconds: float
    engine_error: str | None = None

    @property
    def terraform_final_status(self) -> str | None:
        """Expose le statut Terraform sans le confondre avec celui du moteur."""

        if self.report is not None:
            return self.report.final_status
        if self.plan_pipeline_result is not None:
            return self.plan_pipeline_result.final_status.value
        return None

    @property
    def json(self) -> str | None:
        """Retourne le JSON en memoire lorsqu'un rapport a ete construit."""

        return self.report.to_json() if self.report is not None else None

    @property
    def text(self) -> str | None:
        """Retourne le texte en memoire lorsqu'un rapport a ete construit."""

        return self.report.render_text() if self.report is not None else None

    def to_dict(self) -> dict[str, Any]:
        """Retourne une synthese E2E sans sorties Terraform brutes."""

        return {
            "cloud": self.cloud,
            "engine_status": self.engine_status.value,
            "terraform_final_status": self.terraform_final_status,
            "report_written": self.report_written,
            "json_path": str(self.json_path) if self.json_path is not None else None,
            "text_path": str(self.text_path) if self.text_path is not None else None,
            "duration_seconds": self.duration_seconds,
            "engine_error": self.engine_error,
            "report": self.report.to_dict() if self.report is not None else None,
        }


class TerraformEndToEndPipeline:
    """Connecte exactement une execution PLAN-3 a exactement un rapport PLAN-5."""

    INTERNAL_ERROR_MESSAGE = "Internal Terraform engine error."

    def __init__(
        self,
        plan_pipeline: TerraformPlanPipeline,
        report_builder: TerraformReportBuilder,
    ) -> None:
        self.plan_pipeline = plan_pipeline
        self.report_builder = report_builder

    def run(
        self,
        cloud: str,
        write_report: bool = False,
        report_directory: Path | None = None,
        plan_output_path: Path | None = None,
    ) -> TerraformEndToEndResult:
        """Execute un passage logique Terraform puis construit un rapport unique."""

        normalised_cloud = self._normalise_cloud(cloud)
        started_at = time.perf_counter()
        plan_result: TerraformPlanPipelineResult | None = None
        report: TerraformExecutionReport | None = None

        try:
            if plan_output_path is None:
                plan_result = self.plan_pipeline.run(normalised_cloud)
            else:
                plan_result = self.plan_pipeline.run(
                    normalised_cloud,
                    plan_output_path=plan_output_path,
                )
            report = self.report_builder.build(plan_result)
            json_path: Path | None = None
            text_path: Path | None = None
            if write_report:
                json_path, text_path = self.report_builder.write_report(
                    report,
                    output_directory=report_directory,
                )
            return TerraformEndToEndResult(
                cloud=normalised_cloud,
                engine_status=TerraformEngineStatus.PASS,
                plan_pipeline_result=plan_result,
                report=report,
                report_written=write_report,
                json_path=json_path,
                text_path=text_path,
                duration_seconds=round(time.perf_counter() - started_at, 6),
            )
        except Exception:
            return TerraformEndToEndResult(
                cloud=normalised_cloud,
                engine_status=TerraformEngineStatus.FAIL,
                plan_pipeline_result=plan_result,
                report=report,
                report_written=False,
                json_path=None,
                text_path=None,
                duration_seconds=round(time.perf_counter() - started_at, 6),
                engine_error=self.INTERNAL_ERROR_MESSAGE,
            )

    @staticmethod
    def _normalise_cloud(cloud: str) -> str:
        return TerraformValidationPipeline._normalise_cloud(cloud)


def build_default_engine(
    repository_root: Path | None = None,
) -> TerraformEndToEndPipeline:
    """Assemble les composants valides PLAN-1 a PLAN-5 pour une execution reelle."""

    runner = TerraformRunner()
    validation_pipeline = TerraformValidationPipeline(
        runner,
        repository_root=repository_root,
    )
    plan_pipeline = TerraformPlanPipeline(
        runner,
        validation_pipeline=validation_pipeline,
    )
    report_builder = TerraformReportBuilder(repository_root=repository_root)
    return TerraformEndToEndPipeline(plan_pipeline, report_builder)


def _display_value(value: object | None) -> str:
    return str(value) if value is not None else "NONE"


def _print_safe_summary(result: TerraformEndToEndResult) -> None:
    """Affiche uniquement les champs synthetiques demandes pour la validation."""

    report = result.report
    plan_result = result.plan_pipeline_result
    values = {
        "engine_status": result.engine_status.value,
        "cloud": result.cloud,
        "fmt_status": report.fmt_status if report is not None else None,
        "init_status": report.init_status if report is not None else None,
        "validate_status": report.validate_status if report is not None else None,
        "plan_status": report.plan_status if report is not None else None,
        "plan_exit_code": report.plan_exit_code if report is not None else None,
        "terraform_final_status": result.terraform_final_status,
        "failed_step": (
            plan_result.failed_step if plan_result is not None else None
        ),
        "error_category": (
            report.error_category if report is not None else None
        ),
        "reason_code": report.reason_code if report is not None else None,
        "run_id": report.run_id if report is not None else None,
        "report_json": (
            result.json_path
            if result.json_path is not None
            else ("IN_MEMORY" if report is not None else None)
        ),
        "report_text": (
            result.text_path
            if result.text_path is not None
            else ("IN_MEMORY" if report is not None else None)
        ),
    }
    for key, value in values.items():
        print(f"{key}={_display_value(value)}")


def main(argv: Sequence[str] | None = None) -> int:
    """Point d'entree minimal pour les validations PowerShell GCP et OCI."""

    parser = argparse.ArgumentParser(
        description="Run the safe Terraform end-to-end plan pipeline."
    )
    parser.add_argument("--cloud", required=True, choices=("gcp", "oci"))
    parser.add_argument("--write-report", action="store_true")
    parser.add_argument("--report-directory", type=Path)
    arguments = parser.parse_args(argv)

    engine = build_default_engine()
    result = engine.run(
        cloud=arguments.cloud,
        write_report=arguments.write_report,
        report_directory=arguments.report_directory,
    )
    _print_safe_summary(result)
    return 0 if result.engine_status is TerraformEngineStatus.PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
