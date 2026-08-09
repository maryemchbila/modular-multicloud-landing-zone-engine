"""Pipeline de validation suivi d'un plan Terraform speculatif."""

from __future__ import annotations

import logging
import time
from pathlib import Path

from terraform_error_classifier import TerraformErrorClassifier
from terraform_models import (
    TerraformErrorClassification,
    TerraformPipelineStatus,
    TerraformPlanPipelineResult,
    TerraformPlanStatus,
    TerraformResult,
    TerraformValidationPipelineResult,
)
from terraform_pipeline import TerraformValidationPipeline
from terraform_runner import TerraformRunner


LOGGER = logging.getLogger(__name__)


class TerraformPlanPipeline:
    """Compose la validation PLAN-2 et un terraform plan non destructif."""

    PLAN_ARGS = ["plan", "-input=false", "-no-color", "-detailed-exitcode"]

    def __init__(
        self,
        runner: TerraformRunner,
        validation_pipeline: TerraformValidationPipeline | None = None,
        plan_timeout: float = 180.0,
        error_classifier: TerraformErrorClassifier | None = None,
    ) -> None:
        self.runner = runner
        self.error_classifier = error_classifier or TerraformErrorClassifier()
        self.validation_pipeline = (
            validation_pipeline
            if validation_pipeline is not None
            else TerraformValidationPipeline(
                runner, error_classifier=self.error_classifier
            )
        )
        self.plan_timeout = self._validate_timeout(plan_timeout)

    def run(self, cloud: str) -> TerraformPlanPipelineResult:
        """Valide la configuration puis lance plan uniquement si elle est valide."""

        started_at = time.perf_counter()
        validation_result = self.validation_pipeline.run(cloud)

        if validation_result.final_status is not TerraformPipelineStatus.PASS:
            final_status = (
                TerraformPlanStatus.BLOCKED
                if validation_result.final_status is TerraformPipelineStatus.BLOCKED
                else TerraformPlanStatus.ERROR
            )
            return self._build_result(
                validation_result=validation_result,
                plan_result=None,
                plan_status=TerraformPlanStatus.SKIPPED,
                final_status=final_status,
                failed_step=validation_result.failed_step,
                started_at=started_at,
                error_classification=validation_result.error_classification,
            )

        working_directory = Path(validation_result.working_directory)
        plan_result = self.runner.run(
            self.PLAN_ARGS,
            cwd=working_directory,
            timeout=self.plan_timeout,
        )
        plan_status = self._interpret_plan_result(plan_result)
        failed_step = (
            "plan"
            if plan_status in {TerraformPlanStatus.ERROR, TerraformPlanStatus.BLOCKED}
            else None
        )
        self._log_plan(validation_result.cloud, plan_result, plan_status)
        return self._build_result(
            validation_result=validation_result,
            plan_result=plan_result,
            plan_status=plan_status,
            final_status=plan_status,
            failed_step=failed_step,
            started_at=started_at,
            error_classification=(
                self.error_classifier.classify("plan", plan_result)
                if failed_step == "plan"
                else None
            ),
        )

    @staticmethod
    def _interpret_plan_result(result: TerraformResult) -> TerraformPlanStatus:
        if result.timed_out:
            return TerraformPlanStatus.BLOCKED
        if result.exit_code == 0:
            return TerraformPlanStatus.NO_CHANGES
        if result.exit_code == 2:
            return TerraformPlanStatus.CHANGES_DETECTED
        return TerraformPlanStatus.ERROR

    @staticmethod
    def _validate_timeout(timeout: float) -> float:
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or timeout <= 0
        ):
            raise ValueError(
                "Le timeout Terraform pour plan doit etre strictement positif."
            )
        return float(timeout)

    @staticmethod
    def _build_result(
        validation_result: TerraformValidationPipelineResult,
        plan_result: TerraformResult | None,
        plan_status: TerraformPlanStatus,
        final_status: TerraformPlanStatus,
        failed_step: str | None,
        started_at: float,
        error_classification: TerraformErrorClassification | None,
    ) -> TerraformPlanPipelineResult:
        return TerraformPlanPipelineResult(
            cloud=validation_result.cloud,
            working_directory=validation_result.working_directory,
            validation_result=validation_result,
            plan_result=plan_result,
            plan_status=plan_status,
            final_status=final_status,
            failed_step=failed_step,
            duration_seconds=time.perf_counter() - started_at,
            error_classification=error_classification,
        )

    @staticmethod
    def _log_plan(
        cloud: str,
        result: TerraformResult,
        status: TerraformPlanStatus,
    ) -> None:
        LOGGER.info(
            "[terraform] cloud=%s step=plan status=%s cwd=%s "
            "exit_code=%s duration=%.3fs timed_out=%s",
            cloud,
            status.value,
            result.working_directory,
            result.exit_code,
            result.duration_seconds,
            result.timed_out,
        )
