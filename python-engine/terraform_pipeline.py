"""Pipeline local de formatage et de validation Terraform."""

from __future__ import annotations

import logging
import time
from pathlib import Path

from terraform_error_classifier import TerraformErrorClassifier
from terraform_models import (
    TerraformPipelineStatus,
    TerraformResult,
    TerraformValidationPipelineResult,
    TerraformWorkingDirectoryError,
    UnknownTerraformCloudError,
)
from terraform_runner import TerraformRunner


LOGGER = logging.getLogger(__name__)


class TerraformValidationPipeline:
    """Orchestre fmt, init et validate via un TerraformRunner injecte."""

    CLOUD_DIRECTORIES = {
        "gcp": Path("hcl-generator") / "generated" / "gcp",
        "oci": Path("hcl-generator") / "generated" / "oci",
    }
    FMT_ARGS = ["fmt", "-check", "-recursive"]
    INIT_ARGS = ["init", "-backend=false", "-input=false", "-no-color"]
    VALIDATE_ARGS = ["validate", "-no-color"]

    def __init__(
        self,
        runner: TerraformRunner,
        repository_root: Path | None = None,
        fmt_timeout: float = 30.0,
        init_timeout: float = 120.0,
        validate_timeout: float = 60.0,
        error_classifier: TerraformErrorClassifier | None = None,
    ) -> None:
        self.runner = runner
        self.repository_root = (
            Path(repository_root).expanduser().resolve()
            if repository_root is not None
            else Path(__file__).resolve().parent.parent
        )
        self.fmt_timeout = self._validate_timeout("fmt", fmt_timeout)
        self.init_timeout = self._validate_timeout("init", init_timeout)
        self.validate_timeout = self._validate_timeout(
            "validate", validate_timeout
        )
        self.error_classifier = error_classifier or TerraformErrorClassifier()

    def run(self, cloud: str) -> TerraformValidationPipelineResult:
        """Execute les trois etapes dans l'ordre, avec arret au premier echec."""

        normalised_cloud = self._normalise_cloud(cloud)
        working_directory = self.resolve_working_directory(normalised_cloud)
        started_at = time.perf_counter()

        fmt_result = self.runner.run(
            self.FMT_ARGS,
            cwd=working_directory,
            timeout=self.fmt_timeout,
        )
        self._log_step(normalised_cloud, "fmt", fmt_result)
        if not fmt_result.success:
            return self._build_result(
                normalised_cloud,
                working_directory,
                started_at,
                fmt_result=fmt_result,
                failed_step="fmt",
            )

        init_result = self.runner.run(
            self.INIT_ARGS,
            cwd=working_directory,
            timeout=self.init_timeout,
        )
        self._log_step(normalised_cloud, "init", init_result)
        if not init_result.success:
            return self._build_result(
                normalised_cloud,
                working_directory,
                started_at,
                fmt_result=fmt_result,
                init_result=init_result,
                failed_step="init",
            )

        validate_result = self.runner.run(
            self.VALIDATE_ARGS,
            cwd=working_directory,
            timeout=self.validate_timeout,
        )
        self._log_step(normalised_cloud, "validate", validate_result)
        if not validate_result.success:
            return self._build_result(
                normalised_cloud,
                working_directory,
                started_at,
                fmt_result=fmt_result,
                init_result=init_result,
                validate_result=validate_result,
                failed_step="validate",
            )

        return self._build_result(
            normalised_cloud,
            working_directory,
            started_at,
            fmt_result=fmt_result,
            init_result=init_result,
            validate_result=validate_result,
        )

    def resolve_working_directory(self, cloud: str) -> Path:
        """Resout une racine Terraform controlee sans dependre du cwd courant."""

        normalised_cloud = self._normalise_cloud(cloud)
        working_directory = (
            self.repository_root / self.CLOUD_DIRECTORIES[normalised_cloud]
        ).resolve()
        if not working_directory.exists():
            raise TerraformWorkingDirectoryError(
                f"Le repertoire Terraform n'existe pas : {working_directory}"
            )
        if not working_directory.is_dir():
            raise TerraformWorkingDirectoryError(
                f"Le chemin Terraform n'est pas un dossier : {working_directory}"
            )
        return working_directory

    @classmethod
    def _normalise_cloud(cls, cloud: str) -> str:
        if not isinstance(cloud, str):
            raise UnknownTerraformCloudError(
                "Le cloud Terraform doit etre 'gcp' ou 'oci'."
            )
        normalised_cloud = cloud.strip().casefold()
        if normalised_cloud not in cls.CLOUD_DIRECTORIES:
            raise UnknownTerraformCloudError(
                f"Cloud Terraform inconnu : {cloud!r}. Valeurs autorisees : gcp, oci."
            )
        return normalised_cloud

    @staticmethod
    def _validate_timeout(step: str, timeout: float) -> float:
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or timeout <= 0
        ):
            raise ValueError(
                f"Le timeout Terraform pour {step} doit etre strictement positif."
            )
        return float(timeout)

    @staticmethod
    def _status_for_result(
        result: TerraformResult | None,
    ) -> TerraformPipelineStatus:
        if result is None:
            return TerraformPipelineStatus.SKIPPED
        if result.timed_out:
            return TerraformPipelineStatus.BLOCKED
        if result.success:
            return TerraformPipelineStatus.PASS
        return TerraformPipelineStatus.FAIL

    def _build_result(
        self,
        cloud: str,
        working_directory: Path,
        started_at: float,
        fmt_result: TerraformResult | None = None,
        init_result: TerraformResult | None = None,
        validate_result: TerraformResult | None = None,
        failed_step: str | None = None,
    ) -> TerraformValidationPipelineResult:
        fmt_status = self._status_for_result(fmt_result)
        init_status = self._status_for_result(init_result)
        validate_status = self._status_for_result(validate_result)

        if failed_step is None:
            final_status = TerraformPipelineStatus.PASS
        else:
            failed_result = {
                "fmt": fmt_result,
                "init": init_result,
                "validate": validate_result,
            }[failed_step]
            final_status = self._status_for_result(failed_result)

        error_classification = None
        if failed_step is not None:
            failed_result = {
                "fmt": fmt_result,
                "init": init_result,
                "validate": validate_result,
            }[failed_step]
            if failed_result is not None:
                error_classification = self.error_classifier.classify(
                    failed_step, failed_result
                )

        return TerraformValidationPipelineResult(
            cloud=cloud,
            working_directory=str(working_directory),
            fmt_result=fmt_result,
            init_result=init_result,
            validate_result=validate_result,
            fmt_status=fmt_status,
            init_status=init_status,
            validate_status=validate_status,
            final_status=final_status,
            failed_step=failed_step,
            duration_seconds=time.perf_counter() - started_at,
            error_classification=error_classification,
        )

    @classmethod
    def _log_step(cls, cloud: str, step: str, result: TerraformResult) -> None:
        status = cls._status_for_result(result)
        LOGGER.info(
            "[terraform] cloud=%s step=%s status=%s cwd=%s "
            "exit_code=%s duration=%.3fs timed_out=%s",
            cloud,
            step,
            status.value,
            result.working_directory,
            result.exit_code,
            result.duration_seconds,
            result.timed_out,
        )
