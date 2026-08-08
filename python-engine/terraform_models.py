"""Modeles et erreurs partages par le runner Terraform."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class TerraformRunnerError(RuntimeError):
    """Erreur locale empechant le runner Terraform de terminer normalement."""


class TerraformNotFoundError(TerraformRunnerError):
    """Le binaire Terraform configure est introuvable."""


class TerraformWorkingDirectoryError(TerraformRunnerError):
    """Le repertoire de travail Terraform est invalide."""


class TerraformArgumentsError(TerraformRunnerError):
    """Les arguments Terraform ne constituent pas une commande acceptee."""


class UnsafeTerraformCommandError(TerraformArgumentsError):
    """La commande demandee pourrait modifier ou detruire l'infrastructure."""


class TerraformExecutionError(TerraformRunnerError):
    """Terraform n'a pas pu etre lance par le systeme d'exploitation."""


class UnknownTerraformCloudError(ValueError):
    """Le cloud demande ne correspond a aucune racine Terraform autorisee."""


class TerraformPipelineStatus(str, Enum):
    """Statut d'une etape ou du pipeline de validation Terraform."""

    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    SKIPPED = "SKIPPED"


@dataclass(frozen=True)
class TerraformResult:
    """Resultat complet et serialisable d'une execution Terraform."""

    command: str
    args: tuple[str, ...]
    working_directory: str
    exit_code: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool
    success: bool

    def to_dict(self) -> dict[str, Any]:
        """Retourne une representation directement exploitable en JSON."""

        return {
            "command": self.command,
            "args": list(self.args),
            "working_directory": self.working_directory,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_seconds": self.duration_seconds,
            "timed_out": self.timed_out,
            "success": self.success,
        }


@dataclass(frozen=True)
class TerraformValidationPipelineResult:
    """Resultat structure des etapes fmt, init et validate."""

    cloud: str
    working_directory: str
    fmt_result: TerraformResult | None
    init_result: TerraformResult | None
    validate_result: TerraformResult | None
    fmt_status: TerraformPipelineStatus
    init_status: TerraformPipelineStatus
    validate_status: TerraformPipelineStatus
    final_status: TerraformPipelineStatus
    failed_step: str | None
    duration_seconds: float

    def to_dict(self) -> dict[str, Any]:
        """Retourne une representation JSON-compatible du pipeline."""

        return {
            "cloud": self.cloud,
            "working_directory": self.working_directory,
            "fmt": self._step_to_dict(self.fmt_status, self.fmt_result),
            "init": self._step_to_dict(self.init_status, self.init_result),
            "validate": self._step_to_dict(
                self.validate_status, self.validate_result
            ),
            "final_status": self.final_status.value,
            "failed_step": self.failed_step,
            "duration_seconds": self.duration_seconds,
        }

    @staticmethod
    def _step_to_dict(
        status: TerraformPipelineStatus,
        result: TerraformResult | None,
    ) -> dict[str, Any]:
        return {
            "status": status.value,
            "result": result.to_dict() if result is not None else None,
        }
