"""Modeles et erreurs partages par le runner Terraform."""

from __future__ import annotations

from dataclasses import dataclass
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
