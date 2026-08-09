"""Execution locale, non interactive et securisee de Terraform."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Sequence

from terraform_models import (
    TerraformArgumentsError,
    TerraformExecutionError,
    TerraformNotFoundError,
    TerraformResult,
    TerraformWorkingDirectoryError,
    UnsafeTerraformCommandError,
)


LOGGER = logging.getLogger(__name__)


class TerraformRunner:
    """Lance une commande Terraform autorisee dans un repertoire explicite."""

    DEFAULT_TIMEOUT = 60.0
    ALLOWED_COMMANDS = frozenset(
        {"version", "fmt", "init", "validate", "providers", "plan", "show"}
    )
    UNSAFE_COMMANDS = frozenset({"apply", "destroy"})

    def __init__(
        self,
        terraform_binary: str = "terraform",
        default_timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        if not terraform_binary or not terraform_binary.strip():
            raise ValueError("terraform_binary ne peut pas etre vide")
        self.terraform_binary = terraform_binary
        self.default_timeout = self._validate_timeout(default_timeout)

    def run(
        self,
        args: Sequence[str],
        cwd: Path,
        timeout: float | None = None,
    ) -> TerraformResult:
        """Execute Terraform et retourne stdout, stderr, code et duree separes."""

        safe_args = self._validate_args(args)
        working_directory = self._resolve_working_directory(cwd)
        executable = self._find_terraform()
        effective_timeout = self._validate_timeout(
            self.default_timeout if timeout is None else timeout
        )
        command = [executable, *safe_args]
        child_environment = os.environ.copy()
        child_environment["TF_IN_AUTOMATION"] = "1"
        child_environment["TF_INPUT"] = "0"

        LOGGER.info(
            "Terraform command: %s; cwd: %s",
            safe_args[0],
            working_directory,
        )
        started_at = time.perf_counter()

        try:
            completed = subprocess.run(
                command,
                cwd=str(working_directory),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=effective_timeout,
                env=child_environment,
                stdin=subprocess.DEVNULL,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            duration = time.perf_counter() - started_at
            result = TerraformResult(
                command=executable,
                args=safe_args,
                working_directory=str(working_directory),
                exit_code=None,
                stdout=self._normalise_output(exc.stdout),
                stderr=self._normalise_output(exc.stderr),
                duration_seconds=duration,
                timed_out=True,
                success=False,
            )
            LOGGER.warning(
                "Terraform command timed out; cwd: %s; duration: %.3fs",
                working_directory,
                duration,
            )
            return result
        except OSError as exc:
            raise TerraformExecutionError(
                f"Impossible de lancer Terraform ({executable}) : {exc}"
            ) from exc

        duration = time.perf_counter() - started_at
        result = TerraformResult(
            command=executable,
            args=safe_args,
            working_directory=str(working_directory),
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            duration_seconds=duration,
            timed_out=False,
            success=completed.returncode == 0,
        )
        LOGGER.info(
            "Terraform finished; cwd: %s; exit_code: %s; duration: %.3fs",
            working_directory,
            completed.returncode,
            duration,
        )
        return result

    def _find_terraform(self) -> str:
        executable = shutil.which(self.terraform_binary)
        if executable is None:
            raise TerraformNotFoundError(
                f"Binaire Terraform introuvable : {self.terraform_binary!r}. "
                "Installez Terraform ou fournissez son chemin explicite."
            )
        return executable

    @classmethod
    def _validate_args(cls, args: Sequence[str]) -> tuple[str, ...]:
        if isinstance(args, (str, bytes)):
            raise TerraformArgumentsError(
                "Les arguments Terraform doivent etre fournis sous forme de liste."
            )

        try:
            validated_args = tuple(args)
        except TypeError as exc:
            raise TerraformArgumentsError(
                "Les arguments Terraform doivent etre une sequence de chaines."
            ) from exc

        if not validated_args:
            raise TerraformArgumentsError("Une commande Terraform est obligatoire.")
        if any(not isinstance(argument, str) or not argument for argument in validated_args):
            raise TerraformArgumentsError(
                "Chaque argument Terraform doit etre une chaine non vide."
            )

        normalised_tokens = {argument.strip().casefold() for argument in validated_args}
        blocked = normalised_tokens.intersection(cls.UNSAFE_COMMANDS)
        if blocked:
            command = sorted(blocked)[0]
            raise UnsafeTerraformCommandError(
                f"Commande Terraform interdite dans ce runner : {command}"
            )

        subcommand = validated_args[0].strip().casefold()
        if subcommand not in cls.ALLOWED_COMMANDS:
            raise TerraformArgumentsError(
                f"Commande Terraform non autorisee : {validated_args[0]!r}"
            )
        return validated_args

    @staticmethod
    def _resolve_working_directory(cwd: Path) -> Path:
        try:
            working_directory = Path(cwd).expanduser().resolve()
        except (OSError, TypeError, ValueError) as exc:
            raise TerraformWorkingDirectoryError(
                f"Repertoire Terraform invalide : {cwd!r}"
            ) from exc

        if not working_directory.exists():
            raise TerraformWorkingDirectoryError(
                f"Le repertoire Terraform n'existe pas : {working_directory}"
            )
        if not working_directory.is_dir():
            raise TerraformWorkingDirectoryError(
                f"Le chemin Terraform n'est pas un dossier : {working_directory}"
            )
        return working_directory

    @staticmethod
    def _validate_timeout(timeout: float) -> float:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise ValueError("Le timeout Terraform doit etre un nombre positif.")
        if timeout <= 0:
            raise ValueError("Le timeout Terraform doit etre strictement positif.")
        return float(timeout)

    @staticmethod
    def _normalise_output(output: str | bytes | None) -> str:
        if output is None:
            return ""
        if isinstance(output, bytes):
            return output.decode("utf-8", errors="replace")
        return output
