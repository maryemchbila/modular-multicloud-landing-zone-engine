"""Rapports synthetiques et surs produits depuis un resultat Terraform plan."""

from __future__ import annotations

import json
import re
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from terraform_models import TerraformPlanPipelineResult, TerraformResult


@dataclass(frozen=True)
class TerraformExecutionReport:
    """Vue stable d'un pipeline plan, sans stdout ni stderr bruts."""

    schema_version: str
    run_id: str
    generated_at: str
    cloud: str
    working_directory: str
    fmt_status: str
    init_status: str
    validate_status: str
    plan_status: str
    final_status: str
    failed_step: str | None
    total_duration_seconds: float
    fmt_exit_code: int | None
    init_exit_code: int | None
    validate_exit_code: int | None
    plan_exit_code: int | None
    fmt_duration_seconds: float | None
    init_duration_seconds: float | None
    validate_duration_seconds: float | None
    plan_duration_seconds: float | None
    fmt_timed_out: bool | None
    init_timed_out: bool | None
    validate_timed_out: bool | None
    plan_timed_out: bool | None
    error_category: str | None
    reason_code: str | None
    error_message: str | None
    add_count: int | None
    change_count: int | None
    destroy_count: int | None

    def to_dict(self) -> dict[str, Any]:
        """Retourne la structure JSON stable du schema PLAN-5 version 1.0."""

        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "generated_at": self.generated_at,
            "cloud": self.cloud,
            "working_directory": self.working_directory,
            "steps": {
                "fmt": self._step_to_dict(
                    self.fmt_status,
                    self.fmt_exit_code,
                    self.fmt_duration_seconds,
                    self.fmt_timed_out,
                ),
                "init": self._step_to_dict(
                    self.init_status,
                    self.init_exit_code,
                    self.init_duration_seconds,
                    self.init_timed_out,
                ),
                "validate": self._step_to_dict(
                    self.validate_status,
                    self.validate_exit_code,
                    self.validate_duration_seconds,
                    self.validate_timed_out,
                ),
                "plan": self._step_to_dict(
                    self.plan_status,
                    self.plan_exit_code,
                    self.plan_duration_seconds,
                    self.plan_timed_out,
                ),
            },
            "changes": {
                "add": self.add_count,
                "change": self.change_count,
                "destroy": self.destroy_count,
            },
            "error": (
                {
                    "category": self.error_category,
                    "reason_code": self.reason_code,
                    "message": self.error_message,
                }
                if self.error_category is not None
                else None
            ),
            "failed_step": self.failed_step,
            "final_status": self.final_status,
            "total_duration_seconds": self.total_duration_seconds,
            "safety": {
                "apply_executed": False,
                "destroy_executed": False,
            },
        }

    def to_json(self, indent: int | None = 2) -> str:
        """Serialise le rapport en JSON UTF-8 compatible."""

        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def render_text(self) -> str:
        """Produit un resume lisible ne contenant aucune sortie Terraform brute."""

        separator = "=" * 56
        lines = [
            separator,
            " TERRAFORM PLAN REPORT",
            separator,
            f"Run ID          : {self.run_id}",
            f"Generated At    : {self.generated_at}",
            f"Cloud           : {self.cloud.upper()}",
            f"Working Dir     : {self.working_directory}",
            "",
            f"FMT             : {self.fmt_status}",
            f"INIT            : {self.init_status}",
            f"VALIDATE        : {self.validate_status}",
            f"PLAN            : {self.plan_status}",
            "",
            f"Add             : {self._display_count(self.add_count)}",
            f"Change          : {self._display_count(self.change_count)}",
            f"Destroy         : {self._display_count(self.destroy_count)}",
        ]
        if self.failed_step is not None:
            lines.extend(("", f"Failed Step     : {self.failed_step}"))
        if self.error_category is not None:
            lines.extend(
                (
                    f"Error Category  : {self.error_category}",
                    f"Reason Code     : {self.reason_code}",
                    f"Error Message   : {self.error_message}",
                )
            )
        lines.extend(
            (
                "",
                f"Final Status    : {self.final_status}",
                f"Total Duration  : {self.total_duration_seconds:.6f}s",
                "",
                "Infrastructure changes applied : NO",
                separator,
            )
        )
        return "\n".join(lines)

    @staticmethod
    def _step_to_dict(
        status: str,
        exit_code: int | None,
        duration_seconds: float | None,
        timed_out: bool | None,
    ) -> dict[str, Any]:
        return {
            "status": status,
            "exit_code": exit_code,
            "duration_seconds": duration_seconds,
            "timed_out": timed_out,
        }

    @staticmethod
    def _display_count(value: int | None) -> str:
        return str(value) if value is not None else "N/A"


class TerraformReportBuilder:
    """Transforme un resultat PLAN-3 en rapport, sans lancer Terraform."""

    SCHEMA_VERSION = "1.0"
    DEFAULT_REPORT_DIRECTORY = Path("artifacts") / "terraform" / "reports"
    _PLAN_COUNTS_PATTERN = re.compile(
        r"\bPlan:\s*(\d+)\s+to add,\s*(\d+)\s+to change,\s*"
        r"(\d+)\s+to destroy\.?",
        re.IGNORECASE,
    )
    _NO_CHANGES_PATTERN = re.compile(r"\bNo changes\.?", re.IGNORECASE)
    _SAFE_RUN_ID_PATTERN = re.compile(
        r"\Atfplan_[a-z0-9_-]+_\d{8}T\d{6}Z_[0-9a-f]{8}\Z"
    )

    def __init__(
        self,
        repository_root: Path | None = None,
        now_factory: Callable[[], datetime] | None = None,
        uuid_factory: Callable[[], UUID] | None = None,
    ) -> None:
        self.repository_root = (
            Path(repository_root).expanduser().resolve()
            if repository_root is not None
            else Path(__file__).resolve().parent.parent
        )
        self._now_factory = now_factory or (lambda: datetime.now(timezone.utc))
        self._uuid_factory = uuid_factory or uuid4

    def build(self, result: TerraformPlanPipelineResult) -> TerraformExecutionReport:
        """Construit un rapport en memoire, sans ecriture ni autre effet de bord."""

        generated_datetime = self._utc_now()
        generated_at = self._iso_utc(generated_datetime)
        run_id = self._build_run_id(
            result.cloud,
            generated_datetime,
            self._uuid_factory(),
        )
        validation = result.validation_result
        step_results = (
            validation.fmt_result,
            validation.init_result,
            validation.validate_result,
            result.plan_result,
        )
        total_duration = round(
            sum(
                step_result.duration_seconds
                for step_result in step_results
                if step_result is not None
            ),
            6,
        )
        add_count, change_count, destroy_count = self._extract_plan_counts(
            result.plan_result
        )
        classification = result.error_classification

        return TerraformExecutionReport(
            schema_version=self.SCHEMA_VERSION,
            run_id=run_id,
            generated_at=generated_at,
            cloud=result.cloud,
            working_directory=self._normalise_working_directory(
                result.working_directory
            ),
            fmt_status=validation.fmt_status.value,
            init_status=validation.init_status.value,
            validate_status=validation.validate_status.value,
            plan_status=result.plan_status.value,
            final_status=result.final_status.value,
            failed_step=result.failed_step,
            total_duration_seconds=total_duration,
            fmt_exit_code=self._exit_code(validation.fmt_result),
            init_exit_code=self._exit_code(validation.init_result),
            validate_exit_code=self._exit_code(validation.validate_result),
            plan_exit_code=self._exit_code(result.plan_result),
            fmt_duration_seconds=self._duration(validation.fmt_result),
            init_duration_seconds=self._duration(validation.init_result),
            validate_duration_seconds=self._duration(validation.validate_result),
            plan_duration_seconds=self._duration(result.plan_result),
            fmt_timed_out=self._timed_out(validation.fmt_result),
            init_timed_out=self._timed_out(validation.init_result),
            validate_timed_out=self._timed_out(validation.validate_result),
            plan_timed_out=self._timed_out(result.plan_result),
            error_category=(
                classification.category.value
                if classification is not None
                else None
            ),
            reason_code=(
                classification.reason_code
                if classification is not None
                else None
            ),
            error_message=(
                classification.message if classification is not None else None
            ),
            add_count=add_count,
            change_count=change_count,
            destroy_count=destroy_count,
        )

    def write_report(
        self,
        report: TerraformExecutionReport,
        output_directory: Path | None = None,
    ) -> tuple[Path, Path]:
        """Ecrit explicitement les variantes JSON et texte en UTF-8 atomique."""

        if not self._SAFE_RUN_ID_PATTERN.fullmatch(report.run_id):
            raise ValueError("run_id invalide pour un nom de fichier de rapport")
        report_directory = (
            Path(output_directory).expanduser().resolve()
            if output_directory is not None
            else (self.repository_root / self.DEFAULT_REPORT_DIRECTORY).resolve()
        )
        report_directory.mkdir(parents=True, exist_ok=True)
        json_path = report_directory / f"{report.run_id}.json"
        text_path = report_directory / f"{report.run_id}.txt"
        self._write_atomic(json_path, report.to_json() + "\n")
        self._write_atomic(text_path, report.render_text() + "\n")
        return json_path, text_path

    def _utc_now(self) -> datetime:
        generated_datetime = self._now_factory()
        if generated_datetime.tzinfo is None:
            raise ValueError("now_factory doit retourner un datetime avec fuseau")
        return generated_datetime.astimezone(timezone.utc)

    @staticmethod
    def _iso_utc(value: datetime) -> str:
        return value.isoformat(timespec="seconds").replace("+00:00", "Z")

    @classmethod
    def _build_run_id(cls, cloud: str, generated_at: datetime, value: UUID) -> str:
        safe_cloud = re.sub(r"[^a-z0-9_-]+", "-", cloud.casefold()).strip("-_")
        if not safe_cloud:
            safe_cloud = "cloud"
        timestamp = generated_at.strftime("%Y%m%dT%H%M%SZ")
        return f"tfplan_{safe_cloud}_{timestamp}_{value.hex[:8]}"

    def _normalise_working_directory(self, working_directory: str) -> str:
        path = Path(working_directory).expanduser().resolve()
        try:
            return path.relative_to(self.repository_root).as_posix()
        except ValueError:
            return path.as_posix()

    @classmethod
    def _extract_plan_counts(
        cls,
        result: TerraformResult | None,
    ) -> tuple[int | None, int | None, int | None]:
        if result is None:
            return None, None, None
        output = "\n".join((result.stdout or "", result.stderr or ""))
        match = cls._PLAN_COUNTS_PATTERN.search(output)
        if match is not None:
            return tuple(int(value) for value in match.groups())
        if cls._NO_CHANGES_PATTERN.search(output):
            return 0, 0, 0
        return None, None, None

    @staticmethod
    def _exit_code(result: TerraformResult | None) -> int | None:
        return result.exit_code if result is not None else None

    @staticmethod
    def _duration(result: TerraformResult | None) -> float | None:
        return round(result.duration_seconds, 6) if result is not None else None

    @staticmethod
    def _timed_out(result: TerraformResult | None) -> bool | None:
        return result.timed_out if result is not None else None

    @staticmethod
    def _write_atomic(path: Path, content: str) -> None:
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                newline="\n",
                dir=path.parent,
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary_file:
                temporary_file.write(content)
                temporary_path = Path(temporary_file.name)
            temporary_path.replace(path)
        finally:
            if temporary_path is not None and temporary_path.exists():
                temporary_path.unlink()
