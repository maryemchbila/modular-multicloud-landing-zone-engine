"""Adaptateur d'execution du generateur Go existant."""

import subprocess
from pathlib import Path


class GoClientError(RuntimeError):
    pass


def run_generator(request_path: Path) -> str:
    project_root = Path(__file__).resolve().parent.parent
    go_directory = project_root / "hcl-generator"
    executable = go_directory / "hcl-generator.exe"

    if not executable.is_file():
        raise GoClientError(
            f"Executable Go introuvable : {executable}\n"
            "Compilez-le depuis hcl-generator avec : go build -o hcl-generator.exe ."
        )

    try:
        result = subprocess.run(
            [str(executable), str(request_path.resolve())],
            cwd=str(go_directory),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        raise GoClientError(
            "Le generateur Go n'a pas termine dans le delai de 30 secondes"
        ) from exc
    except OSError as exc:
        raise GoClientError(f"Impossible de lancer le generateur Go : {exc}") from exc

    if result.returncode != 0:
        details = result.stderr.strip() or result.stdout.strip() or "aucun detail retourne"
        raise GoClientError(
            f"Le generateur Go a echoue (code {result.returncode}) :\n{details}"
        )

    return result.stdout.strip()
