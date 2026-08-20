"""Redaction centralisee des donnees potentiellement sensibles."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any


REDACTED = "********"
_SENSITIVE_KEY = re.compile(
    r"(?:password|secret|token|private[_-]?key|credentials|api[_-]?key|client[_-]?secret)",
    re.IGNORECASE,
)


def is_sensitive_key(key: object) -> bool:
    """Indique si un nom de champ doit etre masque."""

    return bool(_SENSITIVE_KEY.search(str(key)))


def redact_sensitive_data(
    value: Any,
    *,
    sensitive_values: Sequence[str] = (),
) -> Any:
    """Retourne une copie sanitisee sans modifier l'objet fourni."""

    known_values = tuple(
        sorted(
            {
                item
                for item in sensitive_values
                if isinstance(item, str) and item
            },
            key=len,
            reverse=True,
        )
    )
    return _redact(value, known_values)


def _redact(value: Any, known_values: tuple[str, ...]) -> Any:
    if isinstance(value, Mapping):
        return {
            key: (
                REDACTED
                if is_sensitive_key(key)
                else _redact(item, known_values)
            )
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        return tuple(_redact(item, known_values) for item in value)
    if isinstance(value, list):
        return [_redact(item, known_values) for item in value]
    if isinstance(value, str):
        sanitized = value
        for secret_value in known_values:
            sanitized = sanitized.replace(secret_value, REDACTED)
        sanitized = re.sub(
            r"(?i)((?:password|secret|token|private[_-]?key|credentials|"
            r"api[_-]?key|client[_-]?secret)\s*[=:]\s*)([^\s,;]+)",
            rf"\1{REDACTED}",
            sanitized,
        )
        return sanitized
    return value
