"""Validation centralisee du contexte client/environnement."""

import re


VALID_ENVIRONMENTS = frozenset({"dev", "staging", "prod"})
_CLIENT_ID = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")


class ClientContextError(ValueError):
    pass


def validate_client_id(client_id: str) -> str:
    if not isinstance(client_id, str) or not _CLIENT_ID.fullmatch(client_id):
        raise ClientContextError(
            "client_id doit contenir uniquement des lettres minuscules, "
            "des chiffres et des tirets, sans tiret initial ou final"
        )
    return client_id


def validate_environment(environment: str) -> str:
    if not isinstance(environment, str) or environment not in VALID_ENVIRONMENTS:
        raise ClientContextError(
            "environment doit valoir exactement dev, staging ou prod"
        )
    return environment


def validate_client_context(client_id: str, environment: str) -> None:
    validate_client_id(client_id)
    validate_environment(environment)
