"""Classification pure et conservatrice des erreurs Terraform deja capturees."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern

from terraform_models import (
    TerraformErrorCategory,
    TerraformErrorClassification,
    TerraformResult,
)


@dataclass(frozen=True)
class _ErrorRule:
    pattern: Pattern[str]
    reason_code: str


def _rule(pattern: str, reason_code: str) -> _ErrorRule:
    return _ErrorRule(re.compile(pattern, re.IGNORECASE | re.DOTALL), reason_code)


class TerraformErrorClassifier:
    """Classe une erreur sans commande, acces Cloud ou modification de fichier.

    TIMEOUT repose d'abord sur le signal structure ``timed_out``. Pour le texte,
    l'ordre des categories est explicite et stable : authentification, variables,
    state, provider, reseau, HCL, puis inconnu. Dans chaque categorie, stderr est
    examine avant stdout.
    """

    CATEGORY_PRIORITY = (
        TerraformErrorCategory.TIMEOUT,
        TerraformErrorCategory.AUTHENTICATION_REQUIRED,
        TerraformErrorCategory.VARIABLES_MISSING,
        TerraformErrorCategory.STATE_ERROR,
        TerraformErrorCategory.PROVIDER_ERROR,
        TerraformErrorCategory.NETWORK_ERROR,
        TerraformErrorCategory.HCL_ERROR,
        TerraformErrorCategory.UNKNOWN_ERROR,
    )

    _MESSAGES = {
        TerraformErrorCategory.TIMEOUT: "Terraform execution timed out.",
        TerraformErrorCategory.AUTHENTICATION_REQUIRED: (
            "Terraform authentication is required."
        ),
        TerraformErrorCategory.VARIABLES_MISSING: (
            "A required Terraform variable is missing."
        ),
        TerraformErrorCategory.STATE_ERROR: "Terraform could not access the state.",
        TerraformErrorCategory.PROVIDER_ERROR: (
            "Terraform provider failed to start or respond."
        ),
        TerraformErrorCategory.NETWORK_ERROR: (
            "Terraform encountered a network error."
        ),
        TerraformErrorCategory.HCL_ERROR: (
            "A Terraform configuration error was detected."
        ),
        TerraformErrorCategory.UNKNOWN_ERROR: (
            "Terraform failed with an unclassified error."
        ),
    }

    _RULES = {
        TerraformErrorCategory.AUTHENTICATION_REQUIRED: (
            _rule(
                r"(?:google:\s*)?could not find default credentials|"
                r"\bdefault credentials\b",
                "AUTH_NO_GCP_ADC",
            ),
            _rule(
                r"could not find a proper configuration for private key|"
                r"\bconfig file profile\b|\bcould not find (?:tenancy|user ocid)\b",
                "AUTH_OCI_CONFIG_MISSING",
            ),
            _rule(r"\bnotauthorizedornotfound\b", "AUTH_OCI_NOT_AUTHORIZED"),
            _rule(r"\binvalid_grant\b", "AUTH_INVALID_GRANT"),
            _rule(
                r"\bauthentication (?:is )?(?:required|failed)\b|"
                r"\bnot authenticated\b|\bunauthorized\b|"
                r"\baccess token\b|\bcredentials?\b|"
                r"\bprivate key\b|\bhttp\s+401\b|\bstatus(?: code)?\s*401\b|"
                r"\b401\b",
                "AUTH_CREDENTIALS_REQUIRED",
            ),
            _rule(
                r"(?:\b(?:iam|api|cloud|google|oci)\b.{0,100}\bpermission denied\b)|"
                r"(?:\bpermission denied\b.{0,100}\b(?:iam|api|cloud|google|oci)\b)",
                "AUTH_PERMISSION_DENIED",
            ),
        ),
        TerraformErrorCategory.VARIABLES_MISSING: (
            _rule(
                r"\bno value for required variable\b|"
                r"\brequired variable (?:is )?not set\b|"
                r"\bvariable\b.{0,100}\bhas no value\b",
                "VAR_REQUIRED_MISSING",
            ),
            _rule(
                r"(?:\binput variable\b.{0,100}\b(?:missing|required|no value)\b)|"
                r"(?:\b(?:missing|required|no value)\b.{0,100}\binput variable\b)",
                "VAR_REQUIRED_MISSING",
            ),
            _rule(
                r"\bmissing required argument\b.{0,100}\binput variable\b|"
                r"\binput variable\b.{0,100}\bmissing required argument\b",
                "VAR_REQUIRED_MISSING",
            ),
        ),
        TerraformErrorCategory.STATE_ERROR: (
            _rule(
                r"\berror acquiring the state lock\b|\bstate lock\b|"
                r"\berror locking state\b|\bstate\b.{0,50}\b(?:is )?locked\b",
                "STATE_LOCKED",
            ),
            _rule(
                r"\bfailed to (?:load|read) state\b|\berror refreshing state\b",
                "STATE_READ_FAILED",
            ),
            _rule(r"\bfailed to save state\b", "STATE_SAVE_FAILED"),
            _rule(
                r"\bbackend initialization required\b|"
                r"\bbackend configuration changed\b",
                "STATE_BACKEND_INITIALIZATION_REQUIRED",
            ),
            _rule(r"\bstate (?:snapshot|file)\b|\block info\b", "STATE_ACCESS_FAILED"),
        ),
        TerraformErrorCategory.PROVIDER_ERROR: (
            _rule(r"\bplugin did not respond\b", "PROVIDER_PLUGIN_NO_RESPONSE"),
            _rule(
                r"\bgetproviderschema\b|\bfailed to (?:obtain )?provider schema\b",
                "PROVIDER_SCHEMA_FAILURE",
            ),
            _rule(r"\bfailed to load plugin schemas\b", "PROVIDER_SCHEMA_FAILURE"),
            _rule(
                r"\bfailed to instantiate provider\b|\bfailed to load provider\b|"
                r"\bfailed to (?:install|download) provider\b",
                "PROVIDER_LOAD_FAILURE",
            ),
            _rule(
                r"\bincompatible api version with plugin\b|"
                r"\bunrecognized remote plugin message\b",
                "PROVIDER_PLUGIN_PROTOCOL_ERROR",
            ),
            _rule(
                r"\bprovider produced inconsistent\b",
                "PROVIDER_INCONSISTENT_RESULT",
            ),
            _rule(
                r"\bprovider plugin\b|\bplugin (?:started|address|rpc)\b",
                "PROVIDER_PLUGIN_FAILURE",
            ),
        ),
        TerraformErrorCategory.NETWORK_ERROR: (
            _rule(r"\bconnection refused\b", "NETWORK_CONNECTION_REFUSED"),
            _rule(
                r"\bno such host\b|\bname resolution\b|\bdns\b",
                "NETWORK_DNS_FAILURE",
            ),
            _rule(
                r"\bx509:\s*certificate signed by unknown authority\b",
                "NETWORK_CERTIFICATE_ERROR",
            ),
            _rule(
                r"\bconnection reset\b|\bdial tcp\b|\bproxyconnect\b|"
                r"\bnetwork is unreachable\b",
                "NETWORK_CONNECTION_FAILURE",
            ),
            _rule(
                r"\bconnection timed out\b|\btls handshake timeout\b|"
                r"\bi/o timeout\b|"
                r"(?:\bcontext deadline exceeded\b.{0,100}"
                r"\b(?:https?|registry|cloud|api|remote|dial tcp)\b)|"
                r"(?:\b(?:https?|registry|cloud|api|remote|dial tcp)\b.{0,100}"
                r"\bcontext deadline exceeded\b)",
                "NETWORK_REMOTE_TIMEOUT",
            ),
        ),
        TerraformErrorCategory.HCL_ERROR: (
            _rule(r"\bunsupported argument\b", "HCL_UNSUPPORTED_ARGUMENT"),
            _rule(r"\bunsupported block type\b", "HCL_UNSUPPORTED_BLOCK_TYPE"),
            _rule(r"\breference to undeclared resource\b", "HCL_UNDECLARED_RESOURCE"),
            _rule(
                r"\breference to undeclared input variable\b",
                "HCL_UNDECLARED_VARIABLE",
            ),
            _rule(r"\bmissing required argument\b", "HCL_MISSING_REQUIRED_ARGUMENT"),
            _rule(
                r"\binvalid value for input variable\b",
                "HCL_INVALID_VARIABLE_VALUE",
            ),
            _rule(
                r"\binvalid (?:expression|reference|function argument|index|"
                r"for_each argument|count argument)\b",
                "HCL_INVALID_EXPRESSION",
            ),
            _rule(
                r"\bincorrect attribute value type\b",
                "HCL_INCORRECT_ATTRIBUTE_TYPE",
            ),
            _rule(r"\bcycle:", "HCL_DEPENDENCY_CYCLE"),
            _rule(
                r"\bduplicate (?:resource|variable|output)\b",
                "HCL_DUPLICATE_DECLARATION",
            ),
        ),
    }

    def classify(
        self,
        step: str,
        result: TerraformResult,
    ) -> TerraformErrorClassification | None:
        """Retourne un diagnostic pour un echec, et ``None`` pour un succes."""

        failed_step = self._normalise_step(step)
        if result.timed_out:
            return self._classification(
                TerraformErrorCategory.TIMEOUT,
                failed_step,
                result,
                "TERRAFORM_TIMEOUT",
            )

        if result.exit_code == 0 or result.success:
            return None
        if failed_step == "plan" and result.exit_code == 2:
            return None

        sources = (result.stderr or "", result.stdout or "")
        for category in self.CATEGORY_PRIORITY[1:-1]:
            for source in sources:
                for rule in self._RULES[category]:
                    if rule.pattern.search(source):
                        return self._classification(
                            category,
                            failed_step,
                            result,
                            rule.reason_code,
                        )

        if failed_step == "fmt":
            return self._classification(
                TerraformErrorCategory.HCL_ERROR,
                failed_step,
                result,
                "HCL_FORMAT_ERROR",
            )

        return self._classification(
            TerraformErrorCategory.UNKNOWN_ERROR,
            failed_step,
            result,
            "UNKNOWN_TERRAFORM_ERROR",
        )

    @classmethod
    def _classification(
        cls,
        category: TerraformErrorCategory,
        failed_step: str,
        result: TerraformResult,
        reason_code: str,
    ) -> TerraformErrorClassification:
        return TerraformErrorClassification(
            category=category,
            failed_step=failed_step,
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            reason_code=reason_code,
            message=cls._MESSAGES[category],
        )

    @staticmethod
    def _normalise_step(step: str) -> str:
        if not isinstance(step, str) or not step.strip():
            raise ValueError("step doit etre une chaine non vide")
        return step.strip().casefold()
