"""Tests unitaires du classificateur pur d'erreurs Terraform."""

import json
import unittest

from terraform_error_classifier import TerraformErrorClassifier
from terraform_models import (
    TerraformErrorCategory,
    TerraformErrorClassification,
    TerraformResult,
)


class TerraformErrorClassifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.classifier = TerraformErrorClassifier()

    @staticmethod
    def _result(
        *,
        exit_code: int | None = 1,
        timed_out: bool = False,
        stdout: str = "",
        stderr: str = "",
        success: bool | None = None,
    ) -> TerraformResult:
        return TerraformResult(
            command="terraform",
            args=("plan",),
            working_directory="terraform-root",
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=0.1,
            timed_out=timed_out,
            success=(exit_code == 0 and not timed_out) if success is None else success,
        )

    def _classify(
        self, text: str, step: str = "plan"
    ) -> TerraformErrorClassification | None:
        return self.classifier.classify(step, self._result(stderr=text))

    def assert_category(self, text: str, category: TerraformErrorCategory) -> None:
        classification = self._classify(text)
        self.assertIsNotNone(classification)
        self.assertEqual(classification.category, category)

    def test_timeout_uses_structured_signal_before_text(self) -> None:
        classification = self.classifier.classify(
            "plan",
            self._result(
                exit_code=None,
                timed_out=True,
                stderr="Unsupported argument",
            ),
        )
        self.assertEqual(classification.category, TerraformErrorCategory.TIMEOUT)

    def test_gcp_default_credentials_are_authentication_required(self) -> None:
        self.assert_category(
            "google: could not find default credentials",
            TerraformErrorCategory.AUTHENTICATION_REQUIRED,
        )

    def test_oci_private_key_configuration_is_authentication_required(self) -> None:
        classification = self._classify(
            "could not find a proper configuration for private key "
            "in config file profile"
        )
        self.assertEqual(
            classification.category,
            TerraformErrorCategory.AUTHENTICATION_REQUIRED,
        )
        self.assertEqual(classification.reason_code, "AUTH_OCI_CONFIG_MISSING")

    def test_required_variable_without_value_is_variables_missing(self) -> None:
        self.assert_category(
            "No value for required variable",
            TerraformErrorCategory.VARIABLES_MISSING,
        )

    def test_state_lock_acquisition_is_state_error(self) -> None:
        self.assert_category(
            "Error acquiring the state lock",
            TerraformErrorCategory.STATE_ERROR,
        )

    def test_plugin_did_not_respond_is_provider_error(self) -> None:
        classification = self._classify("Plugin did not respond")
        self.assertEqual(classification.category, TerraformErrorCategory.PROVIDER_ERROR)
        self.assertEqual(
            classification.reason_code, "PROVIDER_PLUGIN_NO_RESPONSE"
        )

    def test_get_provider_schema_is_provider_error(self) -> None:
        self.assert_category(
            "Error: GetProviderSchema request failed",
            TerraformErrorCategory.PROVIDER_ERROR,
        )

    def test_failed_plugin_schemas_is_provider_error(self) -> None:
        self.assert_category(
            "Failed to load plugin schemas",
            TerraformErrorCategory.PROVIDER_ERROR,
        )

    def test_connection_refused_is_network_error(self) -> None:
        self.assert_category(
            "dial tcp: connection refused",
            TerraformErrorCategory.NETWORK_ERROR,
        )

    def test_no_such_host_is_network_error(self) -> None:
        self.assert_category(
            "lookup registry: no such host",
            TerraformErrorCategory.NETWORK_ERROR,
        )

    def test_generic_x509_failure_is_network_error(self) -> None:
        self.assert_category(
            "request failed: x509: certificate signed by unknown authority",
            TerraformErrorCategory.NETWORK_ERROR,
        )

    def test_remote_context_deadline_is_network_error(self) -> None:
        self.assert_category(
            "registry API request failed: context deadline exceeded",
            TerraformErrorCategory.NETWORK_ERROR,
        )

    def test_context_deadline_without_network_context_is_unknown(self) -> None:
        self.assert_category(
            "context deadline exceeded while processing local operation",
            TerraformErrorCategory.UNKNOWN_ERROR,
        )

    def test_provider_x509_context_is_provider_error(self) -> None:
        self.assert_category(
            "GetProviderSchema: provider plugin RPC failed: "
            "x509: certificate signed by unknown authority",
            TerraformErrorCategory.PROVIDER_ERROR,
        )

    def test_unsupported_argument_is_hcl_error(self) -> None:
        self.assert_category("Unsupported argument", TerraformErrorCategory.HCL_ERROR)

    def test_undeclared_resource_is_hcl_error(self) -> None:
        self.assert_category(
            "Reference to undeclared resource",
            TerraformErrorCategory.HCL_ERROR,
        )

    def test_unknown_nonzero_failure_is_unknown_error(self) -> None:
        self.assert_category(
            "Something unexpected happened",
            TerraformErrorCategory.UNKNOWN_ERROR,
        )

    def test_exit_zero_has_no_classification(self) -> None:
        classification = self.classifier.classify(
            "validate",
            self._result(exit_code=0, stderr="Unsupported argument"),
        )
        self.assertIsNone(classification)

    def test_plan_exit_two_has_no_classification(self) -> None:
        classification = self.classifier.classify(
            "plan",
            self._result(exit_code=2, stdout="Plan: 1 to add"),
        )
        self.assertIsNone(classification)

    def test_stdout_is_used_when_stderr_is_empty(self) -> None:
        classification = self.classifier.classify(
            "init",
            self._result(stdout="connection refused"),
        )
        self.assertEqual(classification.category, TerraformErrorCategory.NETWORK_ERROR)

    def test_stderr_is_prioritised_within_a_category(self) -> None:
        classification = self.classifier.classify(
            "validate",
            self._result(
                stderr="GetProviderSchema failed",
                stdout="Plugin did not respond",
            ),
        )
        self.assertEqual(classification.reason_code, "PROVIDER_SCHEMA_FAILURE")

    def test_authentication_classification_does_not_copy_secret(self) -> None:
        secret = "very-sensitive-token-value"
        classification = self._classify(
            f"token={secret}; could not find default credentials"
        )
        payload = json.dumps(classification.to_dict())
        self.assertNotIn(secret, payload)
        self.assertNotIn("token=", payload)

    def test_local_windows_permission_denied_is_not_automatically_auth(self) -> None:
        classification = self._classify(
            r"open C:\terraform\plugin-cache: permission denied on Windows"
        )
        self.assertEqual(classification.category, TerraformErrorCategory.UNKNOWN_ERROR)

    def test_locked_state_variant_is_state_error(self) -> None:
        classification = self._classify("The remote state is locked by another process")
        self.assertEqual(classification.category, TerraformErrorCategory.STATE_ERROR)
        self.assertEqual(classification.reason_code, "STATE_LOCKED")

    def test_missing_variable_can_be_detected_during_plan(self) -> None:
        classification = self._classify("Required variable not set", step="plan")
        self.assertEqual(classification.failed_step, "plan")
        self.assertEqual(
            classification.category, TerraformErrorCategory.VARIABLES_MISSING
        )

    def test_provider_error_can_be_detected_during_validate(self) -> None:
        classification = self._classify("Plugin did not respond", step="validate")
        self.assertEqual(classification.failed_step, "validate")
        self.assertEqual(classification.category, TerraformErrorCategory.PROVIDER_ERROR)

    def test_network_error_can_be_detected_during_init(self) -> None:
        classification = self._classify("network is unreachable", step="init")
        self.assertEqual(classification.failed_step, "init")
        self.assertEqual(classification.category, TerraformErrorCategory.NETWORK_ERROR)

    def test_failed_step_is_normalised(self) -> None:
        classification = self._classify("Unsupported argument", step=" Validate ")
        self.assertEqual(classification.failed_step, "validate")

    def test_reason_code_is_stable_and_specific(self) -> None:
        classification = self._classify("connection refused")
        self.assertEqual(classification.reason_code, "NETWORK_CONNECTION_REFUSED")

    def test_serialised_classification_contains_no_injected_secret(self) -> None:
        secret = "secret-from-terraform-tfvars"
        classification = self._classify(
            f"password={secret}\nNo value for required variable"
        )
        payload = classification.to_dict()
        encoded = json.dumps(payload)
        self.assertEqual(payload["category"], "VARIABLES_MISSING")
        self.assertNotIn(secret, encoded)
        self.assertNotIn("password", encoded.casefold())

    def test_missing_resource_argument_is_hcl_not_missing_variable(self) -> None:
        classification = self._classify(
            'Missing required argument: The argument "project" '
            "is required for resource."
        )
        self.assertEqual(classification.category, TerraformErrorCategory.HCL_ERROR)
        self.assertEqual(
            classification.reason_code, "HCL_MISSING_REQUIRED_ARGUMENT"
        )

    def test_fmt_nonzero_without_specific_text_is_format_error(self) -> None:
        classification = self._classify("main.tf", step="fmt")
        self.assertEqual(classification.category, TerraformErrorCategory.HCL_ERROR)
        self.assertEqual(classification.reason_code, "HCL_FORMAT_ERROR")

    def test_category_priority_is_explicit(self) -> None:
        self.assertEqual(
            TerraformErrorClassifier.CATEGORY_PRIORITY,
            (
                TerraformErrorCategory.TIMEOUT,
                TerraformErrorCategory.AUTHENTICATION_REQUIRED,
                TerraformErrorCategory.VARIABLES_MISSING,
                TerraformErrorCategory.STATE_ERROR,
                TerraformErrorCategory.PROVIDER_ERROR,
                TerraformErrorCategory.NETWORK_ERROR,
                TerraformErrorCategory.HCL_ERROR,
                TerraformErrorCategory.UNKNOWN_ERROR,
            ),
        )


if __name__ == "__main__":
    unittest.main()
