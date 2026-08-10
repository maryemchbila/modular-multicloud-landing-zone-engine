"""Tests des modeles generiques du Security Policy Gate POLICY-1."""

import json
import unittest
from dataclasses import FrozenInstanceError, replace

from security_models import RuleStatus, SecuritySeverity
from security_policy_models import (
    INTERNAL_SECURITY_POLICY_ID,
    INTERNAL_SECURITY_POLICY_PROFILE,
    INTERNAL_SECURITY_POLICY_VERSION,
    InvalidSecurityPolicyError,
    PolicyDecision,
    PolicyDecisionStatus,
    PolicyReasonCode,
    PolicyTriggeredFinding,
    build_default_security_policy,
)


class SecurityPolicyModelsTests(unittest.TestCase):
    @staticmethod
    def _decision(
        status: PolicyDecisionStatus = PolicyDecisionStatus.ALLOW,
    ) -> PolicyDecision:
        flags = {
            PolicyDecisionStatus.ALLOW: (False, True),
            PolicyDecisionStatus.REQUIRE_APPROVAL: (True, False),
            PolicyDecisionStatus.BLOCK: (False, False),
        }[status]
        return PolicyDecision(
            decision=status,
            policy_id=INTERNAL_SECURITY_POLICY_ID,
            policy_version=INTERNAL_SECURITY_POLICY_VERSION,
            reason_code=PolicyReasonCode.ALLOW_BASELINE_MET,
            message="Synthetic deterministic decision.",
            triggered_rules=("GCP_INTERNAL_NETWORK_001",),
            triggered_findings=(
                PolicyTriggeredFinding(
                    rule_id="GCP_INTERNAL_NETWORK_001",
                    cloud="gcp",
                    resource_address="google_compute_firewall.web",
                    severity=SecuritySeverity.MEDIUM,
                    status=RuleStatus.WARNING,
                    title="Synthetic warning",
                ),
            ),
            severity_summary={
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 1,
                "LOW": 0,
                "INFO": 0,
            },
            requires_human_approval=flags[0],
            deployment_allowed=flags[1],
        )

    def test_decision_status_values_are_exact(self) -> None:
        self.assertEqual(
            [status.value for status in PolicyDecisionStatus],
            ["ALLOW", "REQUIRE_APPROVAL", "BLOCK"],
        )

    def test_decision_status_priority_is_stable(self) -> None:
        self.assertGreater(
            PolicyDecisionStatus.BLOCK.priority,
            PolicyDecisionStatus.REQUIRE_APPROVAL.priority,
        )
        self.assertGreater(
            PolicyDecisionStatus.REQUIRE_APPROVAL.priority,
            PolicyDecisionStatus.ALLOW.priority,
        )

    def test_default_policy_is_internal_and_valid(self) -> None:
        policy = build_default_security_policy()
        self.assertEqual(policy.policy_id, INTERNAL_SECURITY_POLICY_ID)
        self.assertEqual(policy.policy_version, INTERNAL_SECURITY_POLICY_VERSION)
        self.assertEqual(policy.profile, INTERNAL_SECURITY_POLICY_PROFILE)
        self.assertEqual(policy.framework, "INTERNAL_SECURITY_BASELINE")
        self.assertTrue(policy.enabled)

    def test_empty_policy_id_is_rejected(self) -> None:
        with self.assertRaises(InvalidSecurityPolicyError):
            replace(build_default_security_policy(), policy_id=" ")

    def test_empty_policy_version_is_rejected(self) -> None:
        with self.assertRaises(InvalidSecurityPolicyError):
            replace(build_default_security_policy(), policy_version="")

    def test_empty_profile_is_rejected(self) -> None:
        with self.assertRaises(InvalidSecurityPolicyError):
            replace(build_default_security_policy(), profile="")

    def test_negative_threshold_is_rejected(self) -> None:
        for field_name in (
            "critical_fail_threshold",
            "high_fail_threshold",
            "medium_fail_threshold",
            "minimum_resources_required",
        ):
            with self.subTest(field_name=field_name):
                with self.assertRaises(InvalidSecurityPolicyError):
                    replace(build_default_security_policy(), **{field_name: -1})

    def test_boolean_configuration_is_validated_strictly(self) -> None:
        with self.assertRaises(InvalidSecurityPolicyError):
            replace(build_default_security_policy(), enabled=1)

    def test_policy_is_immutable(self) -> None:
        policy = build_default_security_policy()
        with self.assertRaises(FrozenInstanceError):
            policy.enabled = False

    def test_decision_flags_for_all_statuses(self) -> None:
        for status, expected in (
            (PolicyDecisionStatus.ALLOW, (False, True)),
            (PolicyDecisionStatus.REQUIRE_APPROVAL, (True, False)),
            (PolicyDecisionStatus.BLOCK, (False, False)),
        ):
            with self.subTest(status=status):
                decision = self._decision(status)
                self.assertEqual(
                    (
                        decision.requires_human_approval,
                        decision.deployment_allowed,
                    ),
                    expected,
                )

    def test_incoherent_decision_flags_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "incoherents"):
            replace(self._decision(), deployment_allowed=False)

    def test_decision_is_immutable(self) -> None:
        decision = self._decision()
        with self.assertRaises(FrozenInstanceError):
            decision.message = "changed"
        with self.assertRaises(TypeError):
            decision.severity_summary["HIGH"] = 4

    def test_decision_to_dict_uses_text_enums_and_safe_shape(self) -> None:
        payload = self._decision().to_dict()
        self.assertEqual(payload["decision"], "ALLOW")
        self.assertEqual(payload["reason_code"], "POLICY_ALLOW_BASELINE_MET")
        self.assertEqual(payload["triggered_findings"][0]["status"], "WARNING")
        self.assertEqual(payload["triggered_findings"][0]["severity"], "MEDIUM")
        self.assertEqual(
            tuple(payload["triggered_findings"][0]),
            ("rule_id", "cloud", "resource_address", "severity", "status", "title"),
        )

    def test_decision_to_json_is_stable_and_valid(self) -> None:
        decision = self._decision()
        self.assertEqual(decision.to_json(), decision.to_json())
        self.assertEqual(json.loads(decision.to_json()), decision.to_dict())
        self.assertNotIn("timestamp", decision.to_dict())

    def test_severity_summary_is_normalised_to_stable_order(self) -> None:
        decision = replace(
            self._decision(),
            severity_summary={
                "INFO": 0,
                "LOW": 0,
                "MEDIUM": 1,
                "HIGH": 0,
                "CRITICAL": 0,
            },
        )
        self.assertEqual(
            tuple(decision.severity_summary),
            ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"),
        )

    def test_reason_codes_are_stable(self) -> None:
        self.assertEqual(
            [code.value for code in PolicyReasonCode],
            [
                "POLICY_ALLOW_BASELINE_MET",
                "POLICY_APPROVAL_REQUIRED",
                "POLICY_BLOCK_CRITICAL_FINDING",
                "POLICY_BLOCK_THRESHOLD_EXCEEDED",
                "POLICY_INSUFFICIENT_SECURITY_DATA",
                "POLICY_APPROVAL_EXCEPTION_APPLIED",
            ],
        )


if __name__ == "__main__":
    unittest.main()
