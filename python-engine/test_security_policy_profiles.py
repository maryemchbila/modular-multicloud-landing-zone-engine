"""Tests POLICY-2 des profils et seuils configurables."""

import json
import unittest
from dataclasses import FrozenInstanceError

from security_evaluation import MultiCloudSecurityEvaluationResult
from security_models import (
    RuleStatus,
    SecurityFinding,
    SecurityScanResult,
    SecuritySeverity,
)
from security_policy_gate import SecurityPolicyGate
from security_policy_models import (
    InvalidSecurityPolicyError,
    PolicyDecisionStatus,
    SecurityPolicyProfile,
    SecurityPolicyThresholds,
    build_baseline_security_policy,
    build_custom_security_policy,
    build_default_security_policy,
    build_security_policy_for_profile,
    build_strict_security_policy,
)


class SecurityPolicyProfilesTests(unittest.TestCase):
    @staticmethod
    def _finding(
        *,
        rule_id: str = "GCP_INTERNAL_NETWORK_001",
        cloud: str = "gcp",
        status: RuleStatus = RuleStatus.PASS,
        severity: SecuritySeverity = SecuritySeverity.LOW,
        address: str | None = None,
    ) -> SecurityFinding:
        return SecurityFinding(
            rule_id=rule_id,
            cloud=cloud,
            resource_type="synthetic_resource",
            resource_name="policy2_fixture",
            resource_address=address or f"{cloud}_resource.policy2_fixture",
            status=status,
            severity=severity,
            title="Synthetic POLICY-2 finding",
            message="Synthetic profile result.",
            recommendation="Use safe synthetic configuration.",
        )

    @classmethod
    def _result(
        cls,
        *findings: SecurityFinding,
        resources_total: int = 1,
    ) -> MultiCloudSecurityEvaluationResult:
        cloud_results = {}
        for cloud in ("gcp", "oci"):
            selected = tuple(item for item in findings if item.cloud == cloud)
            if selected:
                cloud_results[cloud] = SecurityScanResult.build(cloud, selected)
        return MultiCloudSecurityEvaluationResult(
            cloud_results=cloud_results,
            resources_total=resources_total,
        )

    @staticmethod
    def _custom_thresholds(**overrides: int) -> SecurityPolicyThresholds:
        values = {
            "block_fail_critical": 1,
            "block_fail_high": 0,
            "approval_fail_high": 1,
            "approval_fail_medium": 1,
            "approval_warning_high": 0,
            "approval_warning_medium": 0,
        }
        values.update(overrides)
        return SecurityPolicyThresholds(**values)

    @classmethod
    def _custom_policy(cls, **threshold_overrides: int):
        return build_custom_security_policy(
            policy_id="INTERNAL_SECURITY_POLICY_CUSTOM_TEST",
            policy_version="1.0-test",
            name="Synthetic custom policy",
            description="Internal test-only custom policy.",
            thresholds=cls._custom_thresholds(**threshold_overrides),
        )

    def _decision(self, policy, status, severity):
        finding = self._finding(status=status, severity=severity)
        return SecurityPolicyGate(policy).evaluate(self._result(finding))

    def test_profile_enum_values_are_exact(self) -> None:
        self.assertEqual(
            [profile.value for profile in SecurityPolicyProfile],
            ["BASELINE", "STRICT", "CUSTOM"],
        )

    def test_default_factory_is_exact_baseline_alias(self) -> None:
        self.assertEqual(
            build_default_security_policy(),
            build_baseline_security_policy(),
        )

    def test_baseline_thresholds_preserve_policy1(self) -> None:
        self.assertEqual(
            build_baseline_security_policy().effective_thresholds.to_dict(),
            {
                "block_fail_critical": 1,
                "block_fail_high": 0,
                "approval_fail_high": 1,
                "approval_fail_medium": 1,
                "approval_warning_high": 0,
                "approval_warning_medium": 0,
            },
        )

    def test_baseline_clean_allows(self) -> None:
        decision = self._decision(
            build_baseline_security_policy(),
            RuleStatus.PASS,
            SecuritySeverity.LOW,
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.ALLOW)

    def test_baseline_medium_warning_allows(self) -> None:
        decision = self._decision(
            build_baseline_security_policy(),
            RuleStatus.WARNING,
            SecuritySeverity.MEDIUM,
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.ALLOW)

    def test_baseline_medium_failure_requires_approval(self) -> None:
        decision = self._decision(
            build_baseline_security_policy(),
            RuleStatus.FAIL,
            SecuritySeverity.MEDIUM,
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)

    def test_baseline_high_failure_requires_approval(self) -> None:
        decision = self._decision(
            build_baseline_security_policy(),
            RuleStatus.FAIL,
            SecuritySeverity.HIGH,
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)

    def test_baseline_critical_failure_blocks(self) -> None:
        decision = self._decision(
            build_baseline_security_policy(),
            RuleStatus.FAIL,
            SecuritySeverity.CRITICAL,
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.BLOCK)

    def test_baseline_insufficient_and_all_skipped_require_approval(self) -> None:
        gate = SecurityPolicyGate(build_baseline_security_policy())
        empty = gate.evaluate(self._result(resources_total=0))
        skipped = gate.evaluate(
            self._result(self._finding(status=RuleStatus.SKIPPED))
        )
        self.assertIs(empty.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)
        self.assertIs(skipped.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)

    def test_strict_clean_allows(self) -> None:
        decision = self._decision(
            build_strict_security_policy(),
            RuleStatus.PASS,
            SecuritySeverity.LOW,
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.ALLOW)

    def test_strict_medium_warning_requires_approval(self) -> None:
        decision = self._decision(
            build_strict_security_policy(),
            RuleStatus.WARNING,
            SecuritySeverity.MEDIUM,
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)

    def test_strict_high_warning_requires_approval(self) -> None:
        decision = self._decision(
            build_strict_security_policy(),
            RuleStatus.WARNING,
            SecuritySeverity.HIGH,
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)

    def test_strict_medium_failure_requires_approval(self) -> None:
        decision = self._decision(
            build_strict_security_policy(),
            RuleStatus.FAIL,
            SecuritySeverity.MEDIUM,
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)

    def test_strict_high_and_critical_failures_block(self) -> None:
        policy = build_strict_security_policy()
        for severity in (SecuritySeverity.HIGH, SecuritySeverity.CRITICAL):
            with self.subTest(severity=severity):
                decision = self._decision(policy, RuleStatus.FAIL, severity)
                self.assertIs(decision.decision, PolicyDecisionStatus.BLOCK)

    def test_strict_insufficient_data_requires_approval(self) -> None:
        decision = SecurityPolicyGate(build_strict_security_policy()).evaluate(
            self._result(resources_total=3)
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)

    def test_custom_policy_is_explicit_and_serialises_profile(self) -> None:
        policy = self._custom_policy()
        self.assertIs(policy.profile, SecurityPolicyProfile.CUSTOM)
        self.assertEqual(policy.to_dict()["profile"], "CUSTOM")
        self.assertEqual(json.loads(policy.to_json()), policy.to_dict())

    def test_custom_high_block_threshold_above_one(self) -> None:
        policy = self._custom_policy(
            block_fail_high=3,
            approval_fail_high=1,
        )
        two = self._result(
            *(
                self._finding(
                    rule_id=f"GCP_INTERNAL_NETWORK_00{index}",
                    address=f"gcp_resource.high_{index}",
                    status=RuleStatus.FAIL,
                    severity=SecuritySeverity.HIGH,
                )
                for index in (1, 2)
            )
        )
        three = self._result(
            *two.cloud_results["gcp"].findings,
            self._finding(
                rule_id="GCP_INTERNAL_NETWORK_003",
                address="gcp_resource.high_3",
                status=RuleStatus.FAIL,
                severity=SecuritySeverity.HIGH,
            ),
        )
        self.assertIs(
            SecurityPolicyGate(policy).evaluate(two).decision,
            PolicyDecisionStatus.REQUIRE_APPROVAL,
        )
        self.assertIs(
            SecurityPolicyGate(policy).evaluate(three).decision,
            PolicyDecisionStatus.BLOCK,
        )

    def test_zero_block_threshold_disables_only_high_block(self) -> None:
        policy = self._custom_policy(
            block_fail_high=0,
            approval_fail_high=1,
        )
        decision = self._decision(
            policy,
            RuleStatus.FAIL,
            SecuritySeverity.HIGH,
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)

    def test_custom_medium_behavior_is_configurable(self) -> None:
        policy = self._custom_policy(
            approval_fail_medium=0,
            approval_warning_medium=1,
        )
        medium_fail = self._decision(
            policy,
            RuleStatus.FAIL,
            SecuritySeverity.MEDIUM,
        )
        medium_warning = self._decision(
            policy,
            RuleStatus.WARNING,
            SecuritySeverity.MEDIUM,
        )
        self.assertIs(medium_fail.decision, PolicyDecisionStatus.ALLOW)
        self.assertIs(
            medium_warning.decision,
            PolicyDecisionStatus.REQUIRE_APPROVAL,
        )

    def test_custom_critical_always_blocks(self) -> None:
        decision = self._decision(
            self._custom_policy(block_fail_high=0),
            RuleStatus.FAIL,
            SecuritySeverity.CRITICAL,
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.BLOCK)

    def test_critical_threshold_cannot_be_zero_or_greater_than_one(self) -> None:
        for value in (0, 2):
            with self.subTest(value=value):
                with self.assertRaises(InvalidSecurityPolicyError):
                    self._custom_thresholds(block_fail_critical=value)

    def test_negative_and_non_integer_thresholds_are_rejected(self) -> None:
        for value in (-1, True, 1.5):
            with self.subTest(value=value):
                with self.assertRaises(InvalidSecurityPolicyError):
                    self._custom_thresholds(block_fail_high=value)

    def test_custom_without_noncritical_protection_is_rejected(self) -> None:
        thresholds = SecurityPolicyThresholds(
            block_fail_critical=1,
            block_fail_high=0,
            approval_fail_high=0,
            approval_fail_medium=0,
            approval_warning_high=0,
            approval_warning_medium=0,
        )
        with self.assertRaises(InvalidSecurityPolicyError):
            build_custom_security_policy(
                policy_id="INTERNAL_CUSTOM_EMPTY",
                policy_version="1",
                name="Empty custom",
                description="Synthetic invalid custom policy.",
                thresholds=thresholds,
            )

    def test_profile_selection_supports_baseline_and_strict_only(self) -> None:
        self.assertIs(
            build_security_policy_for_profile("baseline").profile,
            SecurityPolicyProfile.BASELINE,
        )
        self.assertIs(
            build_security_policy_for_profile(SecurityPolicyProfile.STRICT).profile,
            SecurityPolicyProfile.STRICT,
        )
        with self.assertRaises(InvalidSecurityPolicyError):
            build_security_policy_for_profile(SecurityPolicyProfile.CUSTOM)

    def test_thresholds_and_policy_are_immutable(self) -> None:
        thresholds = self._custom_thresholds()
        policy = self._custom_policy()
        with self.assertRaises(FrozenInstanceError):
            thresholds.block_fail_high = 4
        with self.assertRaises(FrozenInstanceError):
            policy.profile = SecurityPolicyProfile.STRICT

    def test_decision_serialises_selected_profile(self) -> None:
        decision = self._decision(
            build_strict_security_policy(),
            RuleStatus.PASS,
            SecuritySeverity.LOW,
        )
        self.assertEqual(decision.to_dict()["profile"], "STRICT")


if __name__ == "__main__":
    unittest.main()
