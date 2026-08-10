"""Tests POLICY-2 des exceptions controlees et tracables."""

import json
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

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
    PolicyReasonCode,
    SecurityPolicyException,
    build_baseline_security_policy,
    build_strict_security_policy,
)


FIXED_TIME = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)


class SecurityPolicyExceptionsTests(unittest.TestCase):
    @staticmethod
    def _finding(
        *,
        rule_id: str = "GCP_INTERNAL_NETWORK_001",
        cloud: str = "gcp",
        status: RuleStatus = RuleStatus.FAIL,
        severity: SecuritySeverity = SecuritySeverity.HIGH,
        address: str | None = None,
        message: str = "Synthetic exception fixture.",
        recommendation: str = "Use safe synthetic configuration.",
    ) -> SecurityFinding:
        return SecurityFinding(
            rule_id=rule_id,
            cloud=cloud,
            resource_type="synthetic_resource",
            resource_name="policy2_exception_fixture",
            resource_address=address or f"{cloud}_resource.policy2_exception_fixture",
            status=status,
            severity=severity,
            title="Synthetic controlled exception finding",
            message=message,
            recommendation=recommendation,
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
    def _exception(**overrides) -> SecurityPolicyException:
        values = {
            "exception_id": "EXC-CHANGE-001",
            "reason": "Temporary approved migration exception",
            "rule_ids": ("GCP_INTERNAL_NETWORK_001",),
        }
        values.update(overrides)
        return SecurityPolicyException(**values)

    def _strict_decision(
        self,
        finding: SecurityFinding,
        exception: SecurityPolicyException,
        *,
        evaluated_at: datetime | None = None,
    ):
        policy = build_strict_security_policy(exceptions=(exception,))
        return SecurityPolicyGate(policy).evaluate(
            self._result(finding),
            evaluated_at=evaluated_at,
        )

    def test_exception_requires_id_and_reason(self) -> None:
        for field_name in ("exception_id", "reason"):
            with self.subTest(field_name=field_name):
                with self.assertRaises(InvalidSecurityPolicyError):
                    self._exception(**{field_name: " "})

    def test_exception_requires_at_least_one_scope(self) -> None:
        with self.assertRaisesRegex(InvalidSecurityPolicyError, "scope"):
            self._exception(rule_ids=(), clouds=(), resource_addresses=())

    def test_exception_scope_is_sorted_and_deduplicated(self) -> None:
        exception = self._exception(
            rule_ids=("RULE_B", "RULE_A", "RULE_B"),
            clouds=("OCI", "gcp", "oci"),
            resource_addresses=("resource.z", "resource.a"),
        )
        self.assertEqual(exception.rule_ids, ("RULE_A", "RULE_B"))
        self.assertEqual(exception.clouds, ("gcp", "oci"))
        self.assertEqual(
            exception.resource_addresses,
            ("resource.a", "resource.z"),
        )

    def test_duplicate_exception_ids_are_rejected(self) -> None:
        first = self._exception()
        second = self._exception(clouds=("gcp",))
        with self.assertRaisesRegex(InvalidSecurityPolicyError, "uniques"):
            build_strict_security_policy(exceptions=(first, second))

    def test_exception_is_immutable(self) -> None:
        exception = self._exception(metadata={"ticket": "CHG-001"})
        with self.assertRaises(FrozenInstanceError):
            exception.enabled = False
        with self.assertRaises(TypeError):
            exception.metadata["ticket"] = "changed"

    def test_expiration_requires_aware_datetime(self) -> None:
        with self.assertRaisesRegex(InvalidSecurityPolicyError, "fuseau"):
            self._exception(expires_at=datetime(2026, 8, 11))

    def test_exception_serialization_is_stable_and_excludes_metadata(self) -> None:
        exception = self._exception(
            expires_at=FIXED_TIME + timedelta(days=1),
            reference="CHG-001",
            metadata={"internal": "not-public"},
        )
        payload = exception.to_dict()
        self.assertEqual(payload["expires_at"], "2026-08-11T12:00:00Z")
        self.assertNotIn("metadata", payload)
        self.assertEqual(json.loads(exception.to_json()), payload)
        self.assertEqual(exception.to_json(), exception.to_json())

    def test_sensitive_id_reason_and_reference_are_rejected(self) -> None:
        for field_name, value in (
            ("exception_id", "FAKE_TOKEN_POLICY2"),
            ("reason", "Contains FAKE_PASSWORD_POLICY2"),
            ("reference", "FAKE_PRIVATE_KEY_POLICY2"),
        ):
            with self.subTest(field_name=field_name):
                with self.assertRaises(InvalidSecurityPolicyError):
                    self._exception(**{field_name: value})

    def test_rule_scope_matches_only_selected_rule(self) -> None:
        exception = self._exception(rule_ids=("GCP_INTERNAL_NETWORK_001",))
        matching = self._strict_decision(self._finding(), exception)
        other = self._strict_decision(
            self._finding(rule_id="GCP_INTERNAL_NETWORK_002"),
            exception,
        )
        self.assertIs(matching.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)
        self.assertIs(other.decision, PolicyDecisionStatus.BLOCK)

    def test_cloud_scope_matches_only_selected_cloud(self) -> None:
        exception = self._exception(rule_ids=(), clouds=("gcp",))
        gcp = self._strict_decision(self._finding(), exception)
        oci = self._strict_decision(
            self._finding(
                rule_id="OCI_INTERNAL_NETWORK_001",
                cloud="oci",
            ),
            exception,
        )
        self.assertIs(gcp.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)
        self.assertIs(oci.decision, PolicyDecisionStatus.BLOCK)

    def test_unknown_exception_cloud_is_rejected_as_invalid_policy(self) -> None:
        with self.assertRaises(InvalidSecurityPolicyError):
            self._exception(rule_ids=(), clouds=("azure",))

    def test_resource_scope_matches_only_selected_address(self) -> None:
        address = "google_compute_firewall.legacy_admin"
        exception = self._exception(
            rule_ids=(),
            resource_addresses=(address,),
        )
        matching = self._strict_decision(
            self._finding(address=address),
            exception,
        )
        other = self._strict_decision(
            self._finding(address="google_compute_firewall.current_admin"),
            exception,
        )
        self.assertIs(matching.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)
        self.assertIs(other.decision, PolicyDecisionStatus.BLOCK)

    def test_multiple_scope_dimensions_use_and_semantics(self) -> None:
        address = "google_compute_firewall.legacy_admin"
        exception = self._exception(
            rule_ids=("GCP_INTERNAL_NETWORK_001", "GCP_INTERNAL_NETWORK_002"),
            clouds=("gcp",),
            resource_addresses=(address,),
        )
        matching = self._strict_decision(
            self._finding(address=address),
            exception,
        )
        wrong_address = self._strict_decision(
            self._finding(address="google_compute_firewall.other"),
            exception,
        )
        self.assertIs(matching.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)
        self.assertIs(wrong_address.decision, PolicyDecisionStatus.BLOCK)

    def test_disabled_exception_is_ignored(self) -> None:
        decision = self._strict_decision(
            self._finding(),
            self._exception(enabled=False),
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.BLOCK)
        self.assertEqual(decision.applied_exception_ids, ())

    def test_non_expiring_exception_does_not_require_evaluation_time(self) -> None:
        decision = self._strict_decision(self._finding(), self._exception())
        self.assertIs(decision.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)
        self.assertIsNone(decision.evaluation_time)

    def test_active_exception_uses_injected_time(self) -> None:
        decision = self._strict_decision(
            self._finding(),
            self._exception(expires_at=FIXED_TIME + timedelta(hours=1)),
            evaluated_at=FIXED_TIME,
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)
        self.assertEqual(decision.evaluation_time, "2026-08-10T12:00:00Z")

    def test_expired_exception_is_ignored(self) -> None:
        decision = self._strict_decision(
            self._finding(),
            self._exception(expires_at=FIXED_TIME),
            evaluated_at=FIXED_TIME,
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.BLOCK)
        self.assertEqual(decision.applied_exception_ids, ())

    def test_expiring_exception_requires_injected_time(self) -> None:
        with self.assertRaisesRegex(ValueError, "evaluated_at"):
            self._strict_decision(
                self._finding(),
                self._exception(expires_at=FIXED_TIME + timedelta(days=1)),
            )

    def test_naive_evaluation_time_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "fuseau"):
            self._strict_decision(
                self._finding(),
                self._exception(),
                evaluated_at=datetime(2026, 8, 10),
            )

    def test_strict_high_exception_forces_approval_and_traceability(self) -> None:
        decision = self._strict_decision(self._finding(), self._exception())
        self.assertIs(decision.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)
        self.assertIs(
            decision.reason_code,
            PolicyReasonCode.APPROVAL_EXCEPTION_APPLIED,
        )
        self.assertEqual(decision.applied_exception_ids, ("EXC-CHANGE-001",))
        self.assertEqual(len(decision.excepted_findings), 1)
        self.assertEqual(decision.triggered_findings, ())

    def test_baseline_high_exception_never_downgrades_to_allow(self) -> None:
        exception = self._exception()
        policy = build_baseline_security_policy(exceptions=(exception,))
        decision = SecurityPolicyGate(policy).evaluate(
            self._result(self._finding())
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)
        self.assertIs(
            decision.reason_code,
            PolicyReasonCode.APPROVAL_EXCEPTION_APPLIED,
        )

    def test_critical_finding_cannot_be_excepted(self) -> None:
        critical = self._finding(severity=SecuritySeverity.CRITICAL)
        decision = self._strict_decision(critical, self._exception())
        self.assertIs(decision.decision, PolicyDecisionStatus.BLOCK)
        self.assertEqual(decision.applied_exception_ids, ())
        self.assertEqual(decision.excepted_findings, ())
        self.assertEqual(decision.triggered_findings[0].severity, SecuritySeverity.CRITICAL)

    def test_critical_block_wins_while_noncritical_exception_is_traced(self) -> None:
        high = self._finding()
        critical = self._finding(
            rule_id="OCI_INTERNAL_COMPUTE_001",
            cloud="oci",
            severity=SecuritySeverity.CRITICAL,
        )
        policy = build_strict_security_policy(exceptions=(self._exception(),))
        decision = SecurityPolicyGate(policy).evaluate(
            self._result(high, critical, resources_total=2)
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.BLOCK)
        self.assertEqual(decision.applied_exception_ids, ("EXC-CHANGE-001",))
        self.assertEqual(decision.excepted_findings[0].severity, SecuritySeverity.HIGH)
        self.assertEqual(decision.triggered_findings[0].severity, SecuritySeverity.CRITICAL)

    def test_gcp_high_excepted_and_oci_clean_require_approval(self) -> None:
        high = self._finding()
        oci_pass = self._finding(
            rule_id="OCI_INTERNAL_NETWORK_001",
            cloud="oci",
            status=RuleStatus.PASS,
            severity=SecuritySeverity.LOW,
        )
        policy = build_strict_security_policy(exceptions=(self._exception(),))
        decision = SecurityPolicyGate(policy).evaluate(
            self._result(high, oci_pass, resources_total=2)
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.REQUIRE_APPROVAL)
        self.assertEqual(decision.applied_exception_ids, ("EXC-CHANGE-001",))

    def test_gcp_scoped_exception_never_affects_oci_high_failure(self) -> None:
        gcp_high = self._finding()
        oci_high = self._finding(
            rule_id="OCI_INTERNAL_NETWORK_001",
            cloud="oci",
        )
        exception = self._exception(rule_ids=(), clouds=("gcp",))
        policy = build_strict_security_policy(exceptions=(exception,))
        decision = SecurityPolicyGate(policy).evaluate(
            self._result(gcp_high, oci_high, resources_total=2)
        )
        self.assertIs(decision.decision, PolicyDecisionStatus.BLOCK)
        self.assertEqual(decision.applied_exception_ids, ("EXC-CHANGE-001",))
        self.assertEqual(decision.triggered_findings[0].cloud, "oci")

    def test_only_materially_applied_exception_ids_are_reported(self) -> None:
        applied = self._exception()
        disabled = self._exception(
            exception_id="EXC-DISABLED-002",
            enabled=False,
        )
        nonmatching = self._exception(
            exception_id="EXC-OTHER-003",
            rule_ids=("GCP_INTERNAL_NETWORK_003",),
        )
        policy = build_strict_security_policy(
            exceptions=(nonmatching, disabled, applied)
        )
        decision = SecurityPolicyGate(policy).evaluate(
            self._result(self._finding())
        )
        self.assertEqual(decision.applied_exception_ids, ("EXC-CHANGE-001",))

    def test_baseline_medium_warning_exception_is_not_materially_applied(self) -> None:
        warning = self._finding(
            status=RuleStatus.WARNING,
            severity=SecuritySeverity.MEDIUM,
        )
        policy = build_baseline_security_policy(exceptions=(self._exception(),))
        decision = SecurityPolicyGate(policy).evaluate(self._result(warning))
        self.assertIs(decision.decision, PolicyDecisionStatus.ALLOW)
        self.assertEqual(decision.applied_exception_ids, ())

    def test_original_evaluation_result_is_not_modified(self) -> None:
        result = self._result(self._finding())
        policy = build_strict_security_policy(exceptions=(self._exception(),))
        before = result.to_json()
        SecurityPolicyGate(policy).evaluate(result)
        self.assertEqual(result.to_json(), before)
        self.assertEqual(result.failed, 1)

    def test_policy_and_exceptions_are_not_modified(self) -> None:
        exception = self._exception()
        policy = build_strict_security_policy(exceptions=(exception,))
        before = policy.to_json()
        SecurityPolicyGate(policy).evaluate(self._result(self._finding()))
        self.assertEqual(policy.to_json(), before)
        self.assertEqual(exception.to_json(), exception.to_json())

    def test_exception_and_finding_secrets_are_not_serialised(self) -> None:
        secrets = (
            "FAKE_PASSWORD_POLICY2",
            "FAKE_TOKEN_POLICY2",
            "FAKE_PRIVATE_KEY_POLICY2",
            "FAKE_SECRET_POLICY2",
        )
        exception = self._exception(
            metadata={
                "password": secrets[0],
                "token": secrets[1],
                "private_key": secrets[2],
                "secret": secrets[3],
            }
        )
        finding = self._finding(
            message=f"Hidden {secrets[0]} {secrets[1]}",
            recommendation=f"Hidden {secrets[2]} {secrets[3]}",
        )
        policy = build_strict_security_policy(exceptions=(exception,))
        decision = SecurityPolicyGate(policy).evaluate(self._result(finding))
        payloads = (
            exception.to_json(),
            policy.to_json(),
            decision.to_json(),
            decision.message,
            json.dumps([item.to_dict() for item in decision.triggered_findings]),
            json.dumps([item.to_dict() for item in decision.excepted_findings]),
        )
        for payload in payloads:
            for secret in secrets:
                self.assertNotIn(secret, payload)

    def test_multiple_exception_ids_and_findings_are_deterministic(self) -> None:
        first = self._exception(exception_id="EXC-Z-002")
        second = self._exception(exception_id="EXC-A-001")
        policy = build_strict_security_policy(exceptions=(first, second))
        findings = (
            self._finding(address="gcp_resource.z"),
            self._finding(address="gcp_resource.a"),
        )
        gate = SecurityPolicyGate(policy)
        forward = gate.evaluate(self._result(*findings)).to_json()
        reverse = gate.evaluate(self._result(*reversed(findings))).to_json()
        self.assertEqual(forward, reverse)
        decision = gate.evaluate(self._result(*findings))
        self.assertEqual(
            decision.applied_exception_ids,
            ("EXC-A-001", "EXC-Z-002"),
        )
        self.assertEqual(
            [item.resource_address for item in decision.excepted_findings],
            ["gcp_resource.a", "gcp_resource.z"],
        )


if __name__ == "__main__":
    unittest.main()
