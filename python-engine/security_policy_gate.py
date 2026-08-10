"""Decision pure fondee sur un resultat de securite deja calcule."""

from __future__ import annotations

from collections.abc import Iterable

from security_evaluation import MultiCloudSecurityEvaluationResult
from security_models import RuleStatus, SecurityFinding, SecuritySeverity
from security_policy_models import (
    PolicyDecision,
    PolicyDecisionStatus,
    PolicyReasonCode,
    PolicyTriggeredFinding,
    SecurityPolicy,
    SecurityPolicyDisabledError,
    build_default_security_policy,
)


_EVALUATED_STATUSES = frozenset(
    {RuleStatus.PASS, RuleStatus.FAIL, RuleStatus.WARNING}
)
_ISSUE_STATUSES = frozenset({RuleStatus.FAIL, RuleStatus.WARNING})


class SecurityPolicyGate:
    """Evalue une politique sans relancer scanner, regles ou Terraform."""

    def __init__(self, policy: SecurityPolicy) -> None:
        if not isinstance(policy, SecurityPolicy):
            raise TypeError("policy doit etre une SecurityPolicy")
        self._policy = policy

    @property
    def policy(self) -> SecurityPolicy:
        return self._policy

    def evaluate(
        self,
        evaluation_result: MultiCloudSecurityEvaluationResult,
    ) -> PolicyDecision:
        """Retourne une decision deterministe depuis les findings existants."""

        if not self._policy.enabled:
            raise SecurityPolicyDisabledError(
                f"La politique {self._policy.policy_id!r} est desactivee"
            )
        if not isinstance(evaluation_result, MultiCloudSecurityEvaluationResult):
            raise TypeError(
                "evaluation_result doit etre un MultiCloudSecurityEvaluationResult"
            )

        findings = tuple(
            finding
            for scan_result in evaluation_result.cloud_results.values()
            for finding in scan_result.findings
        )
        issue_findings = tuple(
            finding for finding in findings if finding.status in _ISSUE_STATUSES
        )
        severity_summary = self._severity_summary(issue_findings)
        failures = {
            severity: tuple(
                finding
                for finding in findings
                if finding.status is RuleStatus.FAIL
                and finding.severity is severity
            )
            for severity in SecuritySeverity
        }

        critical_failures = failures[SecuritySeverity.CRITICAL]
        critical_threshold_reached = self._threshold_reached(
            len(critical_failures), self._policy.critical_fail_threshold
        )
        if critical_threshold_reached and self._policy.block_on_critical:
            return self._decision(
                status=PolicyDecisionStatus.BLOCK,
                reason_code=PolicyReasonCode.BLOCK_CRITICAL_FINDING,
                message="Critical failed findings reached the policy threshold.",
                triggered_findings=critical_failures,
                severity_summary=severity_summary,
            )

        high_failures = failures[SecuritySeverity.HIGH]
        high_threshold_reached = self._threshold_reached(
            len(high_failures), self._policy.high_fail_threshold
        )
        if high_threshold_reached and not self._policy.approval_on_high:
            return self._decision(
                status=PolicyDecisionStatus.BLOCK,
                reason_code=PolicyReasonCode.BLOCK_THRESHOLD_EXCEEDED,
                message="High-severity failed findings reached the blocking threshold.",
                triggered_findings=high_failures,
                severity_summary=severity_summary,
            )

        insufficient = self._insufficient_data(evaluation_result, findings)
        if insufficient:
            unavailable_findings = tuple(
                finding
                for finding in findings
                if finding.status not in _EVALUATED_STATUSES
            )
            return self._decision(
                status=PolicyDecisionStatus.REQUIRE_APPROVAL,
                reason_code=PolicyReasonCode.INSUFFICIENT_SECURITY_DATA,
                message=(
                    "Security data is insufficient for an automatic policy "
                    "authorization."
                ),
                triggered_findings=unavailable_findings,
                severity_summary=severity_summary,
            )

        if critical_threshold_reached:
            return self._approval_decision(
                "Critical failed findings require human approval.",
                critical_failures,
                severity_summary,
            )

        if high_threshold_reached:
            return self._approval_decision(
                "High-severity failed findings require human approval.",
                high_failures,
                severity_summary,
            )

        medium_failures = failures[SecuritySeverity.MEDIUM]
        if self._threshold_reached(
            len(medium_failures), self._policy.medium_fail_threshold
        ):
            return self._approval_decision(
                "Medium-severity failed findings reached the approval threshold.",
                medium_failures,
                severity_summary,
            )

        return self._decision(
            status=PolicyDecisionStatus.ALLOW,
            reason_code=PolicyReasonCode.ALLOW_BASELINE_MET,
            message="No blocking or approval condition was met by the policy.",
            triggered_findings=issue_findings,
            severity_summary=severity_summary,
        )

    def _insufficient_data(
        self,
        result: MultiCloudSecurityEvaluationResult,
        findings: tuple[SecurityFinding, ...],
    ) -> bool:
        if result.resources_total < self._policy.minimum_resources_required:
            return True
        if result.findings_total == 0:
            return True
        if not any(finding.status in _EVALUATED_STATUSES for finding in findings):
            return True
        return (
            self._policy.require_complete_security_evaluation
            and any(finding.status is RuleStatus.SKIPPED for finding in findings)
        )

    @staticmethod
    def _threshold_reached(count: int, threshold: int) -> bool:
        return threshold > 0 and count >= threshold

    def _approval_decision(
        self,
        message: str,
        triggered_findings: Iterable[SecurityFinding],
        severity_summary: dict[str, int],
    ) -> PolicyDecision:
        return self._decision(
            status=PolicyDecisionStatus.REQUIRE_APPROVAL,
            reason_code=PolicyReasonCode.APPROVAL_REQUIRED,
            message=message,
            triggered_findings=triggered_findings,
            severity_summary=severity_summary,
        )

    def _decision(
        self,
        *,
        status: PolicyDecisionStatus,
        reason_code: PolicyReasonCode,
        message: str,
        triggered_findings: Iterable[SecurityFinding],
        severity_summary: dict[str, int],
    ) -> PolicyDecision:
        safe_findings = tuple(
            sorted(
                (self._safe_finding(finding) for finding in triggered_findings),
                key=lambda finding: (
                    -finding.severity.priority,
                    finding.rule_id,
                    finding.resource_address,
                    finding.cloud,
                ),
            )
        )
        triggered_rules = tuple(dict.fromkeys(item.rule_id for item in safe_findings))
        return PolicyDecision(
            decision=status,
            policy_id=self._policy.policy_id,
            policy_version=self._policy.policy_version,
            reason_code=reason_code,
            message=message,
            triggered_rules=triggered_rules,
            triggered_findings=safe_findings,
            severity_summary=severity_summary,
            requires_human_approval=(
                status is PolicyDecisionStatus.REQUIRE_APPROVAL
            ),
            deployment_allowed=(status is PolicyDecisionStatus.ALLOW),
        )

    @staticmethod
    def _safe_finding(finding: SecurityFinding) -> PolicyTriggeredFinding:
        return PolicyTriggeredFinding(
            rule_id=finding.rule_id,
            cloud=finding.cloud,
            resource_address=finding.resource_address,
            severity=finding.severity,
            status=finding.status,
            title=finding.title,
        )

    @staticmethod
    def _severity_summary(
        findings: Iterable[SecurityFinding],
    ) -> dict[str, int]:
        collected = tuple(findings)
        return {
            severity.value: sum(
                finding.severity is severity for finding in collected
            )
            for severity in SecuritySeverity
        }


def build_default_security_policy_gate() -> SecurityPolicyGate:
    """Construit un gate utilisant la baseline interne non officielle."""

    return SecurityPolicyGate(build_default_security_policy())
