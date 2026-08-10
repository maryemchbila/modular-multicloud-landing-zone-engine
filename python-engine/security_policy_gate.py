"""Decision pure fondee sur un resultat de securite deja calcule."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone

from security_evaluation import MultiCloudSecurityEvaluationResult
from security_models import RuleStatus, SecurityFinding, SecuritySeverity
from security_policy_models import (
    PolicyDecision,
    PolicyDecisionStatus,
    PolicyReasonCode,
    PolicyTriggeredFinding,
    SecurityPolicy,
    SecurityPolicyDisabledError,
    SecurityPolicyException,
    SecurityPolicyThresholds,
    build_default_security_policy,
)


_EVALUATED_STATUSES = frozenset(
    {RuleStatus.PASS, RuleStatus.FAIL, RuleStatus.WARNING}
)
_ISSUE_STATUSES = frozenset({RuleStatus.FAIL, RuleStatus.WARNING})


class SecurityPolicyGate:
    """Evalue profils, seuils et exceptions sans aucun effet de bord."""

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
        *,
        evaluated_at: datetime | None = None,
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

        evaluation_time = self._evaluation_time(evaluated_at)
        findings = tuple(
            finding
            for scan_result in evaluation_result.cloud_results.values()
            for finding in scan_result.findings
        )
        issue_findings = tuple(
            finding for finding in findings if finding.status in _ISSUE_STATUSES
        )
        severity_summary = self._severity_summary(issue_findings)
        thresholds = self._policy.effective_thresholds
        effective_findings, excepted_findings, exception_ids = (
            self._apply_exceptions(findings, thresholds, evaluation_time)
        )

        critical_failures = self._matching_findings(
            effective_findings,
            RuleStatus.FAIL,
            SecuritySeverity.CRITICAL,
            thresholds.block_fail_critical,
        )
        if critical_failures:
            return self._decision(
                status=PolicyDecisionStatus.BLOCK,
                reason_code=PolicyReasonCode.BLOCK_CRITICAL_FINDING,
                message="Critical failed findings reached the policy threshold.",
                triggered_findings=critical_failures,
                severity_summary=severity_summary,
                applied_exception_ids=exception_ids,
                excepted_findings=excepted_findings,
                evaluated_at=evaluation_time,
            )

        high_block_failures = self._matching_findings(
            effective_findings,
            RuleStatus.FAIL,
            SecuritySeverity.HIGH,
            thresholds.block_fail_high,
        )
        if high_block_failures:
            return self._decision(
                status=PolicyDecisionStatus.BLOCK,
                reason_code=PolicyReasonCode.BLOCK_THRESHOLD_EXCEEDED,
                message="High-severity failed findings reached the blocking threshold.",
                triggered_findings=high_block_failures,
                severity_summary=severity_summary,
                applied_exception_ids=exception_ids,
                excepted_findings=excepted_findings,
                evaluated_at=evaluation_time,
            )

        if self._insufficient_data(evaluation_result, findings):
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
                applied_exception_ids=exception_ids,
                excepted_findings=excepted_findings,
                evaluated_at=evaluation_time,
            )

        if exception_ids:
            return self._decision(
                status=PolicyDecisionStatus.REQUIRE_APPROVAL,
                reason_code=PolicyReasonCode.APPROVAL_EXCEPTION_APPLIED,
                message="Controlled policy exceptions require human approval.",
                triggered_findings=(),
                severity_summary=severity_summary,
                applied_exception_ids=exception_ids,
                excepted_findings=excepted_findings,
                evaluated_at=evaluation_time,
            )

        approval_conditions = (
            (
                RuleStatus.FAIL,
                SecuritySeverity.HIGH,
                thresholds.approval_fail_high,
                "High-severity failed findings require human approval.",
            ),
            (
                RuleStatus.FAIL,
                SecuritySeverity.MEDIUM,
                thresholds.approval_fail_medium,
                "Medium-severity failed findings reached the approval threshold.",
            ),
            (
                RuleStatus.WARNING,
                SecuritySeverity.HIGH,
                thresholds.approval_warning_high,
                "High-severity warnings require human approval.",
            ),
            (
                RuleStatus.WARNING,
                SecuritySeverity.MEDIUM,
                thresholds.approval_warning_medium,
                "Medium-severity warnings require human approval.",
            ),
        )
        for status, severity, threshold, message in approval_conditions:
            triggered = self._matching_findings(
                effective_findings,
                status,
                severity,
                threshold,
            )
            if triggered:
                return self._decision(
                    status=PolicyDecisionStatus.REQUIRE_APPROVAL,
                    reason_code=PolicyReasonCode.APPROVAL_REQUIRED,
                    message=message,
                    triggered_findings=triggered,
                    severity_summary=severity_summary,
                    applied_exception_ids=(),
                    excepted_findings=(),
                    evaluated_at=evaluation_time,
                )

        return self._decision(
            status=PolicyDecisionStatus.ALLOW,
            reason_code=PolicyReasonCode.ALLOW_BASELINE_MET,
            message="No blocking or approval condition was met by the policy.",
            triggered_findings=issue_findings,
            severity_summary=severity_summary,
            applied_exception_ids=(),
            excepted_findings=(),
            evaluated_at=evaluation_time,
        )

    def _evaluation_time(
        self,
        evaluated_at: datetime | None,
    ) -> datetime | None:
        requires_time = any(
            exception.enabled and exception.expires_at is not None
            for exception in self._policy.exceptions
        )
        if evaluated_at is None:
            if requires_time:
                raise ValueError(
                    "evaluated_at est requis pour evaluer les expirations"
                )
            return None
        if (
            not isinstance(evaluated_at, datetime)
            or evaluated_at.tzinfo is None
            or evaluated_at.utcoffset() is None
        ):
            raise ValueError("evaluated_at doit etre un datetime avec fuseau")
        return evaluated_at.astimezone(timezone.utc)

    def _apply_exceptions(
        self,
        findings: tuple[SecurityFinding, ...],
        thresholds: SecurityPolicyThresholds,
        evaluated_at: datetime | None,
    ) -> tuple[
        tuple[SecurityFinding, ...],
        tuple[SecurityFinding, ...],
        tuple[str, ...],
    ]:
        active_exceptions = tuple(
            exception
            for exception in self._policy.exceptions
            if exception.is_active_at(evaluated_at)
        )
        effective: list[SecurityFinding] = []
        excepted: list[SecurityFinding] = []
        exception_ids: set[str] = set()
        for finding in findings:
            matching = tuple(
                exception
                for exception in active_exceptions
                if self._is_exception_candidate(finding, thresholds)
                and exception.matches(finding)
            )
            if matching:
                excepted.append(finding)
                exception_ids.update(
                    exception.exception_id for exception in matching
                )
            else:
                effective.append(finding)
        return tuple(effective), tuple(excepted), tuple(sorted(exception_ids))

    @staticmethod
    def _is_exception_candidate(
        finding: SecurityFinding,
        thresholds: SecurityPolicyThresholds,
    ) -> bool:
        if finding.severity is SecuritySeverity.CRITICAL:
            return False
        configured_conditions = {
            (RuleStatus.FAIL, SecuritySeverity.HIGH): (
                thresholds.block_fail_high,
                thresholds.approval_fail_high,
            ),
            (RuleStatus.FAIL, SecuritySeverity.MEDIUM): (
                thresholds.approval_fail_medium,
            ),
            (RuleStatus.WARNING, SecuritySeverity.HIGH): (
                thresholds.approval_warning_high,
            ),
            (RuleStatus.WARNING, SecuritySeverity.MEDIUM): (
                thresholds.approval_warning_medium,
            ),
        }
        return any(
            threshold > 0
            for threshold in configured_conditions.get(
                (finding.status, finding.severity),
                (),
            )
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
    def _matching_findings(
        findings: Iterable[SecurityFinding],
        status: RuleStatus,
        severity: SecuritySeverity,
        threshold: int,
    ) -> tuple[SecurityFinding, ...]:
        if threshold == 0:
            return ()
        matches = tuple(
            finding
            for finding in findings
            if finding.status is status and finding.severity is severity
        )
        return matches if len(matches) >= threshold else ()

    def _decision(
        self,
        *,
        status: PolicyDecisionStatus,
        reason_code: PolicyReasonCode,
        message: str,
        triggered_findings: Iterable[SecurityFinding],
        severity_summary: dict[str, int],
        applied_exception_ids: Iterable[str],
        excepted_findings: Iterable[SecurityFinding],
        evaluated_at: datetime | None,
    ) -> PolicyDecision:
        safe_findings = self._safe_findings(triggered_findings)
        safe_excepted_findings = self._safe_findings(excepted_findings)
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
            profile=self._policy.profile,
            applied_exception_ids=tuple(applied_exception_ids),
            excepted_findings=safe_excepted_findings,
            evaluation_time=(
                evaluated_at.isoformat(timespec="seconds").replace("+00:00", "Z")
                if evaluated_at is not None
                else None
            ),
        )

    @classmethod
    def _safe_findings(
        cls,
        findings: Iterable[SecurityFinding],
    ) -> tuple[PolicyTriggeredFinding, ...]:
        return tuple(
            sorted(
                (cls._safe_finding(finding) for finding in findings),
                key=lambda finding: (
                    -finding.severity.priority,
                    finding.rule_id,
                    finding.resource_address,
                    finding.cloud,
                ),
            )
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
