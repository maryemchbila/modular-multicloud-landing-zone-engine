"""Factory deterministe du pack de regles GCP internes CIS-3."""

from __future__ import annotations

from security_gcp_rules import (
    GcpBucketVersioningRule,
    GcpDeletionProtectionRule,
    GcpPrimitiveEditorRoleRule,
    GcpPrimitiveOwnerRoleRule,
    GcpPublicBucketAccessRule,
    GcpPublicIpExposureRule,
    GcpShieldedVmRule,
    GcpUniformBucketAccessRule,
    GcpUnrestrictedAllPortsIngressRule,
    GcpUnrestrictedRdpIngressRule,
    GcpUnrestrictedSshIngressRule,
    GcpWildcardPermissionRule,
)
from security_rule import SecurityRule


def build_gcp_security_rule_pack() -> tuple[SecurityRule, ...]:
    """Construit les 12 regles internes, triees par rule_id croissant."""

    rules: tuple[SecurityRule, ...] = (
        GcpPublicIpExposureRule(),
        GcpShieldedVmRule(),
        GcpDeletionProtectionRule(),
        GcpUnrestrictedSshIngressRule(),
        GcpUnrestrictedRdpIngressRule(),
        GcpUnrestrictedAllPortsIngressRule(),
        GcpPublicBucketAccessRule(),
        GcpUniformBucketAccessRule(),
        GcpBucketVersioningRule(),
        GcpPrimitiveOwnerRoleRule(),
        GcpPrimitiveEditorRoleRule(),
        GcpWildcardPermissionRule(),
    )
    return tuple(sorted(rules, key=lambda rule: rule.metadata.rule_id))
