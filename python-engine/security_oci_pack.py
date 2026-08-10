"""Factory deterministe du pack de regles OCI internes CIS-4."""

from __future__ import annotations

from security_oci_rules import (
    OciBroadSubjectAssignmentRule,
    OciCustomerManagedKeyRule,
    OciInTransitEncryptionRule,
    OciManageAllResourcesStatementRule,
    OciObjectVersioningRule,
    OciPublicIpExposureRule,
    OciPublicObjectStorageRule,
    OciSecureBootRule,
    OciUnrestrictedAllPortsIngressRule,
    OciUnrestrictedRdpIngressRule,
    OciUnrestrictedSshIngressRule,
    OciWildcardPermissionRule,
)
from security_rule import SecurityRule


def build_oci_security_rule_pack() -> tuple[SecurityRule, ...]:
    """Construit les 12 regles internes, triees par rule_id croissant."""

    rules: tuple[SecurityRule, ...] = (
        OciPublicIpExposureRule(),
        OciSecureBootRule(),
        OciInTransitEncryptionRule(),
        OciUnrestrictedSshIngressRule(),
        OciUnrestrictedRdpIngressRule(),
        OciUnrestrictedAllPortsIngressRule(),
        OciPublicObjectStorageRule(),
        OciObjectVersioningRule(),
        OciCustomerManagedKeyRule(),
        OciManageAllResourcesStatementRule(),
        OciWildcardPermissionRule(),
        OciBroadSubjectAssignmentRule(),
    )
    return tuple(sorted(rules, key=lambda rule: rule.metadata.rule_id))
