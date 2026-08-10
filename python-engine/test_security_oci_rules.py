"""Tests unitaires des 12 regles OCI internes CIS-4."""

import unittest

from security_models import RuleStatus, SecurityResource, SecuritySeverity
from security_oci_rules import (
    OCI_COMPUTE_RESOURCE_TYPE,
    OCI_IAM_RESOURCE_TYPE,
    OCI_NETWORK_RESOURCE_TYPE,
    OCI_STORAGE_RESOURCE_TYPE,
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


class OciSecurityRuleTests(unittest.TestCase):
    @staticmethod
    def _resource(
        resource_type: str,
        service: str,
        attributes: dict,
    ) -> SecurityResource:
        names = {
            "compute": "oci_vm_test_01",
            "network": "security_list_test_01",
            "storage": "oci_bucket_test_01",
            "iam": "oci_policy_test_01",
        }
        resource_name = names[service]
        return SecurityResource(
            cloud="oci",
            service=service,
            resource_type=resource_type,
            resource_name=resource_name,
            resource_address=f"{resource_type}.{resource_name}",
            attributes=attributes,
        )

    def _evaluate(self, rule, attributes: dict):
        return rule.evaluate(
            self._resource(
                rule.metadata.resource_type,
                rule.metadata.service,
                attributes,
            )
        )

    def assert_status(self, rule, attributes: dict, status: RuleStatus) -> None:
        finding = self._evaluate(rule, attributes)
        self.assertIs(finding.status, status)
        self.assertEqual(finding.rule_id, rule.metadata.rule_id)
        self.assertEqual(finding.severity, rule.metadata.severity)

    def test_public_ip_false_passes(self) -> None:
        self.assert_status(
            OciPublicIpExposureRule(),
            {"public_ip": False},
            RuleStatus.PASS,
        )

    def test_public_ip_true_fails_high(self) -> None:
        rule = OciPublicIpExposureRule()
        self.assert_status(rule, {"public_ip": True}, RuleStatus.FAIL)
        self.assertIs(rule.metadata.severity, SecuritySeverity.HIGH)

    def test_public_ip_missing_is_skipped(self) -> None:
        self.assert_status(OciPublicIpExposureRule(), {}, RuleStatus.SKIPPED)

    def test_secure_boot_true_passes(self) -> None:
        self.assert_status(
            OciSecureBootRule(),
            {"secure_boot": True},
            RuleStatus.PASS,
        )

    def test_secure_boot_false_warns_medium(self) -> None:
        rule = OciSecureBootRule()
        self.assert_status(rule, {"secure_boot": False}, RuleStatus.WARNING)
        self.assertIs(rule.metadata.severity, SecuritySeverity.MEDIUM)

    def test_secure_boot_missing_is_skipped(self) -> None:
        self.assert_status(OciSecureBootRule(), {}, RuleStatus.SKIPPED)

    def test_in_transit_encryption_true_passes(self) -> None:
        self.assert_status(
            OciInTransitEncryptionRule(),
            {"in_transit_encryption": True},
            RuleStatus.PASS,
        )

    def test_in_transit_encryption_false_warns_medium(self) -> None:
        rule = OciInTransitEncryptionRule()
        self.assert_status(
            rule,
            {"in_transit_encryption": False},
            RuleStatus.WARNING,
        )
        self.assertIs(rule.metadata.severity, SecuritySeverity.MEDIUM)

    def test_in_transit_encryption_missing_is_skipped(self) -> None:
        self.assert_status(OciInTransitEncryptionRule(), {}, RuleStatus.SKIPPED)

    def test_unrestricted_ssh_ingress_fails(self) -> None:
        self.assert_status(
            OciUnrestrictedSshIngressRule(),
            {
                "direction": "INGRESS",
                "source_ranges": ["0.0.0.0/0"],
                "allowed_ports": [22],
                "protocol": "tcp",
            },
            RuleStatus.FAIL,
        )

    def test_restricted_ssh_ingress_passes(self) -> None:
        self.assert_status(
            OciUnrestrictedSshIngressRule(),
            {
                "direction": "INGRESS",
                "source_ranges": ["10.0.0.0/8"],
                "allowed_ports": [22],
                "protocol": "tcp",
            },
            RuleStatus.PASS,
        )

    def test_restricted_ssh_source_does_not_require_ports(self) -> None:
        self.assert_status(
            OciUnrestrictedSshIngressRule(),
            {
                "direction": "INGRESS",
                "source_ranges": ["10.0.0.0/8"],
            },
            RuleStatus.PASS,
        )

    def test_unrestricted_ingress_without_ssh_port_passes(self) -> None:
        self.assert_status(
            OciUnrestrictedSshIngressRule(),
            {
                "direction": "INGRESS",
                "source_ranges": ["0.0.0.0/0"],
                "allowed_ports": [443],
                "protocol": "tcp",
            },
            RuleStatus.PASS,
        )

    def test_non_ingress_ssh_rule_passes_without_other_attributes(self) -> None:
        self.assert_status(
            OciUnrestrictedSshIngressRule(),
            {"direction": "EGRESS"},
            RuleStatus.PASS,
        )

    def test_ssh_missing_ports_is_skipped(self) -> None:
        self.assert_status(
            OciUnrestrictedSshIngressRule(),
            {
                "direction": "INGRESS",
                "source_ranges": ["0.0.0.0/0"],
                "protocol": "tcp",
            },
            RuleStatus.SKIPPED,
        )

    def test_unrestricted_rdp_ingress_fails(self) -> None:
        self.assert_status(
            OciUnrestrictedRdpIngressRule(),
            {
                "direction": "INGRESS",
                "source_ranges": ["0.0.0.0/0"],
                "allowed_ports": [3389],
                "protocol": "tcp",
            },
            RuleStatus.FAIL,
        )

    def test_restricted_rdp_ingress_passes(self) -> None:
        self.assert_status(
            OciUnrestrictedRdpIngressRule(),
            {
                "direction": "INGRESS",
                "source_ranges": ["192.0.2.0/24"],
                "allowed_ports": [3389],
                "protocol": "tcp",
            },
            RuleStatus.PASS,
        )

    def test_unrestricted_ingress_without_rdp_port_passes(self) -> None:
        self.assert_status(
            OciUnrestrictedRdpIngressRule(),
            {
                "direction": "INGRESS",
                "source_ranges": ["0.0.0.0/0"],
                "allowed_ports": [22],
                "protocol": "tcp",
            },
            RuleStatus.PASS,
        )

    def test_rdp_missing_source_ranges_is_skipped(self) -> None:
        self.assert_status(
            OciUnrestrictedRdpIngressRule(),
            {
                "direction": "INGRESS",
                "allowed_ports": [3389],
                "protocol": "tcp",
            },
            RuleStatus.SKIPPED,
        )

    def test_unrestricted_all_ports_ingress_fails_high(self) -> None:
        rule = OciUnrestrictedAllPortsIngressRule()
        self.assert_status(
            rule,
            {
                "direction": "INGRESS",
                "source_ranges": ["0.0.0.0/0"],
                "all_ports": True,
            },
            RuleStatus.FAIL,
        )
        self.assertIs(rule.metadata.severity, SecuritySeverity.HIGH)

    def test_restricted_all_ports_ingress_passes(self) -> None:
        self.assert_status(
            OciUnrestrictedAllPortsIngressRule(),
            {
                "direction": "INGRESS",
                "source_ranges": ["10.0.0.0/8"],
                "all_ports": True,
            },
            RuleStatus.PASS,
        )

    def test_unrestricted_source_without_all_ports_passes(self) -> None:
        self.assert_status(
            OciUnrestrictedAllPortsIngressRule(),
            {
                "direction": "INGRESS",
                "source_ranges": ["0.0.0.0/0"],
                "all_ports": False,
            },
            RuleStatus.PASS,
        )

    def test_all_ports_missing_flag_is_skipped(self) -> None:
        self.assert_status(
            OciUnrestrictedAllPortsIngressRule(),
            {
                "direction": "INGRESS",
                "source_ranges": ["0.0.0.0/0"],
            },
            RuleStatus.SKIPPED,
        )

    def test_private_object_storage_passes(self) -> None:
        self.assert_status(
            OciPublicObjectStorageRule(),
            {"public_access": False},
            RuleStatus.PASS,
        )

    def test_public_object_storage_fails_high(self) -> None:
        rule = OciPublicObjectStorageRule()
        self.assert_status(rule, {"public_access": True}, RuleStatus.FAIL)
        self.assertIs(rule.metadata.severity, SecuritySeverity.HIGH)

    def test_public_access_missing_is_skipped(self) -> None:
        self.assert_status(OciPublicObjectStorageRule(), {}, RuleStatus.SKIPPED)

    def test_object_versioning_true_passes(self) -> None:
        self.assert_status(
            OciObjectVersioningRule(),
            {"versioning_enabled": True},
            RuleStatus.PASS,
        )

    def test_object_versioning_false_warns(self) -> None:
        self.assert_status(
            OciObjectVersioningRule(),
            {"versioning_enabled": False},
            RuleStatus.WARNING,
        )

    def test_object_versioning_missing_is_skipped(self) -> None:
        self.assert_status(OciObjectVersioningRule(), {}, RuleStatus.SKIPPED)

    def test_customer_managed_key_true_passes(self) -> None:
        self.assert_status(
            OciCustomerManagedKeyRule(),
            {"customer_managed_key": True},
            RuleStatus.PASS,
        )

    def test_customer_managed_key_false_warns(self) -> None:
        self.assert_status(
            OciCustomerManagedKeyRule(),
            {"customer_managed_key": False},
            RuleStatus.WARNING,
        )

    def test_customer_managed_key_missing_is_skipped(self) -> None:
        self.assert_status(OciCustomerManagedKeyRule(), {}, RuleStatus.SKIPPED)

    def test_canonical_manage_all_resources_statement_fails(self) -> None:
        self.assert_status(
            OciManageAllResourcesStatementRule(),
            {"statements": ["manage all-resources"]},
            RuleStatus.FAIL,
        )

    def test_manage_all_statement_comparison_is_case_normalised(self) -> None:
        self.assert_status(
            OciManageAllResourcesStatementRule(),
            {"statements": [" MANAGE ALL-RESOURCES "]},
            RuleStatus.FAIL,
        )

    def test_restricted_statement_passes(self) -> None:
        self.assert_status(
            OciManageAllResourcesStatementRule(),
            {"statements": ["read buckets"]},
            RuleStatus.PASS,
        )

    def test_full_policy_language_is_not_parsed_as_canonical_token(self) -> None:
        self.assert_status(
            OciManageAllResourcesStatementRule(),
            {"statements": ["Allow group admins to manage all-resources in tenancy"]},
            RuleStatus.PASS,
        )

    def test_statements_missing_is_skipped(self) -> None:
        self.assert_status(
            OciManageAllResourcesStatementRule(),
            {},
            RuleStatus.SKIPPED,
        )

    def test_exact_wildcard_permission_fails(self) -> None:
        self.assert_status(
            OciWildcardPermissionRule(),
            {"permissions": ["*"]},
            RuleStatus.FAIL,
        )

    def test_normal_permission_passes(self) -> None:
        self.assert_status(
            OciWildcardPermissionRule(),
            {"permissions": ["objectstorage-namespaces-read"]},
            RuleStatus.PASS,
        )

    def test_permission_containing_asterisk_is_not_exact_wildcard(self) -> None:
        self.assert_status(
            OciWildcardPermissionRule(),
            {"permissions": ["objectstorage-*"]},
            RuleStatus.PASS,
        )

    def test_permissions_missing_is_skipped(self) -> None:
        self.assert_status(OciWildcardPermissionRule(), {}, RuleStatus.SKIPPED)

    def test_broad_subject_true_warns_medium(self) -> None:
        rule = OciBroadSubjectAssignmentRule()
        self.assert_status(rule, {"broad_subject": True}, RuleStatus.WARNING)
        self.assertIs(rule.metadata.severity, SecuritySeverity.MEDIUM)

    def test_broad_subject_false_passes(self) -> None:
        self.assert_status(
            OciBroadSubjectAssignmentRule(),
            {"broad_subject": False},
            RuleStatus.PASS,
        )

    def test_broad_subject_missing_is_skipped(self) -> None:
        self.assert_status(OciBroadSubjectAssignmentRule(), {}, RuleStatus.SKIPPED)

    def test_invalid_attribute_type_is_skipped(self) -> None:
        finding = self._evaluate(OciSecureBootRule(), {"secure_boot": "true"})

        self.assertIs(finding.status, RuleStatus.SKIPPED)
        self.assertEqual(
            finding.message,
            "Required security attribute is unavailable.",
        )

    def test_rules_do_not_mutate_resource_attributes(self) -> None:
        attributes = {"public_ip": True}
        resource = self._resource(OCI_COMPUTE_RESOURCE_TYPE, "compute", attributes)

        OciPublicIpExposureRule().evaluate(resource)

        self.assertEqual(resource.attributes, attributes)

    def test_resource_type_constants_match_oci_generator_conventions(self) -> None:
        self.assertEqual(OCI_COMPUTE_RESOURCE_TYPE, "oci_core_instance")
        self.assertEqual(OCI_NETWORK_RESOURCE_TYPE, "oci_core_security_list")
        self.assertEqual(OCI_STORAGE_RESOURCE_TYPE, "oci_objectstorage_bucket")
        self.assertEqual(OCI_IAM_RESOURCE_TYPE, "oci_identity_policy")


if __name__ == "__main__":
    unittest.main()
