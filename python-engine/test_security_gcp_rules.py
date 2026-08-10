"""Tests unitaires des 12 regles GCP internes CIS-3."""

import unittest

from security_gcp_rules import (
    GCP_COMPUTE_RESOURCE_TYPE,
    GCP_IAM_RESOURCE_TYPE,
    GCP_NETWORK_RESOURCE_TYPE,
    GCP_STORAGE_RESOURCE_TYPE,
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
from security_models import RuleStatus, SecurityResource, SecuritySeverity


class GcpSecurityRuleTests(unittest.TestCase):
    @staticmethod
    def _resource(
        resource_type: str,
        service: str,
        attributes: dict,
    ) -> SecurityResource:
        names = {
            "compute": "vm_test_01",
            "network": "firewall_test_01",
            "storage": "bucket_test_01",
            "iam": "binding_test_01",
        }
        resource_name = names[service]
        return SecurityResource(
            cloud="gcp",
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
            GcpPublicIpExposureRule(),
            {"public_ip": False},
            RuleStatus.PASS,
        )

    def test_public_ip_true_fails_high(self) -> None:
        rule = GcpPublicIpExposureRule()
        self.assert_status(rule, {"public_ip": True}, RuleStatus.FAIL)
        self.assertIs(rule.metadata.severity, SecuritySeverity.HIGH)

    def test_public_ip_missing_is_skipped(self) -> None:
        self.assert_status(GcpPublicIpExposureRule(), {}, RuleStatus.SKIPPED)

    def test_shielded_vm_true_passes(self) -> None:
        self.assert_status(
            GcpShieldedVmRule(),
            {"shielded_vm": True},
            RuleStatus.PASS,
        )

    def test_shielded_vm_false_warns_medium(self) -> None:
        rule = GcpShieldedVmRule()
        self.assert_status(rule, {"shielded_vm": False}, RuleStatus.WARNING)
        self.assertIs(rule.metadata.severity, SecuritySeverity.MEDIUM)

    def test_shielded_vm_missing_is_skipped(self) -> None:
        self.assert_status(GcpShieldedVmRule(), {}, RuleStatus.SKIPPED)

    def test_deletion_protection_true_passes(self) -> None:
        self.assert_status(
            GcpDeletionProtectionRule(),
            {"deletion_protection": True},
            RuleStatus.PASS,
        )

    def test_deletion_protection_false_warns(self) -> None:
        self.assert_status(
            GcpDeletionProtectionRule(),
            {"deletion_protection": False},
            RuleStatus.WARNING,
        )

    def test_deletion_protection_missing_is_skipped(self) -> None:
        self.assert_status(GcpDeletionProtectionRule(), {}, RuleStatus.SKIPPED)

    def test_unrestricted_ssh_ingress_fails(self) -> None:
        self.assert_status(
            GcpUnrestrictedSshIngressRule(),
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
            GcpUnrestrictedSshIngressRule(),
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
            GcpUnrestrictedSshIngressRule(),
            {
                "direction": "INGRESS",
                "source_ranges": ["10.0.0.0/8"],
            },
            RuleStatus.PASS,
        )

    def test_unrestricted_ingress_without_ssh_port_passes(self) -> None:
        self.assert_status(
            GcpUnrestrictedSshIngressRule(),
            {
                "direction": "INGRESS",
                "source_ranges": ["0.0.0.0/0"],
                "allowed_ports": [443],
                "protocol": "tcp",
            },
            RuleStatus.PASS,
        )

    def test_unrestricted_udp_port_22_passes_ssh_rule(self) -> None:
        self.assert_status(
            GcpUnrestrictedSshIngressRule(),
            {
                "direction": "INGRESS",
                "source_ranges": ["0.0.0.0/0"],
                "allowed_ports": [22],
                "protocol": "udp",
            },
            RuleStatus.PASS,
        )

    def test_ssh_missing_ports_is_skipped(self) -> None:
        self.assert_status(
            GcpUnrestrictedSshIngressRule(),
            {
                "direction": "INGRESS",
                "source_ranges": ["0.0.0.0/0"],
                "protocol": "tcp",
            },
            RuleStatus.SKIPPED,
        )

    def test_unrestricted_rdp_ingress_fails(self) -> None:
        self.assert_status(
            GcpUnrestrictedRdpIngressRule(),
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
            GcpUnrestrictedRdpIngressRule(),
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
            GcpUnrestrictedRdpIngressRule(),
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
            GcpUnrestrictedRdpIngressRule(),
            {
                "direction": "INGRESS",
                "allowed_ports": [3389],
                "protocol": "tcp",
            },
            RuleStatus.SKIPPED,
        )

    def test_unrestricted_all_ports_ingress_fails_high(self) -> None:
        rule = GcpUnrestrictedAllPortsIngressRule()
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
            GcpUnrestrictedAllPortsIngressRule(),
            {
                "direction": "INGRESS",
                "source_ranges": ["10.0.0.0/8"],
                "all_ports": True,
            },
            RuleStatus.PASS,
        )

    def test_unrestricted_source_without_all_ports_passes(self) -> None:
        self.assert_status(
            GcpUnrestrictedAllPortsIngressRule(),
            {
                "direction": "INGRESS",
                "source_ranges": ["0.0.0.0/0"],
                "all_ports": False,
            },
            RuleStatus.PASS,
        )

    def test_all_ports_missing_flag_is_skipped(self) -> None:
        self.assert_status(
            GcpUnrestrictedAllPortsIngressRule(),
            {
                "direction": "INGRESS",
                "source_ranges": ["0.0.0.0/0"],
            },
            RuleStatus.SKIPPED,
        )

    def test_private_bucket_passes(self) -> None:
        self.assert_status(
            GcpPublicBucketAccessRule(),
            {"public_access": False},
            RuleStatus.PASS,
        )

    def test_public_bucket_fails_high(self) -> None:
        rule = GcpPublicBucketAccessRule()
        self.assert_status(rule, {"public_access": True}, RuleStatus.FAIL)
        self.assertIs(rule.metadata.severity, SecuritySeverity.HIGH)

    def test_public_bucket_attribute_missing_is_skipped(self) -> None:
        self.assert_status(GcpPublicBucketAccessRule(), {}, RuleStatus.SKIPPED)

    def test_uniform_bucket_access_true_passes(self) -> None:
        self.assert_status(
            GcpUniformBucketAccessRule(),
            {"uniform_bucket_level_access": True},
            RuleStatus.PASS,
        )

    def test_uniform_bucket_access_false_warns(self) -> None:
        self.assert_status(
            GcpUniformBucketAccessRule(),
            {"uniform_bucket_level_access": False},
            RuleStatus.WARNING,
        )

    def test_uniform_bucket_access_missing_is_skipped(self) -> None:
        self.assert_status(GcpUniformBucketAccessRule(), {}, RuleStatus.SKIPPED)

    def test_bucket_versioning_true_passes(self) -> None:
        self.assert_status(
            GcpBucketVersioningRule(),
            {"versioning_enabled": True},
            RuleStatus.PASS,
        )

    def test_bucket_versioning_false_warns(self) -> None:
        self.assert_status(
            GcpBucketVersioningRule(),
            {"versioning_enabled": False},
            RuleStatus.WARNING,
        )

    def test_bucket_versioning_missing_is_skipped(self) -> None:
        self.assert_status(GcpBucketVersioningRule(), {}, RuleStatus.SKIPPED)

    def test_owner_role_fails(self) -> None:
        self.assert_status(
            GcpPrimitiveOwnerRoleRule(),
            {"roles": ["roles/owner"]},
            RuleStatus.FAIL,
        )

    def test_non_owner_role_passes(self) -> None:
        self.assert_status(
            GcpPrimitiveOwnerRoleRule(),
            {"roles": ["roles/viewer"]},
            RuleStatus.PASS,
        )

    def test_owner_roles_missing_is_skipped(self) -> None:
        self.assert_status(GcpPrimitiveOwnerRoleRule(), {}, RuleStatus.SKIPPED)

    def test_editor_role_warns_medium(self) -> None:
        rule = GcpPrimitiveEditorRoleRule()
        self.assert_status(
            rule,
            {"roles": ["roles/editor"]},
            RuleStatus.WARNING,
        )
        self.assertIs(rule.metadata.severity, SecuritySeverity.MEDIUM)

    def test_non_editor_role_passes(self) -> None:
        self.assert_status(
            GcpPrimitiveEditorRoleRule(),
            {"roles": ["roles/viewer"]},
            RuleStatus.PASS,
        )

    def test_editor_roles_missing_is_skipped(self) -> None:
        self.assert_status(GcpPrimitiveEditorRoleRule(), {}, RuleStatus.SKIPPED)

    def test_exact_wildcard_permission_fails(self) -> None:
        self.assert_status(
            GcpWildcardPermissionRule(),
            {"permissions": ["*"]},
            RuleStatus.FAIL,
        )

    def test_normal_permissions_pass(self) -> None:
        self.assert_status(
            GcpWildcardPermissionRule(),
            {"permissions": ["storage.objects.get"]},
            RuleStatus.PASS,
        )

    def test_permission_containing_asterisk_is_not_exact_wildcard(self) -> None:
        self.assert_status(
            GcpWildcardPermissionRule(),
            {"permissions": ["storage.*"]},
            RuleStatus.PASS,
        )

    def test_permissions_missing_is_skipped(self) -> None:
        self.assert_status(GcpWildcardPermissionRule(), {}, RuleStatus.SKIPPED)

    def test_invalid_attribute_type_is_skipped(self) -> None:
        finding = self._evaluate(
            GcpPublicIpExposureRule(),
            {"public_ip": "false"},
        )

        self.assertIs(finding.status, RuleStatus.SKIPPED)
        self.assertEqual(
            finding.message,
            "Required security attribute is unavailable.",
        )

    def test_rules_do_not_mutate_resource_attributes(self) -> None:
        attributes = {"public_ip": True}
        resource = self._resource(GCP_COMPUTE_RESOURCE_TYPE, "compute", attributes)

        GcpPublicIpExposureRule().evaluate(resource)

        self.assertEqual(resource.attributes, attributes)

    def test_resource_type_constants_match_gcp_generator_conventions(self) -> None:
        self.assertEqual(GCP_COMPUTE_RESOURCE_TYPE, "google_compute_instance")
        self.assertEqual(GCP_NETWORK_RESOURCE_TYPE, "google_compute_firewall")
        self.assertEqual(GCP_STORAGE_RESOURCE_TYPE, "google_storage_bucket")
        self.assertEqual(GCP_IAM_RESOURCE_TYPE, "google_project_iam_member")


if __name__ == "__main__":
    unittest.main()
