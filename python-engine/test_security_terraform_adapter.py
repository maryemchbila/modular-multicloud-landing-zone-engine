"""Tests de l'adaptateur pur Terraform plan vers SecurityResource."""

import json
import subprocess
import unittest
from copy import deepcopy
from unittest.mock import patch

import security_terraform_adapter
from security_evaluation import build_default_multicloud_security_engine
from security_gcp_pack import build_gcp_security_rule_pack
from security_models import RuleStatus, SecurityScanStatus, SecuritySeverity
from security_oci_pack import build_oci_security_rule_pack
from security_scanner import SecurityComplianceScanner
from security_terraform_adapter import (
    SUPPORTED_GCP_RESOURCE_TYPES,
    SUPPORTED_OCI_RESOURCE_TYPES,
    TerraformSecurityAdaptationResult,
    TerraformSecurityResourceAdapter,
)
from terraform_runner import TerraformRunner


class TerraformSecurityResourceAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = TerraformSecurityResourceAdapter()

    @staticmethod
    def _entry(
        resource_type: str,
        name: str,
        values: dict | None = None,
        *,
        address: str | None = None,
        mode: str | None = "managed",
    ) -> dict:
        entry = {
            "address": address or f"{resource_type}.{name}",
            "type": resource_type,
            "name": name,
            "values": {} if values is None else values,
        }
        if mode is not None:
            entry["mode"] = mode
        return entry

    @staticmethod
    def _plan(
        resources: list | None = None,
        *,
        child_modules: list | None = None,
    ) -> dict:
        root_module = {"resources": resources or []}
        if child_modules is not None:
            root_module["child_modules"] = child_modules
        return {
            "format_version": "1.2",
            "terraform_version": "1.14.0",
            "planned_values": {"root_module": root_module},
        }

    @staticmethod
    def _gcp_compute_values(
        *,
        public: bool = False,
        shielded: bool = True,
        deletion_protection: bool = True,
    ) -> dict:
        interface = {"network": "default"}
        if public:
            interface["access_config"] = [{}]
        return {
            "network_interface": [interface],
            "shielded_instance_config": [
                {"enable_secure_boot": shielded}
            ],
            "deletion_protection": deletion_protection,
        }

    @staticmethod
    def _gcp_firewall_values(
        *,
        ports: list[str] | None = None,
        source_ranges: list[str] | None = None,
        protocol: str = "tcp",
        direction: str = "INGRESS",
        include_ports: bool = True,
    ) -> dict:
        allow = {"protocol": protocol}
        if include_ports:
            allow["ports"] = ["22"] if ports is None else ports
        return {
            "direction": direction,
            "source_ranges": source_ranges or ["0.0.0.0/0"],
            "allow": [allow],
        }

    @staticmethod
    def _oci_compute_values(
        *,
        public: bool = False,
        secure_boot: bool = True,
        in_transit: bool = True,
    ) -> dict:
        return {
            "create_vnic_details": [{"assign_public_ip": public}],
            "platform_config": [{"is_secure_boot_enabled": secure_boot}],
            "launch_options": [
                {"is_pv_encryption_in_transit_enabled": in_transit}
            ],
        }

    @staticmethod
    def _oci_security_list_values(
        *,
        port_min: int = 22,
        port_max: int = 22,
        source: str = "0.0.0.0/0",
        protocol: str = "6",
    ) -> dict:
        return {
            "ingress_security_rules": [
                {
                    "source": source,
                    "protocol": protocol,
                    "tcp_options": [
                        {
                            "destination_port_range": [
                                {"min": port_min, "max": port_max}
                            ]
                        }
                    ],
                }
            ]
        }

    def _adapt_one(self, entry: dict):
        result = self.adapter.from_plan_dict(self._plan([entry]))
        self.assertEqual(result.resources_seen, 1)
        self.assertEqual(result.resources_adapted, 1)
        self.assertEqual(result.resources_skipped, 0)
        self.assertEqual(len(result.resources), 1)
        return result.resources[0]

    def test_empty_plan(self) -> None:
        result = self.adapter.from_plan_dict({})
        self.assertEqual(result.resources, ())
        self.assertEqual(result.resources_seen, 0)
        self.assertIn(self.adapter.PLANNED_VALUES_MISSING, result.warnings)

    def test_planned_values_absent(self) -> None:
        result = self.adapter.from_plan_dict({"format_version": "1.2"})
        self.assertEqual(result.resources_adapted, 0)
        self.assertEqual(result.resources_skipped, 0)

    def test_root_module_absent(self) -> None:
        result = self.adapter.from_plan_dict({"planned_values": {}})
        self.assertEqual(result.resources, ())
        self.assertIn(self.adapter.ROOT_MODULE_MISSING, result.warnings)

    def test_root_module_resources_empty(self) -> None:
        result = self.adapter.from_plan_dict(self._plan())
        self.assertEqual(result.resources, ())
        self.assertEqual(result.warnings, ())

    def test_gcp_compute_resource(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "google_compute_instance",
                "vm_private",
                self._gcp_compute_values(),
            )
        )
        self.assertEqual(resource.cloud, "gcp")
        self.assertEqual(resource.service, "compute")
        self.assertEqual(
            resource.attributes,
            {
                "public_ip": False,
                "shielded_vm": True,
                "deletion_protection": True,
            },
        )

    def test_gcp_network_resource(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "google_compute_firewall",
                "allow_ssh",
                self._gcp_firewall_values(),
            )
        )
        self.assertEqual(resource.service, "network")
        self.assertEqual(resource.attributes["protocol"], "tcp")
        self.assertEqual(resource.attributes["allowed_ports"], (22,))

    def test_gcp_storage_resource(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "google_storage_bucket",
                "logs",
                {
                    "public_access_prevention": "enforced",
                    "uniform_bucket_level_access": True,
                    "versioning": [{"enabled": True}],
                },
            )
        )
        self.assertEqual(
            resource.attributes,
            {
                "public_access": False,
                "uniform_bucket_level_access": True,
                "versioning_enabled": True,
            },
        )

    def test_gcp_iam_resource(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "google_project_iam_member",
                "owner",
                {
                    "role": "roles/owner",
                    "member": "user:owner@example.test",
                },
            )
        )
        self.assertEqual(resource.attributes["roles"], ("roles/owner",))
        self.assertEqual(
            resource.attributes["members"],
            ("user:owner@example.test",),
        )
        self.assertNotIn("permissions", resource.attributes)

    def test_oci_compute_resource(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "oci_core_instance",
                "vm_private",
                self._oci_compute_values(),
            )
        )
        self.assertEqual(resource.cloud, "oci")
        self.assertEqual(
            resource.attributes,
            {
                "public_ip": False,
                "secure_boot": True,
                "in_transit_encryption": True,
            },
        )

    def test_oci_network_resource(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "oci_core_security_list",
                "ssh",
                self._oci_security_list_values(),
            )
        )
        self.assertEqual(resource.attributes["protocol"], "tcp")
        self.assertEqual(resource.attributes["allowed_ports"], (22,))
        self.assertFalse(resource.attributes["all_ports"])

    def test_oci_storage_resource(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "oci_objectstorage_bucket",
                "archive",
                {
                    "access_type": "NoPublicAccess",
                    "versioning": "Enabled",
                    "kms_key_id": "ocid1.key.synthetic",
                },
            )
        )
        self.assertEqual(
            resource.attributes,
            {
                "public_access": False,
                "versioning_enabled": True,
                "customer_managed_key": True,
            },
        )

    def test_oci_iam_resource(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "oci_identity_policy",
                "restricted",
                {"statements": ["read buckets", "inspect compartments"]},
            )
        )
        self.assertEqual(
            resource.attributes["statements"],
            ("inspect compartments", "read buckets"),
        )
        self.assertNotIn("permissions", resource.attributes)
        self.assertNotIn("broad_subject", resource.attributes)

    def test_unknown_resource_type_is_diagnostic_only(self) -> None:
        result = self.adapter.from_plan_dict(
            self._plan([self._entry("google_sql_database_instance", "db")])
        )
        self.assertEqual(result.resources, ())
        self.assertEqual(result.resources_seen, 1)
        self.assertEqual(result.resources_adapted, 0)
        self.assertEqual(result.resources_skipped, 1)
        self.assertEqual(
            result.unsupported_resource_types,
            ("google_sql_database_instance",),
        )

    def test_multiple_resources_are_adapted(self) -> None:
        result = self.adapter.from_plan_dict(
            self._plan(
                [
                    self._entry(
                        "google_compute_instance",
                        "gcp_vm",
                        self._gcp_compute_values(),
                    ),
                    self._entry(
                        "oci_core_instance",
                        "oci_vm",
                        self._oci_compute_values(),
                    ),
                ]
            )
        )
        self.assertEqual(result.resources_seen, 2)
        self.assertEqual(result.resources_adapted, 2)
        self.assertEqual({item.cloud for item in result.resources}, {"gcp", "oci"})

    def test_child_module_resources_are_adapted(self) -> None:
        child = {
            "address": "module.compute",
            "resources": [
                self._entry(
                    "google_compute_instance",
                    "child_vm",
                    self._gcp_compute_values(),
                    address="module.compute.google_compute_instance.child_vm",
                )
            ],
        }
        result = self.adapter.from_plan_dict(self._plan(child_modules=[child]))
        self.assertEqual(result.resources_adapted, 1)
        self.assertTrue(result.resources[0].resource_address.startswith("module."))

    def test_nested_child_modules_are_adapted(self) -> None:
        grandchild = {
            "address": "module.parent.module.storage",
            "resources": [
                self._entry(
                    "oci_objectstorage_bucket",
                    "nested_bucket",
                    {"access_type": "NoPublicAccess"},
                    address=(
                        "module.parent.module.storage."
                        "oci_objectstorage_bucket.nested_bucket"
                    ),
                )
            ],
        }
        child = {
            "address": "module.parent",
            "resources": [],
            "child_modules": [grandchild],
        }
        result = self.adapter.from_plan_dict(self._plan(child_modules=[child]))
        self.assertEqual(result.resources_seen, 1)
        self.assertEqual(result.resources[0].cloud, "oci")

    def test_resource_order_is_deterministic(self) -> None:
        entries = [
            self._entry(
                "oci_core_instance",
                "zeta",
                self._oci_compute_values(),
            ),
            self._entry(
                "google_compute_instance",
                "alpha",
                self._gcp_compute_values(),
            ),
        ]
        first = self.adapter.from_plan_dict(self._plan(entries))
        second = self.adapter.from_plan_dict(self._plan(list(reversed(entries))))
        self.assertEqual(first.to_json(), second.to_json())
        self.assertEqual([item.cloud for item in first.resources], ["gcp", "oci"])

    def test_input_is_not_mutated(self) -> None:
        plan = self._plan(
            [
                self._entry(
                    "google_compute_instance",
                    "immutable",
                    self._gcp_compute_values(public=True),
                )
            ]
        )
        before = deepcopy(plan)
        self.adapter.from_plan_dict(plan)
        self.assertEqual(plan, before)

    def test_gcp_private_instance_has_public_ip_false(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "google_compute_instance",
                "private",
                self._gcp_compute_values(public=False),
            )
        )
        self.assertFalse(resource.attributes["public_ip"])

    def test_gcp_access_config_means_public_ip_true(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "google_compute_instance",
                "public",
                self._gcp_compute_values(public=True),
            )
        )
        self.assertTrue(resource.attributes["public_ip"])

    def test_gcp_shielded_vm_true(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "google_compute_instance",
                "shielded",
                self._gcp_compute_values(shielded=True),
            )
        )
        self.assertTrue(resource.attributes["shielded_vm"])

    def test_gcp_shielded_vm_false(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "google_compute_instance",
                "unshielded",
                self._gcp_compute_values(shielded=False),
            )
        )
        self.assertFalse(resource.attributes["shielded_vm"])

    def test_gcp_deletion_protection_true(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "google_compute_instance",
                "protected",
                self._gcp_compute_values(deletion_protection=True),
            )
        )
        self.assertTrue(resource.attributes["deletion_protection"])

    def test_gcp_deletion_protection_false(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "google_compute_instance",
                "unprotected",
                self._gcp_compute_values(deletion_protection=False),
            )
        )
        self.assertFalse(resource.attributes["deletion_protection"])

    def test_gcp_compute_missing_fields_are_not_invented(self) -> None:
        resource = self._adapt_one(
            self._entry("google_compute_instance", "unknown", {})
        )
        self.assertEqual(resource.attributes, {})

    def test_gcp_public_ssh_is_normalised(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "google_compute_firewall",
                "ssh_public",
                self._gcp_firewall_values(ports=["22"]),
            )
        )
        self.assertEqual(resource.attributes["source_ranges"], ("0.0.0.0/0",))
        self.assertEqual(resource.attributes["allowed_ports"], (22,))

    def test_gcp_restricted_ssh_is_normalised(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "google_compute_firewall",
                "ssh_private",
                self._gcp_firewall_values(source_ranges=["10.0.0.0/8"]),
            )
        )
        self.assertEqual(resource.attributes["source_ranges"], ("10.0.0.0/8",))

    def test_gcp_public_rdp_is_normalised(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "google_compute_firewall",
                "rdp_public",
                self._gcp_firewall_values(ports=["3389"]),
            )
        )
        self.assertEqual(resource.attributes["allowed_ports"], (3389,))

    def test_gcp_all_ports_public_is_normalised(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "google_compute_firewall",
                "all_public",
                self._gcp_firewall_values(include_ports=False),
            )
        )
        self.assertTrue(resource.attributes["all_ports"])

    def test_gcp_tcp_protocol_is_normalised(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "google_compute_firewall",
                "tcp",
                self._gcp_firewall_values(protocol="TCP"),
            )
        )
        self.assertEqual(resource.attributes["protocol"], "tcp")

    def test_gcp_multiple_ports_are_preserved(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "google_compute_firewall",
                "admin",
                self._gcp_firewall_values(ports=["3389", "22", "443"]),
            )
        )
        self.assertEqual(resource.attributes["allowed_ports"], (22, 443, 3389))

    def test_gcp_network_missing_fields_are_not_invented(self) -> None:
        resource = self._adapt_one(
            self._entry("google_compute_firewall", "unknown", {})
        )
        self.assertEqual(resource.attributes, {})

    def test_gcp_unknown_ports_do_not_invent_all_ports(self) -> None:
        values = self._gcp_firewall_values()
        values["allow"][0]["ports"] = None
        resource = self._adapt_one(
            self._entry("google_compute_firewall", "unknown_ports", values)
        )
        self.assertNotIn("allowed_ports", resource.attributes)
        self.assertNotIn("all_ports", resource.attributes)

    def test_gcp_multiple_allow_blocks_become_distinct_resources(self) -> None:
        result = self.adapter.from_plan_dict(
            self._plan(
                [
                    self._entry(
                        "google_compute_firewall",
                        "multi",
                        {
                            "direction": "INGRESS",
                            "source_ranges": ["0.0.0.0/0"],
                            "allow": [
                                {"protocol": "tcp", "ports": ["3389"]},
                                {"protocol": "tcp", "ports": ["22"]},
                            ],
                        },
                    )
                ]
            )
        )
        self.assertEqual(result.resources_seen, 1)
        self.assertEqual(result.resources_adapted, 1)
        self.assertEqual(len(result.resources), 2)
        self.assertNotEqual(
            result.resources[0].resource_address,
            result.resources[1].resource_address,
        )

    def test_gcp_firewall_output_reaches_expected_finding(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "google_compute_firewall",
                "ssh_public",
                self._gcp_firewall_values(),
            )
        )
        result = SecurityComplianceScanner(build_gcp_security_rule_pack()).scan(
            "gcp",
            [resource],
        )
        ssh = next(
            finding
            for finding in result.findings
            if finding.rule_id == "GCP_INTERNAL_NETWORK_001"
        )
        self.assertIs(ssh.status, RuleStatus.FAIL)

    def test_gcp_public_access_is_only_inferred_when_enforced(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "google_storage_bucket",
                "inherited",
                {"public_access_prevention": "inherited"},
            )
        )
        self.assertNotIn("public_access", resource.attributes)

    def test_gcp_versioning_and_uniform_access_are_mapped(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "google_storage_bucket",
                "secure",
                {
                    "uniform_bucket_level_access": False,
                    "versioning": [{"enabled": False}],
                },
            )
        )
        self.assertFalse(resource.attributes["uniform_bucket_level_access"])
        self.assertFalse(resource.attributes["versioning_enabled"])

    def test_gcp_iam_editor_and_members_are_mapped(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "google_project_iam_member",
                "editor",
                {
                    "role": "roles/editor",
                    "member": "group:editors@example.test",
                },
            )
        )
        self.assertEqual(resource.attributes["roles"], ("roles/editor",))
        self.assertEqual(len(resource.attributes["members"]), 1)

    def test_gcp_iam_permissions_are_never_invented_or_copied(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "google_project_iam_member",
                "custom",
                {"role": "roles/viewer", "permissions": ["*"]},
            )
        )
        self.assertNotIn("permissions", resource.attributes)

    def test_oci_public_ip_is_mapped(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "oci_core_instance",
                "public",
                self._oci_compute_values(public=True),
            )
        )
        self.assertTrue(resource.attributes["public_ip"])

    def test_oci_compute_missing_fields_are_not_invented(self) -> None:
        resource = self._adapt_one(self._entry("oci_core_instance", "unknown", {}))
        self.assertEqual(resource.attributes, {})

    def test_oci_protocol_six_is_normalised_to_tcp(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "oci_core_security_list",
                "tcp",
                self._oci_security_list_values(protocol="6"),
            )
        )
        self.assertEqual(resource.attributes["protocol"], "tcp")

    def test_oci_protocol_seventeen_is_normalised_to_udp(self) -> None:
        values = {
            "ingress_security_rules": [
                {"source": "0.0.0.0/0", "protocol": "17"}
            ]
        }
        resource = self._adapt_one(
            self._entry("oci_core_security_list", "udp", values)
        )
        self.assertEqual(resource.attributes["protocol"], "udp")

    def test_oci_public_ssh_is_normalised(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "oci_core_security_list",
                "ssh",
                self._oci_security_list_values(port_min=22, port_max=22),
            )
        )
        self.assertEqual(resource.attributes["allowed_ports"], (22,))

    def test_oci_public_rdp_is_normalised(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "oci_core_security_list",
                "rdp",
                self._oci_security_list_values(port_min=3389, port_max=3389),
            )
        )
        self.assertEqual(resource.attributes["allowed_ports"], (3389,))

    def test_oci_all_ports_public_is_normalised(self) -> None:
        values = {
            "ingress_security_rules": [
                {"source": "0.0.0.0/0", "protocol": "all"}
            ]
        }
        resource = self._adapt_one(
            self._entry("oci_core_security_list", "all", values)
        )
        self.assertTrue(resource.attributes["all_ports"])

    def test_oci_unknown_tcp_options_do_not_invent_all_ports(self) -> None:
        values = {
            "ingress_security_rules": [
                {
                    "source": "0.0.0.0/0",
                    "protocol": "6",
                    "tcp_options": None,
                }
            ]
        }
        resource = self._adapt_one(
            self._entry("oci_core_security_list", "unknown_ports", values)
        )
        self.assertNotIn("allowed_ports", resource.attributes)
        self.assertNotIn("all_ports", resource.attributes)

    def test_oci_network_output_reaches_expected_finding(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "oci_core_security_list",
                "ssh_public",
                self._oci_security_list_values(),
            )
        )
        result = SecurityComplianceScanner(build_oci_security_rule_pack()).scan(
            "oci",
            [resource],
        )
        ssh = next(
            finding
            for finding in result.findings
            if finding.rule_id == "OCI_INTERNAL_NETWORK_001"
        )
        self.assertIs(ssh.status, RuleStatus.FAIL)

    def test_oci_public_bucket_is_mapped(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "oci_objectstorage_bucket",
                "public",
                {"access_type": "ObjectRead"},
            )
        )
        self.assertTrue(resource.attributes["public_access"])

    def test_oci_disabled_versioning_is_mapped(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "oci_objectstorage_bucket",
                "unversioned",
                {"versioning": "Disabled"},
            )
        )
        self.assertFalse(resource.attributes["versioning_enabled"])

    def test_oci_missing_key_is_not_invented(self) -> None:
        resource = self._adapt_one(
            self._entry("oci_objectstorage_bucket", "unknown_key", {})
        )
        self.assertNotIn("customer_managed_key", resource.attributes)

    def test_oci_manage_all_statement_is_preserved_without_parsing(self) -> None:
        resource = self._adapt_one(
            self._entry(
                "oci_identity_policy",
                "broad",
                {"statements": ["manage all-resources"]},
            )
        )
        self.assertEqual(resource.attributes["statements"], ("manage all-resources",))

    def test_non_managed_resource_is_skipped(self) -> None:
        result = self.adapter.from_plan_dict(
            self._plan(
                [
                    self._entry(
                        "google_compute_instance",
                        "data_vm",
                        self._gcp_compute_values(),
                        mode="data",
                    )
                ]
            )
        )
        self.assertEqual(result.resources, ())
        self.assertIn(self.adapter.NON_MANAGED_RESOURCE_SKIPPED, result.warnings)

    def test_missing_values_produces_missing_security_attributes(self) -> None:
        entry = self._entry("google_compute_instance", "missing_values")
        entry.pop("values")
        resource = self._adapt_one(entry)
        self.assertEqual(resource.attributes, {})

    def test_invalid_resource_entry_is_skipped(self) -> None:
        result = self.adapter.from_plan_dict(self._plan(["invalid"]))
        self.assertEqual(result.resources_seen, 1)
        self.assertEqual(result.resources_skipped, 1)
        self.assertIn(self.adapter.RESOURCE_ENTRY_INVALID, result.warnings)

    def test_adaptation_result_to_dict_is_stable(self) -> None:
        result = self.adapter.from_plan_dict(
            self._plan(
                [
                    self._entry(
                        "google_compute_instance",
                        "stable",
                        self._gcp_compute_values(),
                    )
                ]
            )
        )
        self.assertEqual(
            tuple(result.to_dict()),
            (
                "resources_seen",
                "resources_adapted",
                "resources_skipped",
                "unsupported_resource_types",
                "warnings",
                "resources",
            ),
        )

    def test_adaptation_result_to_json_is_valid(self) -> None:
        result = self.adapter.from_plan_dict(self._plan())
        self.assertEqual(json.loads(result.to_json()), result.to_dict())

    def test_sensitive_values_structures_are_ignored(self) -> None:
        entry = self._entry(
            "google_compute_instance",
            "safe",
            self._gcp_compute_values(),
        )
        entry["sensitive_values"] = {"password": "FAKE_PASSWORD_CIS6"}
        entry["before_sensitive"] = {"token": "FAKE_TOKEN_CIS6"}
        entry["after_sensitive"] = {"secret": "FAKE_SECRET_CIS6"}
        plan = self._plan([entry])
        plan["prior_state"] = {"private_key": "FAKE_PRIVATE_KEY_CIS6"}
        payload = self.adapter.from_plan_dict(plan).to_json()
        self.assertNotIn("FAKE_PASSWORD_CIS6", payload)
        self.assertNotIn("FAKE_TOKEN_CIS6", payload)
        self.assertNotIn("FAKE_SECRET_CIS6", payload)
        self.assertNotIn("FAKE_PRIVATE_KEY_CIS6", payload)

    def test_fake_secrets_in_values_are_not_copied(self) -> None:
        fake_secrets = (
            "FAKE_PASSWORD_CIS6",
            "FAKE_TOKEN_CIS6",
            "FAKE_PRIVATE_KEY_CIS6",
            "FAKE_SECRET_CIS6",
        )
        values = self._gcp_compute_values()
        values.update(
            {
                "password": fake_secrets[0],
                "token": fake_secrets[1],
                "private_key": fake_secrets[2],
                "secret": fake_secrets[3],
            }
        )
        adaptation = self.adapter.from_plan_dict(
            self._plan(
                [self._entry("google_compute_instance", "secret_test", values)]
            )
        )
        engine_result = build_default_multicloud_security_engine().evaluate(
            adaptation.resources
        )
        payloads = (
            repr(adaptation.resources[0].attributes),
            json.dumps(adaptation.to_dict()),
            adaptation.to_json(),
            engine_result.to_json(),
        )
        for payload in payloads:
            for secret in fake_secrets:
                self.assertNotIn(secret, payload)

    def test_supported_type_sets_are_exact(self) -> None:
        self.assertEqual(len(SUPPORTED_GCP_RESOURCE_TYPES), 4)
        self.assertEqual(len(SUPPORTED_OCI_RESOURCE_TYPES), 4)

    def test_rule_inventory_remains_twenty_four(self) -> None:
        engine = build_default_multicloud_security_engine()
        self.assertEqual(len(engine.catalog.rules), 24)
        self.assertEqual(len(engine.catalog.select(cloud="gcp")), 12)
        self.assertEqual(len(engine.catalog.select(cloud="oci")), 12)

    def test_adapter_module_defines_no_security_rules(self) -> None:
        names = set(security_terraform_adapter.__dict__)
        self.assertNotIn("SecurityRule", names)

    def test_plan_dict_must_be_a_mapping(self) -> None:
        with self.assertRaises(TypeError):
            self.adapter.from_plan_dict([])

    def test_result_validates_resource_counts(self) -> None:
        with self.assertRaises(ValueError):
            TerraformSecurityAdaptationResult(
                resources=(),
                resources_seen=0,
                resources_adapted=1,
            )

    def test_synthetic_plan_to_multicloud_engine_e2e(self) -> None:
        entries = [
            self._entry(
                "google_compute_instance",
                "gcp_public",
                self._gcp_compute_values(
                    public=True,
                    shielded=False,
                    deletion_protection=False,
                ),
            ),
            self._entry(
                "google_compute_firewall",
                "gcp_ssh",
                self._gcp_firewall_values(),
            ),
            self._entry(
                "google_storage_bucket",
                "gcp_secure_bucket",
                {
                    "public_access_prevention": "enforced",
                    "uniform_bucket_level_access": True,
                    "versioning": [{"enabled": True}],
                },
            ),
            self._entry(
                "google_project_iam_member",
                "gcp_owner",
                {"role": "roles/owner", "member": "user:test@example.test"},
            ),
            self._entry(
                "oci_core_instance",
                "oci_public",
                self._oci_compute_values(
                    public=True,
                    secure_boot=False,
                    in_transit=False,
                ),
            ),
            self._entry(
                "oci_core_security_list",
                "oci_ssh",
                self._oci_security_list_values(),
            ),
            self._entry(
                "oci_objectstorage_bucket",
                "oci_secure_bucket",
                {
                    "access_type": "NoPublicAccess",
                    "versioning": "Enabled",
                    "kms_key_id": "ocid1.key.synthetic",
                },
            ),
            self._entry(
                "oci_identity_policy",
                "oci_manage_all",
                {"statements": ["manage all-resources"]},
            ),
        ]
        adaptation = self.adapter.from_plan_dict(self._plan(entries))
        result = build_default_multicloud_security_engine().evaluate(
            adaptation.resources
        )
        self.assertEqual(adaptation.resources_seen, 8)
        self.assertEqual(adaptation.resources_adapted, 8)
        self.assertEqual(result.clouds_evaluated, ("gcp", "oci"))
        self.assertEqual(result.resources_total, 8)
        self.assertEqual(result.findings_total, 24)
        self.assertEqual(result.failed, 6)
        self.assertEqual(result.warnings, 4)
        self.assertEqual(result.skipped, 3)
        self.assertEqual(result.severity_counts[SecuritySeverity.HIGH], 6)
        self.assertEqual(result.severity_counts[SecuritySeverity.MEDIUM], 4)
        self.assertIs(result.evaluation_status, SecurityScanStatus.FAIL)

    def test_adapter_never_runs_terraform_or_subprocess(self) -> None:
        with (
            patch.object(TerraformRunner, "run") as terraform_run,
            patch.object(subprocess, "run") as process_run,
        ):
            result = self.adapter.from_plan_dict(self._plan())
        self.assertEqual(result.resources, ())
        terraform_run.assert_not_called()
        process_run.assert_not_called()

    def test_adapter_has_no_cloud_sdk_or_environment_dependency(self) -> None:
        module_names = set(security_terraform_adapter.__dict__)
        self.assertTrue(
            {
                "google",
                "google.auth",
                "google.cloud",
                "oci",
                "os",
                "subprocess",
            }.isdisjoint(module_names)
        )


if __name__ == "__main__":
    unittest.main()
