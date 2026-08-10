"""Tests de l'orchestrateur d'evaluation de securite multi-cloud."""

import json
import subprocess
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

import security_evaluation
from security_catalog import SecurityRuleCatalog
from security_evaluation import (
    MultiCloudSecurityEvaluationEngine,
    MultiCloudSecurityEvaluationResult,
    build_default_multicloud_security_engine,
)
from security_gcp_rules import (
    GCP_COMPUTE_RESOURCE_TYPE,
    GCP_IAM_RESOURCE_TYPE,
    GCP_NETWORK_RESOURCE_TYPE,
    GCP_STORAGE_RESOURCE_TYPE,
)
from security_models import (
    RuleStatus,
    SecurityFinding,
    SecurityResource,
    SecurityRuleMetadata,
    SecurityScanStatus,
    SecuritySeverity,
    UnknownSecurityCloudError,
)
from security_oci_rules import (
    OCI_COMPUTE_RESOURCE_TYPE,
    OCI_IAM_RESOURCE_TYPE,
    OCI_NETWORK_RESOURCE_TYPE,
    OCI_STORAGE_RESOURCE_TYPE,
)
from security_rule import SecurityRule
from security_scanner import SecurityComplianceScanner
from terraform_runner import TerraformRunner


class _EvaluationTestRule(SecurityRule):
    """Regle synthetique reservee aux tests d'orchestration."""

    def __init__(
        self,
        metadata: SecurityRuleMetadata,
        status: RuleStatus,
        *,
        failure: Exception | None = None,
    ) -> None:
        super().__init__(metadata)
        self.status = status
        self.failure = failure
        self.evaluation_count = 0

    def evaluate(self, resource: SecurityResource) -> SecurityFinding:
        self.evaluation_count += 1
        if self.failure is not None:
            raise self.failure
        return SecurityFinding(
            rule_id=self.metadata.rule_id,
            cloud=resource.cloud,
            resource_type=resource.resource_type,
            resource_name=resource.resource_name,
            resource_address=resource.resource_address,
            status=self.status,
            severity=self.metadata.severity,
            title=self.metadata.title,
            message="Synthetic orchestration result.",
            recommendation=self.metadata.recommendation,
        )


class MultiCloudSecurityEvaluationTests(unittest.TestCase):
    @staticmethod
    def _resource(
        *,
        cloud: str,
        service: str,
        resource_type: str,
        name: str,
        attributes: dict,
    ) -> SecurityResource:
        return SecurityResource(
            cloud=cloud,
            service=service,
            resource_type=resource_type,
            resource_name=name,
            resource_address=f"{resource_type}.{name}",
            attributes=attributes,
        )

    @classmethod
    def _gcp_compute(
        cls,
        name: str = "gcp_vm_secure",
        *,
        public_ip: bool = False,
        shielded_vm: bool = True,
        deletion_protection: bool = True,
        extra_attributes: dict | None = None,
    ) -> SecurityResource:
        attributes = {
            "public_ip": public_ip,
            "shielded_vm": shielded_vm,
            "deletion_protection": deletion_protection,
        }
        attributes.update(extra_attributes or {})
        return cls._resource(
            cloud="gcp",
            service="compute",
            resource_type=GCP_COMPUTE_RESOURCE_TYPE,
            name=name,
            attributes=attributes,
        )

    @classmethod
    def _oci_compute(
        cls,
        name: str = "oci_vm_secure",
        *,
        public_ip: bool = False,
        secure_boot: bool = True,
        in_transit_encryption: bool = True,
        extra_attributes: dict | None = None,
    ) -> SecurityResource:
        attributes = {
            "public_ip": public_ip,
            "secure_boot": secure_boot,
            "in_transit_encryption": in_transit_encryption,
        }
        attributes.update(extra_attributes or {})
        return cls._resource(
            cloud="oci",
            service="compute",
            resource_type=OCI_COMPUTE_RESOURCE_TYPE,
            name=name,
            attributes=attributes,
        )

    @classmethod
    def _gcp_network(cls, name: str = "gcp_firewall_ssh") -> SecurityResource:
        return cls._resource(
            cloud="gcp",
            service="network",
            resource_type=GCP_NETWORK_RESOURCE_TYPE,
            name=name,
            attributes={
                "direction": "ingress",
                "source_ranges": ["0.0.0.0/0"],
                "protocol": "tcp",
                "allowed_ports": [22],
                "all_ports": False,
            },
        )

    @classmethod
    def _oci_network(cls, name: str = "oci_security_list_ssh") -> SecurityResource:
        return cls._resource(
            cloud="oci",
            service="network",
            resource_type=OCI_NETWORK_RESOURCE_TYPE,
            name=name,
            attributes={
                "direction": "ingress",
                "source_ranges": ["0.0.0.0/0"],
                "protocol": "tcp",
                "allowed_ports": [22],
                "all_ports": False,
            },
        )

    @classmethod
    def _gcp_storage(cls) -> SecurityResource:
        return cls._resource(
            cloud="gcp",
            service="storage",
            resource_type=GCP_STORAGE_RESOURCE_TYPE,
            name="gcp_bucket_private",
            attributes={
                "public_access": False,
                "uniform_bucket_level_access": True,
                "versioning_enabled": True,
            },
        )

    @classmethod
    def _oci_storage(cls) -> SecurityResource:
        return cls._resource(
            cloud="oci",
            service="storage",
            resource_type=OCI_STORAGE_RESOURCE_TYPE,
            name="oci_bucket_private",
            attributes={
                "public_access": False,
                "versioning_enabled": True,
                "customer_managed_key": True,
            },
        )

    @classmethod
    def _gcp_iam(cls) -> SecurityResource:
        return cls._resource(
            cloud="gcp",
            service="iam",
            resource_type=GCP_IAM_RESOURCE_TYPE,
            name="gcp_owner_binding",
            attributes={
                "roles": ["roles/owner"],
                "permissions": ["resourcemanager.projects.get"],
            },
        )

    @classmethod
    def _oci_iam(cls) -> SecurityResource:
        return cls._resource(
            cloud="oci",
            service="iam",
            resource_type=OCI_IAM_RESOURCE_TYPE,
            name="oci_manage_all_policy",
            attributes={
                "statements": ["manage all-resources"],
                "permissions": ["objectstorage-namespaces-read"],
                "broad_subject": False,
            },
        )

    @classmethod
    def _e2e_resources(cls) -> list[SecurityResource]:
        return [
            cls._gcp_compute(),
            cls._gcp_compute(
                "gcp_vm_public",
                public_ip=True,
                shielded_vm=False,
                deletion_protection=False,
            ),
            cls._gcp_network(),
            cls._gcp_storage(),
            cls._gcp_iam(),
            cls._oci_compute(),
            cls._oci_compute(
                "oci_vm_public",
                public_ip=True,
                secure_boot=False,
                in_transit_encryption=False,
            ),
            cls._oci_network(),
            cls._oci_storage(),
            cls._oci_iam(),
        ]

    @staticmethod
    def _metadata(
        *,
        rule_id: str,
        cloud: str = "gcp",
        status: RuleStatus = RuleStatus.PASS,
        severity: SecuritySeverity = SecuritySeverity.LOW,
        enabled: bool = True,
    ) -> tuple[SecurityRuleMetadata, RuleStatus]:
        return (
            SecurityRuleMetadata(
                rule_id=rule_id,
                cloud=cloud,
                service="compute",
                resource_type=(
                    GCP_COMPUTE_RESOURCE_TYPE
                    if cloud == "gcp"
                    else OCI_COMPUTE_RESOURCE_TYPE
                ),
                title=f"Synthetic rule {rule_id}",
                description="Internal orchestration test fixture.",
                severity=severity,
                recommendation="Use a safe synthetic configuration.",
                enabled=enabled,
                tags=("synthetic",),
                profiles=("baseline",),
                framework="INTERNAL_SECURITY_BASELINE",
                framework_version="test-v1",
            ),
            status,
        )

    @classmethod
    def _test_rule(cls, **kwargs) -> _EvaluationTestRule:
        metadata, status = cls._metadata(**kwargs)
        return _EvaluationTestRule(metadata, status)

    def test_default_factory_builds_engine(self) -> None:
        self.assertIsInstance(
            build_default_multicloud_security_engine(),
            MultiCloudSecurityEvaluationEngine,
        )

    def test_default_catalog_contains_twenty_four_rules(self) -> None:
        engine = build_default_multicloud_security_engine()
        self.assertEqual(len(engine.catalog.rules), 24)

    def test_default_catalog_contains_twelve_gcp_rules(self) -> None:
        engine = build_default_multicloud_security_engine()
        self.assertEqual(len(engine.catalog.select(cloud="gcp")), 12)

    def test_default_catalog_contains_twelve_oci_rules(self) -> None:
        engine = build_default_multicloud_security_engine()
        self.assertEqual(len(engine.catalog.select(cloud="oci")), 12)

    def test_empty_resources_return_empty_pass(self) -> None:
        result = build_default_multicloud_security_engine().evaluate([])
        self.assertEqual(result.cloud_results, {})
        self.assertEqual(result.clouds_evaluated, ())
        self.assertEqual(result.resources_total, 0)
        self.assertEqual(result.findings_total, 0)
        self.assertIs(result.evaluation_status, SecurityScanStatus.PASS)

    def test_gcp_only_evaluates_gcp(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [self._gcp_compute()]
        )
        self.assertEqual(result.clouds_evaluated, ("gcp",))
        self.assertEqual(result.findings_total, 3)

    def test_oci_only_evaluates_oci(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [self._oci_compute()]
        )
        self.assertEqual(result.clouds_evaluated, ("oci",))
        self.assertEqual(result.findings_total, 3)

    def test_mixed_resources_evaluate_both_clouds(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [self._oci_compute(), self._gcp_compute()]
        )
        self.assertEqual(result.clouds_evaluated, ("gcp", "oci"))
        self.assertEqual(set(result.cloud_results), {"gcp", "oci"})

    def test_cloud_order_is_deterministic(self) -> None:
        resources = [self._oci_compute(), self._gcp_compute()]
        result = build_default_multicloud_security_engine().evaluate(resources)
        self.assertEqual(tuple(result.cloud_results), ("gcp", "oci"))

    def test_resources_total_counts_input_resources(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [self._gcp_compute(), self._oci_compute(), self._gcp_network()]
        )
        self.assertEqual(result.resources_total, 3)

    def test_findings_total_sums_cloud_scan_results(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [self._gcp_compute(), self._oci_compute()]
        )
        expected = sum(
            scan.total_rules_evaluated for scan in result.cloud_results.values()
        )
        self.assertEqual(result.findings_total, expected)

    def test_passed_count_is_aggregated(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [self._gcp_compute(), self._oci_compute()]
        )
        self.assertEqual(result.passed, 6)

    def test_failed_count_is_aggregated(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [
                self._gcp_compute("gcp_public", public_ip=True),
                self._oci_compute("oci_public", public_ip=True),
            ]
        )
        self.assertEqual(result.failed, 2)

    def test_warning_count_is_aggregated(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [
                self._gcp_compute("gcp_warning", shielded_vm=False),
                self._oci_compute("oci_warning", secure_boot=False),
            ]
        )
        self.assertEqual(result.warnings, 2)

    def test_skipped_count_is_aggregated(self) -> None:
        catalog = SecurityRuleCatalog()
        metadata, _ = self._metadata(rule_id="TEST_GCP_COMPUTE_SKIPPED")
        catalog.register(
            _EvaluationTestRule(metadata, RuleStatus.FAIL, failure=RuntimeError())
        )
        with self.assertLogs("security_scanner", level="WARNING"):
            result = MultiCloudSecurityEvaluationEngine(catalog).evaluate(
                [self._gcp_compute()]
            )
        self.assertEqual(result.skipped, 1)

    def test_not_applicable_count_is_aggregated(self) -> None:
        catalog = SecurityRuleCatalog()
        catalog.register(
            self._test_rule(
                rule_id="TEST_GCP_COMPUTE_NA",
                status=RuleStatus.NOT_APPLICABLE,
            )
        )
        result = MultiCloudSecurityEvaluationEngine(catalog).evaluate(
            [self._gcp_compute()]
        )
        self.assertEqual(result.not_applicable, 1)

    def test_high_severity_count_is_aggregated(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [
                self._gcp_compute("gcp_public", public_ip=True),
                self._oci_compute("oci_public", public_ip=True),
            ]
        )
        self.assertEqual(result.severity_counts[SecuritySeverity.HIGH], 2)

    def test_medium_severity_count_is_aggregated(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [
                self._gcp_compute("gcp_warning", shielded_vm=False),
                self._oci_compute("oci_warning", secure_boot=False),
            ]
        )
        self.assertEqual(result.severity_counts[SecuritySeverity.MEDIUM], 2)

    def test_global_status_pass(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [self._gcp_compute(), self._oci_compute()]
        )
        self.assertIs(result.evaluation_status, SecurityScanStatus.PASS)

    def test_global_status_pass_with_warnings(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [self._gcp_compute(shielded_vm=False), self._oci_compute()]
        )
        self.assertIs(
            result.evaluation_status,
            SecurityScanStatus.PASS_WITH_WARNINGS,
        )

    def test_global_status_fail_takes_precedence(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [
                self._gcp_compute(public_ip=True),
                self._oci_compute(secure_boot=False),
            ]
        )
        self.assertIs(result.evaluation_status, SecurityScanStatus.FAIL)

    def test_gcp_rules_never_run_on_oci(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [self._oci_compute()]
        )
        self.assertTrue(
            all(
                finding.rule_id.startswith("OCI_INTERNAL_")
                for finding in result.cloud_results["oci"].findings
            )
        )

    def test_oci_rules_never_run_on_gcp(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [self._gcp_compute()]
        )
        self.assertTrue(
            all(
                finding.rule_id.startswith("GCP_INTERNAL_")
                for finding in result.cloud_results["gcp"].findings
            )
        )

    def test_baseline_profile_selects_default_rules(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [self._gcp_compute()], profile=" BASELINE "
        )
        self.assertEqual(result.findings_total, 3)

    def test_unknown_profile_returns_zero_rule_scan(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [self._gcp_compute()], profile="does-not-exist"
        )
        self.assertEqual(result.clouds_evaluated, ("gcp",))
        self.assertEqual(result.findings_total, 0)
        self.assertIs(result.evaluation_status, SecurityScanStatus.PASS)

    def test_network_service_filter(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [self._gcp_network()], services={"network"}
        )
        self.assertEqual(result.findings_total, 3)
        self.assertTrue(
            all(
                "NETWORK" in finding.rule_id
                for finding in result.cloud_results["gcp"].findings
            )
        )

    def test_iam_service_filter(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [self._oci_iam()], services={"iam"}
        )
        self.assertEqual(result.findings_total, 3)
        self.assertTrue(
            all(
                "IAM" in finding.rule_id
                for finding in result.cloud_results["oci"].findings
            )
        )

    def test_multiple_service_filters_do_not_duplicate_rules(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [self._gcp_network(), self._gcp_iam()],
            services={"network", "iam", "NETWORK"},
        )
        self.assertEqual(result.findings_total, 6)
        self.assertEqual(
            len({finding.rule_id for finding in result.cloud_results["gcp"].findings}),
            6,
        )

    def test_empty_services_selects_zero_rules(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [self._gcp_compute()], services=()
        )
        self.assertEqual(result.findings_total, 0)

    def test_tag_filter_uses_catalog_semantics(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [self._gcp_network()], tags={"ssh"}
        )
        self.assertEqual(result.findings_total, 1)
        self.assertEqual(
            result.cloud_results["gcp"].findings[0].rule_id,
            "GCP_INTERNAL_NETWORK_001",
        )

    def test_tag_match_any_is_supported(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [self._oci_network()], tags={"ssh", "rdp"}, tag_match="any"
        )
        self.assertEqual(result.findings_total, 2)

    def test_tag_match_all_is_supported(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [self._oci_network()], tags={"network", "ingress"}, tag_match="all"
        )
        self.assertEqual(result.findings_total, 3)

    def test_enabled_only_excludes_disabled_rule(self) -> None:
        catalog = SecurityRuleCatalog()
        catalog.register_many(
            (
                self._test_rule(rule_id="TEST_GCP_COMPUTE_ENABLED"),
                self._test_rule(
                    rule_id="TEST_GCP_COMPUTE_DISABLED",
                    enabled=False,
                ),
            )
        )
        result = MultiCloudSecurityEvaluationEngine(catalog).evaluate(
            [self._gcp_compute()]
        )
        self.assertEqual(result.findings_total, 1)

    def test_enabled_only_false_includes_disabled_rule(self) -> None:
        catalog = SecurityRuleCatalog()
        catalog.register_many(
            (
                self._test_rule(rule_id="TEST_GCP_COMPUTE_ENABLED"),
                self._test_rule(
                    rule_id="TEST_GCP_COMPUTE_DISABLED",
                    enabled=False,
                ),
            )
        )
        result = MultiCloudSecurityEvaluationEngine(catalog).evaluate(
            [self._gcp_compute()], enabled_only=False
        )
        self.assertEqual(result.findings_total, 2)

    def test_reversed_input_has_identical_serialisation(self) -> None:
        resources = self._e2e_resources()
        engine = build_default_multicloud_security_engine()
        first = engine.evaluate(resources)
        second = engine.evaluate(tuple(reversed(resources)))
        self.assertEqual(first.to_json(), second.to_json())

    def test_to_dict_has_stable_shape(self) -> None:
        payload = build_default_multicloud_security_engine().evaluate(
            [self._gcp_compute(), self._oci_compute()]
        ).to_dict()
        self.assertEqual(
            tuple(payload),
            (
                "evaluation_status",
                "resources_total",
                "findings_total",
                "clouds_evaluated",
                "summary",
                "severity_counts",
                "cloud_results",
            ),
        )
        self.assertEqual(tuple(payload["cloud_results"]), ("gcp", "oci"))

    def test_to_json_is_valid(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [self._gcp_compute()]
        )
        self.assertEqual(json.loads(result.to_json()), result.to_dict())

    def test_serialisation_has_no_raw_attributes(self) -> None:
        payload = build_default_multicloud_security_engine().evaluate(
            [self._gcp_compute(extra_attributes={"raw_marker": "RAW_VALUE"})]
        ).to_dict()
        self.assertNotIn("attributes", json.dumps(payload))
        self.assertNotIn("RAW_VALUE", json.dumps(payload))

    def test_fake_secrets_are_not_serialised(self) -> None:
        secrets = ("FAKE_PASSWORD", "FAKE_TOKEN", "FAKE_PRIVATE_KEY")
        resource = self._oci_compute(
            extra_attributes={
                "password": secrets[0],
                "token": secrets[1],
                "private_key": secrets[2],
            }
        )
        result = build_default_multicloud_security_engine().evaluate([resource])
        for payload in (json.dumps(result.to_dict()), result.to_json()):
            for secret in secrets:
                self.assertNotIn(secret, payload)

    def test_scanner_exception_remains_skipped(self) -> None:
        catalog = SecurityRuleCatalog()
        metadata, _ = self._metadata(rule_id="TEST_GCP_COMPUTE_EXCEPTION")
        rule = _EvaluationTestRule(
            metadata,
            RuleStatus.FAIL,
            failure=RuntimeError("internal detail"),
        )
        catalog.register(rule)
        with self.assertLogs("security_scanner", level="WARNING"):
            result = MultiCloudSecurityEvaluationEngine(catalog).evaluate(
                [self._gcp_compute()]
            )
        self.assertEqual(
            result.cloud_results["gcp"].findings[0].status,
            RuleStatus.SKIPPED,
        )
        self.assertIs(
            result.evaluation_status,
            SecurityScanStatus.PASS_WITH_WARNINGS,
        )

    def test_default_factory_adds_no_rules_beyond_existing_packs(self) -> None:
        rule_ids = {
            rule.metadata.rule_id
            for rule in build_default_multicloud_security_engine().catalog.rules
        }
        self.assertEqual(len(rule_ids), 24)
        self.assertEqual(
            sum(rule_id.startswith("GCP_INTERNAL_") for rule_id in rule_ids),
            12,
        )
        self.assertEqual(
            sum(rule_id.startswith("OCI_INTERNAL_") for rule_id in rule_ids),
            12,
        )

    def test_engine_reuses_catalog_select(self) -> None:
        engine = build_default_multicloud_security_engine()
        with patch.object(
            engine.catalog,
            "select",
            wraps=engine.catalog.select,
        ) as select:
            engine.evaluate([self._gcp_compute(), self._oci_compute()])
        self.assertEqual(select.call_count, 2)

    def test_engine_reuses_compliance_scanner(self) -> None:
        with patch(
            "security_evaluation.SecurityComplianceScanner",
            wraps=SecurityComplianceScanner,
        ) as scanner:
            build_default_multicloud_security_engine().evaluate(
                [self._gcp_compute(), self._oci_compute()]
            )
        self.assertEqual(scanner.call_count, 2)

    def test_cloud_results_are_existing_scan_result_objects(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [self._gcp_compute()]
        )
        self.assertEqual(
            type(result.cloud_results["gcp"]).__name__,
            "SecurityScanResult",
        )

    def test_result_mapping_is_immutable(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            [self._gcp_compute()]
        )
        with self.assertRaises(TypeError):
            result.cloud_results["oci"] = result.cloud_results["gcp"]

    def test_result_fields_are_frozen(self) -> None:
        result = build_default_multicloud_security_engine().evaluate([])
        with self.assertRaises(FrozenInstanceError):
            result.resources_total = 4

    def test_result_rejects_mismatched_cloud_key(self) -> None:
        scan_result = SecurityComplianceScanner([]).scan("gcp", [])
        with self.assertRaisesRegex(ValueError, "correspond"):
            MultiCloudSecurityEvaluationResult(
                cloud_results={"oci": scan_result},
                resources_total=0,
            )

    def test_engine_requires_catalog(self) -> None:
        with self.assertRaises(TypeError):
            MultiCloudSecurityEvaluationEngine(object())

    def test_engine_rejects_non_resource_input_item(self) -> None:
        with self.assertRaisesRegex(TypeError, "SecurityResource"):
            build_default_multicloud_security_engine().evaluate([object()])

    def test_security_resource_still_rejects_unknown_cloud(self) -> None:
        with self.assertRaises(UnknownSecurityCloudError):
            self._resource(
                cloud="azure",
                service="compute",
                resource_type="virtual_machine",
                name="unsupported",
                attributes={},
            )

    def test_invalid_tag_match_is_not_hidden(self) -> None:
        with self.assertRaises(ValueError):
            build_default_multicloud_security_engine().evaluate(
                [], tag_match="invalid"
            )

    def test_invalid_enabled_only_is_not_hidden(self) -> None:
        with self.assertRaises(TypeError):
            build_default_multicloud_security_engine().evaluate(
                [], enabled_only="yes"
            )

    def test_resource_attributes_are_not_modified(self) -> None:
        resource = self._gcp_compute()
        before = dict(resource.attributes)
        build_default_multicloud_security_engine().evaluate([resource])
        self.assertEqual(resource.attributes, before)

    def test_no_timestamp_is_added(self) -> None:
        payload = build_default_multicloud_security_engine().evaluate([]).to_dict()
        self.assertNotIn("timestamp", payload)

    def test_synthetic_multicloud_e2e(self) -> None:
        result = build_default_multicloud_security_engine().evaluate(
            self._e2e_resources()
        )
        self.assertEqual(result.clouds_evaluated, ("gcp", "oci"))
        self.assertEqual(result.resources_total, 10)
        self.assertEqual(result.findings_total, 30)
        self.assertEqual(result.passed, 20)
        self.assertEqual(result.failed, 6)
        self.assertEqual(result.warnings, 4)
        self.assertEqual(result.skipped, 0)
        self.assertEqual(result.not_applicable, 0)
        self.assertEqual(result.severity_counts[SecuritySeverity.HIGH], 6)
        self.assertEqual(result.severity_counts[SecuritySeverity.MEDIUM], 4)
        self.assertIs(result.evaluation_status, SecurityScanStatus.FAIL)
        self.assertEqual(result.to_json(), result.to_json())

    def test_engine_never_runs_terraform_or_subprocess(self) -> None:
        with (
            patch.object(TerraformRunner, "run") as terraform_run,
            patch.object(subprocess, "run") as process_run,
        ):
            result = build_default_multicloud_security_engine().evaluate(
                [self._gcp_compute(), self._oci_compute()]
            )
        self.assertEqual(result.resources_total, 2)
        terraform_run.assert_not_called()
        process_run.assert_not_called()

    def test_engine_module_has_no_cloud_sdk_or_environment_dependency(self) -> None:
        module_names = set(security_evaluation.__dict__)
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
