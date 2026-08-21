from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from catalog import CatalogError, CatalogLoader
from client_config import discover_client_config, load_client_config, select_runtime_configuration
from validators import validate_request
from web.services import WebOrchestrationService


class CatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.loader = CatalogLoader()

    def test_ten_standard_templates_load(self) -> None:
        templates = self.loader.list_templates()
        self.assertEqual(len(templates), 10)
        self.assertEqual({item.provider for item in templates}, {"gcp", "oci"})
        self.assertEqual(
            {item.module for item in templates},
            {"compute", "network", "storage", "iam", "landing-zone"},
        )

    def test_templates_match_supported_fields_and_safe_defaults(self) -> None:
        gcp_storage = self.loader.get("gcp-storage-standard")
        self.assertTrue(gcp_storage.defaults["uniform_bucket_level_access"])
        oci_compute = self.loader.get("oci-compute-standard")
        self.assertFalse(oci_compute.defaults["assign_public_ip"])
        oci_network = self.loader.get("oci-network-standard")
        self.assertTrue(oci_network.defaults["prohibit_public_ip_on_vnic"])
        oci_storage = self.loader.get("oci-storage-standard")
        self.assertEqual(oci_storage.defaults["access_type"], "NoPublicAccess")
        self.assertEqual(oci_storage.defaults["versioning"], "Enabled")

    def test_composites_have_deterministic_dependency_order(self) -> None:
        for provider in ("gcp", "oci"):
            template = self.loader.get(f"{provider}-landing-zone-standard")
            self.assertEqual(
                [component.template_id for component in template.components],
                [
                    f"{provider}-network-standard",
                    f"{provider}-storage-standard",
                    f"{provider}-iam-standard",
                    f"{provider}-compute-standard",
                ],
            )

    def test_template_id_rejects_all_path_forms(self) -> None:
        for value in (
            "../../template",
            "../gcp",
            "..\\oci",
            "C:\\absolute\\template",
            "/absolute/template",
            "gcp/network-standard",
        ):
            with self.subTest(value=value), self.assertRaises(CatalogError):
                self.loader.get(value)

    def test_loader_rejects_schema_extensions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "gcp").mkdir()
            (root / "gcp" / "compute-standard.yaml").write_text(
                "template_id: gcp-compute-standard\nprovider: gcp\nmodule: compute\n"
                "name: Example\ndescription: Example\ndefaults: {}\n"
                "required_parameters: []\noptional_parameters: []\n"
                "security_defaults: {}\ncomponents: []\nsecret: forbidden\n",
                encoding="utf-8",
            )
            with self.assertRaises(CatalogError):
                CatalogLoader(root).get("gcp-compute-standard")

    def test_every_template_builds_only_existing_valid_request_models(self) -> None:
        path = discover_client_config("example-client")
        self.assertIsNotNone(path)
        config = load_client_config(path, runtime_client_id="example-client")
        service = WebOrchestrationService(self.loader)
        samples = {
            "gcp-compute-standard": {
                "resource_name": "vm_web", "name": "vm-web", "machine_type": "e2-medium",
                "zone": "europe-west1-b", "network": "default",
            },
            "gcp-network-standard": {
                "resource_name": "vpc_web", "name": "vpc-web", "subnet_resource_name": "subnet_web",
                "subnet_name": "subnet-web", "cidr": "10.42.0.0/24", "region": "europe-west1",
            },
            "gcp-storage-standard": {
                "resource_name": "bucket_web", "name": "example-bucket-web-2026", "location": "EU",
            },
            "gcp-iam-standard": {
                "resource_name": "sa_web", "account_id": "sa-web", "display_name": "Example Service Account",
                "description": "Example least privilege service account",
            },
            "oci-compute-standard": {
                "resource_name": "oci_vm_web", "display_name": "oci-vm-web",
                "availability_domain": "Uocm:EU-FRANKFURT-1-AD-1", "shape": "VM.Standard.E4.Flex",
                "subnet_id": "ocid1.subnet.oc1.eu-frankfurt-1.example", "image_id": "ocid1.image.oc1.eu-frankfurt-1.example",
            },
            "oci-network-standard": {
                "resource_name": "oci_vcn_web", "display_name": "oci-vcn-web", "vcn_cidr": "10.52.0.0/16",
                "dns_label": "vcnweb", "subnet_resource_name": "oci_subnet_web", "subnet_display_name": "oci-subnet-web",
                "subnet_cidr": "10.52.1.0/24", "subnet_dns_label": "subweb",
                "availability_domain": "Uocm:EU-FRANKFURT-1-AD-1", "internet_gateway_resource_name": "oci_igw_web",
                "internet_gateway_display_name": "oci-igw-web", "route_table_resource_name": "oci_rt_web",
                "route_table_display_name": "oci-rt-web",
            },
            "oci-storage-standard": {
                "resource_name": "oci_bucket_web", "namespace": "exampletenancy", "name": "oci-bucket-web",
            },
            "oci-iam-standard": {
                "tenancy_ocid": "ocid1.tenancy.oc1..example", "user_resource_name": "oci_user_web",
                "user_name": "example-user", "user_description": "Example observability user",
                "group_resource_name": "oci_group_web", "group_name": "example-readers",
                "group_description": "Example metrics readers", "membership_resource_name": "oci_membership_web",
                "policy_resource_name": "oci_policy_web", "policy_name": "example-read-policy",
                "policy_description": "Example narrow read policy",
                "policy_statements": "Allow group example-readers to read metrics in compartment example-compartment",
            },
        }
        for provider in ("gcp", "oci"):
            runtime = select_runtime_configuration(config, "dev", provider, terraform_version="1.15.7")
            for template in self.loader.list_templates(provider):
                if template.components:
                    submitted = {}
                    for component in template.components:
                        submitted.update(
                            {
                                f"{component.parameter_prefix}{name}": value
                                for name, value in samples[component.template_id].items()
                            }
                        )
                else:
                    submitted = samples[template.template_id]
                values = service.validate_parameters(template, submitted)
                requests = service._build_requests(runtime, template, values)
                self.assertEqual(len(requests), 4 if template.components else 1)
                for _, request_model in requests:
                    validate_request(request_model)


if __name__ == "__main__":
    unittest.main()
