package network_test

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"hcl-generator/generator"
	"hcl-generator/generator/internal/testutil"
	"hcl-generator/models"
)

func TestOCINetworkCreateGeneratesLinkedResources(t *testing.T) {
	modulePath := filepath.Join(
		t.TempDir(),
		"generated",
		"oci",
		"modules",
		"network",
	)
	request := publicNetworkRequest(modulePath)
	if err := generator.GenerateAtomically(request); err != nil {
		t.Fatalf("OCI Network Create failed: %v", err)
	}

	files := testutil.SnapshotTerraformFiles(t, modulePath)
	mainContent := string(files["main.tf"])
	for _, fragment := range []string{
		`resource "oci_core_vcn" "oci_vcn_test_01"`,
		"compartment_id = var.oci_vcn_test_01_compartment_id",
		"cidr_block     = var.oci_vcn_test_01_cidr_block",
		`resource "oci_core_internet_gateway" "oci_igw_test_01"`,
		"vcn_id         = oci_core_vcn.oci_vcn_test_01.id",
		"enabled        = true",
		`resource "oci_core_route_table" "oci_rt_test_01"`,
		`destination       = "0.0.0.0/0"`,
		`destination_type  = "CIDR_BLOCK"`,
		"network_entity_id = oci_core_internet_gateway.oci_igw_test_01.id",
		`resource "oci_core_subnet" "oci_subnet_test_01"`,
		"route_table_id             = oci_core_route_table.oci_rt_test_01.id",
		"prohibit_public_ip_on_vnic = var.oci_subnet_test_01_prohibit_public_ip_on_vnic",
	} {
		if !strings.Contains(mainContent, fragment) {
			t.Fatalf("main.tf is missing %q\n%s", fragment, mainContent)
		}
	}

	variablesContent := string(files["variables.tf"])
	tfvarsContent := string(files["terraform.tfvars"])
	for _, name := range []string{
		"oci_vcn_test_01_compartment_id",
		"oci_vcn_test_01_cidr_block",
		"oci_vcn_test_01_display_name",
		"oci_vcn_test_01_dns_label",
		"oci_subnet_test_01_cidr_block",
		"oci_subnet_test_01_display_name",
		"oci_subnet_test_01_dns_label",
		"oci_subnet_test_01_availability_domain",
		"oci_subnet_test_01_prohibit_public_ip_on_vnic",
		"oci_igw_test_01_display_name",
		"oci_rt_test_01_display_name",
	} {
		if !strings.Contains(variablesContent, `variable "`+name+`"`) {
			t.Fatalf("variables.tf is missing %q", name)
		}
		if !strings.Contains(tfvarsContent, name) {
			t.Fatalf("terraform.tfvars is missing %q", name)
		}
	}
	if !regexp.MustCompile(
		`(?m)^oci_subnet_test_01_prohibit_public_ip_on_vnic\s+= false$`,
	).Match(files["terraform.tfvars"]) {
		t.Fatal("public subnet boolean is not an unquoted false")
	}

	outputsContent := string(files["outputs.tf"])
	outputs := map[string]string{
		"oci_vcn_test_01_id":    "oci_core_vcn.oci_vcn_test_01.id",
		"oci_subnet_test_01_id": "oci_core_subnet.oci_subnet_test_01.id",
		"oci_igw_test_01_id":    "oci_core_internet_gateway.oci_igw_test_01.id",
		"oci_rt_test_01_id":     "oci_core_route_table.oci_rt_test_01.id",
	}
	for name, traversal := range outputs {
		if !strings.Contains(outputsContent, `output "`+name+`"`) ||
			!strings.Contains(outputsContent, traversal) {
			t.Fatalf("output %q does not contain traversal %q", name, traversal)
		}
	}
}

func TestOCINetworkCreateAddsSecondNetworkAndPreservesFirst(
	t *testing.T,
) {
	modulePath := filepath.Join(
		t.TempDir(),
		"generated",
		"oci",
		"modules",
		"network",
	)
	requests := []*models.Request{
		publicNetworkRequest(modulePath),
		testutil.OCINetworkRequest(
			modulePath,
			"oci_vcn_private_01",
			"oci-vcn-private-01",
			"oci_subnet_private_01",
			"oci-subnet-private-01",
			"10.40.0.0/16",
			"10.40.10.0/24",
			"oci_igw_private_01",
			"oci-igw-private-01",
			"oci_rt_private_01",
			"oci-rt-private-01",
			true,
		),
	}
	requests[1].OCINetworkResource.DNSLabel = "vcnpriv01"
	requests[1].OCINetworkResource.SubnetDNSLabel = "subpriv01"

	for _, request := range requests {
		if err := generator.GenerateAtomically(request); err != nil {
			t.Fatalf("OCI Network Create failed: %v", err)
		}
	}

	files := testutil.SnapshotTerraformFiles(t, modulePath)
	for _, filename := range testutil.TerraformFilenames {
		content := string(files[filename])
		for _, name := range []string{
			"oci_vcn_test_01",
			"oci_vcn_private_01",
		} {
			if !strings.Contains(content, name) {
				t.Fatalf("%s is missing %s", filename, name)
			}
		}
	}
	if !regexp.MustCompile(
		`(?m)^oci_subnet_private_01_prohibit_public_ip_on_vnic\s+= true$`,
	).Match(files["terraform.tfvars"]) {
		t.Fatal("restricted subnet boolean is not an unquoted true")
	}
}

func TestOCINetworkDuplicateLeavesAllFilesUnchanged(t *testing.T) {
	modulePath := filepath.Join(
		t.TempDir(),
		"generated",
		"oci",
		"modules",
		"network",
	)
	request := publicNetworkRequest(modulePath)
	if err := generator.GenerateAtomically(request); err != nil {
		t.Fatalf("OCI Network Create failed: %v", err)
	}
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	err := generator.GenerateAtomically(request)
	if err == nil || !strings.Contains(err.Error(), "doublon OCI network") {
		t.Fatalf("duplicate returned unexpected error: %v", err)
	}
	after := testutil.SnapshotTerraformFiles(t, modulePath)
	for _, filename := range testutil.TerraformFilenames {
		if !bytes.Equal(before[filename], after[filename]) {
			t.Fatalf("%s changed after duplicate OCI Network Create", filename)
		}
	}
}

func TestOCINetworkCreateDoesNotModifyOtherProviderModules(t *testing.T) {
	root := t.TempDir()
	gcpComputePath := filepath.Join(root, "generated", "gcp", "modules", "compute")
	gcpNetworkPath := filepath.Join(root, "generated", "gcp", "modules", "network")
	ociComputePath := filepath.Join(root, "generated", "oci", "modules", "compute")
	ociNetworkPath := filepath.Join(root, "generated", "oci", "modules", "network")

	seedRequests := []*models.Request{
		testutil.ComputeRequest(
			"create",
			gcpComputePath,
			"vm_isolation_01",
			"vm-isolation-01",
			"e2-medium",
		),
		testutil.NetworkRequest(
			"create",
			gcpNetworkPath,
			"vpc_isolation_01",
			"vpc-isolation-01",
			"subnet_isolation_01",
			"subnet-isolation-01",
			"10.70.0.0/24",
			"europe-west1",
		),
		testutil.OCIComputeRequest(
			ociComputePath,
			"oci_vm_isolation_01",
			"oci-vm-isolation-01",
			false,
		),
	}
	for _, request := range seedRequests {
		if err := generator.GenerateAtomically(request); err != nil {
			t.Fatalf("seed request failed: %v", err)
		}
	}

	gcpComputeBefore := testutil.SnapshotTerraformFiles(t, gcpComputePath)
	gcpNetworkBefore := testutil.SnapshotTerraformFiles(t, gcpNetworkPath)
	ociComputeBefore := testutil.SnapshotTerraformFiles(t, ociComputePath)

	if err := generator.GenerateAtomically(
		publicNetworkRequest(ociNetworkPath),
	); err != nil {
		t.Fatalf("OCI Network Create failed: %v", err)
	}

	testutil.AssertTerraformFilesEqual(
		t,
		gcpComputeBefore,
		testutil.SnapshotTerraformFiles(t, gcpComputePath),
	)
	testutil.AssertTerraformFilesEqual(
		t,
		gcpNetworkBefore,
		testutil.SnapshotTerraformFiles(t, gcpNetworkPath),
	)
	testutil.AssertModuleFilesEqual(
		t,
		ociComputeBefore,
		testutil.SnapshotTerraformFiles(t, ociComputePath),
	)
}

func publicNetworkRequest(modulePath string) *models.Request {
	return testutil.OCINetworkRequest(
		modulePath,
		"oci_vcn_test_01",
		"oci-vcn-test-01",
		"oci_subnet_test_01",
		"oci-subnet-test-01",
		"10.30.0.0/16",
		"10.30.1.0/24",
		"oci_igw_test_01",
		"oci-igw-test-01",
		"oci_rt_test_01",
		"oci-rt-test-01",
		false,
	)
}
