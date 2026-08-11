package network_test

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"hcl-generator/generator"
	"hcl-generator/generator/common"
	"hcl-generator/generator/internal/testutil"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

func TestOCINetworkUpdateChangesOnlyTfvars(t *testing.T) {
	modulePath := createExistingOCINetwork(t)
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	request := updateNetworkRequest(modulePath)
	request.OCINetworkResource.SubnetCIDR = "10.30.20.0/24"
	if err := generator.GenerateAtomically(request); err != nil {
		t.Fatalf("OCI Network Update failed: %v", err)
	}

	after := testutil.SnapshotTerraformFiles(t, modulePath)
	for _, filename := range []string{
		"main.tf",
		"variables.tf",
		"outputs.tf",
	} {
		if !bytes.Equal(before[filename], after[filename]) {
			t.Fatalf("%s changed during tfvars-only Update", filename)
		}
	}
	if bytes.Equal(before["terraform.tfvars"], after["terraform.tfvars"]) {
		t.Fatal("terraform.tfvars did not change")
	}
	if !regexp.MustCompile(
		`(?m)^oci_subnet_test_01_cidr_block\s+= "10.30.20.0/24"$`,
	).Match(after["terraform.tfvars"]) {
		t.Fatal("updated subnet CIDR is missing")
	}
	if countNetworkResources(after["main.tf"]) != 4 {
		t.Fatal("Update added or removed an OCI Network resource")
	}
}

func TestOCINetworkUpdateDisplayNamesAndPublicIPProtection(
	t *testing.T,
) {
	modulePath := createExistingOCINetwork(t)
	request := updateNetworkRequest(modulePath)
	request.OCINetworkResource.DisplayName = "oci-vcn-production-01"
	request.OCINetworkResource.SubnetDisplayName = "oci-subnet-production-01"
	request.OCINetworkResource.InternetGatewayDisplayName = "oci-igw-production-01"
	request.OCINetworkResource.RouteTableDisplayName = "oci-rt-production-01"
	prohibitPublicIP := true
	request.OCINetworkResource.ProhibitPublicIPOnVNIC = &prohibitPublicIP

	if err := generator.GenerateAtomically(request); err != nil {
		t.Fatalf("OCI Network Update failed: %v", err)
	}
	files := testutil.SnapshotTerraformFiles(t, modulePath)
	tfvars := string(files["terraform.tfvars"])
	for _, expected := range []string{
		`oci_vcn_test_01_display_name`,
		`"oci-vcn-production-01"`,
		`oci_subnet_test_01_display_name`,
		`"oci-subnet-production-01"`,
		`oci_igw_test_01_display_name`,
		`"oci-igw-production-01"`,
		`oci_rt_test_01_display_name`,
		`"oci-rt-production-01"`,
	} {
		if !strings.Contains(tfvars, expected) {
			t.Fatalf("terraform.tfvars is missing %q", expected)
		}
	}
	if !regexp.MustCompile(
		`(?m)^oci_subnet_test_01_prohibit_public_ip_on_vnic\s+= true$`,
	).Match(files["terraform.tfvars"]) {
		t.Fatal("public-IP protection is not an unquoted true")
	}

	prohibitPublicIP = false
	request.OCINetworkResource.ProhibitPublicIPOnVNIC = &prohibitPublicIP
	if err := generator.GenerateAtomically(request); err != nil {
		t.Fatalf("second OCI Network Update failed: %v", err)
	}
	files = testutil.SnapshotTerraformFiles(t, modulePath)
	if !regexp.MustCompile(
		`(?m)^oci_subnet_test_01_prohibit_public_ip_on_vnic\s+= false$`,
	).Match(files["terraform.tfvars"]) {
		t.Fatal("public-IP protection is not an unquoted false")
	}
}

func TestOCINetworkUpdateRejectsMissingResourcesWithoutChanges(
	t *testing.T,
) {
	tests := []struct {
		name     string
		mutate   func(*models.OCINetworkRequest)
		expected string
	}{
		{
			name: "VCN",
			mutate: func(resource *models.OCINetworkRequest) {
				resource.ResourceName = "oci_vcn_inexistant_999"
			},
			expected: "OCI VCN resource not found: oci_vcn_inexistant_999",
		},
		{
			name: "subnet",
			mutate: func(resource *models.OCINetworkRequest) {
				resource.SubnetResourceName = "oci_subnet_inexistant_999"
			},
			expected: "OCI Subnet resource not found: " +
				"oci_subnet_inexistant_999",
		},
		{
			name: "Internet Gateway",
			mutate: func(resource *models.OCINetworkRequest) {
				resource.InternetGatewayResourceName = "oci_igw_inexistante_999"
			},
			expected: "OCI Internet Gateway resource not found: " +
				"oci_igw_inexistante_999",
		},
		{
			name: "Route Table",
			mutate: func(resource *models.OCINetworkRequest) {
				resource.RouteTableResourceName = "oci_rt_inexistante_999"
			},
			expected: "OCI Route Table resource not found: " +
				"oci_rt_inexistante_999",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modulePath := createExistingOCINetwork(t)
			request := updateNetworkRequest(modulePath)
			test.mutate(request.OCINetworkResource)
			before := testutil.SnapshotTerraformFiles(t, modulePath)

			err := generator.GenerateAtomically(request)
			if err == nil || !strings.Contains(err.Error(), test.expected) {
				t.Fatalf("unexpected missing-resource error: %v", err)
			}
			testutil.AssertTerraformFilesEqual(
				t,
				before,
				testutil.SnapshotTerraformFiles(t, modulePath),
			)
		})
	}
}

func TestOCINetworkUpdateRejectsBrokenRelationsWithoutChanges(
	t *testing.T,
) {
	tests := []struct {
		name     string
		mutate   func(*hclwrite.File)
		expected string
	}{
		{
			name: "subnet to VCN",
			mutate: func(file *hclwrite.File) {
				block := common.FindBlock(
					file,
					"resource",
					"oci_core_subnet",
					"oci_subnet_test_01",
				)
				block.Body().SetAttributeTraversal(
					"vcn_id",
					common.ResourceTraversal(
						"oci_core_vcn",
						"wrong_vcn",
						"id",
					),
				)
			},
			expected: "OCI subnet oci_subnet_test_01 is not linked to VCN " +
				"oci_vcn_test_01",
		},
		{
			name: "route table to VCN",
			mutate: func(file *hclwrite.File) {
				block := common.FindBlock(
					file,
					"resource",
					"oci_core_route_table",
					"oci_rt_test_01",
				)
				block.Body().SetAttributeTraversal(
					"vcn_id",
					common.ResourceTraversal(
						"oci_core_vcn",
						"wrong_vcn",
						"id",
					),
				)
			},
			expected: "OCI Route Table oci_rt_test_01 is not linked to VCN " +
				"oci_vcn_test_01",
		},
		{
			name: "Internet Gateway to VCN",
			mutate: func(file *hclwrite.File) {
				block := common.FindBlock(
					file,
					"resource",
					"oci_core_internet_gateway",
					"oci_igw_test_01",
				)
				block.Body().SetAttributeTraversal(
					"vcn_id",
					common.ResourceTraversal(
						"oci_core_vcn",
						"wrong_vcn",
						"id",
					),
				)
			},
			expected: "OCI Internet Gateway oci_igw_test_01 is not linked " +
				"to VCN oci_vcn_test_01",
		},
		{
			name: "subnet to Route Table",
			mutate: func(file *hclwrite.File) {
				block := common.FindBlock(
					file,
					"resource",
					"oci_core_subnet",
					"oci_subnet_test_01",
				)
				block.Body().SetAttributeTraversal(
					"route_table_id",
					common.ResourceTraversal(
						"oci_core_route_table",
						"wrong_route_table",
						"id",
					),
				)
			},
			expected: "OCI subnet oci_subnet_test_01 is not linked to " +
				"Route Table oci_rt_test_01",
		},
		{
			name: "default route to Internet Gateway",
			mutate: func(file *hclwrite.File) {
				block := common.FindBlock(
					file,
					"resource",
					"oci_core_route_table",
					"oci_rt_test_01",
				)
				for _, nested := range block.Body().Blocks() {
					if nested.Type() == "route_rules" {
						nested.Body().SetAttributeTraversal(
							"network_entity_id",
							common.ResourceTraversal(
								"oci_core_internet_gateway",
								"wrong_igw",
								"id",
							),
						)
					}
				}
			},
			expected: "OCI Route Table oci_rt_test_01 default route is not " +
				"linked to Internet Gateway oci_igw_test_01",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modulePath := createExistingOCINetwork(t)
			mainPath := filepath.Join(modulePath, "main.tf")
			mainFile, err := common.LoadExistingFile(mainPath)
			if err != nil {
				t.Fatalf("load main.tf: %v", err)
			}
			test.mutate(mainFile)
			if err := os.WriteFile(
				mainPath,
				common.FormattedBytes(mainFile),
				0o600,
			); err != nil {
				t.Fatalf("write altered main.tf: %v", err)
			}
			before := testutil.SnapshotTerraformFiles(t, modulePath)

			err = generator.GenerateAtomically(
				updateNetworkRequest(modulePath),
			)
			if err == nil || !strings.Contains(err.Error(), test.expected) {
				t.Fatalf("unexpected relation error: %v", err)
			}
			testutil.AssertTerraformFilesEqual(
				t,
				before,
				testutil.SnapshotTerraformFiles(t, modulePath),
			)
		})
	}
}

func TestOCINetworkUpdateRejectsMissingDeclarationsWithoutChanges(
	t *testing.T,
) {
	tests := []struct {
		name     string
		filename string
		mutate   func(*hclwrite.File)
		expected string
	}{
		{
			name:     "variable",
			filename: "variables.tf",
			mutate: func(file *hclwrite.File) {
				block := common.FindBlock(
					file,
					"variable",
					"oci_vcn_test_01_cidr_block",
				)
				file.Body().RemoveBlock(block)
			},
			expected: "OCI Network variable missing or duplicated: " +
				"oci_vcn_test_01_cidr_block",
		},
		{
			name:     "tfvar",
			filename: "terraform.tfvars",
			mutate: func(file *hclwrite.File) {
				file.Body().RemoveAttribute(
					"oci_subnet_test_01_cidr_block",
				)
			},
			expected: "OCI Network tfvar not found: " +
				"oci_subnet_test_01_cidr_block",
		},
		{
			name:     "output",
			filename: "outputs.tf",
			mutate: func(file *hclwrite.File) {
				block := common.FindBlock(
					file,
					"output",
					"oci_igw_test_01_id",
				)
				file.Body().RemoveBlock(block)
			},
			expected: "OCI Network output missing or duplicated: " +
				"oci_igw_test_01_id",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modulePath := createExistingOCINetwork(t)
			targetPath := testutil.TerraformFilePath(modulePath, test.filename)
			file, err := common.LoadExistingFile(targetPath)
			if err != nil {
				t.Fatalf("load %s: %v", test.filename, err)
			}
			test.mutate(file)
			if err := os.WriteFile(
				targetPath,
				common.FormattedBytes(file),
				0o600,
			); err != nil {
				t.Fatalf("write altered %s: %v", test.filename, err)
			}
			before := testutil.SnapshotTerraformFiles(t, modulePath)

			err = generator.GenerateAtomically(
				updateNetworkRequest(modulePath),
			)
			if err == nil || !strings.Contains(err.Error(), test.expected) {
				t.Fatalf("unexpected declaration error: %v", err)
			}
			testutil.AssertTerraformFilesEqual(
				t,
				before,
				testutil.SnapshotTerraformFiles(t, modulePath),
			)
		})
	}
}

func TestOCINetworkUpdateIsIsolatedFromOtherModules(t *testing.T) {
	root := t.TempDir()
	gcpNetworkPath := filepath.Join(root, "generated", "gcp", "modules", "network")
	ociComputePath := filepath.Join(root, "generated", "oci", "modules", "compute")
	ociNetworkPath := filepath.Join(root, "generated", "oci", "modules", "network")

	seedRequests := []*models.Request{
		testutil.NetworkRequest(
			"create",
			gcpNetworkPath,
			"vpc_update_isolation_01",
			"vpc-update-isolation-01",
			"subnet_update_isolation_01",
			"subnet-update-isolation-01",
			"10.90.0.0/24",
			"europe-west1",
		),
		testutil.OCIComputeRequest(
			ociComputePath,
			"oci_vm_update_isolation_01",
			"oci-vm-update-isolation-01",
			false,
		),
		testutil.OCINetworkRequest(
			ociNetworkPath,
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
		),
	}
	for _, request := range seedRequests {
		if err := generator.GenerateAtomically(request); err != nil {
			t.Fatalf("seed request failed: %v", err)
		}
	}

	gcpBefore := testutil.SnapshotTerraformFiles(t, gcpNetworkPath)
	ociComputeBefore := testutil.SnapshotTerraformFiles(t, ociComputePath)
	update := updateNetworkRequest(ociNetworkPath)
	update.OCINetworkResource.SubnetCIDR = "10.30.20.0/24"
	if err := generator.GenerateAtomically(update); err != nil {
		t.Fatalf("OCI Network Update failed: %v", err)
	}

	testutil.AssertTerraformFilesEqual(
		t,
		gcpBefore,
		testutil.SnapshotTerraformFiles(t, gcpNetworkPath),
	)
	testutil.AssertModuleFilesEqual(
		t,
		ociComputeBefore,
		testutil.SnapshotTerraformFiles(t, ociComputePath),
	)
}

func createExistingOCINetwork(t testing.TB) string {
	t.Helper()
	modulePath := filepath.Join(
		t.TempDir(),
		"generated",
		"oci",
		"modules",
		"network",
	)
	request := testutil.OCINetworkRequest(
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
	if err := generator.GenerateAtomically(request); err != nil {
		t.Fatalf("seed OCI Network Create failed: %v", err)
	}
	return modulePath
}

func updateNetworkRequest(modulePath string) *models.Request {
	request := testutil.OCINetworkRequest(
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
	request.Action = "update"
	return request
}

func countNetworkResources(mainContent []byte) int {
	count := 0
	for _, resourceType := range []string{
		"oci_core_vcn",
		"oci_core_subnet",
		"oci_core_internet_gateway",
		"oci_core_route_table",
	} {
		count += strings.Count(
			string(mainContent),
			`resource "`+resourceType+`"`,
		)
	}
	return count
}
