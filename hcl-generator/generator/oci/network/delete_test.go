package network_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hcl-generator/generator"
	"hcl-generator/generator/common"
	"hcl-generator/generator/internal/testutil"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

func TestOCINetworkDeleteRemovesOnlyTargetNetwork(t *testing.T) {
	modulePath := createTwoOCINetworks(t)
	if err := generator.GenerateAtomically(
		deleteNetworkRequest(modulePath, "a"),
	); err != nil {
		t.Fatalf("OCI Network Delete failed: %v", err)
	}

	files := testutil.SnapshotTerraformFiles(t, modulePath)
	for _, filename := range testutil.TerraformFilenames {
		content := string(files[filename])
		for _, target := range []string{
			"oci_vcn_delete_a_01",
			"oci_subnet_delete_a_01",
			"oci_igw_delete_a_01",
			"oci_rt_delete_a_01",
		} {
			if strings.Contains(content, target) {
				t.Fatalf("%s still contains deleted target %s", filename, target)
			}
		}
		for _, preserved := range []string{
			"oci_vcn_delete_b_01",
			"oci_subnet_delete_b_01",
			"oci_igw_delete_b_01",
			"oci_rt_delete_b_01",
		} {
			if !strings.Contains(content, preserved) {
				t.Fatalf("%s lost preserved target %s", filename, preserved)
			}
		}
	}
	if countNetworkResources(files["main.tf"]) != 4 {
		t.Fatal("Delete did not preserve exactly one complete OCI Network")
	}
}

func TestOCINetworkDeleteRejectsMissingResourcesWithoutChanges(
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
			name: "Subnet",
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
			modulePath := createTwoOCINetworks(t)
			request := deleteNetworkRequest(modulePath, "a")
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

func TestOCINetworkDeleteRejectsMixedNetworksWithoutChanges(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*models.OCINetworkRequest)
		expected string
	}{
		{
			name: "Subnet from network B",
			mutate: func(resource *models.OCINetworkRequest) {
				resource.SubnetResourceName = "oci_subnet_delete_b_01"
			},
			expected: "OCI Subnet oci_subnet_delete_b_01 is not linked " +
				"to VCN oci_vcn_delete_a_01",
		},
		{
			name: "Route Table from network B",
			mutate: func(resource *models.OCINetworkRequest) {
				resource.RouteTableResourceName = "oci_rt_delete_b_01"
			},
			expected: "OCI Route Table oci_rt_delete_b_01 is not linked " +
				"to VCN oci_vcn_delete_a_01",
		},
		{
			name: "Internet Gateway from network B",
			mutate: func(resource *models.OCINetworkRequest) {
				resource.InternetGatewayResourceName = "oci_igw_delete_b_01"
			},
			expected: "OCI Internet Gateway oci_igw_delete_b_01 is not linked " +
				"to VCN oci_vcn_delete_a_01",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modulePath := createTwoOCINetworks(t)
			request := deleteNetworkRequest(modulePath, "a")
			test.mutate(request.OCINetworkResource)
			before := testutil.SnapshotTerraformFiles(t, modulePath)

			err := generator.GenerateAtomically(request)
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

func TestOCINetworkDeleteRejectsExternalNetworkDependency(t *testing.T) {
	modulePath := createTwoOCINetworks(t)
	mainPath := filepath.Join(modulePath, "main.tf")
	mainFile, err := common.LoadExistingFile(mainPath)
	if err != nil {
		t.Fatalf("load main.tf: %v", err)
	}
	dependent := hclwrite.NewBlock(
		"resource",
		[]string{"oci_core_security_list", "consumer"},
	)
	dependent.Body().SetAttributeTraversal(
		"vcn_id",
		common.ResourceTraversal(
			"oci_core_vcn",
			"oci_vcn_delete_a_01",
			"id",
		),
	)
	common.AppendBlock(mainFile, dependent)
	if err := os.WriteFile(
		mainPath,
		common.FormattedBytes(mainFile),
		0o600,
	); err != nil {
		t.Fatalf("write main.tf dependency: %v", err)
	}
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	err = generator.GenerateAtomically(deleteNetworkRequest(modulePath, "a"))
	if err == nil || !strings.Contains(
		err.Error(),
		"Cannot delete OCI Network oci_vcn_delete_a_01: "+
			"referenced by another OCI Network block",
	) {
		t.Fatalf("unexpected external-dependency error: %v", err)
	}
	testutil.AssertTerraformFilesEqual(
		t,
		before,
		testutil.SnapshotTerraformFiles(t, modulePath),
	)
}

func TestOCINetworkDeleteRejectsCertainOCIComputeDependency(t *testing.T) {
	modulePath := createTwoOCINetworks(t)
	computePath := filepath.Join(filepath.Dir(modulePath), "compute")
	if err := os.MkdirAll(computePath, 0o755); err != nil {
		t.Fatalf("create Compute module: %v", err)
	}
	computeMain := hclwrite.NewEmptyFile()
	instance := hclwrite.NewBlock(
		"resource",
		[]string{"oci_core_instance", "consumer"},
	)
	instance.Body().SetAttributeTraversal(
		"subnet_id",
		common.ResourceTraversal(
			"oci_core_subnet",
			"oci_subnet_delete_a_01",
			"id",
		),
	)
	common.AppendBlock(computeMain, instance)
	if err := os.WriteFile(
		filepath.Join(computePath, "main.tf"),
		common.FormattedBytes(computeMain),
		0o600,
	); err != nil {
		t.Fatalf("write Compute main.tf: %v", err)
	}
	if err := os.WriteFile(
		common.TerraformTfvarsPath(computePath),
		[]byte("\n"),
		0o600,
	); err != nil {
		t.Fatalf("write Compute terraform.tfvars: %v", err)
	}
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	err := generator.GenerateAtomically(deleteNetworkRequest(modulePath, "a"))
	if err == nil || !strings.Contains(
		err.Error(),
		"Cannot delete OCI Network oci_vcn_delete_a_01: subnet "+
			"oci_subnet_delete_a_01 is referenced by OCI Compute configuration",
	) {
		t.Fatalf("unexpected OCI Compute dependency error: %v", err)
	}
	testutil.AssertTerraformFilesEqual(
		t,
		before,
		testutil.SnapshotTerraformFiles(t, modulePath),
	)
}

func TestOCINetworkDeleteToleratesMissingDeclarations(t *testing.T) {
	modulePath := createTwoOCINetworks(t)
	variablesPath := filepath.Join(modulePath, "variables.tf")
	variables, err := common.LoadExistingFile(variablesPath)
	if err != nil {
		t.Fatalf("load variables.tf: %v", err)
	}
	variable := common.FindBlock(
		variables,
		"variable",
		"oci_vcn_delete_a_01_dns_label",
	)
	variables.Body().RemoveBlock(variable)
	if err := os.WriteFile(
		variablesPath,
		common.FormattedBytes(variables),
		0o600,
	); err != nil {
		t.Fatalf("write variables.tf: %v", err)
	}

	tfvarsPath := common.TerraformTfvarsPath(modulePath)
	tfvars, err := common.LoadExistingFile(tfvarsPath)
	if err != nil {
		t.Fatalf("load terraform.tfvars: %v", err)
	}
	tfvars.Body().RemoveAttribute("oci_vcn_delete_a_01_dns_label")
	if err := os.WriteFile(
		tfvarsPath,
		common.FormattedBytes(tfvars),
		0o600,
	); err != nil {
		t.Fatalf("write terraform.tfvars: %v", err)
	}

	if err := generator.GenerateAtomically(
		deleteNetworkRequest(modulePath, "a"),
	); err != nil {
		t.Fatalf("Delete with missing declarations failed: %v", err)
	}
	files := testutil.SnapshotTerraformFiles(t, modulePath)
	for _, filename := range testutil.TerraformFilenames {
		if strings.Contains(string(files[filename]), "oci_vcn_delete_a_01") {
			t.Fatalf("%s kept target after tolerant Delete", filename)
		}
	}
}

func TestOCINetworkDeleteIsolatedAndAvoidsUncertainOCIDMatch(t *testing.T) {
	root := t.TempDir()
	gcpPath := filepath.Join(root, "generated", "gcp", "modules", "network")
	ociComputePath := filepath.Join(root, "generated", "oci", "modules", "compute")
	ociNetworkPath := filepath.Join(root, "generated", "oci", "modules", "network")

	seedRequests := []*models.Request{
		testutil.NetworkRequest(
			"create",
			gcpPath,
			"vpc_delete_isolation_01",
			"vpc-delete-isolation-01",
			"subnet_delete_isolation_01",
			"subnet-delete-isolation-01",
			"10.95.0.0/24",
			"europe-west1",
		),
		testutil.OCIComputeRequest(
			ociComputePath,
			"oci_vm_delete_isolation_01",
			"oci-vm-delete-isolation-01",
			false,
		),
	}
	for _, request := range seedRequests {
		if err := generator.GenerateAtomically(request); err != nil {
			t.Fatalf("seed request failed: %v", err)
		}
	}
	createNetworkPairAtPath(t, ociNetworkPath)
	gcpBefore := testutil.SnapshotTerraformFiles(t, gcpPath)
	ociComputeBefore := testutil.SnapshotTerraformFiles(t, ociComputePath)

	if err := generator.GenerateAtomically(
		deleteNetworkRequest(ociNetworkPath, "a"),
	); err != nil {
		t.Fatalf("OCI Network Delete failed: %v", err)
	}
	testutil.AssertTerraformFilesEqual(
		t,
		gcpBefore,
		testutil.SnapshotTerraformFiles(t, gcpPath),
	)
	testutil.AssertModuleFilesEqual(
		t,
		ociComputeBefore,
		testutil.SnapshotTerraformFiles(t, ociComputePath),
	)
}

func createTwoOCINetworks(t testing.TB) string {
	t.Helper()
	modulePath := filepath.Join(
		t.TempDir(),
		"generated",
		"oci",
		"modules",
		"network",
	)
	createNetworkPairAtPath(t, modulePath)
	return modulePath
}

func createNetworkPairAtPath(t testing.TB, modulePath string) {
	t.Helper()
	requests := []*models.Request{
		testutil.OCINetworkRequest(
			modulePath,
			"oci_vcn_delete_a_01",
			"oci-vcn-delete-a-01",
			"oci_subnet_delete_a_01",
			"oci-subnet-delete-a-01",
			"10.90.0.0/16",
			"10.90.1.0/24",
			"oci_igw_delete_a_01",
			"oci-igw-delete-a-01",
			"oci_rt_delete_a_01",
			"oci-rt-delete-a-01",
			true,
		),
		testutil.OCINetworkRequest(
			modulePath,
			"oci_vcn_delete_b_01",
			"oci-vcn-delete-b-01",
			"oci_subnet_delete_b_01",
			"oci-subnet-delete-b-01",
			"10.91.0.0/16",
			"10.91.1.0/24",
			"oci_igw_delete_b_01",
			"oci-igw-delete-b-01",
			"oci_rt_delete_b_01",
			"oci-rt-delete-b-01",
			true,
		),
	}
	for _, request := range requests {
		if err := generator.GenerateAtomically(request); err != nil {
			t.Fatalf("seed OCI Network Create failed: %v", err)
		}
	}
}

func deleteNetworkRequest(modulePath string, suffix string) *models.Request {
	return &models.Request{
		Action:     "delete",
		Provider:   "oci",
		Module:     "network",
		ModulePath: modulePath,
		OCINetworkResource: &models.OCINetworkRequest{
			ResourceName:                "oci_vcn_delete_" + suffix + "_01",
			SubnetResourceName:          "oci_subnet_delete_" + suffix + "_01",
			InternetGatewayResourceName: "oci_igw_delete_" + suffix + "_01",
			RouteTableResourceName:      "oci_rt_delete_" + suffix + "_01",
		},
	}
}
