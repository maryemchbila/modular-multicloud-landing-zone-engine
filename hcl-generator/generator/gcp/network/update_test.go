package network_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hcl-generator/generator"
	"hcl-generator/generator/internal/testutil"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

func TestNetworkUpdateScenarios(t *testing.T) {
	modulePath := t.TempDir()
	create := testutil.NetworkRequest(
		"create",
		modulePath,
		"vpc_dev_01",
		"vpc-dev-01",
		"subnet_dev_01",
		"subnet-dev-01",
		"10.40.0.0/24",
		"europe-west1")

	if err := generator.GenerateAtomically(create); err != nil {
		t.Fatalf("Network Create failed: %v", err)
	}

	beforeCIDR := testutil.SnapshotTerraformFiles(t, modulePath)
	update := testutil.NetworkRequest(
		"update",
		modulePath,
		"vpc_dev_01",
		"vpc-dev-01",
		"subnet_dev_01",
		"subnet-dev-01",
		"10.81.0.0/24",
		"europe-west1")

	if err := generator.GenerateAtomically(update); err != nil {
		t.Fatalf("CIDR-only Network Update failed: %v", err)
	}

	afterCIDR := testutil.SnapshotTerraformFiles(t, modulePath)
	for _, filename := range []string{"main.tf", "variables.tf", "outputs.tf"} {
		if !bytes.Equal(beforeCIDR[filename], afterCIDR[filename]) {
			t.Fatalf("%s changed during CIDR-only Network Update", filename)
		}
	}
	expectedCIDR := bytes.Replace(
		beforeCIDR["terraform.tfvars"],
		[]byte(`subnet_dev_01_cidr   = "10.40.0.0/24"`),
		[]byte(`subnet_dev_01_cidr   = "10.81.0.0/24"`),
		1,
	)
	if !bytes.Equal(expectedCIDR, afterCIDR["terraform.tfvars"]) {
		t.Fatal("CIDR-only update changed more than subnet_dev_01_cidr")
	}

	update.NetworkResource.Name = "vpc-dev-production"
	update.NetworkResource.SubnetName = "subnet-dev-production"
	if err := generator.GenerateAtomically(update); err != nil {
		t.Fatalf("name Network Update failed: %v", err)
	}
	afterNames := testutil.SnapshotTerraformFiles(t, modulePath)
	tfvarsAfterNames := string(afterNames["terraform.tfvars"])
	if !strings.Contains(
		tfvarsAfterNames,
		`vpc_dev_01_name      = "vpc-dev-production"`,
	) {
		t.Fatal("updated VPC name is missing")
	}
	if !strings.Contains(
		tfvarsAfterNames,
		`subnet_dev_01_name   = "subnet-dev-production"`,
	) {
		t.Fatal("updated subnet name is missing")
	}

	update.NetworkResource.CIDR = "10.82.0.0/24"
	update.NetworkResource.Region = "europe-west3"
	if err := generator.GenerateAtomically(update); err != nil {
		t.Fatalf("CIDR and region Network Update failed: %v", err)
	}
	afterRegion := testutil.SnapshotTerraformFiles(t, modulePath)
	tfvarsAfterRegion := string(afterRegion["terraform.tfvars"])
	for _, expected := range []string{
		`subnet_dev_01_cidr   = "10.82.0.0/24"`,
		`subnet_dev_01_region = "europe-west3"`,
	} {
		if !strings.Contains(tfvarsAfterRegion, expected) {
			t.Fatalf("final tfvars is missing %q", expected)
		}
	}

	mainContent := string(afterRegion["main.tf"])
	if count := strings.Count(
		mainContent,
		`resource "google_compute_network" "vpc_dev_01"`,
	); count != 1 {
		t.Fatalf("VPC resource count = %d, want 1", count)
	}
	if count := strings.Count(
		mainContent,
		`resource "google_compute_subnetwork" "subnet_dev_01"`,
	); count != 1 {
		t.Fatalf("subnet resource count = %d, want 1", count)
	}
	if !strings.Contains(
		mainContent,
		"google_compute_network.vpc_dev_01.id",
	) {
		t.Fatal("subnet network reference is not an HCL resource traversal")
	}
	if strings.Contains(
		mainContent,
		`"google_compute_network.vpc_dev_01.id"`,
	) {
		t.Fatal("subnet network reference was serialized as a string")
	}
	if !bytes.Equal(beforeCIDR["outputs.tf"], afterRegion["outputs.tf"]) {
		t.Fatal("outputs.tf changed during Network Update")
	}

	beforeMissing := afterRegion
	missingVPC := testutil.NetworkRequest(
		"update",
		modulePath,
		"vpc_inexistant_999",
		"unused",
		"subnet_dev_01",
		"unused",
		"10.90.0.0/24",
		"europe-west1")

	err := generator.GenerateAtomically(missingVPC)
	if err == nil ||
		err.Error() != "Network resource not found: vpc_inexistant_999" {
		t.Fatalf("unexpected missing VPC error: %v", err)
	}
	testutil.AssertTerraformFilesEqual(t, beforeMissing, testutil.SnapshotTerraformFiles(t, modulePath))

	missingSubnet := testutil.NetworkRequest(
		"update",
		modulePath,
		"vpc_dev_01",
		"unused",
		"subnet_inexistant_999",
		"unused",
		"10.90.0.0/24",
		"europe-west1")

	err = generator.GenerateAtomically(missingSubnet)
	if err == nil ||
		err.Error() != "Subnetwork resource not found: subnet_inexistant_999" {
		t.Fatalf("unexpected missing subnet error: %v", err)
	}
	testutil.AssertTerraformFilesEqual(t, beforeMissing, testutil.SnapshotTerraformFiles(t, modulePath))
}

func TestNetworkUpdateMigratesLegacyVariables(t *testing.T) {
	modulePath := t.TempDir()
	writeLegacyNetworkFixture(t, modulePath)
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	update := testutil.NetworkRequest(
		"update",
		modulePath,
		"vpc_legacy_01",
		"vpc-legacy-01",
		"subnet_legacy_01",
		"subnet-legacy-01",
		"10.91.0.0/24",
		"europe-west1")

	if err := generator.GenerateAtomically(update); err != nil {
		t.Fatalf("legacy Network Update failed: %v", err)
	}

	after := testutil.SnapshotTerraformFiles(t, modulePath)
	mainContent := string(after["main.tf"])
	variablesContent := string(after["variables.tf"])
	tfvarsContent := string(after["terraform.tfvars"])
	for _, traversal := range []string{
		"var.vpc_legacy_01_name",
		"var.subnet_legacy_01_name",
		"var.subnet_legacy_01_cidr",
		"var.subnet_legacy_01_region",
	} {
		if !strings.Contains(mainContent, traversal) {
			t.Fatalf("migrated main.tf is missing %s", traversal)
		}
	}
	for _, legacy := range []string{"name", "subnet_name", "cidr", "region"} {
		if strings.Contains(mainContent, "var."+legacy) {
			t.Fatalf("legacy traversal var.%s remains", legacy)
		}
		if strings.Contains(variablesContent, `variable "`+legacy+`"`) {
			t.Fatalf("legacy variable %q remains", legacy)
		}
	}
	for _, scoped := range []string{
		"vpc_legacy_01_name",
		"subnet_legacy_01_name",
		"subnet_legacy_01_cidr",
		"subnet_legacy_01_region",
	} {
		if strings.Count(variablesContent, `variable "`+scoped+`"`) != 1 {
			t.Fatalf("variable %q is missing or duplicated", scoped)
		}
		if strings.Count(tfvarsContent, scoped) != 1 {
			t.Fatalf("tfvars %q is missing or duplicated", scoped)
		}
	}
	if !bytes.Equal(before["outputs.tf"], after["outputs.tf"]) {
		t.Fatal("legacy migration changed outputs.tf")
	}
}

func TestNetworkUpdateDoesNotModifyComputeOrStorage(t *testing.T) {
	root := t.TempDir()
	computePath := filepath.Join(root, "compute")
	networkPath := filepath.Join(root, "network")
	storagePath := filepath.Join(root, "storage")

	if err := generator.GenerateAtomically(testutil.ComputeRequest(
		"create",
		computePath,
		"vm_isolation_01",
		"vm-isolation-01",
		"e2-medium")); err != nil {
		t.Fatalf("Compute Create failed: %v", err)
	}
	if err := generator.GenerateAtomically(testutil.ComputeRequest(
		"update",
		computePath,
		"vm_isolation_01",
		"vm-isolation-production",
		"e2-standard-2")); err != nil {
		t.Fatalf("Compute Update failed: %v", err)
	}
	if err := generator.GenerateAtomically(testutil.NetworkRequest(
		"create",
		networkPath,
		"vpc_isolation_01",
		"vpc-isolation-01",
		"subnet_isolation_01",
		"subnet-isolation-01",
		"10.92.0.0/24",
		"europe-west1")); err != nil {
		t.Fatalf("Network Create failed: %v", err)
	}

	uniformAccess := true
	if err := generator.GenerateAtomically(&models.Request{
		Action:     "create",
		Provider:   "gcp",
		Module:     "storage",
		ModulePath: storagePath,
		StorageResource: &models.StorageRequest{
			ResourceName:             "bucket_isolation_01",
			Name:                     "stage2026-isolation-01",
			Location:                 "EU",
			StorageClass:             "STANDARD",
			UniformBucketLevelAccess: &uniformAccess,
		},
	}); err != nil {
		t.Fatalf("Storage Create failed: %v", err)
	}

	computeBefore := testutil.SnapshotTerraformFiles(t, computePath)
	storageBefore := testutil.SnapshotTerraformFiles(t, storagePath)
	if err := generator.GenerateAtomically(testutil.NetworkRequest(
		"update",
		networkPath,
		"vpc_isolation_01",
		"vpc-isolation-production",
		"subnet_isolation_01",
		"subnet-isolation-production",
		"10.93.0.0/24",
		"europe-west3")); err != nil {
		t.Fatalf("Network Update failed: %v", err)
	}

	testutil.AssertTerraformFilesEqual(
		t,
		computeBefore,
		testutil.SnapshotTerraformFiles(t, computePath))

	testutil.AssertTerraformFilesEqual(
		t,
		storageBefore,
		testutil.SnapshotTerraformFiles(t, storagePath))

}

func writeLegacyNetworkFixture(t *testing.T, modulePath string) {
	t.Helper()
	fixtures := map[string]string{
		"main.tf": `
resource "google_compute_network" "vpc_legacy_01" {
  name                    = var.name
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet_legacy_01" {
  name          = var.subnet_name
  ip_cidr_range = var.cidr
  region        = var.region
  network       = google_compute_network.vpc_legacy_01.id
}
`,
		"variables.tf": `
variable "name" {
  type = string
}

variable "subnet_name" {
  type = string
}

variable "cidr" {
  type = string
}

variable "region" {
  type = string
}
`,
		"terraform.tfvars": `
name        = "vpc-legacy-01"
subnet_name = "subnet-legacy-01"
cidr        = "10.91.0.0/24"
region      = "europe-west1"
`,
		"outputs.tf": `
output "vpc_legacy_01_id" {
  value = google_compute_network.vpc_legacy_01.id
}

output "subnet_legacy_01_id" {
  value = google_compute_subnetwork.subnet_legacy_01.id
}
`,
	}

	for filename, content := range fixtures {
		formatted := hclwrite.Format([]byte(strings.TrimSpace(content) + "\n"))
		if err := os.WriteFile(
			filepath.Join(modulePath, filename),
			formatted,
			0o644,
		); err != nil {
			t.Fatalf("write %s: %v", filename, err)
		}
	}
}
