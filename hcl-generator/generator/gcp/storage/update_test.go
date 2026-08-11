package storage_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hcl-generator/generator"
	"hcl-generator/generator/internal/testutil"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

func TestStorageUpdateScenarios(t *testing.T) {
	modulePath := testutil.CanonicalModulePath(t, "gcp", "storage")
	if err := generator.GenerateAtomically(testutil.StorageRequest(
		"create",
		modulePath,
		"bucket_test_01",
		"stage2026-storage-test-01",
		"EU",
		"STANDARD",
		true)); err != nil {
		t.Fatalf("Storage Create failed: %v", err)
	}

	beforeClass := testutil.SnapshotTerraformFiles(t, modulePath)
	update := testutil.StorageRequest(
		"update",
		modulePath,
		"bucket_test_01",
		"stage2026-storage-test-01",
		"EU",
		"NEARLINE",
		true)

	if err := generator.GenerateAtomically(update); err != nil {
		t.Fatalf("storage_class-only Storage Update failed: %v", err)
	}

	afterClass := testutil.SnapshotTerraformFiles(t, modulePath)
	for _, filename := range []string{"main.tf", "variables.tf", "outputs.tf"} {
		if !bytes.Equal(beforeClass[filename], afterClass[filename]) {
			t.Fatalf("%s changed during storage_class-only update", filename)
		}
	}
	expectedClass := bytes.Replace(
		beforeClass["terraform.tfvars"],
		[]byte(`bucket_test_01_storage_class               = "STANDARD"`),
		[]byte(`bucket_test_01_storage_class               = "NEARLINE"`),
		1,
	)
	if !bytes.Equal(expectedClass, afterClass["terraform.tfvars"]) {
		t.Fatal("storage_class-only update changed more than the target value")
	}

	update.StorageResource.Name = "stage2026-storage-production-01"
	if err := generator.GenerateAtomically(update); err != nil {
		t.Fatalf("name Storage Update failed: %v", err)
	}
	afterName := testutil.SnapshotTerraformFiles(t, modulePath)
	if !strings.Contains(
		string(afterName["terraform.tfvars"]),
		`bucket_test_01_name                        = "stage2026-storage-production-01"`,
	) {
		t.Fatal("updated bucket name is missing")
	}

	update.StorageResource.Location = "EUROPE-WEST1"
	update.StorageResource.StorageClass = "COLDLINE"
	if err := generator.GenerateAtomically(update); err != nil {
		t.Fatalf("location and class Storage Update failed: %v", err)
	}
	afterLocation := testutil.SnapshotTerraformFiles(t, modulePath)
	tfvarsAfterLocation := string(afterLocation["terraform.tfvars"])
	for _, expected := range []string{
		`bucket_test_01_location                    = "EUROPE-WEST1"`,
		`bucket_test_01_storage_class               = "COLDLINE"`,
	} {
		if !strings.Contains(tfvarsAfterLocation, expected) {
			t.Fatalf("final tfvars is missing %q", expected)
		}
	}

	if err := generator.GenerateAtomically(testutil.StorageRequest(
		"create",
		modulePath,
		"bucket_public_test_01",
		"stage2026-public-test-01",
		"EU",
		"STANDARD",
		true)); err != nil {
		t.Fatalf("public bucket Storage Create failed: %v", err)
	}
	beforeBoolean := testutil.SnapshotTerraformFiles(t, modulePath)
	if err := generator.GenerateAtomically(testutil.StorageRequest(
		"update",
		modulePath,
		"bucket_public_test_01",
		"stage2026-public-test-01",
		"EU",
		"STANDARD",
		false)); err != nil {
		t.Fatalf("boolean Storage Update failed: %v", err)
	}
	afterBoolean := testutil.SnapshotTerraformFiles(t, modulePath)
	tfvarsAfterBoolean := string(afterBoolean["terraform.tfvars"])
	if !strings.Contains(
		tfvarsAfterBoolean,
		"bucket_public_test_01_uniform_bucket_level_access = false",
	) {
		t.Fatal("updated boolean is missing or is not a native HCL boolean")
	}
	if strings.Contains(
		tfvarsAfterBoolean,
		`bucket_public_test_01_uniform_bucket_level_access = "false"`,
	) {
		t.Fatal("updated boolean was serialized as a string")
	}

	mainContent := string(afterBoolean["main.tf"])
	for _, resourceName := range []string{
		"bucket_test_01",
		"bucket_public_test_01",
	} {
		if count := strings.Count(
			mainContent,
			`resource "google_storage_bucket" "`+resourceName+`"`,
		); count != 1 {
			t.Fatalf("bucket %s resource count = %d, want 1", resourceName, count)
		}
	}
	if !bytes.Equal(beforeBoolean["outputs.tf"], afterBoolean["outputs.tf"]) {
		t.Fatal("outputs.tf changed during boolean Storage Update")
	}

	beforeMissing := afterBoolean
	missing := testutil.StorageRequest(
		"update",
		modulePath,
		"bucket_inexistant_999",
		"bucket-inexistant-999",
		"EU",
		"STANDARD",
		true)

	err := generator.GenerateAtomically(missing)
	if err == nil ||
		err.Error() != "Storage resource not found: bucket_inexistant_999" {
		t.Fatalf("unexpected missing bucket error: %v", err)
	}
	testutil.AssertTerraformFilesEqual(t, beforeMissing, testutil.SnapshotTerraformFiles(t, modulePath))
}

func TestStorageUpdateMigratesLegacyVariables(t *testing.T) {
	modulePath := testutil.CanonicalModulePath(t, "gcp", "storage")
	writeLegacyStorageFixture(t, modulePath)
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	if err := generator.GenerateAtomically(testutil.StorageRequest(
		"update",
		modulePath,
		"bucket_legacy_01",
		"stage2026-legacy-01",
		"EU",
		"STANDARD",
		true)); err != nil {
		t.Fatalf("legacy Storage Update failed: %v", err)
	}

	after := testutil.SnapshotTerraformFiles(t, modulePath)
	mainContent := string(after["main.tf"])
	variablesContent := string(after["variables.tf"])
	tfvarsContent := string(after["terraform.tfvars"])
	for _, scoped := range []string{
		"bucket_legacy_01_name",
		"bucket_legacy_01_location",
		"bucket_legacy_01_storage_class",
		"bucket_legacy_01_uniform_bucket_level_access",
	} {
		if !strings.Contains(mainContent, "var."+scoped) {
			t.Fatalf("migrated main.tf is missing var.%s", scoped)
		}
		if strings.Count(variablesContent, `variable "`+scoped+`"`) != 1 {
			t.Fatalf("variable %q is missing or duplicated", scoped)
		}
		if strings.Count(tfvarsContent, scoped) != 1 {
			t.Fatalf("tfvars %q is missing or duplicated", scoped)
		}
	}
	for _, legacy := range []string{
		"name",
		"location",
		"storage_class",
		"uniform_bucket_level_access",
	} {
		if strings.Contains(mainContent, "var."+legacy) {
			t.Fatalf("legacy traversal var.%s remains", legacy)
		}
		if strings.Contains(variablesContent, `variable "`+legacy+`"`) {
			t.Fatalf("legacy variable %q remains", legacy)
		}
	}
	if !bytes.Equal(before["outputs.tf"], after["outputs.tf"]) {
		t.Fatal("legacy migration changed outputs.tf")
	}
}

func TestStorageUpdateDoesNotModifyComputeOrNetwork(t *testing.T) {
	root := filepath.Join(t.TempDir(), "generated", "gcp", "modules")
	computePath := filepath.Join(root, "compute")
	networkPath := filepath.Join(root, "network")
	storagePath := filepath.Join(root, "storage")

	if err := generator.GenerateAtomically(testutil.ComputeRequest(
		"create",
		computePath,
		"vm_storage_isolation_01",
		"vm-storage-isolation-01",
		"e2-medium")); err != nil {
		t.Fatalf("Compute Create failed: %v", err)
	}
	if err := generator.GenerateAtomically(testutil.ComputeRequest(
		"update",
		computePath,
		"vm_storage_isolation_01",
		"vm-storage-isolation-production",
		"e2-standard-2")); err != nil {
		t.Fatalf("Compute Update failed: %v", err)
	}
	if err := generator.GenerateAtomically(testutil.NetworkRequest(
		"create",
		networkPath,
		"vpc_storage_isolation_01",
		"vpc-storage-isolation-01",
		"subnet_storage_isolation_01",
		"subnet-storage-isolation-01",
		"10.94.0.0/24",
		"europe-west1")); err != nil {
		t.Fatalf("Network Create failed: %v", err)
	}
	if err := generator.GenerateAtomically(testutil.NetworkRequest(
		"update",
		networkPath,
		"vpc_storage_isolation_01",
		"vpc-storage-isolation-production",
		"subnet_storage_isolation_01",
		"subnet-storage-isolation-production",
		"10.95.0.0/24",
		"europe-west3")); err != nil {
		t.Fatalf("Network Update failed: %v", err)
	}
	if err := generator.GenerateAtomically(testutil.StorageRequest(
		"create",
		storagePath,
		"bucket_isolation_01",
		"stage2026-storage-isolation-01",
		"EU",
		"STANDARD",
		true)); err != nil {
		t.Fatalf("Storage Create failed: %v", err)
	}

	computeBefore := testutil.SnapshotTerraformFiles(t, computePath)
	networkBefore := testutil.SnapshotTerraformFiles(t, networkPath)
	if err := generator.GenerateAtomically(testutil.StorageRequest(
		"update",
		storagePath,
		"bucket_isolation_01",
		"stage2026-storage-isolation-production",
		"EUROPE-WEST1",
		"COLDLINE",
		false)); err != nil {
		t.Fatalf("Storage Update failed: %v", err)
	}

	testutil.AssertModuleFilesEqual(
		t,
		computeBefore,
		testutil.SnapshotTerraformFiles(t, computePath))

	testutil.AssertModuleFilesEqual(
		t,
		networkBefore,
		testutil.SnapshotTerraformFiles(t, networkPath))

}

func writeLegacyStorageFixture(t *testing.T, modulePath string) {
	t.Helper()
	fixtures := map[string]string{
		"main.tf": `
resource "google_storage_bucket" "bucket_legacy_01" {
  name                        = var.name
  location                    = var.location
  storage_class               = var.storage_class
  uniform_bucket_level_access = var.uniform_bucket_level_access
}
`,
		"variables.tf": `
variable "name" {
  type = string
}

variable "location" {
  type = string
}

variable "storage_class" {
  type = string
}

variable "uniform_bucket_level_access" {
  type = bool
}
`,
		"terraform.tfvars": `
name                        = "stage2026-legacy-01"
location                    = "EU"
storage_class               = "STANDARD"
uniform_bucket_level_access = true
`,
		"outputs.tf": `
output "bucket_legacy_01_id" {
  value = google_storage_bucket.bucket_legacy_01.id
}

output "bucket_legacy_01_url" {
  value = google_storage_bucket.bucket_legacy_01.url
}
`,
	}

	for filename, content := range fixtures {
		formatted := hclwrite.Format([]byte(strings.TrimSpace(content) + "\n"))
		if err := os.WriteFile(
			testutil.TerraformFilePath(modulePath, filename),
			formatted,
			0o644,
		); err != nil {
			t.Fatalf("write %s: %v", filename, err)
		}
	}
}
