package compute_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hcl-generator/generator"
	"hcl-generator/generator/common"
	"hcl-generator/generator/internal/testutil"
	"hcl-generator/validation"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

func TestComputeDeleteRemovesOnlyTargetResource(t *testing.T) {
	modulePath := testutil.CanonicalModulePath(t, "gcp", "compute")
	for _, resourceName := range []string{"vm_delete_a_01", "vm_delete_b_01"} {
		if err := generator.GenerateAtomically(testutil.ComputeRequest(
			"create",
			modulePath,
			resourceName,
			strings.ReplaceAll(resourceName, "_", "-"),
			"e2-medium")); err != nil {
			t.Fatalf("Compute Create %s failed: %v", resourceName, err)
		}
	}
	addLegacyComputeOutput(t, modulePath, "vm_delete_a_01")
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	if err := generator.GenerateAtomically(testutil.ComputeDeleteRequest(
		modulePath,
		"vm_delete_a_01")); err != nil {
		t.Fatalf("Compute Delete failed: %v", err)
	}

	after := testutil.SnapshotTerraformFiles(t, modulePath)
	for _, filename := range testutil.TerraformFilenames {
		if bytes.Contains(after[filename], []byte("vm_delete_a_01")) {
			t.Fatalf("%s still contains the deleted resource", filename)
		}
		if !bytes.Contains(after[filename], []byte("vm_delete_b_01")) {
			t.Fatalf("%s lost the independent VM", filename)
		}
		if bytes.Contains(after[filename], []byte("\n\n\n")) {
			t.Fatalf("%s contains excessive blank lines after delete", filename)
		}
	}

	if count := strings.Count(
		string(after["main.tf"]),
		`resource "google_compute_instance" "vm_delete_b_01"`,
	); count != 1 {
		t.Fatalf("remaining VM resource count = %d, want 1", count)
	}
	if count := strings.Count(
		string(after["variables.tf"]),
		`variable "vm_delete_b_01_`,
	); count != 5 {
		t.Fatalf("remaining VM variable count = %d, want 5", count)
	}
	if count := strings.Count(
		string(after["terraform.tfvars"]),
		"vm_delete_b_01_",
	); count != 5 {
		t.Fatalf("remaining VM tfvars count = %d, want 5", count)
	}
	if count := strings.Count(
		string(after["outputs.tf"]),
		`output "vm_delete_b_01_`,
	); count != 2 {
		t.Fatalf("remaining VM output count = %d, want 2", count)
	}
	if !bytes.Contains(before["outputs.tf"], []byte("legacy_instance_id")) {
		t.Fatal("legacy output fixture was not created")
	}
	if bytes.Contains(after["outputs.tf"], []byte("legacy_instance_id")) {
		t.Fatal("legacy output referencing the deleted VM remains")
	}
}

func TestComputeDeleteMissingResourceDoesNotModifyFiles(t *testing.T) {
	modulePath := testutil.CanonicalModulePath(t, "gcp", "compute")
	if err := generator.GenerateAtomically(testutil.ComputeRequest(
		"create",
		modulePath,
		"vm_existing_01",
		"vm-existing-01",
		"e2-medium")); err != nil {
		t.Fatalf("Compute Create failed: %v", err)
	}
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	err := generator.GenerateAtomically(testutil.ComputeDeleteRequest(
		modulePath,
		"vm_inexistante_999"))

	if err == nil ||
		err.Error() != "Compute resource not found: vm_inexistante_999" {
		t.Fatalf("unexpected missing resource error: %v", err)
	}
	testutil.AssertTerraformFilesEqual(t, before, testutil.SnapshotTerraformFiles(t, modulePath))
}

func TestComputeDeleteBlocksReferencedResource(t *testing.T) {
	modulePath := testutil.CanonicalModulePath(t, "gcp", "compute")
	for _, resourceName := range []string{"vm_source_01", "vm_consumer_01"} {
		if err := generator.GenerateAtomically(testutil.ComputeRequest(
			"create",
			modulePath,
			resourceName,
			strings.ReplaceAll(resourceName, "_", "-"),
			"e2-medium")); err != nil {
			t.Fatalf("Compute Create %s failed: %v", resourceName, err)
		}
	}

	files, err := common.LoadExistingTerraformFiles(modulePath)
	if err != nil {
		t.Fatalf("load Compute fixture: %v", err)
	}
	consumer := common.FindBlock(
		files.Main,
		"resource",
		"google_compute_instance",
		"vm_consumer_01",
	)
	if consumer == nil {
		t.Fatal("consumer resource is missing")
	}
	consumer.Body().SetAttributeTraversal(
		"source_instance",
		common.ResourceTraversal(
			"google_compute_instance",
			"vm_source_01",
			"id",
		),
	)
	if err := os.WriteFile(
		filepath.Join(modulePath, "main.tf"),
		common.FormattedBytes(files.Main),
		0o644,
	); err != nil {
		t.Fatalf("write dependency fixture: %v", err)
	}
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	err = generator.GenerateAtomically(testutil.ComputeDeleteRequest(modulePath, "vm_source_01"))
	if err == nil ||
		err.Error() !=
			"Cannot delete Compute resource vm_source_01: referenced by another block" {
		t.Fatalf("unexpected dependency error: %v", err)
	}
	testutil.AssertTerraformFilesEqual(t, before, testutil.SnapshotTerraformFiles(t, modulePath))
}

func TestComputeDeleteNonRegressionAndModuleIsolation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "generated", "gcp", "modules")
	computePath := filepath.Join(root, "compute")
	networkPath := filepath.Join(root, "network")
	storagePath := filepath.Join(root, "storage")

	for _, resourceName := range []string{"vm_delete_01", "vm_keep_01"} {
		if err := generator.GenerateAtomically(testutil.ComputeRequest(
			"create",
			computePath,
			resourceName,
			strings.ReplaceAll(resourceName, "_", "-"),
			"e2-medium")); err != nil {
			t.Fatalf("Compute Create %s failed: %v", resourceName, err)
		}
	}
	if err := generator.GenerateAtomically(testutil.NetworkRequest(
		"create",
		networkPath,
		"vpc_delete_isolation_01",
		"vpc-delete-isolation-01",
		"subnet_delete_isolation_01",
		"subnet-delete-isolation-01",
		"10.96.0.0/24",
		"europe-west1")); err != nil {
		t.Fatalf("Network Create failed: %v", err)
	}
	if err := generator.GenerateAtomically(testutil.NetworkRequest(
		"update",
		networkPath,
		"vpc_delete_isolation_01",
		"vpc-delete-isolation-production",
		"subnet_delete_isolation_01",
		"subnet-delete-isolation-production",
		"10.97.0.0/24",
		"europe-west3")); err != nil {
		t.Fatalf("Network Update failed: %v", err)
	}
	if err := generator.GenerateAtomically(testutil.StorageRequest(
		"create",
		storagePath,
		"bucket_delete_isolation_01",
		"stage2026-delete-isolation-01",
		"EU",
		"STANDARD",
		true)); err != nil {
		t.Fatalf("Storage Create failed: %v", err)
	}
	if err := generator.GenerateAtomically(testutil.StorageRequest(
		"update",
		storagePath,
		"bucket_delete_isolation_01",
		"stage2026-delete-isolation-production",
		"EUROPE-WEST1",
		"COLDLINE",
		false)); err != nil {
		t.Fatalf("Storage Update failed: %v", err)
	}

	networkBefore := testutil.SnapshotTerraformFiles(t, networkPath)
	storageBefore := testutil.SnapshotTerraformFiles(t, storagePath)
	if err := generator.GenerateAtomically(testutil.ComputeDeleteRequest(
		computePath,
		"vm_delete_01")); err != nil {
		t.Fatalf("Compute Delete failed: %v", err)
	}

	if err := generator.GenerateAtomically(testutil.ComputeRequest(
		"create",
		computePath,
		"vm_after_delete_01",
		"vm-after-delete-01",
		"e2-medium")); err != nil {
		t.Fatalf("Compute Create after Delete failed: %v", err)
	}
	if err := generator.GenerateAtomically(testutil.ComputeRequest(
		"update",
		computePath,
		"vm_keep_01",
		"vm-keep-production",
		"e2-standard-2")); err != nil {
		t.Fatalf("Compute Update after Delete failed: %v", err)
	}

	testutil.AssertModuleFilesEqual(
		t,
		networkBefore,
		testutil.SnapshotTerraformFiles(t, networkPath))

	testutil.AssertModuleFilesEqual(
		t,
		storageBefore,
		testutil.SnapshotTerraformFiles(t, storagePath))

}

func TestComputeDeleteValidationUsesOnlyResourceName(t *testing.T) {
	request := testutil.ComputeDeleteRequest(
		filepath.Join(t.TempDir(), "generated", "gcp", "modules", "compute"),
		"vm_delete_test_01")

	if err := validation.ValidateRequest(request); err != nil {
		t.Fatalf("minimal Compute Delete validation failed: %v", err)
	}

	request.ComputeResource.ResourceName = "invalid resource"
	if err := validation.ValidateRequest(request); err == nil {
		t.Fatal("invalid Terraform resource name was accepted")
	}
}

func addLegacyComputeOutput(
	t *testing.T,
	modulePath string,
	resourceName string,
) {
	t.Helper()
	files, err := common.LoadExistingTerraformFiles(modulePath)
	if err != nil {
		t.Fatalf("load outputs fixture: %v", err)
	}
	block := hclwrite.NewBlock("output", []string{"legacy_instance_id"})
	block.Body().SetAttributeTraversal(
		"value",
		common.ResourceTraversal(
			"google_compute_instance",
			resourceName,
			"id",
		),
	)
	common.AppendBlock(files.Outputs, block)
	if err := os.WriteFile(
		filepath.Join(modulePath, "outputs.tf"),
		common.FormattedBytes(files.Outputs),
		0o644,
	); err != nil {
		t.Fatalf("write outputs fixture: %v", err)
	}
}
