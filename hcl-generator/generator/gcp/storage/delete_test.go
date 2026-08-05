package storage_test

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

func TestStorageDeleteRemovesOnlyTargetBucket(t *testing.T) {
	modulePath := t.TempDir()
	createStorageDeleteBucket(t, modulePath, "a", true)
	createStorageDeleteBucket(t, modulePath, "b", false)

	before := testutil.SnapshotTerraformFiles(t, modulePath)
	if err := generator.GenerateAtomically(testutil.StorageDeleteRequest(
		modulePath,
		"bucket_delete_a_01")); err != nil {
		t.Fatalf("Storage Delete failed: %v", err)
	}
	after := testutil.SnapshotTerraformFiles(t, modulePath)

	target := "bucket_delete_a_01"
	for _, filename := range testutil.TerraformFilenames {
		if bytes.Contains(after[filename], []byte(target)) {
			t.Fatalf("%s still contains target %q", filename, target)
		}
		if !bytes.Contains(after[filename], []byte("bucket_delete_b_01")) {
			t.Fatalf("%s lost independent bucket", filename)
		}
	}
	if !bytes.Contains(
		before["terraform.tfvars"],
		[]byte("bucket_delete_a_01_uniform_bucket_level_access = true"),
	) {
		t.Fatal("boolean fixture is missing before deletion")
	}
	if !bytes.Contains(
		after["terraform.tfvars"],
		[]byte("bucket_delete_b_01_uniform_bucket_level_access = false"),
	) {
		t.Fatal("independent boolean tfvar changed during deletion")
	}

	assertStorageBucketElements(t, after, "bucket_delete_b_01")
}

func TestStorageDeleteMissingBucketLeavesAllFilesUnchanged(t *testing.T) {
	modulePath := t.TempDir()
	createStorageDeleteBucket(t, modulePath, "test", true)
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	err := generator.GenerateAtomically(testutil.StorageDeleteRequest(
		modulePath,
		"bucket_inexistant_999"))

	if err == nil ||
		err.Error() != "Storage resource not found: bucket_inexistant_999" {
		t.Fatalf("unexpected missing bucket error: %v", err)
	}
	testutil.AssertTerraformFilesEqual(t, before, testutil.SnapshotTerraformFiles(t, modulePath))
}

func TestStorageDeleteBlocksInternalDependency(t *testing.T) {
	modulePath := t.TempDir()
	createStorageDeleteBucket(t, modulePath, "test", true)

	files, err := common.LoadExistingTerraformFiles(modulePath)
	if err != nil {
		t.Fatalf("load Storage fixture: %v", err)
	}
	dependent := hclwrite.NewBlock(
		"resource",
		[]string{"google_storage_bucket_object", "dependent_object_01"},
	)
	dependent.Body().SetAttributeTraversal(
		"bucket",
		common.ResourceTraversal(
			"google_storage_bucket",
			"bucket_delete_test_01",
			"name",
		),
	)
	common.AppendBlock(files.Main, dependent)
	if err := os.WriteFile(
		filepath.Join(modulePath, "main.tf"),
		common.FormattedBytes(files.Main),
		0o644,
	); err != nil {
		t.Fatalf("write Storage dependency fixture: %v", err)
	}
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	err = generator.GenerateAtomically(testutil.StorageDeleteRequest(
		modulePath,
		"bucket_delete_test_01"))

	if err == nil ||
		err.Error() !=
			"Cannot delete Storage resource bucket_delete_test_01: referenced by another block" {
		t.Fatalf("unexpected dependency error: %v", err)
	}
	testutil.AssertTerraformFilesEqual(t, before, testutil.SnapshotTerraformFiles(t, modulePath))
}

func TestStorageDeleteToleratesMissingExpectedVariable(t *testing.T) {
	modulePath := t.TempDir()
	createStorageDeleteBucket(t, modulePath, "test", true)

	files, err := common.LoadExistingTerraformFiles(modulePath)
	if err != nil {
		t.Fatalf("load Storage fixture: %v", err)
	}
	common.RemoveBlocks(files.Variables, func(block *hclwrite.Block) bool {
		return block.Type() == "variable" &&
			len(block.Labels()) == 1 &&
			block.Labels()[0] == "bucket_delete_test_01_location"
	})
	if err := os.WriteFile(
		filepath.Join(modulePath, "variables.tf"),
		common.FormattedBytes(files.Variables),
		0o644,
	); err != nil {
		t.Fatalf("write incomplete Storage fixture: %v", err)
	}

	if err := generator.GenerateAtomically(testutil.StorageDeleteRequest(
		modulePath,
		"bucket_delete_test_01")); err != nil {
		t.Fatalf("Storage Delete with missing variable failed: %v", err)
	}
	after := testutil.SnapshotTerraformFiles(t, modulePath)
	for _, filename := range testutil.TerraformFilenames {
		if bytes.Contains(after[filename], []byte("bucket_delete_test_01")) {
			t.Fatalf("%s retained target elements", filename)
		}
	}
}

func TestStorageDeleteNonRegressionAndModuleIsolation(t *testing.T) {
	root := t.TempDir()
	computePath := filepath.Join(root, "compute")
	networkPath := filepath.Join(root, "network")
	storagePath := filepath.Join(root, "storage")

	for _, resourceName := range []string{
		"vm_storage_delete_01",
		"vm_storage_keep_01",
	} {
		if err := generator.GenerateAtomically(testutil.ComputeRequest(
			"create",
			computePath,
			resourceName,
			strings.ReplaceAll(resourceName, "_", "-"),
			"e2-medium")); err != nil {
			t.Fatalf("Compute Create failed: %v", err)
		}
	}
	if err := generator.GenerateAtomically(testutil.ComputeRequest(
		"update",
		computePath,
		"vm_storage_keep_01",
		"vm-storage-keep-production",
		"e2-standard-2")); err != nil {
		t.Fatalf("Compute Update failed: %v", err)
	}
	if err := generator.GenerateAtomically(testutil.ComputeDeleteRequest(
		computePath,
		"vm_storage_delete_01")); err != nil {
		t.Fatalf("Compute Delete failed: %v", err)
	}

	for _, fixture := range []struct {
		suffix string
		cidr   string
	}{
		{"a", "10.196.0.0/24"},
		{"b", "10.197.0.0/24"},
	} {
		if err := generator.GenerateAtomically(testutil.NetworkRequest(
			"create",
			networkPath,
			"vpc_delete_"+fixture.suffix+"_01",
			"vpc-delete-"+fixture.suffix+"-01",
			"subnet_delete_"+fixture.suffix+"_01",
			"subnet-delete-"+fixture.suffix+"-01",
			fixture.cidr,
			"europe-west1",
		)); err != nil {
			t.Fatalf("Network Create %s failed: %v", fixture.suffix, err)
		}
	}
	if err := generator.GenerateAtomically(testutil.NetworkRequest(
		"update",
		networkPath,
		"vpc_delete_b_01",
		"vpc-delete-b-production",
		"subnet_delete_b_01",
		"subnet-delete-b-production",
		"10.198.0.0/24",
		"europe-west3")); err != nil {
		t.Fatalf("Network Update failed: %v", err)
	}
	if err := generator.GenerateAtomically(testutil.NetworkDeleteRequest(
		networkPath,
		"vpc_delete_a_01",
		"subnet_delete_a_01")); err != nil {
		t.Fatalf("Network Delete failed: %v", err)
	}

	createStorageDeleteBucket(t, storagePath, "a", true)
	createStorageDeleteBucket(t, storagePath, "b", false)
	if err := generator.GenerateAtomically(testutil.StorageRequest(
		"update",
		storagePath,
		"bucket_delete_b_01",
		"stage2026-delete-b-production",
		"EUROPE-WEST1",
		"COLDLINE",
		true)); err != nil {
		t.Fatalf("Storage Update failed: %v", err)
	}

	computeBefore := testutil.SnapshotTerraformFiles(t, computePath)
	networkBefore := testutil.SnapshotTerraformFiles(t, networkPath)
	if err := generator.GenerateAtomically(testutil.StorageDeleteRequest(
		storagePath,
		"bucket_delete_a_01")); err != nil {
		t.Fatalf("Storage Delete failed: %v", err)
	}
	testutil.AssertTerraformFilesEqual(
		t,
		computeBefore,
		testutil.SnapshotTerraformFiles(t, computePath))

	testutil.AssertTerraformFilesEqual(
		t,
		networkBefore,
		testutil.SnapshotTerraformFiles(t, networkPath))

	createStorageDeleteBucket(t, storagePath, "after", true)
	if err := generator.GenerateAtomically(testutil.StorageRequest(
		"update",
		storagePath,
		"bucket_delete_b_01",
		"stage2026-delete-b-final",
		"EU",
		"ARCHIVE",
		false)); err != nil {
		t.Fatalf("Storage Update after Delete failed: %v", err)
	}
}

func TestStorageDeleteValidationUsesOnlyResourceName(t *testing.T) {
	request := testutil.StorageDeleteRequest(
		filepath.Join(t.TempDir(), "generated", "gcp", "storage"),
		"bucket_delete_test_01")

	if err := validation.ValidateRequest(request); err != nil {
		t.Fatalf("minimal Storage Delete validation failed: %v", err)
	}

	request.StorageResource.ResourceName = "invalid bucket"
	if err := validation.ValidateRequest(request); err == nil {
		t.Fatal("invalid Terraform bucket identifier was accepted")
	}
}

func createStorageDeleteBucket(
	t *testing.T,
	modulePath string,
	suffix string,
	uniformAccess bool,
) {
	t.Helper()
	if err := generator.GenerateAtomically(testutil.StorageRequest(
		"create",
		modulePath,
		"bucket_delete_"+suffix+"_01",
		"stage2026-delete-"+suffix+"-01",
		"EU",
		"STANDARD",
		uniformAccess)); err != nil {
		t.Fatalf("Storage Create %s failed: %v", suffix, err)
	}
}

func assertStorageBucketElements(
	t *testing.T,
	files map[string][]byte,
	resourceName string,
) {
	t.Helper()
	expectations := map[string][]string{
		"main.tf": {
			`resource "google_storage_bucket" "` + resourceName + `"`,
		},
		"variables.tf": {
			`variable "` + resourceName + `_name"`,
			`variable "` + resourceName + `_location"`,
			`variable "` + resourceName + `_storage_class"`,
			`variable "` + resourceName + `_uniform_bucket_level_access"`,
		},
		"terraform.tfvars": {
			resourceName + "_name",
			resourceName + "_location",
			resourceName + "_storage_class",
			resourceName + "_uniform_bucket_level_access",
		},
		"outputs.tf": {
			`output "` + resourceName + `_id"`,
			`output "` + resourceName + `_url"`,
		},
	}
	for filename, values := range expectations {
		for _, value := range values {
			if !bytes.Contains(files[filename], []byte(value)) {
				t.Fatalf("%s is missing %q", filename, value)
			}
		}
	}
}
