package storage_test

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

func TestOCIStorageCreateGeneratesBucketWithTraversals(t *testing.T) {
	modulePath := storageModulePath(t)
	request := testutil.OCIStorageRequest(
		modulePath,
		"oci_bucket_secure_01",
		"oci-bucket-secure-01",
		"NoPublicAccess",
		"Standard",
		"Enabled",
		true,
	)
	if err := generator.GenerateAtomically(request); err != nil {
		t.Fatalf("OCI Storage Create failed: %v", err)
	}

	files := testutil.SnapshotTerraformFiles(t, modulePath)
	mainContent := string(files["main.tf"])
	for _, fragment := range []string{
		`resource "oci_objectstorage_bucket" "oci_bucket_secure_01"`,
		"compartment_id        = var.oci_bucket_secure_01_compartment_id",
		"namespace             = var.oci_bucket_secure_01_namespace",
		"name                  = var.oci_bucket_secure_01_name",
		"access_type           = var.oci_bucket_secure_01_access_type",
		"storage_tier          = var.oci_bucket_secure_01_storage_tier",
		"versioning            = var.oci_bucket_secure_01_versioning",
		"object_events_enabled = var.oci_bucket_secure_01_object_events_enabled",
	} {
		if !strings.Contains(mainContent, fragment) {
			t.Fatalf("main.tf is missing %q\n%s", fragment, mainContent)
		}
	}

	variables := string(files["variables.tf"])
	tfvars := string(files["terraform.tfvars"])
	for _, suffix := range []string{
		"compartment_id",
		"namespace",
		"name",
		"access_type",
		"storage_tier",
		"versioning",
		"object_events_enabled",
	} {
		name := "oci_bucket_secure_01_" + suffix
		if !strings.Contains(variables, `variable "`+name+`"`) {
			t.Fatalf("variables.tf is missing %q", name)
		}
		if !strings.Contains(tfvars, name) {
			t.Fatalf("terraform.tfvars is missing %q", name)
		}
	}
	if !regexp.MustCompile(
		`(?m)^oci_bucket_secure_01_object_events_enabled\s+= true$`,
	).Match(files["terraform.tfvars"]) {
		t.Fatal("object_events_enabled is not an unquoted true")
	}

	outputs := string(files["outputs.tf"])
	for _, attribute := range []string{"id", "name", "namespace", "etag"} {
		name := "oci_bucket_secure_01_" + attribute
		traversal := "oci_objectstorage_bucket.oci_bucket_secure_01." +
			attribute
		if !strings.Contains(outputs, `output "`+name+`"`) ||
			!strings.Contains(outputs, traversal) {
			t.Fatalf("output %q does not use %q", name, traversal)
		}
	}
}

func TestOCIStorageCreateAppendsArchiveBucketWithoutOverwrite(t *testing.T) {
	modulePath := storageModulePath(t)
	first := testutil.OCIStorageRequest(
		modulePath,
		"oci_bucket_standard_01",
		"oci-bucket-standard-01",
		"NoPublicAccess",
		"Standard",
		"Enabled",
		true,
	)
	second := testutil.OCIStorageRequest(
		modulePath,
		"oci_bucket_archive_01",
		"oci-bucket-archive-01",
		"NoPublicAccess",
		"Archive",
		"Enabled",
		false,
	)
	for _, request := range []*models.Request{first, second} {
		if err := generator.GenerateAtomically(request); err != nil {
			t.Fatalf("OCI Storage Create failed: %v", err)
		}
	}

	files := testutil.SnapshotTerraformFiles(t, modulePath)
	for _, filename := range testutil.TerraformFilenames {
		content := string(files[filename])
		for _, name := range []string{
			"oci_bucket_standard_01",
			"oci_bucket_archive_01",
		} {
			if !strings.Contains(content, name) {
				t.Fatalf("%s is missing %s", filename, name)
			}
		}
	}
	tfvars := files["terraform.tfvars"]
	if !regexp.MustCompile(
		`(?m)^oci_bucket_archive_01_storage_tier\s+= "Archive"$`,
	).Match(tfvars) {
		t.Fatal("archive tier was not generated")
	}
	if !regexp.MustCompile(
		`(?m)^oci_bucket_archive_01_object_events_enabled\s+= false$`,
	).Match(tfvars) {
		t.Fatal("object_events_enabled is not an unquoted false")
	}
}

func TestOCIStorageDuplicateLeavesAllFilesUnchanged(t *testing.T) {
	modulePath := storageModulePath(t)
	request := testutil.OCIStorageRequest(
		modulePath,
		"oci_bucket_duplicate_01",
		"oci-bucket-duplicate-01",
		"NoPublicAccess",
		"Standard",
		"Enabled",
		true,
	)
	if err := generator.GenerateAtomically(request); err != nil {
		t.Fatalf("OCI Storage Create failed: %v", err)
	}
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	err := generator.GenerateAtomically(request)
	if err == nil || !strings.Contains(err.Error(), "doublon OCI storage") {
		t.Fatalf("duplicate returned unexpected error: %v", err)
	}
	after := testutil.SnapshotTerraformFiles(t, modulePath)
	for _, filename := range testutil.TerraformFilenames {
		if !bytes.Equal(before[filename], after[filename]) {
			t.Fatalf("%s changed after duplicate OCI Storage Create", filename)
		}
	}
}

func TestOCIStorageCreateDoesNotModifyOtherModules(t *testing.T) {
	root := t.TempDir()
	gcpComputePath := filepath.Join(root, "generated", "gcp", "modules", "compute")
	gcpStoragePath := filepath.Join(root, "generated", "gcp", "modules", "storage")
	ociComputePath := filepath.Join(root, "generated", "oci", "modules", "compute")
	ociNetworkPath := filepath.Join(root, "generated", "oci", "modules", "network")
	ociStoragePath := filepath.Join(root, "generated", "oci", "modules", "storage")

	seedRequests := []*models.Request{
		testutil.ComputeRequest(
			"create",
			gcpComputePath,
			"vm_storage_isolation_01",
			"vm-storage-isolation-01",
			"e2-medium",
		),
		testutil.StorageRequest(
			"create",
			gcpStoragePath,
			"bucket_storage_isolation_01",
			"stage2026-storage-isolation-01",
			"EU",
			"STANDARD",
			true,
		),
		testutil.OCIComputeRequest(
			ociComputePath,
			"oci_vm_storage_isolation_01",
			"oci-vm-storage-isolation-01",
			false,
		),
		testutil.OCINetworkRequest(
			ociNetworkPath,
			"oci_vcn_storage_isolation_01",
			"oci-vcn-storage-isolation-01",
			"oci_subnet_storage_isolation_01",
			"oci-subnet-storage-isolation-01",
			"10.90.0.0/16",
			"10.90.1.0/24",
			"oci_igw_storage_isolation_01",
			"oci-igw-storage-isolation-01",
			"oci_rt_storage_isolation_01",
			"oci-rt-storage-isolation-01",
			true,
		),
	}
	paths := []string{
		gcpComputePath,
		gcpStoragePath,
		ociComputePath,
		ociNetworkPath,
	}
	before := make([]map[string][]byte, len(paths))
	for index, request := range seedRequests {
		if err := generator.GenerateAtomically(request); err != nil {
			t.Fatalf("seed request failed: %v", err)
		}
		before[index] = testutil.SnapshotTerraformFiles(t, paths[index])
	}

	if err := generator.GenerateAtomically(testutil.OCIStorageRequest(
		ociStoragePath,
		"oci_bucket_isolation_01",
		"oci-bucket-isolation-01",
		"NoPublicAccess",
		"Standard",
		"Enabled",
		true,
	)); err != nil {
		t.Fatalf("OCI Storage Create failed: %v", err)
	}
	for index, path := range paths {
		testutil.AssertModuleFilesEqual(
			t,
			before[index],
			testutil.SnapshotTerraformFiles(t, path),
		)
	}
}

func storageModulePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "generated", "oci", "modules", "storage")
}
