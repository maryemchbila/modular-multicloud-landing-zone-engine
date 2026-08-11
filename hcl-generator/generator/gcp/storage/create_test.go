package storage_test

import (
	"bytes"
	"strings"
	"testing"

	"hcl-generator/generator"
	"hcl-generator/generator/internal/testutil"
)

func TestCreateStorage(t *testing.T) {
	modulePath := testutil.CanonicalModulePath(t, "gcp", "storage")
	request := testutil.StorageRequest(
		"create",
		modulePath,
		"bucket_test",
		"stage2026-bucket-test",
		"EU",
		"STANDARD",
		true,
	)
	if err := generator.GenerateAtomically(request); err != nil {
		t.Fatalf("Storage Create failed: %v", err)
	}

	beforeDuplicate := testutil.SnapshotTerraformFiles(t, modulePath)
	if !strings.Contains(
		string(beforeDuplicate["main.tf"]),
		`resource "google_storage_bucket" "bucket_test"`,
	) {
		t.Fatal("main.tf is missing the storage bucket")
	}
	if !strings.Contains(
		string(beforeDuplicate["terraform.tfvars"]),
		"bucket_test_uniform_bucket_level_access = true",
	) {
		t.Fatal("terraform.tfvars is missing the native boolean")
	}

	if err := generator.GenerateAtomically(request); err == nil {
		t.Fatal("duplicate Storage Create unexpectedly succeeded")
	}
	afterDuplicate := testutil.SnapshotTerraformFiles(t, modulePath)
	for _, filename := range testutil.TerraformFilenames {
		if !bytes.Equal(
			beforeDuplicate[filename],
			afterDuplicate[filename],
		) {
			t.Fatalf("%s changed after duplicate Storage Create", filename)
		}
	}
}
