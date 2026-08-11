package storage_test

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
)

func TestOCIStorageUpdateChangesOnlyRequestedTfvar(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*models.OCIStorageRequest)
		key      string
		expected string
	}{
		{
			name: "storage tier",
			mutate: func(resource *models.OCIStorageRequest) {
				resource.StorageTier = "Archive"
			},
			key:      "oci_bucket_test_01_storage_tier",
			expected: `"Archive"`,
		},
		{
			name: "bucket name",
			mutate: func(resource *models.OCIStorageRequest) {
				resource.Name = "stage2026-oci-bucket-production-01"
			},
			key:      "oci_bucket_test_01_name",
			expected: `"stage2026-oci-bucket-production-01"`,
		},
		{
			name: "versioning",
			mutate: func(resource *models.OCIStorageRequest) {
				resource.Versioning = "Disabled"
			},
			key:      "oci_bucket_test_01_versioning",
			expected: `"Disabled"`,
		},
		{
			name: "access type",
			mutate: func(resource *models.OCIStorageRequest) {
				resource.AccessType = "ObjectRead"
			},
			key:      "oci_bucket_test_01_access_type",
			expected: `"ObjectRead"`,
		},
		{
			name: "object events",
			mutate: func(resource *models.OCIStorageRequest) {
				disabled := false
				resource.ObjectEventsEnabled = &disabled
			},
			key:      "oci_bucket_test_01_object_events_enabled",
			expected: "false",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modulePath, update := createStorageUpdateFixture(t)
			before := testutil.SnapshotTerraformFiles(t, modulePath)
			test.mutate(update.OCIStorageResource)

			if err := generator.GenerateAtomically(update); err != nil {
				t.Fatalf("OCI Storage Update failed: %v", err)
			}
			after := testutil.SnapshotTerraformFiles(t, modulePath)

			for _, filename := range []string{
				"main.tf",
				"variables.tf",
				"outputs.tf",
			} {
				if !bytes.Equal(before[filename], after[filename]) {
					t.Fatalf("%s changed during OCI Storage Update", filename)
				}
			}
			assertOnlyTfvarChanged(
				t,
				before["terraform.tfvars"],
				after["terraform.tfvars"],
				test.key,
				test.expected,
			)
			if count := strings.Count(
				string(after["main.tf"]),
				`resource "oci_objectstorage_bucket" "oci_bucket_test_01"`,
			); count != 1 {
				t.Fatalf("expected one bucket resource, got %d", count)
			}
		})
	}
}

func TestOCIStorageUpdateMissingBucketLeavesAllFilesUnchanged(t *testing.T) {
	modulePath, update := createStorageUpdateFixture(t)
	update.OCIStorageResource.ResourceName = "oci_bucket_inexistant_999"
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	err := generator.GenerateAtomically(update)
	if err == nil ||
		err.Error() !=
			"OCI Storage resource not found: oci_bucket_inexistant_999" {
		t.Fatalf("unexpected missing-resource error: %v", err)
	}
	testutil.AssertTerraformFilesEqual(
		t,
		before,
		testutil.SnapshotTerraformFiles(t, modulePath),
	)
}

func TestOCIStorageUpdateMissingVariableIsAtomic(t *testing.T) {
	modulePath, update := createStorageUpdateFixture(t)
	files, err := common.LoadExistingTerraformFiles(modulePath)
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	missingName := "oci_bucket_test_01_storage_tier"
	for _, block := range files.Variables.Body().Blocks() {
		if block.Type() == "variable" &&
			len(block.Labels()) == 1 &&
			block.Labels()[0] == missingName {
			files.Variables.Body().RemoveBlock(block)
		}
	}
	if err := os.WriteFile(
		filepath.Join(modulePath, "variables.tf"),
		common.FormattedBytes(files.Variables),
		0644,
	); err != nil {
		t.Fatalf("write incomplete fixture: %v", err)
	}
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	err = generator.GenerateAtomically(update)
	if err == nil || !strings.Contains(
		err.Error(),
		"OCI Storage variable missing or duplicated: "+missingName,
	) {
		t.Fatalf("unexpected missing-variable error: %v", err)
	}
	testutil.AssertTerraformFilesEqual(
		t,
		before,
		testutil.SnapshotTerraformFiles(t, modulePath),
	)
}

func TestOCIStorageUpdatePreservesOtherBucketsAndModules(t *testing.T) {
	root := t.TempDir()
	storagePath := filepath.Join(root, "generated", "oci", "modules", "storage")
	computePath := filepath.Join(root, "generated", "oci", "modules", "compute")
	networkPath := filepath.Join(root, "generated", "oci", "modules", "network")
	gcpPath := filepath.Join(root, "generated", "gcp", "modules", "compute")

	first := testutil.OCIStorageRequest(
		storagePath,
		"oci_bucket_test_01",
		"stage2026-oci-bucket-test-01",
		"NoPublicAccess",
		"Standard",
		"Enabled",
		true,
	)
	second := testutil.OCIStorageRequest(
		storagePath,
		"oci_bucket_other_01",
		"stage2026-oci-bucket-other-01",
		"NoPublicAccess",
		"Standard",
		"Enabled",
		true,
	)
	otherRequests := []*models.Request{
		testutil.OCIComputeRequest(
			computePath,
			"oci_vm_update_isolation_01",
			"oci-vm-update-isolation-01",
			false,
		),
		testutil.OCINetworkRequest(
			networkPath,
			"oci_vcn_update_isolation_01",
			"oci-vcn-update-isolation-01",
			"oci_subnet_update_isolation_01",
			"oci-subnet-update-isolation-01",
			"10.91.0.0/16",
			"10.91.1.0/24",
			"oci_igw_update_isolation_01",
			"oci-igw-update-isolation-01",
			"oci_rt_update_isolation_01",
			"oci-rt-update-isolation-01",
			true,
		),
		testutil.ComputeRequest(
			"create",
			gcpPath,
			"vm_update_isolation_01",
			"vm-update-isolation-01",
			"e2-medium",
		),
	}
	for _, request := range append(
		[]*models.Request{first, second},
		otherRequests...,
	) {
		if err := generator.GenerateAtomically(request); err != nil {
			t.Fatalf("seed request failed: %v", err)
		}
	}
	beforeOtherModules := []map[string][]byte{
		testutil.SnapshotTerraformFiles(t, computePath),
		testutil.SnapshotTerraformFiles(t, networkPath),
		testutil.SnapshotTerraformFiles(t, gcpPath),
	}

	update := testutil.OCIStorageRequest(
		storagePath,
		"oci_bucket_test_01",
		"stage2026-oci-bucket-test-01",
		"NoPublicAccess",
		"Archive",
		"Enabled",
		true,
	)
	update.Action = "update"
	if err := generator.GenerateAtomically(update); err != nil {
		t.Fatalf("OCI Storage Update failed: %v", err)
	}
	storageAfter := testutil.SnapshotTerraformFiles(t, storagePath)
	if !regexp.MustCompile(
		`(?m)^oci_bucket_other_01_storage_tier\s+= "Standard"$`,
	).Match(storageAfter["terraform.tfvars"]) {
		t.Fatal("the other OCI Storage bucket was modified or removed")
	}
	for index, path := range []string{computePath, networkPath, gcpPath} {
		testutil.AssertModuleFilesEqual(
			t,
			beforeOtherModules[index],
			testutil.SnapshotTerraformFiles(t, path),
		)
	}
}

func createStorageUpdateFixture(
	t *testing.T,
) (string, *models.Request) {
	t.Helper()
	modulePath := storageModulePath(t)
	create := testutil.OCIStorageRequest(
		modulePath,
		"oci_bucket_test_01",
		"stage2026-oci-bucket-test-01",
		"NoPublicAccess",
		"Standard",
		"Enabled",
		true,
	)
	if err := generator.GenerateAtomically(create); err != nil {
		t.Fatalf("OCI Storage Create fixture failed: %v", err)
	}
	update := testutil.OCIStorageRequest(
		modulePath,
		"oci_bucket_test_01",
		"stage2026-oci-bucket-test-01",
		"NoPublicAccess",
		"Standard",
		"Enabled",
		true,
	)
	update.Action = "update"
	return modulePath, update
}

func assertOnlyTfvarChanged(
	t *testing.T,
	before []byte,
	after []byte,
	expectedKey string,
	expectedValue string,
) {
	t.Helper()
	beforeValues := tfvarLines(before)
	afterValues := tfvarLines(after)
	if len(beforeValues) != len(afterValues) {
		t.Fatalf("tfvars count changed: %d -> %d", len(beforeValues), len(afterValues))
	}
	changed := 0
	for key, beforeLine := range beforeValues {
		afterLine, exists := afterValues[key]
		if !exists {
			t.Fatalf("tfvar %s disappeared", key)
		}
		if beforeLine != afterLine {
			changed++
			if key != expectedKey {
				t.Fatalf("unexpected tfvar changed: %s", key)
			}
		}
	}
	if changed != 1 {
		t.Fatalf("expected exactly one changed tfvar, got %d", changed)
	}
	pattern := regexp.MustCompile(
		`(?m)^` + regexp.QuoteMeta(expectedKey) +
			`\s+= ` + regexp.QuoteMeta(expectedValue) + `$`,
	)
	if !pattern.Match(after) {
		t.Fatalf("updated tfvar %s does not equal %s\n%s", expectedKey, expectedValue, after)
	}
}

func tfvarLines(content []byte) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[1] == "=" {
			result[fields[0]] = strings.TrimSpace(line)
		}
	}
	return result
}
