package storage_test

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hcl-generator/generator"
	"hcl-generator/generator/common"
	"hcl-generator/generator/internal/testutil"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

func TestOCIStorageDeleteRemovesOnlyTargetBucket(t *testing.T) {
	root := t.TempDir()
	storagePath := filepath.Join(root, "generated", "oci", "modules", "storage")
	computePath := filepath.Join(root, "generated", "oci", "modules", "compute")
	networkPath := filepath.Join(root, "generated", "oci", "modules", "network")
	gcpPath := filepath.Join(root, "generated", "gcp", "modules", "storage")

	targetName := "oci_bucket_delete_a_01"
	otherName := "oci_bucket_delete_b_01"
	seedRequests := []*models.Request{
		testutil.OCIStorageRequest(
			storagePath,
			targetName,
			"stage2026-oci-delete-a-01",
			"NoPublicAccess",
			"Standard",
			"Enabled",
			false,
		),
		testutil.OCIStorageRequest(
			storagePath,
			otherName,
			"stage2026-oci-delete-b-01",
			"NoPublicAccess",
			"Standard",
			"Enabled",
			true,
		),
		testutil.OCIComputeRequest(
			computePath,
			"oci_vm_delete_isolation_01",
			"oci-vm-delete-isolation-01",
			false,
		),
		testutil.OCINetworkRequest(
			networkPath,
			"oci_vcn_delete_isolation_01",
			"oci-vcn-delete-isolation-01",
			"oci_subnet_delete_isolation_01",
			"oci-subnet-delete-isolation-01",
			"10.92.0.0/16",
			"10.92.1.0/24",
			"oci_igw_delete_isolation_01",
			"oci-igw-delete-isolation-01",
			"oci_rt_delete_isolation_01",
			"oci-rt-delete-isolation-01",
			true,
		),
		testutil.StorageRequest(
			"create",
			gcpPath,
			"bucket_delete_isolation_01",
			"stage2026-delete-isolation-01",
			"EU",
			"STANDARD",
			true,
		),
	}
	for _, request := range seedRequests {
		if err := generator.GenerateAtomically(request); err != nil {
			t.Fatalf("seed request failed: %v", err)
		}
	}
	otherBefore := []map[string][]byte{
		testutil.SnapshotTerraformFiles(t, computePath),
		testutil.SnapshotTerraformFiles(t, networkPath),
		testutil.SnapshotTerraformFiles(t, gcpPath),
	}

	if err := generator.GenerateAtomically(
		testutil.OCIStorageDeleteRequest(storagePath, targetName),
	); err != nil {
		t.Fatalf("OCI Storage Delete failed: %v", err)
	}

	storageAfter := testutil.SnapshotTerraformFiles(t, storagePath)
	for _, filename := range testutil.TerraformFilenames {
		content := string(storageAfter[filename])
		if strings.Contains(content, targetName) {
			t.Fatalf("%s still contains deleted bucket %s", filename, targetName)
		}
		if !strings.Contains(content, otherName) {
			t.Fatalf("%s lost independent bucket %s", filename, otherName)
		}
	}
	for index, path := range []string{computePath, networkPath, gcpPath} {
		testutil.AssertModuleFilesEqual(
			t,
			otherBefore[index],
			testutil.SnapshotTerraformFiles(t, path),
		)
	}

	updateOther := testutil.OCIStorageRequest(
		storagePath,
		otherName,
		"stage2026-oci-delete-b-01",
		"NoPublicAccess",
		"Archive",
		"Enabled",
		true,
	)
	updateOther.Action = "update"
	if err := generator.GenerateAtomically(updateOther); err != nil {
		t.Fatalf("OCI Storage Update after Delete failed: %v", err)
	}
	if err := generator.GenerateAtomically(testutil.OCIStorageRequest(
		storagePath,
		"oci_bucket_after_delete_01",
		"stage2026-oci-after-delete-01",
		"NoPublicAccess",
		"Standard",
		"Enabled",
		true,
	)); err != nil {
		t.Fatalf("OCI Storage Create after Delete failed: %v", err)
	}
}

func TestOCIStorageDeleteMissingBucketIsAtomic(t *testing.T) {
	modulePath := createStorageDeleteFixture(t)
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	err := generator.GenerateAtomically(testutil.OCIStorageDeleteRequest(
		modulePath,
		"oci_bucket_inexistant_999",
	))
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

func TestOCIStorageDeleteMissingVariableWarnsAndContinues(t *testing.T) {
	modulePath := createStorageDeleteFixture(t)
	files, err := common.LoadExistingTerraformFiles(modulePath)
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	missingName := "oci_bucket_delete_test_01_versioning"
	common.RemoveBlocks(files.Variables, func(block *hclwrite.Block) bool {
		return block.Type() == "variable" &&
			len(block.Labels()) == 1 &&
			block.Labels()[0] == missingName
	})
	if err := os.WriteFile(
		filepath.Join(modulePath, "variables.tf"),
		common.FormattedBytes(files.Variables),
		0644,
	); err != nil {
		t.Fatalf("write incomplete fixture: %v", err)
	}

	output, deleteErr := captureStdout(t, func() error {
		return generator.GenerateAtomically(
			testutil.OCIStorageDeleteRequest(
				modulePath,
				"oci_bucket_delete_test_01",
			),
		)
	})
	if deleteErr != nil {
		t.Fatalf("Delete with missing variable failed: %v", deleteErr)
	}
	if !strings.Contains(
		output,
		"Avertissement OCI Storage : variable absente : "+missingName,
	) {
		t.Fatalf("missing-variable warning not emitted:\n%s", output)
	}
	for filename, content := range testutil.SnapshotTerraformFiles(
		t,
		modulePath,
	) {
		if strings.Contains(string(content), "oci_bucket_delete_test_01") {
			t.Fatalf("%s still contains the deleted bucket", filename)
		}
	}
}

func TestOCIStorageDeleteBlocksInternalDependency(t *testing.T) {
	modulePath := createStorageDeleteFixture(t)
	files, err := common.LoadExistingTerraformFiles(modulePath)
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	dependent := hclwrite.NewBlock(
		"resource",
		[]string{"oci_objectstorage_replication_policy", "dependent_01"},
	)
	dependent.Body().SetAttributeTraversal(
		"bucket_id",
		common.ResourceTraversal(
			"oci_objectstorage_bucket",
			"oci_bucket_delete_test_01",
			"id",
		),
	)
	common.AppendBlock(files.Main, dependent)
	if err := os.WriteFile(
		filepath.Join(modulePath, "main.tf"),
		common.FormattedBytes(files.Main),
		0644,
	); err != nil {
		t.Fatalf("write dependency fixture: %v", err)
	}
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	err = generator.GenerateAtomically(testutil.OCIStorageDeleteRequest(
		modulePath,
		"oci_bucket_delete_test_01",
	))
	expected := "Cannot delete OCI Storage resource " +
		"oci_bucket_delete_test_01: referenced by another OCI Storage block"
	if err == nil || err.Error() != expected {
		t.Fatalf("unexpected dependency error: %v", err)
	}
	testutil.AssertTerraformFilesEqual(
		t,
		before,
		testutil.SnapshotTerraformFiles(t, modulePath),
	)
}

func TestOCIStorageDeleteChecksCertainCrossModuleDependencies(t *testing.T) {
	tests := []struct {
		name         string
		addReference func(*hclwrite.Body)
		blocked      bool
	}{
		{
			name: "explicit traversal",
			addReference: func(body *hclwrite.Body) {
				body.SetAttributeTraversal(
					"bucket_id",
					common.ResourceTraversal(
						"oci_objectstorage_bucket",
						"oci_bucket_delete_test_01",
						"id",
					),
				)
			},
			blocked: true,
		},
		{
			name: "module output traversal",
			addReference: func(body *hclwrite.Body) {
				body.SetAttributeTraversal(
					"bucket_id",
					common.ResourceTraversal(
						"module",
						"storage",
						"oci_bucket_delete_test_01_id",
					),
				)
			},
			blocked: true,
		},
		{
			name: "ambiguous string literal",
			addReference: func(body *hclwrite.Body) {
				body.SetAttributeValue(
					"description",
					cty.StringVal(
						"oci_objectstorage_bucket."+
							"oci_bucket_delete_test_01.id",
					),
				)
			},
			blocked: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modulePath := createStorageDeleteFixture(t)
			computePath := filepath.Join(
				filepath.Dir(modulePath),
				"compute",
			)
			if err := os.MkdirAll(computePath, 0755); err != nil {
				t.Fatalf("create compute fixture: %v", err)
			}
			file := hclwrite.NewEmptyFile()
			block := hclwrite.NewBlock(
				"resource",
				[]string{"test_consumer", "bucket_consumer_01"},
			)
			test.addReference(block.Body())
			common.AppendBlock(file, block)
			if err := os.WriteFile(
				filepath.Join(computePath, "main.tf"),
				common.FormattedBytes(file),
				0644,
			); err != nil {
				t.Fatalf("write compute fixture: %v", err)
			}
			before := testutil.SnapshotTerraformFiles(t, modulePath)

			err := generator.GenerateAtomically(
				testutil.OCIStorageDeleteRequest(
					modulePath,
					"oci_bucket_delete_test_01",
				),
			)
			if test.blocked {
				expected := "Cannot delete OCI Storage resource " +
					"oci_bucket_delete_test_01: referenced by another OCI module"
				if err == nil || err.Error() != expected {
					t.Fatalf("unexpected cross-module error: %v", err)
				}
				testutil.AssertTerraformFilesEqual(
					t,
					before,
					testutil.SnapshotTerraformFiles(t, modulePath),
				)
				return
			}
			if err != nil {
				t.Fatalf("ambiguous literal caused false dependency: %v", err)
			}
		})
	}
}

func createStorageDeleteFixture(t *testing.T) string {
	t.Helper()
	modulePath := storageModulePath(t)
	if err := generator.GenerateAtomically(testutil.OCIStorageRequest(
		modulePath,
		"oci_bucket_delete_test_01",
		"stage2026-oci-delete-test-01",
		"NoPublicAccess",
		"Standard",
		"Enabled",
		false,
	)); err != nil {
		t.Fatalf("OCI Storage Create fixture failed: %v", err)
	}
	return modulePath
}

func captureStdout(
	t *testing.T,
	action func() error,
) (string, error) {
	t.Helper()
	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	os.Stdout = writer
	defer func() {
		os.Stdout = original
	}()

	actionErr := action()
	if err := writer.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	content, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close stdout reader: %v", err)
	}
	return string(content), actionErr
}
