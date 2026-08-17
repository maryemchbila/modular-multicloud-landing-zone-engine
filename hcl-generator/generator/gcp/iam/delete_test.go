package iam_test

import (
	"bytes"
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

func TestIAMDeleteRemovesOnlyTargetIdentity(t *testing.T) {
	modulePath := filepath.Join(t.TempDir(), "generated", "gcp", "modules", "iam")
	for _, request := range []*models.Request{
		iamRequest(
			modulePath,
			"sa_delete_a_01",
			"sa-delete-a-01",
			"Service Account Delete A",
			"Compte temporaire A",
			"roles/logging.logWriter",
		),
		iamRequest(
			modulePath,
			"sa_delete_b_01",
			"sa-delete-b-01",
			"Service Account Delete B",
			"Compte temporaire B",
			"roles/monitoring.metricWriter",
		),
	} {
		if err := generator.GenerateAtomically(request); err != nil {
			t.Fatalf("IAM Create failed: %v", err)
		}
	}

	if err := generator.GenerateAtomically(
		deleteIAMRequest(modulePath, "sa_delete_a_01")); err != nil {
		t.Fatalf("IAM Delete failed: %v", err)
	}

	files := testutil.SnapshotTerraformFiles(t, modulePath)
	for _, filename := range testutil.TerraformFilenames {
		content := string(files[filename])
		if strings.Contains(content, "sa_delete_a_01") {
			t.Fatalf("%s still contains deleted identity", filename)
		}
		if !strings.Contains(content, "sa_delete_b_01") {
			t.Fatalf("%s no longer contains independent identity", filename)
		}
	}
	assertIAMBlockCounts(t, files["main.tf"], "sa_delete_b_01")
}

func TestIAMDeleteMissingResourcesDoNotModifyFiles(t *testing.T) {
	modulePath := filepath.Join(t.TempDir(), "generated", "gcp", "modules", "iam")
	create := iamRequest(
		modulePath,
		"sa_delete_test_01",
		"sa-delete-test-01",
		"Service Account Delete Test",
		"Compte temporaire",
		"roles/logging.logWriter",
	)
	if err := generator.GenerateAtomically(create); err != nil {
		t.Fatalf("IAM Create failed: %v", err)
	}

	t.Run("service account", func(t *testing.T) {
		before := testutil.SnapshotTerraformFiles(t, modulePath)
		err := generator.GenerateAtomically(
			deleteIAMRequest(modulePath, "sa_inexistant_999"))

		if err == nil ||
			err.Error() != "IAM service account not found: sa_inexistant_999" {
			t.Fatalf("unexpected error: %v", err)
		}
		assertTerraformSnapshotEqual(t, before, modulePath)
	})

	t.Run("role binding", func(t *testing.T) {
		files, err := common.LoadExistingTerraformFiles(modulePath)
		if err != nil {
			t.Fatalf("load fixture: %v", err)
		}
		binding := common.FindBlock(
			files.Main,
			"resource",
			"google_project_iam_member",
			"sa_delete_test_01_role",
		)
		if binding == nil {
			t.Fatal("fixture binding not found")
		}
		files.Main.Body().RemoveBlock(binding)
		writeIAMFixtureFile(t, modulePath, "main.tf", files.Main)

		before := testutil.SnapshotTerraformFiles(t, modulePath)
		err = generator.GenerateAtomically(
			deleteIAMRequest(modulePath, "sa_delete_test_01"))

		if err == nil ||
			err.Error() !=
				"IAM role binding not found: sa_delete_test_01_role" {
			t.Fatalf("unexpected error: %v", err)
		}
		assertTerraformSnapshotEqual(t, before, modulePath)
	})
}

func TestIAMDeleteRejectsMismatchedBinding(t *testing.T) {
	modulePath := filepath.Join(t.TempDir(), "generated", "gcp", "modules", "iam")
	for _, name := range []string{"sa_delete_a_01", "sa_delete_b_01"} {
		create := iamRequest(
			modulePath,
			name,
			strings.ReplaceAll(name, "_", "-"),
			name,
			"Compte temporaire",
			"roles/logging.logWriter",
		)
		if err := generator.GenerateAtomically(create); err != nil {
			t.Fatalf("IAM Create failed: %v", err)
		}
	}

	mainPath := filepath.Join(modulePath, "main.tf")
	mainContent, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatalf("read main.tf: %v", err)
	}
	mainContent = bytes.Replace(
		mainContent,
		[]byte("google_service_account.sa_delete_a_01.email"),
		[]byte("google_service_account.sa_delete_b_01.email"),
		1,
	)
	if err := os.WriteFile(mainPath, mainContent, 0o644); err != nil {
		t.Fatalf("write main.tf: %v", err)
	}

	before := testutil.SnapshotTerraformFiles(t, modulePath)
	err = generator.GenerateAtomically(
		deleteIAMRequest(modulePath, "sa_delete_a_01"))

	expected := "IAM role binding sa_delete_a_01_role is not linked to " +
		"service account sa_delete_a_01"
	if err == nil || err.Error() != expected {
		t.Fatalf("unexpected error: %v", err)
	}
	assertTerraformSnapshotEqual(t, before, modulePath)
}

func TestIAMDeleteBlocksInternalDependency(t *testing.T) {
	modulePath := filepath.Join(t.TempDir(), "generated", "gcp", "modules", "iam")
	create := iamRequest(
		modulePath,
		"sa_delete_test_01",
		"sa-delete-test-01",
		"Service Account Delete Test",
		"Compte temporaire",
		"roles/logging.logWriter",
	)
	if err := generator.GenerateAtomically(create); err != nil {
		t.Fatalf("IAM Create failed: %v", err)
	}

	files, err := common.LoadExistingTerraformFiles(modulePath)
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	dependent := hclwrite.NewBlock(
		"resource",
		[]string{"test_iam_consumer", "dependent"},
	)
	dependent.Body().SetAttributeTraversal(
		"service_account_email",
		common.ResourceTraversal(
			"google_service_account",
			"sa_delete_test_01",
			"email",
		),
	)
	common.AppendBlock(files.Main, dependent)
	writeIAMFixtureFile(t, modulePath, "main.tf", files.Main)

	before := testutil.SnapshotTerraformFiles(t, modulePath)
	err = generator.GenerateAtomically(
		deleteIAMRequest(modulePath, "sa_delete_test_01"))

	expected := "Cannot delete IAM resource sa_delete_test_01: " +
		"referenced by another block"
	if err == nil || err.Error() != expected {
		t.Fatalf("unexpected error: %v", err)
	}
	assertTerraformSnapshotEqual(t, before, modulePath)
}

func TestIAMDeleteBlocksCertainCrossModuleDependencies(t *testing.T) {
	tests := []struct {
		name       string
		addContent func(*hclwrite.Block)
	}{
		{
			name: "traversal",
			addContent: func(block *hclwrite.Block) {
				block.Body().SetAttributeTraversal(
					"service_account_email",
					common.ResourceTraversal(
						"google_service_account",
						"sa_delete_test_01",
						"email",
					),
				)
			},
		},
		{
			name: "literal identity",
			addContent: func(block *hclwrite.Block) {
				block.Body().SetAttributeValue(
					"service_account_email",
					cty.StringVal(
						"sa-delete-test-01@example-test-project."+
							"iam.gserviceaccount.com",
					),
				)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			modulePath := filepath.Join(root, "generated", "gcp", "modules", "iam")
			create := iamRequest(
				modulePath,
				"sa_delete_test_01",
				"sa-delete-test-01",
				"Service Account Delete Test",
				"Compte temporaire",
				"roles/logging.logWriter",
			)
			if err := generator.GenerateAtomically(create); err != nil {
				t.Fatalf("IAM Create failed: %v", err)
			}

			computePath := filepath.Join(root, "generated", "gcp", "modules", "compute")
			if err := os.MkdirAll(computePath, 0o755); err != nil {
				t.Fatalf("create compute fixture: %v", err)
			}
			computeFile := hclwrite.NewEmptyFile()
			consumer := hclwrite.NewBlock(
				"resource",
				[]string{"test_compute_consumer", "dependent"},
			)
			test.addContent(consumer)
			common.AppendBlock(computeFile, consumer)
			computeMainPath := filepath.Join(computePath, "main.tf")
			if err := os.WriteFile(
				computeMainPath,
				common.FormattedBytes(computeFile),
				0o644,
			); err != nil {
				t.Fatalf("write compute fixture: %v", err)
			}
			computeBefore, err := os.ReadFile(computeMainPath)
			if err != nil {
				t.Fatalf("read compute fixture: %v", err)
			}

			before := testutil.SnapshotTerraformFiles(t, modulePath)
			err = generator.GenerateAtomically(
				deleteIAMRequest(modulePath, "sa_delete_test_01"))

			expected := "Cannot delete IAM resource sa_delete_test_01: " +
				"referenced by another module"
			if err == nil || err.Error() != expected {
				t.Fatalf("unexpected error: %v", err)
			}
			assertTerraformSnapshotEqual(t, before, modulePath)
			computeAfter, err := os.ReadFile(computeMainPath)
			if err != nil {
				t.Fatalf("read compute fixture: %v", err)
			}
			if !bytes.Equal(computeBefore, computeAfter) {
				t.Fatal("cross-module dependency file was modified")
			}
		})
	}
}

func deleteIAMRequest(
	modulePath string,
	resourceName string,
) *models.Request {
	return &models.Request{
		Action:     "delete",
		Provider:   "gcp",
		Module:     "iam",
		ModulePath: modulePath,
		ProjectID:  "example-test-project",
		IAMResource: &models.IAMRequest{
			ResourceName: resourceName,
		},
	}
}

func writeIAMFixtureFile(
	t *testing.T,
	modulePath string,
	filename string,
	file *hclwrite.File,
) {
	t.Helper()
	if err := os.WriteFile(
		testutil.TerraformFilePath(modulePath, filename),
		common.FormattedBytes(file),
		0o644,
	); err != nil {
		t.Fatalf("write %s: %v", filename, err)
	}
}
