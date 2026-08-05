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

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

func TestIAMUpdateDisplayNameOnly(t *testing.T) {
	modulePath := filepath.Join(t.TempDir(), "generated", "gcp", "iam")
	create := iamRequest(
		modulePath,
		"sa_logging_01",
		"sa-logging-01",
		"Service Account Logging 01",
		"Compte de service pour l'écriture des journaux",
		"roles/logging.logWriter",
	)
	if err := generator.GenerateAtomically(create); err != nil {
		t.Fatalf("IAM Create failed: %v", err)
	}

	before := testutil.SnapshotTerraformFiles(t, modulePath)
	update := iamRequest(
		modulePath,
		"sa_logging_01",
		"sa-logging-01",
		"Service Account Logging Production",
		"Compte de service pour l'écriture des journaux",
		"roles/logging.logWriter",
	)
	update.Action = "update"
	if err := generator.GenerateAtomically(update); err != nil {
		t.Fatalf("IAM Update failed: %v", err)
	}

	after := testutil.SnapshotTerraformFiles(t, modulePath)
	assertOnlyIAMTfvarChanged(
		t,
		before,
		after,
		"sa_logging_01_display_name",
		`"Service Account Logging Production"`,
	)
	assertIAMBlockCounts(t, after["main.tf"], "sa_logging_01")
}

func TestIAMUpdateRoleOnly(t *testing.T) {
	modulePath := filepath.Join(t.TempDir(), "generated", "gcp", "iam")
	create := iamRequest(
		modulePath,
		"sa_storage_viewer_01",
		"sa-storage-viewer-01",
		"Service Account Storage Viewer",
		"Compte de service en lecture sur le stockage",
		"roles/storage.objectViewer",
	)
	if err := generator.GenerateAtomically(create); err != nil {
		t.Fatalf("IAM Create failed: %v", err)
	}

	before := testutil.SnapshotTerraformFiles(t, modulePath)
	update := iamRequest(
		modulePath,
		"sa_storage_viewer_01",
		"sa-storage-viewer-01",
		"Service Account Storage Viewer",
		"Compte de service en lecture sur le stockage",
		"roles/storage.objectCreator",
	)
	update.Action = "update"
	if err := generator.GenerateAtomically(update); err != nil {
		t.Fatalf("IAM Update failed: %v", err)
	}

	after := testutil.SnapshotTerraformFiles(t, modulePath)
	assertOnlyIAMTfvarChanged(
		t,
		before,
		after,
		"sa_storage_viewer_01_role",
		`"roles/storage.objectCreator"`,
	)
	assertIAMBlockCounts(t, after["main.tf"], "sa_storage_viewer_01")
}

func TestIAMUpdateDescriptionOnly(t *testing.T) {
	modulePath := filepath.Join(t.TempDir(), "generated", "gcp", "iam")
	create := iamRequest(
		modulePath,
		"sa_monitoring_01",
		"sa-monitoring-01",
		"Service Account Monitoring 01",
		"Compte de service pour les métriques",
		"roles/monitoring.metricWriter",
	)
	if err := generator.GenerateAtomically(create); err != nil {
		t.Fatalf("IAM Create failed: %v", err)
	}

	before := testutil.SnapshotTerraformFiles(t, modulePath)
	update := iamRequest(
		modulePath,
		"sa_monitoring_01",
		"sa-monitoring-01",
		"Service Account Monitoring 01",
		"Compte de service de production pour les métriques",
		"roles/monitoring.metricWriter",
	)
	update.Action = "update"
	if err := generator.GenerateAtomically(update); err != nil {
		t.Fatalf("IAM Update failed: %v", err)
	}

	after := testutil.SnapshotTerraformFiles(t, modulePath)
	assertOnlyIAMTfvarChanged(
		t,
		before,
		after,
		"sa_monitoring_01_description",
		`"Compte de service de production pour les métriques"`,
	)
}

func TestIAMUpdateMissingResourcesDoNotModifyFiles(t *testing.T) {
	modulePath := filepath.Join(t.TempDir(), "generated", "gcp", "iam")
	create := iamRequest(
		modulePath,
		"sa_logging_01",
		"sa-logging-01",
		"Service Account Logging 01",
		"Compte de service pour les journaux",
		"roles/logging.logWriter",
	)
	if err := generator.GenerateAtomically(create); err != nil {
		t.Fatalf("IAM Create failed: %v", err)
	}

	t.Run("service account", func(t *testing.T) {
		before := testutil.SnapshotTerraformFiles(t, modulePath)
		update := iamRequest(
			modulePath,
			"sa_inexistant_999",
			"sa-inexistant-999",
			"Service Account Inexistant",
			"Test",
			"roles/logging.logWriter",
		)
		update.Action = "update"
		err := generator.GenerateAtomically(update)
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
			"sa_logging_01_role",
		)
		if binding == nil {
			t.Fatal("fixture role binding not found")
		}
		files.Main.Body().RemoveBlock(binding)
		if err := os.WriteFile(
			filepath.Join(modulePath, "main.tf"),
			common.FormattedBytes(files.Main),
			0o644,
		); err != nil {
			t.Fatalf("write fixture: %v", err)
		}

		before := testutil.SnapshotTerraformFiles(t, modulePath)
		update := iamRequest(
			modulePath,
			"sa_logging_01",
			"sa-logging-01",
			"Service Account Logging Production",
			"Compte de service pour les journaux",
			"roles/logging.logWriter",
		)
		update.Action = "update"
		err = generator.GenerateAtomically(update)
		if err == nil ||
			err.Error() != "IAM role binding not found: sa_logging_01_role" {
			t.Fatalf("unexpected error: %v", err)
		}
		assertTerraformSnapshotEqual(t, before, modulePath)
	})
}

func TestIAMUpdateMissingDefinitionsDoNotModifyFiles(t *testing.T) {
	tests := []struct {
		name          string
		remove        func(*common.TerraformFiles)
		filename      string
		expectedError string
	}{
		{
			name: "variable",
			remove: func(files *common.TerraformFiles) {
				block := common.FindBlock(
					files.Variables,
					"variable",
					"sa_logging_01_display_name",
				)
				files.Variables.Body().RemoveBlock(block)
			},
			filename: "variables.tf",
			expectedError: "IAM variable not found: " +
				"sa_logging_01_display_name",
		},
		{
			name: "tfvars",
			remove: func(files *common.TerraformFiles) {
				files.Tfvars.Body().RemoveAttribute(
					"sa_logging_01_description",
				)
			},
			filename: "terraform.tfvars",
			expectedError: "IAM tfvars value not found: " +
				"sa_logging_01_description",
		},
		{
			name: "output",
			remove: func(files *common.TerraformFiles) {
				block := common.FindBlock(
					files.Outputs,
					"output",
					"sa_logging_01_unique_id",
				)
				files.Outputs.Body().RemoveBlock(block)
			},
			filename: "outputs.tf",
			expectedError: "IAM output not found: " +
				"sa_logging_01_unique_id",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modulePath := filepath.Join(
				t.TempDir(),
				"generated",
				"gcp",
				"iam",
			)
			create := iamRequest(
				modulePath,
				"sa_logging_01",
				"sa-logging-01",
				"Service Account Logging 01",
				"Compte de service pour les journaux",
				"roles/logging.logWriter",
			)
			if err := generator.GenerateAtomically(create); err != nil {
				t.Fatalf("IAM Create failed: %v", err)
			}

			files, err := common.LoadExistingTerraformFiles(modulePath)
			if err != nil {
				t.Fatalf("load fixture: %v", err)
			}
			test.remove(files)
			var content []byte
			switch test.filename {
			case "variables.tf":
				content = common.FormattedBytes(files.Variables)
			case "terraform.tfvars":
				content = common.FormattedBytes(files.Tfvars)
			case "outputs.tf":
				content = common.FormattedBytes(files.Outputs)
			default:
				t.Fatalf("unexpected fixture filename: %s", test.filename)
			}
			if err := os.WriteFile(
				filepath.Join(modulePath, test.filename),
				content,
				0o644,
			); err != nil {
				t.Fatalf("write fixture: %v", err)
			}

			before := testutil.SnapshotTerraformFiles(t, modulePath)
			update := iamRequest(
				modulePath,
				"sa_logging_01",
				"sa-logging-01",
				"Service Account Logging Production",
				"Compte de service pour les journaux",
				"roles/logging.logWriter",
			)
			update.Action = "update"
			err = generator.GenerateAtomically(update)
			if err == nil || err.Error() != test.expectedError {
				t.Fatalf("unexpected error: %v", err)
			}
			assertTerraformSnapshotEqual(t, before, modulePath)
		})
	}
}

func assertOnlyIAMTfvarChanged(
	t *testing.T,
	before map[string][]byte,
	after map[string][]byte,
	expectedName string,
	expectedValue string,
) {
	t.Helper()
	for _, filename := range []string{"main.tf", "variables.tf", "outputs.tf"} {
		if !bytes.Equal(before[filename], after[filename]) {
			t.Fatalf("%s changed during IAM Update", filename)
		}
	}
	if bytes.Equal(before["terraform.tfvars"], after["terraform.tfvars"]) {
		t.Fatal("terraform.tfvars did not change during IAM Update")
	}

	beforeValues := terraformAttributeValues(t, before["terraform.tfvars"])
	afterValues := terraformAttributeValues(t, after["terraform.tfvars"])
	for name, beforeValue := range beforeValues {
		afterValue, exists := afterValues[name]
		if !exists {
			t.Fatalf("tfvars value %q was removed", name)
		}
		if name == expectedName {
			if afterValue != expectedValue {
				t.Fatalf("%s = %s, want %s", name, afterValue, expectedValue)
			}
			continue
		}
		if beforeValue != afterValue {
			t.Fatalf("unexpected tfvars change for %s", name)
		}
	}
	if len(beforeValues) != len(afterValues) {
		t.Fatalf(
			"tfvars attribute count changed from %d to %d",
			len(beforeValues),
			len(afterValues),
		)
	}
}

func terraformAttributeValues(
	t *testing.T,
	content []byte,
) map[string]string {
	t.Helper()
	file, diagnostics := hclwrite.ParseConfig(
		content,
		"terraform.tfvars",
		hcl.InitialPos,
	)
	if diagnostics.HasErrors() {
		t.Fatalf("parse terraform.tfvars: %s", diagnostics.Error())
	}
	values := make(map[string]string)
	for name, attribute := range file.Body().Attributes() {
		values[name] = strings.TrimSpace(
			string(attribute.Expr().BuildTokens(nil).Bytes()),
		)
	}
	return values
}

func assertIAMBlockCounts(
	t *testing.T,
	mainContent []byte,
	resourceName string,
) {
	t.Helper()
	content := string(mainContent)
	if count := strings.Count(
		content,
		`resource "google_service_account" "`+resourceName+`"`,
	); count != 1 {
		t.Fatalf("service account block count = %d, want 1", count)
	}
	if count := strings.Count(
		content,
		`resource "google_project_iam_member" "`+resourceName+`_role"`,
	); count != 1 {
		t.Fatalf("role binding block count = %d, want 1", count)
	}
}

func assertTerraformSnapshotEqual(
	t *testing.T,
	before map[string][]byte,
	modulePath string,
) {
	t.Helper()
	after := testutil.SnapshotTerraformFiles(t, modulePath)
	for _, filename := range testutil.TerraformFilenames {
		if !bytes.Equal(before[filename], after[filename]) {
			t.Fatalf("%s changed after failed IAM Update", filename)
		}
	}
}
