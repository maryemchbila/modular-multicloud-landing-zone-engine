package iam_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hcl-generator/generator"
	"hcl-generator/generator/internal/testutil"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

func TestIAMCreateAddsMultipleAccountsAndRejectsDuplicate(t *testing.T) {
	root := t.TempDir()
	modulePath := filepath.Join(root, "generated", "gcp", "modules", "iam")
	writeSiblingSentinels(t, filepath.Dir(modulePath))

	first := iamRequest(
		modulePath,
		"sa_logging_01",
		"sa-logging-01",
		"Service Account Logging 01",
		"Compte de service pour l'ecriture des journaux",
		"roles/logging.logWriter",
	)
	if err := generator.GenerateAtomically(first); err != nil {
		t.Fatalf("first IAM Create failed: %v", err)
	}

	assertValidIAMFiles(t, modulePath)
	firstFiles := testutil.SnapshotTerraformFiles(t, modulePath)
	assertIAMResource(t, firstFiles, first.IAMResource)

	second := iamRequest(
		modulePath,
		"sa_monitoring_01",
		"sa-monitoring-01",
		"Service Account Monitoring 01",
		"Compte de service pour les metriques de monitoring",
		"roles/monitoring.metricWriter",
	)
	if err := generator.GenerateAtomically(second); err != nil {
		t.Fatalf("second IAM Create failed: %v", err)
	}

	secondFiles := testutil.SnapshotTerraformFiles(t, modulePath)
	assertIAMResource(t, secondFiles, first.IAMResource)
	assertIAMResource(t, secondFiles, second.IAMResource)
	beforeDuplicate := cloneSnapshot(secondFiles)

	err := generator.GenerateAtomically(first)
	if err == nil || !strings.Contains(err.Error(), "doublon iam") {
		t.Fatalf("unexpected duplicate result: %v", err)
	}
	afterDuplicate := testutil.SnapshotTerraformFiles(t, modulePath)
	for _, filename := range testutil.TerraformFilenames {
		if !bytes.Equal(beforeDuplicate[filename], afterDuplicate[filename]) {
			t.Fatalf("%s changed after duplicate IAM Create", filename)
		}
	}

	assertSiblingSentinels(t, filepath.Dir(modulePath))
}

func TestIAMCreateAllowsTargetedStorageViewerRole(t *testing.T) {
	modulePath := filepath.Join(t.TempDir(), "generated", "gcp", "modules", "iam")
	request := iamRequest(
		modulePath,
		"sa_storage_viewer_01",
		"sa-storage-viewer-01",
		"Service Account Storage Viewer",
		"Compte de service en lecture seule sur le stockage",
		"roles/storage.objectViewer",
	)

	if err := generator.GenerateAtomically(request); err != nil {
		t.Fatalf("targeted IAM role was rejected: %v", err)
	}
	assertIAMResource(
		t,
		testutil.SnapshotTerraformFiles(t, modulePath),
		request.IAMResource,
	)
}

func iamRequest(
	modulePath string,
	resourceName string,
	accountID string,
	displayName string,
	description string,
	role string,
) *models.Request {
	return &models.Request{
		Action:     "create",
		Provider:   "gcp",
		Module:     "iam",
		ModulePath: modulePath,
		ProjectID:  "example-test-project",
		IAMResource: &models.IAMRequest{
			ResourceName: resourceName,
			AccountID:    accountID,
			DisplayName:  displayName,
			Description:  description,
			ProjectID:    "example-test-project",
			Role:         role,
		},
	}
}

func assertValidIAMFiles(t *testing.T, modulePath string) {
	t.Helper()
	for _, filename := range testutil.TerraformFilenames {
		content, err := os.ReadFile(testutil.TerraformFilePath(modulePath, filename))
		if err != nil {
			t.Fatalf("read %s: %v", filename, err)
		}
		_, diagnostics := hclwrite.ParseConfig(
			content,
			filename,
			hcl.InitialPos,
		)
		if diagnostics.HasErrors() {
			t.Fatalf("%s is invalid HCL: %s", filename, diagnostics.Error())
		}
	}
}

func assertIAMResource(
	t *testing.T,
	files map[string][]byte,
	resource *models.IAMRequest,
) {
	t.Helper()
	mainContent := string(files["main.tf"])
	variablesContent := string(files["variables.tf"])
	tfvarsContent := string(files["terraform.tfvars"])
	outputsContent := string(files["outputs.tf"])

	for _, expected := range []string{
		`resource "google_service_account" "` + resource.ResourceName + `"`,
		`resource "google_project_iam_member" "` + resource.ResourceName + `_role"`,
		"account_id   = var." + resource.ResourceName + "_account_id",
		"display_name = var." + resource.ResourceName + "_display_name",
		"description  = var." + resource.ResourceName + "_description",
		"project      = var." + resource.ResourceName + "_project_id",
		"role    = var." + resource.ResourceName + "_role",
		`member  = "serviceAccount:${google_service_account.` +
			resource.ResourceName + `.email}"`,
	} {
		if !strings.Contains(mainContent, expected) {
			t.Fatalf("main.tf is missing %q", expected)
		}
	}

	for _, name := range []string{
		resource.ResourceName + "_account_id",
		resource.ResourceName + "_display_name",
		resource.ResourceName + "_description",
		resource.ResourceName + "_project_id",
		resource.ResourceName + "_role",
	} {
		if strings.Count(variablesContent, `variable "`+name+`"`) != 1 {
			t.Fatalf("variable %q is missing or duplicated", name)
		}
		if strings.Count(tfvarsContent, name) != 1 {
			t.Fatalf("tfvars %q is missing or duplicated", name)
		}
	}

	for _, name := range []string{
		resource.ResourceName + "_email",
		resource.ResourceName + "_name",
		resource.ResourceName + "_unique_id",
	} {
		if strings.Count(outputsContent, `output "`+name+`"`) != 1 {
			t.Fatalf("output %q is missing or duplicated", name)
		}
	}
}

func cloneSnapshot(source map[string][]byte) map[string][]byte {
	result := make(map[string][]byte, len(source))
	for filename, content := range source {
		result[filename] = bytes.Clone(content)
	}
	return result
}

func writeSiblingSentinels(t *testing.T, generatedPath string) {
	t.Helper()
	for _, module := range []string{"compute", "network", "storage"} {
		path := filepath.Join(generatedPath, module)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("create %s: %v", path, err)
		}
		if err := os.WriteFile(
			filepath.Join(path, "sentinel.txt"),
			[]byte(module+"-unchanged"),
			0o644,
		); err != nil {
			t.Fatalf("write sentinel for %s: %v", module, err)
		}
	}
}

func assertSiblingSentinels(t *testing.T, generatedPath string) {
	t.Helper()
	for _, module := range []string{"compute", "network", "storage"} {
		content, err := os.ReadFile(
			filepath.Join(generatedPath, module, "sentinel.txt"),
		)
		if err != nil {
			t.Fatalf("read sentinel for %s: %v", module, err)
		}
		if string(content) != module+"-unchanged" {
			t.Fatalf("%s sibling was modified", module)
		}
	}
}
