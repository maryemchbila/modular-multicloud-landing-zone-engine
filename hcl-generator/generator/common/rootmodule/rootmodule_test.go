package rootmodule_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hcl-generator/generator/common/rootmodule"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

func TestResolveModulePathSupportsLegacyAndCanonicalLayouts(t *testing.T) {
	root := t.TempDir()
	legacy := filepath.Join(root, "generated", "gcp", "compute")
	canonical := filepath.Join(root, "generated", "gcp", "modules", "compute")

	legacyLayout, err := rootmodule.ResolveModulePath(legacy, "gcp", "compute")
	if err != nil || !legacyLayout.Legacy {
		t.Fatalf("legacy path rejected: layout=%+v err=%v", legacyLayout, err)
	}
	canonicalLayout, err := rootmodule.ResolveModulePath(canonical, "gcp", "compute")
	if err != nil || canonicalLayout.Legacy {
		t.Fatalf("canonical path rejected: layout=%+v err=%v", canonicalLayout, err)
	}
	if legacyLayout.ProviderRoot != canonicalLayout.ProviderRoot {
		t.Fatal("the two layouts do not resolve to the same provider root")
	}
}

func TestPrepareRootModuleAddsOnlyUsefulModulesAndRealDependency(t *testing.T) {
	root := filepath.Join(t.TempDir(), "generated", "gcp")
	write(t, filepath.Join(root, "modules", "network", "main.tf"), `resource "google_compute_network" "vpc_app" {
  name = var.vpc_app_name
}
`)
	write(t, filepath.Join(root, "modules", "network", "variables.tf"), `variable "vpc_app_name" { type = string }
`)
	write(t, filepath.Join(root, "modules", "network", "terraform.tfvars"), `vpc_app_name = "app-network"
`)
	write(t, filepath.Join(root, "modules", "network", "outputs.tf"), `output "vpc_app_id" {
  value = google_compute_network.vpc_app.id
}
`)
	write(t, filepath.Join(root, "modules", "compute", "main.tf"), `resource "google_compute_instance" "vm_app" {
  name = "vm-app"
  network_interface { network = var.vm_app_network }
}
`)
	write(t, filepath.Join(root, "modules", "compute", "variables.tf"), `variable "vm_app_network" { type = string }
`)
	write(t, filepath.Join(root, "modules", "compute", "terraform.tfvars"), `vm_app_network = "app-network"
`)
	write(t, filepath.Join(root, "modules", "compute", "outputs.tf"), `output "vm_app_id" {
  value = google_compute_instance.vm_app.id
}
`)

	plan, err := rootmodule.PrepareRootModule(root, "gcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Report.HasConflicts() {
		t.Fatalf("unexpected conflicts: %v", plan.Report.Conflicts)
	}
	main := parse(t, plan.Prepared[filepath.Join(root, "main.tf")])
	if countBlock(main, "module", "network") != 1 ||
		countBlock(main, "module", "compute") != 1 {
		t.Fatal("useful modules were not added exactly once")
	}
	if countBlock(main, "module", "storage") != 0 ||
		countBlock(main, "module", "iam") != 0 {
		t.Fatal("empty modules must not be called")
	}
	compute := findBlock(main, "module", "compute")
	attribute := compute.Body().GetAttribute("vm_app_network")
	if attribute == nil || strings.TrimSpace(
		string(attribute.Expr().BuildTokens(nil).Bytes()),
	) != "module.network.vpc_app_id" {
		t.Fatal("Compute does not use the real Network module traversal")
	}
	if bytes.Contains(
		plan.Prepared[filepath.Join(root, "terraform.tfvars")],
		[]byte("vm_app_network"),
	) {
		t.Fatal("a value replaced by a module dependency was copied to root tfvars")
	}
}

func TestAnalyzeMigrationIsReadOnlyAndDoesNotExposeValues(t *testing.T) {
	root := filepath.Join(t.TempDir(), "generated", "gcp")
	legacy := filepath.Join(root, "storage")
	write(t, filepath.Join(legacy, "main.tf"), `resource "google_storage_bucket" "logs" {
  name = var.logs_name
}
`)
	write(t, filepath.Join(legacy, "variables.tf"), `variable "logs_name" { type = string }
variable "api_token" { type = string }
`)
	write(t, filepath.Join(legacy, "terraform.tfvars"), `logs_name = "value-that-must-not-appear"
api_token = "secret-that-must-not-appear"
`)
	write(t, filepath.Join(legacy, "outputs.tf"), `output "logs_id" {
  value = google_storage_bucket.logs.id
}
`)
	before := snapshot(t, root)
	plan, err := rootmodule.AnalyzeMigration(root, "gcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	var report bytes.Buffer
	plan.Report.WriteTo(&report)
	for _, forbidden := range []string{
		"value-that-must-not-appear", "secret-that-must-not-appear", "api_token",
	} {
		if strings.Contains(report.String(), forbidden) {
			t.Fatalf("dry-run exposed %q", forbidden)
		}
	}
	after := snapshot(t, root)
	assertSnapshot(t, before, after)
	if _, err := os.Stat(filepath.Join(root, "modules")); !os.IsNotExist(err) {
		t.Fatal("dry-run created the modules directory")
	}
}

func TestRootTfvarsCollisionIsReportedWithoutOverwrite(t *testing.T) {
	root := filepath.Join(t.TempDir(), "generated", "gcp")
	write(t, filepath.Join(root, "terraform.tfvars"), `shared_name = "root-value"
`)
	write(t, filepath.Join(root, "modules", "storage", "main.tf"), `resource "google_storage_bucket" "shared" { name = var.shared_name }
`)
	write(t, filepath.Join(root, "modules", "storage", "variables.tf"), `variable "shared_name" { type = string }
`)
	write(t, filepath.Join(root, "modules", "storage", "terraform.tfvars"), `shared_name = "module-value"
`)
	plan, err := rootmodule.PrepareRootModule(root, "gcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Report.HasConflicts() {
		t.Fatal("tfvars collision was not reported")
	}
	content := string(plan.Prepared[filepath.Join(root, "terraform.tfvars")])
	if !strings.Contains(content, `"root-value"`) || strings.Contains(content, `"module-value"`) {
		t.Fatalf("existing root value was overwritten: %s", content)
	}
}

func TestPrepareRootModuleRemovesStaleManagedDataAfterDelete(t *testing.T) {
	root := filepath.Join(t.TempDir(), "generated", "gcp")
	write(t, filepath.Join(root, "main.tf"), `module "storage" {
  source      = "./modules/storage"
  bucket_name = var.bucket_name
}
`)
	write(t, filepath.Join(root, "variables.tf"), `variable "bucket_name" { type = string }
`)
	write(t, filepath.Join(root, "terraform.tfvars"), `bucket_name = "fixture"
`)
	write(t, filepath.Join(root, "outputs.tf"), `output "bucket_id" {
  value = module.storage.bucket_id
}
`)

	plan, err := rootmodule.PrepareRootModule(root, "gcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"main.tf", "variables.tf", "terraform.tfvars", "outputs.tf"} {
		if len(bytes.TrimSpace(plan.Prepared[filepath.Join(root, name)])) != 0 {
			t.Fatalf("stale managed data remains in %s", name)
		}
	}
}

func TestRootModuleDependencyUsesTraversal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "generated", "gcp")
	modulePath := filepath.Join(root, "modules", "network")
	write(t, filepath.Join(root, "main.tf"), `module "network" {
  source = "./modules/network"
}
module "compute" {
  source  = "./modules/compute"
  network = module.network.vpc_backend_01_id
}
`)
	referenced, err := rootmodule.ModuleOutputsReferencedByAnotherModule(
		modulePath, "network", []string{"vpc_backend_01_id"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !referenced {
		t.Fatal("inter-module traversal was not detected")
	}
}

func TestPrepareFilteredMigrationKeepsFixturesInLegacyFiles(t *testing.T) {
	root := filepath.Join(t.TempDir(), "generated", "gcp")
	legacy := filepath.Join(root, "network")
	write(t, filepath.Join(legacy, "main.tf"), `resource "google_compute_network" "vpc_test_01" {
  name = var.vpc_test_01_name
}
resource "google_compute_network" "vpc_backend_01" {
  name = var.vpc_backend_01_name
}
`)
	write(t, filepath.Join(legacy, "variables.tf"), `variable "vpc_test_01_name" { type = string }
variable "vpc_backend_01_name" { type = string }
`)
	write(t, filepath.Join(legacy, "terraform.tfvars"), `vpc_test_01_name = "fixture"
vpc_backend_01_name = "backend"
`)
	write(t, filepath.Join(legacy, "outputs.tf"), `output "vpc_test_01_id" { value = google_compute_network.vpc_test_01.id }
output "vpc_backend_01_id" { value = google_compute_network.vpc_backend_01.id }
`)

	plan, err := rootmodule.PrepareFilteredMigration(root, "gcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Report.HasConflicts() {
		t.Fatalf("unexpected conflicts: %v", plan.Report.Conflicts)
	}
	legacyMain := string(plan.Prepared[filepath.Join(legacy, "main.tf")])
	canonicalMain := string(plan.Prepared[filepath.Join(root, "modules", "network", "main.tf")])
	if !strings.Contains(legacyMain, `"vpc_test_01"`) || strings.Contains(legacyMain, `"vpc_backend_01"`) {
		t.Fatalf("legacy partition is incorrect: %s", legacyMain)
	}
	if strings.Contains(canonicalMain, `"vpc_test_01"`) || !strings.Contains(canonicalMain, `"vpc_backend_01"`) {
		t.Fatalf("canonical partition is incorrect: %s", canonicalMain)
	}
	rootTfvars := string(plan.Prepared[filepath.Join(root, "terraform.tfvars")])
	legacyTfvars := string(plan.Prepared[filepath.Join(legacy, "terraform.tfvars")])
	if !strings.Contains(rootTfvars, "vpc_backend_01_name") || strings.Contains(rootTfvars, "vpc_test_01_name") {
		t.Fatalf("root tfvars partition is incorrect: %s", rootTfvars)
	}
	if !strings.Contains(legacyTfvars, "vpc_test_01_name") || strings.Contains(legacyTfvars, "vpc_backend_01_name") {
		t.Fatalf("legacy tfvars partition is incorrect: %s", legacyTfvars)
	}
}

func parse(t *testing.T, content []byte) *hclwrite.File {
	t.Helper()
	file, diagnostics := hclwrite.ParseConfig(content, "test.tf", hcl.InitialPos)
	if diagnostics.HasErrors() {
		t.Fatalf("invalid HCL: %s", diagnostics.Error())
	}
	return file
}

func countBlock(file *hclwrite.File, blockType, label string) int {
	count := 0
	for _, block := range file.Body().Blocks() {
		if block.Type() == blockType && len(block.Labels()) == 1 && block.Labels()[0] == label {
			count++
		}
	}
	return count
}

func findBlock(file *hclwrite.File, blockType, label string) *hclwrite.Block {
	for _, block := range file.Body().Blocks() {
		if block.Type() == blockType && len(block.Labels()) == 1 && block.Labels()[0] == label {
			return block
		}
	}
	return nil
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func snapshot(t *testing.T, root string) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			result[path] = content
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertSnapshot(t *testing.T, expected, actual map[string][]byte) {
	t.Helper()
	if len(expected) != len(actual) {
		t.Fatalf("snapshot size changed: %d != %d", len(expected), len(actual))
	}
	for path, content := range expected {
		if !bytes.Equal(content, actual[path]) {
			t.Fatalf("%s changed", path)
		}
	}
}
