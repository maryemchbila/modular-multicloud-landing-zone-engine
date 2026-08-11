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

func TestResolveModulePathAcceptsOnlyCanonicalLayout(t *testing.T) {
	root := t.TempDir()
	legacy := filepath.Join(root, "generated", "gcp", "compute")
	canonical := filepath.Join(root, "generated", "gcp", "modules", "compute")

	if _, err := rootmodule.ResolveModulePath(legacy, "gcp", "compute"); err == nil {
		t.Fatal("legacy path was accepted")
	}
	canonicalLayout, err := rootmodule.ResolveModulePath(canonical, "gcp", "compute")
	if err != nil {
		t.Fatalf("canonical path rejected: layout=%+v err=%v", canonicalLayout, err)
	}
	if canonicalLayout.ProviderRoot != filepath.Join(root, "generated", "gcp") {
		t.Fatalf("unexpected provider root: %s", canonicalLayout.ProviderRoot)
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
