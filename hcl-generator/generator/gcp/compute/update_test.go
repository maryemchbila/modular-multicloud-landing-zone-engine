package compute_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"hcl-generator/generator"
	"hcl-generator/generator/internal/testutil"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

func TestComputeUpdateExistingResource(t *testing.T) {
	modulePath := testutil.CanonicalModulePath(t, "gcp", "compute")
	writeLegacyComputeFixture(t, modulePath)

	beforeFirst := testutil.SnapshotTerraformFiles(t, modulePath)
	update := testutil.ComputeRequest(
		"update",
		modulePath,
		"vm_clean_test_01",
		"vm-clean-test-01",
		"e2-standard-2")

	if err := generator.GenerateAtomically(update); err != nil {
		t.Fatalf("first update failed: %v", err)
	}

	afterFirst := testutil.SnapshotTerraformFiles(t, modulePath)
	mainContent := string(afterFirst["main.tf"])
	tfvarsContent := string(afterFirst["terraform.tfvars"])

	if count := strings.Count(
		mainContent,
		`resource "google_compute_instance" "vm_clean_test_01"`,
	); count != 1 {
		t.Fatalf("target resource count = %d, want 1", count)
	}
	if !strings.Contains(mainContent, "machine_type = var.vm_clean_test_01_machine_type") {
		t.Fatal("target machine_type does not use its resource-scoped variable")
	}
	if !strings.Contains(mainContent, "machine_type = var.machine_type") {
		t.Fatal("the untouched legacy VM no longer uses its original variable")
	}
	if !strings.Contains(
		tfvarsContent,
		`vm_clean_test_01_machine_type = "e2-standard-2"`,
	) {
		t.Fatal("updated machine type is missing from terraform.tfvars")
	}
	if !strings.Contains(tfvarsContent, `"e2-medium"`) {
		t.Fatal("legacy machine type for the other VM was modified")
	}
	if !bytes.Equal(beforeFirst["outputs.tf"], afterFirst["outputs.tf"]) {
		t.Fatal("outputs.tf changed during Compute Update")
	}

	beforeSecond := afterFirst
	update.ComputeResource.Name = "vm-clean-prod-01"
	update.ComputeResource.MachineType = "e2-standard-4"
	if err := generator.GenerateAtomically(update); err != nil {
		t.Fatalf("second update failed: %v", err)
	}

	afterSecond := testutil.SnapshotTerraformFiles(t, modulePath)
	for _, filename := range []string{"main.tf", "variables.tf", "outputs.tf"} {
		if !bytes.Equal(beforeSecond[filename], afterSecond[filename]) {
			t.Fatalf("%s changed during a normal second update", filename)
		}
	}
	secondTfvars := string(afterSecond["terraform.tfvars"])
	secondVariables := string(afterSecond["variables.tf"])
	if !strings.Contains(secondTfvars, `vm_clean_test_01_name         = "vm-clean-prod-01"`) {
		t.Fatal("updated VM name is missing from terraform.tfvars")
	}
	if !strings.Contains(
		secondTfvars,
		`vm_clean_test_01_machine_type = "e2-standard-4"`,
	) {
		t.Fatal("second machine type is missing from terraform.tfvars")
	}
	if count := strings.Count(
		secondTfvars,
		"vm_clean_test_01_machine_type",
	); count != 1 {
		t.Fatalf("machine_type tfvars count = %d, want 1", count)
	}
	if count := strings.Count(
		secondVariables,
		`variable "vm_clean_test_01_machine_type"`,
	); count != 1 {
		t.Fatalf("machine_type variable count = %d, want 1", count)
	}
}

func TestComputeUpdateWritesReplacesAndPreservesRootProjectID(t *testing.T) {
	modulePath := testutil.CanonicalModulePath(t, "gcp", "compute")
	writeLegacyComputeFixture(t, modulePath)

	request := testutil.ComputeRequest(
		"update",
		modulePath,
		"vm_clean_test_01",
		"vm-clean-test-01",
		"e2-standard-2",
	)
	request.ProjectID = "stage2026-multicloud-01"

	if err := generator.GenerateAtomically(request); err != nil {
		t.Fatalf("Compute Update failed: %v", err)
	}

	firstTfvars := testutil.SnapshotTerraformFiles(t, modulePath)["terraform.tfvars"]
	assertTfvarsStringValue(
		t,
		firstTfvars,
		"gcp_project_id",
		"stage2026-multicloud-01",
	)
	assertTfvarsStringValue(t, firstTfvars, "existing_setting", "preserve-me")
	assertTfvarsKeyCount(t, string(firstTfvars), "gcp_project_id", 1)

	request.ProjectID = "stage2026-multicloud-02"
	if err := generator.GenerateAtomically(request); err != nil {
		t.Fatalf("second Compute Update failed: %v", err)
	}

	secondTfvars := testutil.SnapshotTerraformFiles(t, modulePath)["terraform.tfvars"]
	assertTfvarsStringValue(
		t,
		secondTfvars,
		"gcp_project_id",
		"stage2026-multicloud-02",
	)
	assertTfvarsStringValue(t, secondTfvars, "existing_setting", "preserve-me")
	assertTfvarsKeyCount(t, string(secondTfvars), "gcp_project_id", 1)
	if strings.Contains(string(secondTfvars), "stage2026-multicloud-01") {
		t.Fatal("old gcp_project_id value remains after Update")
	}
}

func TestComputeUpdateMissingResourceDoesNotModifyFiles(t *testing.T) {
	modulePath := testutil.CanonicalModulePath(t, "gcp", "compute")
	writeLegacyComputeFixture(t, modulePath)
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	request := testutil.ComputeRequest(
		"update",
		modulePath,
		"vm_inexistante_999",
		"unused",
		"e2-standard-2")

	err := generator.GenerateAtomically(request)
	if err == nil || err.Error() != "Compute resource not found: vm_inexistante_999" {
		t.Fatalf("unexpected error: %v", err)
	}

	after := testutil.SnapshotTerraformFiles(t, modulePath)
	for _, filename := range testutil.TerraformFilenames {
		if !bytes.Equal(before[filename], after[filename]) {
			t.Fatalf("%s changed after a missing-resource update", filename)
		}
	}
}

func TestComputeUpdateRemovesLegacyVariablesAfterLastReference(t *testing.T) {
	modulePath := testutil.CanonicalModulePath(t, "gcp", "compute")
	writeLegacyComputeFixture(t, modulePath)

	for _, resourceName := range []string{"vm_other_01", "vm_clean_test_01"} {
		request := testutil.ComputeRequest(
			"update",
			modulePath,
			resourceName,
			resourceName,
			"e2-medium")

		if err := generator.GenerateAtomically(request); err != nil {
			t.Fatalf("update %s failed: %v", resourceName, err)
		}
	}

	files := testutil.SnapshotTerraformFiles(t, modulePath)
	mainContent := string(files["main.tf"])
	variablesContent := string(files["variables.tf"])
	legacyNames := []string{"name", "machine_type", "zone", "image", "network"}

	for _, name := range legacyNames {
		if strings.Contains(mainContent, "var."+name) {
			t.Fatalf("legacy traversal var.%s remains in main.tf", name)
		}
		if strings.Contains(variablesContent, `variable "`+name+`"`) {
			t.Fatalf("legacy variable %q remains in variables.tf", name)
		}
	}

	tfvarsFile, diagnostics := hclwrite.ParseConfig(
		files["terraform.tfvars"],
		"terraform.tfvars",
		hcl.InitialPos,
	)
	if diagnostics.HasErrors() {
		t.Fatalf("parse terraform.tfvars: %s", diagnostics.Error())
	}
	for _, name := range legacyNames {
		if tfvarsFile.Body().GetAttribute(name) != nil {
			t.Fatalf("legacy tfvars key %q remains", name)
		}
	}
}

func writeLegacyComputeFixture(t *testing.T, modulePath string) {
	t.Helper()
	fixtures := map[string]string{
		"main.tf": `
resource "google_compute_instance" "vm_other_01" {
  name         = var.name
  machine_type = var.machine_type
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = var.image
    }
  }

  network_interface {
    network = var.network
  }
}

resource "google_compute_instance" "vm_clean_test_01" {
  name         = var.name
  machine_type = var.machine_type
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = var.image
    }
  }

  network_interface {
    network = var.network
  }
}
`,
		"variables.tf": `
variable "name" {
  type = string
}

variable "machine_type" {
  type = string
}

variable "zone" {
  type = string
}

variable "image" {
  type = string
}

variable "network" {
  type = string
}
`,
		"terraform.tfvars": `
gcp_project_id = "stage2026-old-project"
existing_setting = "preserve-me"
name         = "vm-other-01"
machine_type = "e2-medium"
zone         = "europe-west1-b"
image        = "debian-cloud/debian-12"
network      = "default"
`,
		"outputs.tf": `
output "instance_id" {
  value = google_compute_instance.vm_other_01.id
}
`,
	}

	for filename, content := range fixtures {
		formatted := hclwrite.Format([]byte(strings.TrimSpace(content) + "\n"))
		if err := os.WriteFile(
			testutil.TerraformFilePath(modulePath, filename),
			formatted,
			0o644,
		); err != nil {
			t.Fatalf("write %s: %v", filename, err)
		}
	}
}
