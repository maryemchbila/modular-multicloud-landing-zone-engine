package compute_test

import (
	"bytes"
	"strings"
	"testing"

	"hcl-generator/generator"
	"hcl-generator/generator/internal/testutil"
)

func TestCreateCompute(t *testing.T) {
	modulePath := testutil.CanonicalModulePath(t, "gcp", "compute")
	request := testutil.ComputeRequest(
		"create",
		modulePath,
		"vm_create_test_01",
		"vm-create-test-01",
		"e2-medium",
	)
	request.ProjectID = "stage2026-multicloud-01"
	if err := generator.GenerateAtomically(request); err != nil {
		t.Fatalf("Compute Create failed: %v", err)
	}

	beforeDuplicate := testutil.SnapshotTerraformFiles(t, modulePath)
	mainContent := string(beforeDuplicate["main.tf"])
	variablesContent := string(beforeDuplicate["variables.tf"])
	tfvarsContent := string(beforeDuplicate["terraform.tfvars"])
	assertTfvarsStringValue(
		t,
		beforeDuplicate["terraform.tfvars"],
		"gcp_project_id",
		"stage2026-multicloud-01",
	)
	assertTfvarsKeyCount(t, tfvarsContent, "gcp_project_id", 1)
	for _, field := range []string{
		"name",
		"machine_type",
		"zone",
		"image",
		"network",
	} {
		scopedName := "vm_create_test_01_" + field
		if !strings.Contains(mainContent, "var."+scopedName) {
			t.Fatalf("main.tf is missing var.%s", scopedName)
		}
		if !strings.Contains(
			variablesContent,
			`variable "`+scopedName+`"`,
		) {
			t.Fatalf("variables.tf is missing %q", scopedName)
		}
		if !strings.Contains(tfvarsContent, scopedName) {
			t.Fatalf("terraform.tfvars is missing %q", scopedName)
		}
	}

	if err := generator.GenerateAtomically(request); err == nil {
		t.Fatal("duplicate Compute Create unexpectedly succeeded")
	}
	afterDuplicate := testutil.SnapshotTerraformFiles(t, modulePath)
	for _, filename := range testutil.TerraformFilenames {
		if !bytes.Equal(
			beforeDuplicate[filename],
			afterDuplicate[filename],
		) {
			t.Fatalf("%s changed after duplicate Compute Create", filename)
		}
	}
}
