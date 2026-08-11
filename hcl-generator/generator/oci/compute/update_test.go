package compute_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"hcl-generator/generator"
	"hcl-generator/generator/common"
	"hcl-generator/generator/internal/testutil"
)

func TestOCIComputeUpdateFinalValuesAndStableFiles(t *testing.T) {
	modulePath := testutil.CanonicalModulePath(t, "oci", "compute")
	create := testutil.OCIComputeRequest(
		modulePath,
		"oci_vm_test_01",
		"oci-vm-test-01",
		false,
	)
	if err := generator.GenerateAtomically(create); err != nil {
		t.Fatalf("create fixture: %v", err)
	}

	beforeShape := testutil.SnapshotTerraformFiles(t, modulePath)
	update := testutil.OCIComputeActionRequest(
		"update",
		modulePath,
		"oci_vm_test_01",
		"oci-vm-test-01",
		false,
	)
	update.OCIComputeResource.Shape = "VM.Standard.E5.Flex"
	if err := generator.GenerateAtomically(update); err != nil {
		t.Fatalf("shape update: %v", err)
	}

	afterShape := testutil.SnapshotTerraformFiles(t, modulePath)
	assertOnlyTfvarsChanged(t, beforeShape, afterShape)
	assertSingleTfvar(
		t,
		afterShape["terraform.tfvars"],
		"oci_vm_test_01_shape",
		`"VM.Standard.E5.Flex"`,
	)

	beforeDisplayName := afterShape
	update.OCIComputeResource.DisplayName = "oci-vm-production-01"
	if err := generator.GenerateAtomically(update); err != nil {
		t.Fatalf("display_name update: %v", err)
	}

	afterDisplayName := testutil.SnapshotTerraformFiles(t, modulePath)
	assertOnlyTfvarsChanged(t, beforeDisplayName, afterDisplayName)
	assertSingleTfvar(
		t,
		afterDisplayName["terraform.tfvars"],
		"oci_vm_test_01_display_name",
		`"oci-vm-production-01"`,
	)

	beforePublicIP := afterDisplayName
	assignPublicIP := true
	update.OCIComputeResource.AssignPublicIP = &assignPublicIP
	if err := generator.GenerateAtomically(update); err != nil {
		t.Fatalf("public IP update: %v", err)
	}

	afterPublicIP := testutil.SnapshotTerraformFiles(t, modulePath)
	assertOnlyTfvarsChanged(t, beforePublicIP, afterPublicIP)
	assertSingleTfvar(
		t,
		afterPublicIP["terraform.tfvars"],
		"oci_vm_test_01_assign_public_ip",
		"true",
	)
	if strings.Contains(
		string(afterPublicIP["terraform.tfvars"]),
		`oci_vm_test_01_assign_public_ip = "true"`,
	) {
		t.Fatal("assign_public_ip was serialized as a string")
	}

	mainContent := string(afterPublicIP["main.tf"])
	if count := strings.Count(
		mainContent,
		`resource "oci_core_instance" "oci_vm_test_01"`,
	); count != 1 {
		t.Fatalf("OCI instance count = %d, want 1", count)
	}
	for _, reference := range []string{
		"availability_domain = var.oci_vm_test_01_availability_domain",
		"compartment_id      = var.oci_vm_test_01_compartment_id",
		"display_name        = var.oci_vm_test_01_display_name",
		"shape               = var.oci_vm_test_01_shape",
		"subnet_id        = var.oci_vm_test_01_subnet_id",
		"assign_public_ip = var.oci_vm_test_01_assign_public_ip",
		"source_id   = var.oci_vm_test_01_image_id",
	} {
		if !strings.Contains(mainContent, reference) {
			t.Fatalf("main.tf lost reference %q", reference)
		}
	}
}

func TestOCIComputeUpdateMissingResourceDoesNotModifyFiles(t *testing.T) {
	modulePath := testutil.CanonicalModulePath(t, "oci", "compute")
	create := testutil.OCIComputeRequest(
		modulePath,
		"oci_vm_test_01",
		"oci-vm-test-01",
		false,
	)
	if err := generator.GenerateAtomically(create); err != nil {
		t.Fatalf("create fixture: %v", err)
	}
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	update := testutil.OCIComputeActionRequest(
		"update",
		modulePath,
		"oci_vm_inexistante_999",
		"unused",
		false,
	)
	err := generator.GenerateAtomically(update)
	if err == nil ||
		err.Error() != "OCI Compute resource not found: oci_vm_inexistante_999" {
		t.Fatalf("unexpected error: %v", err)
	}

	after := testutil.SnapshotTerraformFiles(t, modulePath)
	for _, filename := range testutil.TerraformFilenames {
		if !bytes.Equal(before[filename], after[filename]) {
			t.Fatalf("%s changed after missing-resource update", filename)
		}
	}
}

func TestOCIComputeUpdateRequiresExistingVariablesAndTfvars(t *testing.T) {
	tests := []struct {
		name       string
		removeFrom string
		removeName string
		expected   string
	}{
		{
			name:       "variable",
			removeFrom: "variables.tf",
			removeName: "oci_vm_test_01_shape",
			expected:   "OCI Compute variable missing or duplicated",
		},
		{
			name:       "tfvar",
			removeFrom: "terraform.tfvars",
			removeName: "oci_vm_test_01_shape",
			expected:   "OCI Compute tfvar not found",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modulePath := testutil.CanonicalModulePath(t, "oci", "compute")
			create := testutil.OCIComputeRequest(
				modulePath,
				"oci_vm_test_01",
				"oci-vm-test-01",
				false,
			)
			if err := generator.GenerateAtomically(create); err != nil {
				t.Fatalf("create fixture: %v", err)
			}
			removeTerraformElement(
				t,
				modulePath,
				test.removeFrom,
				test.removeName,
			)
			before := testutil.SnapshotTerraformFiles(t, modulePath)

			update := testutil.OCIComputeActionRequest(
				"update",
				modulePath,
				"oci_vm_test_01",
				"oci-vm-production-01",
				false,
			)
			err := generator.GenerateAtomically(update)
			if err == nil || !strings.Contains(err.Error(), test.expected) {
				t.Fatalf("unexpected error: %v", err)
			}

			after := testutil.SnapshotTerraformFiles(t, modulePath)
			for _, filename := range testutil.TerraformFilenames {
				if !bytes.Equal(before[filename], after[filename]) {
					t.Fatalf("%s changed after integrity error", filename)
				}
			}
		})
	}
}

func removeTerraformElement(
	t *testing.T,
	modulePath string,
	filename string,
	name string,
) {
	t.Helper()
	path := testutil.TerraformFilePath(modulePath, filename)
	file, err := common.LoadExistingFile(path)
	if err != nil {
		t.Fatalf("load %s: %v", filename, err)
	}
	if filename == "variables.tf" {
		for _, block := range file.Body().Blocks() {
			if block.Type() == "variable" &&
				len(block.Labels()) == 1 &&
				block.Labels()[0] == name {
				file.Body().RemoveBlock(block)
				break
			}
		}
	} else {
		file.Body().RemoveAttribute(name)
	}
	if err := os.WriteFile(path, common.FormattedBytes(file), 0o644); err != nil {
		t.Fatalf("write %s: %v", filename, err)
	}
}

func assertOnlyTfvarsChanged(
	t *testing.T,
	before map[string][]byte,
	after map[string][]byte,
) {
	t.Helper()
	for _, filename := range []string{"main.tf", "variables.tf", "outputs.tf"} {
		if !bytes.Equal(before[filename], after[filename]) {
			t.Fatalf("%s changed during a normal OCI Compute Update", filename)
		}
	}
	if bytes.Equal(before["terraform.tfvars"], after["terraform.tfvars"]) {
		t.Fatal("terraform.tfvars did not change")
	}
}

func assertSingleTfvar(
	t *testing.T,
	content []byte,
	name string,
	value string,
) {
	t.Helper()
	text := string(content)
	if count := strings.Count(text, name); count != 1 {
		t.Fatalf("%s count = %d, want 1", name, count)
	}
	lineFound := false
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 &&
			fields[0] == name &&
			fields[1] == "=" &&
			fields[2] == value {
			lineFound = true
			break
		}
	}
	if !lineFound {
		t.Fatalf("%s does not have value %s", name, value)
	}
}
