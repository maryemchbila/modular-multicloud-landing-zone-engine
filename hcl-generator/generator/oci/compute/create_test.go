package compute_test

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"hcl-generator/generator"
	"hcl-generator/generator/internal/testutil"
	"hcl-generator/models"
)

func TestOCIComputeCreateAndDuplicateRollback(t *testing.T) {
	modulePath := filepath.Join(
		t.TempDir(),
		"generated",
		"oci",
		"modules",
		"compute",
	)
	request := testutil.OCIComputeRequest(
		modulePath,
		"oci_vm_test_01",
		"oci-vm-test-01",
		false)

	if err := generator.GenerateAtomically(request); err != nil {
		t.Fatalf("OCI Compute Create failed: %v", err)
	}

	files := testutil.SnapshotTerraformFiles(t, modulePath)
	mainContent := string(files["main.tf"])
	variablesContent := string(files["variables.tf"])
	tfvarsContent := string(files["terraform.tfvars"])
	outputsContent := string(files["outputs.tf"])

	expectedMainFragments := []string{
		`resource "oci_core_instance" "oci_vm_test_01"`,
		"availability_domain = var.oci_vm_test_01_availability_domain",
		"compartment_id      = var.oci_vm_test_01_compartment_id",
		"display_name        = var.oci_vm_test_01_display_name",
		"shape               = var.oci_vm_test_01_shape",
		"create_vnic_details {",
		"subnet_id        = var.oci_vm_test_01_subnet_id",
		"assign_public_ip = var.oci_vm_test_01_assign_public_ip",
		"source_details {",
		`source_type = "image"`,
		"source_id   = var.oci_vm_test_01_image_id",
	}
	for _, fragment := range expectedMainFragments {
		if !strings.Contains(mainContent, fragment) {
			t.Fatalf("main.tf is missing %q", fragment)
		}
	}

	for _, suffix := range []string{
		"display_name",
		"availability_domain",
		"compartment_id",
		"shape",
		"subnet_id",
		"image_id",
		"assign_public_ip",
	} {
		name := "oci_vm_test_01_" + suffix
		if !strings.Contains(
			variablesContent,
			`variable "`+name+`"`,
		) {
			t.Fatalf("variables.tf is missing %q", name)
		}
		if !strings.Contains(tfvarsContent, name) {
			t.Fatalf("terraform.tfvars is missing %q", name)
		}
	}
	if !strings.Contains(
		variablesContent,
		"oci_vm_test_01_assign_public_ip",
	) || !strings.Contains(variablesContent, "type        = bool") {
		t.Fatal("assign_public_ip is not declared as bool")
	}
	if !regexp.MustCompile(
		`(?m)^oci_vm_test_01_assign_public_ip\s+= false$`,
	).MatchString(tfvarsContent) {
		t.Fatal("assign_public_ip is not an unquoted false boolean")
	}

	for _, suffix := range []string{
		"id",
		"display_name",
		"private_ip",
		"public_ip",
	} {
		name := "oci_vm_test_01_" + suffix
		if !strings.Contains(outputsContent, `output "`+name+`"`) {
			t.Fatalf("outputs.tf is missing %q", name)
		}
		if !strings.Contains(
			outputsContent,
			"oci_core_instance.oci_vm_test_01."+suffix,
		) {
			t.Fatalf("output %q does not use a resource traversal", name)
		}
	}

	beforeDuplicate := files
	err := generator.GenerateAtomically(request)
	if err == nil || !strings.Contains(err.Error(), "doublon OCI compute") {
		t.Fatalf("duplicate returned unexpected error: %v", err)
	}
	afterDuplicate := testutil.SnapshotTerraformFiles(t, modulePath)
	for _, filename := range testutil.TerraformFilenames {
		if !bytes.Equal(
			beforeDuplicate[filename],
			afterDuplicate[filename],
		) {
			t.Fatalf("%s changed after duplicate OCI Create", filename)
		}
	}
}

func TestOCIComputeCreateKeepsIndependentInstance(t *testing.T) {
	modulePath := filepath.Join(
		t.TempDir(),
		"generated",
		"oci",
		"modules",
		"compute",
	)
	for _, request := range []*models.Request{
		testutil.OCIComputeRequest(
			modulePath,
			"oci_vm_test_01",
			"oci-vm-test-01",
			false),

		testutil.OCIComputeRequest(
			modulePath,
			"oci_vm_backend_01",
			"oci-vm-backend-01",
			true),
	} {
		if err := generator.GenerateAtomically(request); err != nil {
			t.Fatalf("OCI Compute Create failed: %v", err)
		}
	}

	files := testutil.SnapshotTerraformFiles(t, modulePath)
	for _, filename := range testutil.TerraformFilenames {
		content := string(files[filename])
		for _, name := range []string{
			"oci_vm_test_01",
			"oci_vm_backend_01",
		} {
			if !strings.Contains(content, name) {
				t.Fatalf("%s is missing %s", filename, name)
			}
		}
	}
	if !regexp.MustCompile(
		`(?m)^oci_vm_backend_01_assign_public_ip\s+= true$`,
	).Match(files["terraform.tfvars"]) {
		t.Fatal("second instance public-IP boolean is not true")
	}
	if strings.Contains(string(files["main.tf"]), "google_compute_instance") {
		t.Fatal("OCI request was routed to the GCP generator")
	}
}

func TestGCPAndOCIComputeOutputsAreIsolated(t *testing.T) {
	root := t.TempDir()
	gcpPath := filepath.Join(root, "generated", "gcp", "modules", "compute")
	ociPath := filepath.Join(root, "generated", "oci", "modules", "compute")

	if err := generator.GenerateAtomically(testutil.OCIComputeRequest(
		ociPath,
		"oci_vm_test_01",
		"oci-vm-test-01",
		false)); err != nil {
		t.Fatalf("OCI Compute Create failed: %v", err)
	}
	ociBeforeGCP := testutil.SnapshotTerraformFiles(t, ociPath)

	if err := generator.GenerateAtomically(testutil.ComputeRequest(
		"create",
		gcpPath,
		"vm_gcp_test_01",
		"vm-gcp-test-01",
		"e2-medium")); err != nil {
		t.Fatalf("GCP Compute Create failed: %v", err)
	}
	testutil.AssertTerraformFilesEqual(
		t,
		ociBeforeGCP,
		testutil.SnapshotTerraformFiles(t, ociPath))

	gcpBeforeOCI := testutil.SnapshotTerraformFiles(t, gcpPath)
	if err := generator.GenerateAtomically(testutil.OCIComputeRequest(
		ociPath,
		"oci_vm_backend_01",
		"oci-vm-backend-01",
		true)); err != nil {
		t.Fatalf("second OCI Compute Create failed: %v", err)
	}
	testutil.AssertTerraformFilesEqual(
		t,
		gcpBeforeOCI,
		testutil.SnapshotTerraformFiles(t, gcpPath))

}
