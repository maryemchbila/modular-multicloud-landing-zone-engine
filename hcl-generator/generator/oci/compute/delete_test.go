package compute_test

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
	"github.com/zclconf/go-cty/cty"
)

var ociComputeVariableSuffixes = []string{
	"display_name",
	"availability_domain",
	"compartment_id",
	"shape",
	"subnet_id",
	"image_id",
	"assign_public_ip",
}

var ociComputeOutputSuffixes = []string{
	"id",
	"display_name",
	"private_ip",
	"public_ip",
}

func TestOCIComputeDeleteExistingResourceKeepsIndependentInstance(
	t *testing.T,
) {
	modulePath := ociComputeModulePath(t)
	createOCIComputeFixture(t, modulePath, "oci_vm_delete_a_01")
	createOCIComputeFixture(t, modulePath, "oci_vm_delete_b_01")
	gcpModulePath := filepath.Join(
		filepath.Dir(filepath.Dir(filepath.Dir(modulePath))),
		"gcp",
		"modules",
		"compute",
	)
	gcpCreate := testutil.ComputeRequest(
		"create",
		gcpModulePath,
		"vm_gcp_untouched_01",
		"vm-gcp-untouched-01",
		"e2-medium",
	)
	if err := generator.GenerateAtomically(gcpCreate); err != nil {
		t.Fatalf("create GCP isolation fixture: %v", err)
	}
	gcpBefore := testutil.SnapshotTerraformFiles(t, gcpModulePath)

	request := testutil.OCIComputeDeleteRequest(
		modulePath,
		"oci_vm_delete_a_01",
	)
	if err := generator.GenerateAtomically(request); err != nil {
		t.Fatalf("delete OCI Compute: %v", err)
	}

	files := testutil.SnapshotTerraformFiles(t, modulePath)
	assertOCIComputeInstanceAbsent(t, files, "oci_vm_delete_a_01")
	assertOCIComputeInstancePresent(t, files, "oci_vm_delete_b_01")
	testutil.AssertTerraformFilesEqual(
		t,
		gcpBefore,
		testutil.SnapshotTerraformFiles(t, gcpModulePath),
	)
}

func TestOCIComputeDeleteMissingResourceDoesNotModifyFiles(t *testing.T) {
	modulePath := ociComputeModulePath(t)
	createOCIComputeFixture(t, modulePath, "oci_vm_delete_test_01")
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	request := testutil.OCIComputeDeleteRequest(
		modulePath,
		"oci_vm_inexistante_999",
	)
	err := generator.GenerateAtomically(request)
	if err == nil ||
		err.Error() != "OCI Compute resource not found: oci_vm_inexistante_999" {
		t.Fatalf("unexpected error: %v", err)
	}

	testutil.AssertTerraformFilesEqual(
		t,
		before,
		testutil.SnapshotTerraformFiles(t, modulePath),
	)
}

func TestOCIComputeDeleteBlocksInternalDependency(t *testing.T) {
	modulePath := ociComputeModulePath(t)
	resourceName := "oci_vm_delete_test_01"
	createOCIComputeFixture(t, modulePath, resourceName)

	mainPath := filepath.Join(modulePath, "main.tf")
	mainFile, err := common.LoadExistingFile(mainPath)
	if err != nil {
		t.Fatalf("load main.tf: %v", err)
	}
	dependent := hclwrite.NewBlock(
		"resource",
		[]string{"test_consumer", "dependent"},
	)
	dependent.Body().SetAttributeTraversal(
		"instance_id",
		common.ResourceTraversal(
			"oci_core_instance",
			resourceName,
			"id",
		),
	)
	common.AppendBlock(mainFile, dependent)
	writeHCLFile(t, mainPath, mainFile)
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	request := testutil.OCIComputeDeleteRequest(modulePath, resourceName)
	err = generator.GenerateAtomically(request)
	expected := "Cannot delete OCI Compute resource " + resourceName +
		": referenced by another block"
	if err == nil || err.Error() != expected {
		t.Fatalf("unexpected dependency error: %v", err)
	}
	testutil.AssertTerraformFilesEqual(
		t,
		before,
		testutil.SnapshotTerraformFiles(t, modulePath),
	)
}

func TestOCIComputeDeleteBlocksCertainCrossModuleDependencies(t *testing.T) {
	tests := []struct {
		name      string
		traversal hcl.Traversal
	}{
		{
			name: "direct resource traversal",
			traversal: common.ResourceTraversal(
				"oci_core_instance",
				"oci_vm_delete_test_01",
				"id",
			),
		},
		{
			name: "known output traversal",
			traversal: hcl.Traversal{
				hcl.TraverseRoot{Name: "module"},
				hcl.TraverseAttr{Name: "compute"},
				hcl.TraverseAttr{
					Name: "oci_vm_delete_test_01_id",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modulePath := ociComputeModulePath(t)
			resourceName := "oci_vm_delete_test_01"
			createOCIComputeFixture(t, modulePath, resourceName)
			writeOCIModuleDependency(
				t,
				filepath.Join(
					filepath.Dir(modulePath),
					"network",
					"main.tf",
				),
				test.traversal,
			)
			before := testutil.SnapshotTerraformFiles(t, modulePath)

			request := testutil.OCIComputeDeleteRequest(
				modulePath,
				resourceName,
			)
			err := generator.GenerateAtomically(request)
			expected := "Cannot delete OCI Compute resource " +
				resourceName + ": referenced by another OCI module"
			if err == nil || err.Error() != expected {
				t.Fatalf("unexpected dependency error: %v", err)
			}
			testutil.AssertTerraformFilesEqual(
				t,
				before,
				testutil.SnapshotTerraformFiles(t, modulePath),
			)
		})
	}
}

func TestOCIComputeDeleteAvoidsStringLiteralFalsePositive(t *testing.T) {
	modulePath := ociComputeModulePath(t)
	resourceName := "oci_vm_delete_test_01"
	createOCIComputeFixture(t, modulePath, resourceName)

	mainPath := filepath.Join(modulePath, "main.tf")
	mainFile, err := common.LoadExistingFile(mainPath)
	if err != nil {
		t.Fatalf("load main.tf: %v", err)
	}
	consumer := hclwrite.NewBlock("locals", nil)
	consumer.Body().SetAttributeValue(
		"documentation",
		cty.StringVal("oci_core_instance."+resourceName+".id"),
	)
	common.AppendBlock(mainFile, consumer)
	writeHCLFile(t, mainPath, mainFile)

	request := testutil.OCIComputeDeleteRequest(modulePath, resourceName)
	if err := generator.GenerateAtomically(request); err != nil {
		t.Fatalf("string literal caused a false dependency: %v", err)
	}
	files := testutil.SnapshotTerraformFiles(t, modulePath)
	assertOCIComputeInstanceAbsent(t, files, resourceName)
	if !strings.Contains(
		string(files["main.tf"]),
		"oci_core_instance."+resourceName+".id",
	) {
		t.Fatal("unrelated string literal was removed")
	}
}

func TestOCIComputeDeleteToleratesMissingExpectedVariable(t *testing.T) {
	modulePath := ociComputeModulePath(t)
	resourceName := "oci_vm_delete_test_01"
	createOCIComputeFixture(t, modulePath, resourceName)

	variablesPath := filepath.Join(modulePath, "variables.tf")
	variablesFile, err := common.LoadExistingFile(variablesPath)
	if err != nil {
		t.Fatalf("load variables.tf: %v", err)
	}
	common.RemoveBlocks(variablesFile, func(block *hclwrite.Block) bool {
		return block.Type() == "variable" &&
			len(block.Labels()) == 1 &&
			block.Labels()[0] == resourceName+"_shape"
	})
	writeHCLFile(t, variablesPath, variablesFile)

	request := testutil.OCIComputeDeleteRequest(modulePath, resourceName)
	if err := generator.GenerateAtomically(request); err != nil {
		t.Fatalf("delete with missing variable: %v", err)
	}
	assertOCIComputeInstanceAbsent(
		t,
		testutil.SnapshotTerraformFiles(t, modulePath),
		resourceName,
	)
}

func ociComputeModulePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(
		t.TempDir(),
		"generated",
		"oci",
		"modules",
		"compute",
	)
}

func createOCIComputeFixture(
	t *testing.T,
	modulePath string,
	resourceName string,
) {
	t.Helper()
	request := testutil.OCIComputeRequest(
		modulePath,
		resourceName,
		strings.ReplaceAll(resourceName, "_", "-"),
		false,
	)
	if err := generator.GenerateAtomically(request); err != nil {
		t.Fatalf("create fixture %s: %v", resourceName, err)
	}
}

func writeOCIModuleDependency(
	t *testing.T,
	path string,
	traversal hcl.Traversal,
) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create OCI module directory: %v", err)
	}
	file := hclwrite.NewEmptyFile()
	output := hclwrite.NewBlock("output", []string{"consumer"})
	output.Body().SetAttributeTraversal("value", traversal)
	common.AppendBlock(file, output)
	writeHCLFile(t, path, file)
}

func writeHCLFile(t *testing.T, path string, file *hclwrite.File) {
	t.Helper()
	if err := os.WriteFile(path, common.FormattedBytes(file), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func assertOCIComputeInstanceAbsent(
	t *testing.T,
	files map[string][]byte,
	resourceName string,
) {
	t.Helper()
	if strings.Contains(
		string(files["main.tf"]),
		`resource "oci_core_instance" "`+resourceName+`"`,
	) {
		t.Fatal("target OCI Compute resource remains in main.tf")
	}
	for _, suffix := range ociComputeVariableSuffixes {
		name := resourceName + "_" + suffix
		if strings.Contains(string(files["variables.tf"]), `"`+name+`"`) {
			t.Fatalf("target variable %s remains", name)
		}
		if strings.Contains(string(files["terraform.tfvars"]), name) {
			t.Fatalf("target tfvar %s remains", name)
		}
	}
	for _, suffix := range ociComputeOutputSuffixes {
		name := resourceName + "_" + suffix
		if strings.Contains(string(files["outputs.tf"]), `"`+name+`"`) {
			t.Fatalf("target output %s remains", name)
		}
	}
}

func assertOCIComputeInstancePresent(
	t *testing.T,
	files map[string][]byte,
	resourceName string,
) {
	t.Helper()
	if count := bytes.Count(
		files["main.tf"],
		[]byte(`resource "oci_core_instance" "`+resourceName+`"`),
	); count != 1 {
		t.Fatalf("independent OCI resource count = %d, want 1", count)
	}
	for _, suffix := range ociComputeVariableSuffixes {
		name := resourceName + "_" + suffix
		if !strings.Contains(string(files["variables.tf"]), `"`+name+`"`) {
			t.Fatalf("independent variable %s was removed", name)
		}
		if !strings.Contains(string(files["terraform.tfvars"]), name) {
			t.Fatalf("independent tfvar %s was removed", name)
		}
	}
	for _, suffix := range ociComputeOutputSuffixes {
		name := resourceName + "_" + suffix
		if !strings.Contains(string(files["outputs.tf"]), `"`+name+`"`) {
			t.Fatalf("independent output %s was removed", name)
		}
	}
}
