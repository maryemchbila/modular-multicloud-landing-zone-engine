package iam_test

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"hcl-generator/generator"
	"hcl-generator/generator/common"
	"hcl-generator/generator/internal/testutil"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

func TestOCIIAMUpdateChangesOnlyRequestedTfvar(t *testing.T) {
	tests := []struct {
		name   string
		tfvar  string
		value  string
		mutate func(*models.OCIIAMRequest, string)
	}{
		{
			name:  "user description",
			tfvar: "oci_user_observability_01_description",
			value: "Utilisateur OCI de production pour l'observabilite",
			mutate: func(resource *models.OCIIAMRequest, value string) {
				resource.UserDescription = value
			},
		},
		{
			name:  "group description",
			tfvar: "oci_group_observability_01_description",
			value: "Groupe OCI de production pour l'observabilite",
			mutate: func(resource *models.OCIIAMRequest, value string) {
				resource.GroupDescription = value
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modulePath := seedObservabilityIAM(t)
			before := testutil.SnapshotTerraformFiles(t, modulePath)
			update := updateObservabilityRequest(modulePath)
			test.mutate(update.OCIIAMResource, test.value)

			if err := generator.GenerateAtomically(update); err != nil {
				t.Fatalf("OCI IAM Update failed: %v", err)
			}

			after := testutil.SnapshotTerraformFiles(t, modulePath)
			assertOnlyTfvarsChanged(t, before, after)
			tfvars := string(after["terraform.tfvars"])
			if !strings.Contains(tfvars, test.value) {
				t.Fatalf("updated tfvars does not contain %q", test.value)
			}
			pattern := regexp.MustCompile(
				`(?m)^` + regexp.QuoteMeta(test.tfvar) + `\s*=`,
			)
			if matches := pattern.FindAllString(tfvars, -1); len(matches) != 1 {
				t.Fatalf("%s appears %d times", test.tfvar, len(matches))
			}
		})
	}
}

func TestOCIIAMUpdateReplacesStatementList(t *testing.T) {
	modulePath := seedObservabilityIAM(t)
	before := testutil.SnapshotTerraformFiles(t, modulePath)
	update := updateObservabilityRequest(modulePath)
	update.OCIIAMResource.PolicyStatements = []string{
		"Allow group stage2026-observability-group to read metrics in compartment stage2026",
		"Allow group stage2026-observability-group to read log-groups in compartment stage2026",
	}

	if err := generator.GenerateAtomically(update); err != nil {
		t.Fatalf("OCI IAM Update failed: %v", err)
	}

	after := testutil.SnapshotTerraformFiles(t, modulePath)
	assertOnlyTfvarsChanged(t, before, after)
	tfvars := string(after["terraform.tfvars"])
	for _, statement := range update.OCIIAMResource.PolicyStatements {
		if !strings.Contains(tfvars, `"`+statement+`"`) {
			t.Fatalf("updated statement is missing: %s", statement)
		}
	}
	if strings.Contains(
		tfvars,
		`oci_policy_observability_01_statements = "[`,
	) {
		t.Fatal("policy statements were converted to a JSON string")
	}
	main := string(after["main.tf"])
	for _, resourceType := range []string{
		"oci_identity_group",
		"oci_identity_user",
		"oci_identity_user_group_membership",
		"oci_identity_policy",
	} {
		if count := strings.Count(
			main,
			`resource "`+resourceType+`"`,
		); count != 1 {
			t.Fatalf("%s appears %d times after Update", resourceType, count)
		}
	}
}

func TestOCIIAMUpdateChangesGroupNameWithoutChangingMembership(t *testing.T) {
	modulePath := seedObservabilityIAM(t)
	before := testutil.SnapshotTerraformFiles(t, modulePath)
	update := updateObservabilityRequest(modulePath)
	update.OCIIAMResource.GroupName =
		"stage2026-observability-group-prod"
	update.OCIIAMResource.PolicyStatements = []string{
		"Allow group stage2026-observability-group-prod to read metrics in compartment stage2026",
	}

	if err := generator.GenerateAtomically(update); err != nil {
		t.Fatalf("OCI IAM Update failed: %v", err)
	}

	after := testutil.SnapshotTerraformFiles(t, modulePath)
	assertOnlyTfvarsChanged(t, before, after)
	tfvars := string(after["terraform.tfvars"])
	if !strings.Contains(tfvars, update.OCIIAMResource.GroupName) ||
		!strings.Contains(
			tfvars,
			update.OCIIAMResource.PolicyStatements[0],
		) {
		t.Fatal("group name and policy statements were not updated together")
	}
	if !bytes.Equal(before["main.tf"], after["main.tf"]) {
		t.Fatal("membership or another main.tf resource changed")
	}
}

func TestOCIIAMUpdateMissingResourcesIsAtomic(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*models.OCIIAMRequest)
		expected string
	}{
		{
			name: "user",
			mutate: func(resource *models.OCIIAMRequest) {
				resource.UserResourceName = "oci_user_inexistant_999"
			},
			expected: "OCI IAM user resource not found: oci_user_inexistant_999",
		},
		{
			name: "group",
			mutate: func(resource *models.OCIIAMRequest) {
				resource.GroupResourceName = "oci_group_inexistant_999"
			},
			expected: "OCI IAM group resource not found: oci_group_inexistant_999",
		},
		{
			name: "membership",
			mutate: func(resource *models.OCIIAMRequest) {
				resource.MembershipResourceName =
					"oci_membership_inexistante_999"
			},
			expected: "OCI IAM membership resource not found: oci_membership_inexistante_999",
		},
		{
			name: "policy",
			mutate: func(resource *models.OCIIAMRequest) {
				resource.PolicyResourceName = "oci_policy_inexistante_999"
			},
			expected: "OCI IAM policy resource not found: oci_policy_inexistante_999",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modulePath := seedObservabilityIAM(t)
			before := testutil.SnapshotTerraformFiles(t, modulePath)
			update := updateObservabilityRequest(modulePath)
			test.mutate(update.OCIIAMResource)

			err := generator.GenerateAtomically(update)
			if err == nil || !strings.Contains(err.Error(), test.expected) {
				t.Fatalf("missing resource returned unexpected error: %v", err)
			}
			testutil.AssertTerraformFilesEqual(
				t,
				before,
				testutil.SnapshotTerraformFiles(t, modulePath),
			)
		})
	}
}

func TestOCIIAMUpdateRejectsWrongMembershipRelationAtomically(t *testing.T) {
	modulePath := iamModulePath(t)
	first := observabilityRequest(modulePath)
	second := testutil.OCIIAMRequest(
		modulePath,
		"oci_user_storage_reader_01",
		"stage2026-storage-reader-user",
		"oci_group_storage_readers_01",
		"stage2026-storage-readers-group",
		"oci_membership_storage_reader_01",
		"oci_policy_storage_reader_01",
		"stage2026-storage-reader-policy",
		[]string{
			"Allow group stage2026-storage-readers-group to read object-family in compartment stage2026",
		},
	)
	for _, request := range []*models.Request{first, second} {
		if err := generator.GenerateAtomically(request); err != nil {
			t.Fatalf("seed OCI IAM Create failed: %v", err)
		}
	}
	before := testutil.SnapshotTerraformFiles(t, modulePath)
	update := updateObservabilityRequest(modulePath)
	update.OCIIAMResource.MembershipResourceName =
		second.OCIIAMResource.MembershipResourceName

	err := generator.GenerateAtomically(update)
	if err == nil ||
		!strings.Contains(err.Error(), "is not linked to group") {
		t.Fatalf("wrong membership returned unexpected error: %v", err)
	}
	testutil.AssertTerraformFilesEqual(
		t,
		before,
		testutil.SnapshotTerraformFiles(t, modulePath),
	)
}

func TestOCIIAMUpdateMissingVariableIsAtomic(t *testing.T) {
	modulePath := seedObservabilityIAM(t)
	variablesPath := filepath.Join(modulePath, "variables.tf")
	file, err := common.LoadExistingFile(variablesPath)
	if err != nil {
		t.Fatalf("load variables.tf: %v", err)
	}
	target := "oci_user_observability_01_description"
	removed := common.RemoveBlocks(file, func(block *hclwrite.Block) bool {
		labels := block.Labels()
		return block.Type() == "variable" &&
			len(labels) == 1 &&
			labels[0] == target
	})
	if removed != 1 {
		t.Fatalf("removed %d target variables, want 1", removed)
	}
	if err := os.WriteFile(
		variablesPath,
		common.FormattedBytes(file),
		0600,
	); err != nil {
		t.Fatalf("write variables.tf fixture: %v", err)
	}
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	err = generator.GenerateAtomically(updateObservabilityRequest(modulePath))
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"OCI IAM variable missing or duplicated: "+target,
		) {
		t.Fatalf("missing variable returned unexpected error: %v", err)
	}
	testutil.AssertTerraformFilesEqual(
		t,
		before,
		testutil.SnapshotTerraformFiles(t, modulePath),
	)
}

func TestOCIIAMUpdateRejectsDuplicateActualName(t *testing.T) {
	modulePath := iamModulePath(t)
	first := observabilityRequest(modulePath)
	second := testutil.OCIIAMRequest(
		modulePath,
		"oci_user_storage_reader_01",
		"stage2026-storage-reader-user",
		"oci_group_storage_readers_01",
		"stage2026-storage-readers-group",
		"oci_membership_storage_reader_01",
		"oci_policy_storage_reader_01",
		"stage2026-storage-reader-policy",
		[]string{
			"Allow group stage2026-storage-readers-group to read object-family in compartment stage2026",
		},
	)
	for _, request := range []*models.Request{first, second} {
		if err := generator.GenerateAtomically(request); err != nil {
			t.Fatalf("seed OCI IAM Create failed: %v", err)
		}
	}
	before := testutil.SnapshotTerraformFiles(t, modulePath)
	update := updateObservabilityRequest(modulePath)
	update.OCIIAMResource.UserName = second.OCIIAMResource.UserName

	err := generator.GenerateAtomically(update)
	if err == nil || !strings.Contains(err.Error(), "doublon OCI IAM") {
		t.Fatalf("duplicate actual name returned unexpected error: %v", err)
	}
	testutil.AssertTerraformFilesEqual(
		t,
		before,
		testutil.SnapshotTerraformFiles(t, modulePath),
	)
}

func TestOCIIAMUpdateDoesNotModifyOtherModulesOrAddSecrets(t *testing.T) {
	root := t.TempDir()
	iamPath := filepath.Join(root, "generated", "oci", "iam")
	computePath := filepath.Join(root, "generated", "oci", "compute")
	gcpPath := filepath.Join(root, "generated", "gcp", "compute")
	otherRequests := []*models.Request{
		testutil.OCIComputeRequest(
			computePath,
			"oci_vm_iam_update_isolation_01",
			"oci-vm-iam-update-isolation-01",
			false,
		),
		testutil.ComputeRequest(
			"create",
			gcpPath,
			"vm_iam_update_isolation_01",
			"vm-iam-update-isolation-01",
			"e2-medium",
		),
	}
	paths := []string{computePath, gcpPath}
	before := make([]map[string][]byte, len(paths))
	for index, request := range otherRequests {
		if err := generator.GenerateAtomically(request); err != nil {
			t.Fatalf("seed other module: %v", err)
		}
		before[index] = testutil.SnapshotTerraformFiles(t, paths[index])
	}
	create := observabilityRequest(iamPath)
	if err := generator.GenerateAtomically(create); err != nil {
		t.Fatalf("seed OCI IAM Create failed: %v", err)
	}
	update := updateObservabilityRequest(iamPath)
	update.OCIIAMResource.UserDescription = "Description finale sans secret"
	if err := generator.GenerateAtomically(update); err != nil {
		t.Fatalf("OCI IAM Update failed: %v", err)
	}

	for index, path := range paths {
		testutil.AssertTerraformFilesEqual(
			t,
			before[index],
			testutil.SnapshotTerraformFiles(t, path),
		)
	}
	files := testutil.SnapshotTerraformFiles(t, iamPath)
	content := strings.ToLower(
		string(files["main.tf"]) +
			string(files["variables.tf"]) +
			string(files["terraform.tfvars"]) +
			string(files["outputs.tf"]),
	)
	for _, forbidden := range []string{
		"private_key",
		"fingerprint",
		"auth_token",
		"password",
		"smtp",
		"customer_secret",
		"api_key",
		"secret_key",
	} {
		if strings.Contains(content, forbidden) {
			t.Fatalf("OCI IAM Update contains credential term %q", forbidden)
		}
	}
}

func seedObservabilityIAM(t *testing.T) string {
	t.Helper()
	modulePath := iamModulePath(t)
	if err := generator.GenerateAtomically(
		observabilityRequest(modulePath),
	); err != nil {
		t.Fatalf("seed OCI IAM Create failed: %v", err)
	}
	return modulePath
}

func updateObservabilityRequest(modulePath string) *models.Request {
	return testutil.OCIIAMActionRequest(
		"update",
		modulePath,
		"oci_user_observability_01",
		"stage2026-observability-user",
		"oci_group_observability_01",
		"stage2026-observability-group",
		"oci_membership_observability_01",
		"oci_policy_observability_01",
		"stage2026-observability-policy",
		[]string{
			"Allow group stage2026-observability-group to read metrics in compartment stage2026",
		},
	)
}

func assertOnlyTfvarsChanged(
	t *testing.T,
	before map[string][]byte,
	after map[string][]byte,
) {
	t.Helper()
	for _, filename := range []string{
		"main.tf",
		"variables.tf",
		"outputs.tf",
	} {
		if !bytes.Equal(before[filename], after[filename]) {
			t.Fatalf("%s changed during OCI IAM Update", filename)
		}
	}
	if bytes.Equal(before["terraform.tfvars"], after["terraform.tfvars"]) {
		t.Fatal("terraform.tfvars did not change")
	}
}
