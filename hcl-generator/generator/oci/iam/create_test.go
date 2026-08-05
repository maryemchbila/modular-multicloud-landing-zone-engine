package iam_test

import (
	"path/filepath"
	"strings"
	"testing"

	"hcl-generator/generator"
	"hcl-generator/generator/internal/testutil"
	"hcl-generator/models"
)

func TestOCIIAMCreateGeneratesAtomicLogicalSet(t *testing.T) {
	modulePath := iamModulePath(t)
	request := observabilityRequest(modulePath)
	request.OCIIAMResource.PolicyStatements = []string{
		"Allow group stage2026-observability-group to read metrics in compartment stage2026",
		"Allow group stage2026-observability-group to read log-groups in compartment stage2026",
	}
	if err := generator.GenerateAtomically(request); err != nil {
		t.Fatalf("OCI IAM Create failed: %v", err)
	}

	files := testutil.SnapshotTerraformFiles(t, modulePath)
	mainContent := string(files["main.tf"])
	orderedResources := []string{
		`resource "oci_identity_group" "oci_group_observability_01"`,
		`resource "oci_identity_user" "oci_user_observability_01"`,
		`resource "oci_identity_user_group_membership" "oci_membership_observability_01"`,
		`resource "oci_identity_policy" "oci_policy_observability_01"`,
	}
	previous := -1
	for _, fragment := range orderedResources {
		index := strings.Index(mainContent, fragment)
		if index < 0 {
			t.Fatalf("main.tf is missing %q", fragment)
		}
		if index <= previous {
			t.Fatalf("resource order is incorrect for %q", fragment)
		}
		previous = index
	}
	for _, traversal := range []string{
		"compartment_id = var.oci_group_observability_01_tenancy_ocid",
		"name           = var.oci_group_observability_01_name",
		"compartment_id = var.oci_user_observability_01_tenancy_ocid",
		"group_id = oci_identity_group.oci_group_observability_01.id",
		"user_id  = oci_identity_user.oci_user_observability_01.id",
		"statements     = var.oci_policy_observability_01_statements",
	} {
		if !strings.Contains(mainContent, traversal) {
			t.Fatalf("main.tf is missing traversal %q\n%s", traversal, mainContent)
		}
	}

	variables := string(files["variables.tf"])
	for _, name := range expectedVariableNames() {
		if !strings.Contains(variables, `variable "`+name+`"`) {
			t.Fatalf("variables.tf is missing %q", name)
		}
	}
	if !strings.Contains(variables, "type        = list(string)") {
		t.Fatalf("policy statements type is not list(string)\n%s", variables)
	}

	tfvars := string(files["terraform.tfvars"])
	for _, statement := range request.OCIIAMResource.PolicyStatements {
		if !strings.Contains(tfvars, `"`+statement+`"`) {
			t.Fatalf("terraform.tfvars is missing statement %q", statement)
		}
	}
	if strings.Contains(
		tfvars,
		`oci_policy_observability_01_statements = "[`,
	) {
		t.Fatal("policy statements were serialized as a JSON string")
	}

	outputs := string(files["outputs.tf"])
	for name, traversal := range map[string]string{
		"oci_user_observability_01_id":       "oci_identity_user.oci_user_observability_01.id",
		"oci_user_observability_01_name":     "oci_identity_user.oci_user_observability_01.name",
		"oci_group_observability_01_id":      "oci_identity_group.oci_group_observability_01.id",
		"oci_group_observability_01_name":    "oci_identity_group.oci_group_observability_01.name",
		"oci_membership_observability_01_id": "oci_identity_user_group_membership.oci_membership_observability_01.id",
		"oci_policy_observability_01_id":     "oci_identity_policy.oci_policy_observability_01.id",
		"oci_policy_observability_01_name":   "oci_identity_policy.oci_policy_observability_01.name",
	} {
		if !strings.Contains(outputs, `output "`+name+`"`) ||
			!strings.Contains(outputs, traversal) {
			t.Fatalf("output %q does not use traversal %q", name, traversal)
		}
	}

	allContent := strings.ToLower(
		mainContent + variables + tfvars + outputs,
	)
	for _, forbidden := range []string{
		"private_key",
		"private_key_path",
		"fingerprint",
		"auth_token",
		"password",
		"smtp",
		"customer_secret",
		"secret_key",
		"api_key",
	} {
		if strings.Contains(allContent, forbidden) {
			t.Fatalf("generated OCI IAM contains forbidden credential term %q", forbidden)
		}
	}
}

func TestOCIIAMCreateAppendsSecondLogicalSet(t *testing.T) {
	modulePath := iamModulePath(t)
	requests := []*models.Request{
		observabilityRequest(modulePath),
		testutil.OCIIAMRequest(
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
		),
	}
	for _, request := range requests {
		if err := generator.GenerateAtomically(request); err != nil {
			t.Fatalf("OCI IAM Create failed: %v", err)
		}
	}

	files := testutil.SnapshotTerraformFiles(t, modulePath)
	for _, filename := range testutil.TerraformFilenames {
		content := string(files[filename])
		for _, marker := range []string{
			"observability",
			"storage_reader",
		} {
			if !strings.Contains(content, marker) {
				t.Fatalf("%s is missing logical set %s", filename, marker)
			}
		}
	}
}

func TestOCIIAMCreateDuplicateIsAtomic(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*models.OCIIAMRequest, *models.OCIIAMRequest)
	}{
		{
			name: "User resource",
			mutate: func(base, duplicate *models.OCIIAMRequest) {
				duplicate.UserResourceName = base.UserResourceName
			},
		},
		{
			name: "Group resource",
			mutate: func(base, duplicate *models.OCIIAMRequest) {
				duplicate.GroupResourceName = base.GroupResourceName
			},
		},
		{
			name: "Membership resource",
			mutate: func(base, duplicate *models.OCIIAMRequest) {
				duplicate.MembershipResourceName = base.MembershipResourceName
			},
		},
		{
			name: "Policy resource",
			mutate: func(base, duplicate *models.OCIIAMRequest) {
				duplicate.PolicyResourceName = base.PolicyResourceName
			},
		},
		{
			name: "User OCI name",
			mutate: func(base, duplicate *models.OCIIAMRequest) {
				duplicate.UserName = base.UserName
			},
		},
		{
			name: "Group OCI name",
			mutate: func(base, duplicate *models.OCIIAMRequest) {
				duplicate.GroupName = base.GroupName
			},
		},
		{
			name: "Policy OCI name",
			mutate: func(base, duplicate *models.OCIIAMRequest) {
				duplicate.PolicyName = base.PolicyName
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modulePath := iamModulePath(t)
			base := observabilityRequest(modulePath)
			if err := generator.GenerateAtomically(base); err != nil {
				t.Fatalf("seed OCI IAM Create failed: %v", err)
			}
			before := testutil.SnapshotTerraformFiles(t, modulePath)
			duplicate := testutil.OCIIAMRequest(
				modulePath,
				"oci_user_duplicate_01",
				"stage2026-duplicate-user",
				"oci_group_duplicate_01",
				"stage2026-duplicate-group",
				"oci_membership_duplicate_01",
				"oci_policy_duplicate_01",
				"stage2026-duplicate-policy",
				[]string{
					"Allow group stage2026-duplicate-group to read metrics in compartment stage2026",
				},
			)
			test.mutate(base.OCIIAMResource, duplicate.OCIIAMResource)

			err := generator.GenerateAtomically(duplicate)
			if err == nil || !strings.Contains(err.Error(), "doublon OCI IAM") {
				t.Fatalf("duplicate returned unexpected error: %v", err)
			}
			testutil.AssertTerraformFilesEqual(
				t,
				before,
				testutil.SnapshotTerraformFiles(t, modulePath),
			)
		})
	}
}

func TestOCIIAMCreateDoesNotModifyOtherModules(t *testing.T) {
	root := t.TempDir()
	ociIAMPath := filepath.Join(root, "generated", "oci", "iam")
	ociComputePath := filepath.Join(root, "generated", "oci", "compute")
	ociNetworkPath := filepath.Join(root, "generated", "oci", "network")
	ociStoragePath := filepath.Join(root, "generated", "oci", "storage")
	gcpComputePath := filepath.Join(root, "generated", "gcp", "compute")

	otherRequests := []*models.Request{
		testutil.OCIComputeRequest(
			ociComputePath,
			"oci_vm_iam_isolation_01",
			"oci-vm-iam-isolation-01",
			false,
		),
		testutil.OCINetworkRequest(
			ociNetworkPath,
			"oci_vcn_iam_isolation_01",
			"oci-vcn-iam-isolation-01",
			"oci_subnet_iam_isolation_01",
			"oci-subnet-iam-isolation-01",
			"10.93.0.0/16",
			"10.93.1.0/24",
			"oci_igw_iam_isolation_01",
			"oci-igw-iam-isolation-01",
			"oci_rt_iam_isolation_01",
			"oci-rt-iam-isolation-01",
			true,
		),
		testutil.OCIStorageRequest(
			ociStoragePath,
			"oci_bucket_iam_isolation_01",
			"stage2026-oci-iam-isolation-01",
			"NoPublicAccess",
			"Standard",
			"Enabled",
			true,
		),
		testutil.ComputeRequest(
			"create",
			gcpComputePath,
			"vm_iam_isolation_01",
			"vm-iam-isolation-01",
			"e2-medium",
		),
	}
	paths := []string{
		ociComputePath,
		ociNetworkPath,
		ociStoragePath,
		gcpComputePath,
	}
	before := make([]map[string][]byte, len(paths))
	for index, request := range otherRequests {
		if err := generator.GenerateAtomically(request); err != nil {
			t.Fatalf("seed request failed: %v", err)
		}
		before[index] = testutil.SnapshotTerraformFiles(t, paths[index])
	}

	request := observabilityRequest(ociIAMPath)
	if err := generator.GenerateAtomically(request); err != nil {
		t.Fatalf("OCI IAM Create failed: %v", err)
	}
	for index, path := range paths {
		testutil.AssertTerraformFilesEqual(
			t,
			before[index],
			testutil.SnapshotTerraformFiles(t, path),
		)
	}
}

func observabilityRequest(modulePath string) *models.Request {
	return testutil.OCIIAMRequest(
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

func expectedVariableNames() []string {
	return []string{
		"oci_user_observability_01_tenancy_ocid",
		"oci_user_observability_01_name",
		"oci_user_observability_01_description",
		"oci_group_observability_01_tenancy_ocid",
		"oci_group_observability_01_name",
		"oci_group_observability_01_description",
		"oci_policy_observability_01_compartment_id",
		"oci_policy_observability_01_name",
		"oci_policy_observability_01_description",
		"oci_policy_observability_01_statements",
	}
}

func iamModulePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "generated", "oci", "iam")
}
