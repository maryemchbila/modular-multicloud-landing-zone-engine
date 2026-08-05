package iam_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hcl-generator/generator"
	"hcl-generator/generator/common"
	"hcl-generator/generator/internal/testutil"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

func TestOCIIAMDeleteRemovesOnlyCompleteTargetSet(t *testing.T) {
	modulePath := iamModulePath(t)
	target := deleteTestCreateRequest(modulePath, "a")
	remaining := deleteTestCreateRequest(modulePath, "b")
	for _, request := range []*models.Request{target, remaining} {
		if err := generator.GenerateAtomically(request); err != nil {
			t.Fatalf("seed OCI IAM Create failed: %v", err)
		}
	}

	if err := generator.GenerateAtomically(
		deleteRequestFor(target),
	); err != nil {
		t.Fatalf("OCI IAM Delete failed: %v", err)
	}

	files := testutil.SnapshotTerraformFiles(t, modulePath)
	all := strings.Join([]string{
		string(files["main.tf"]),
		string(files["variables.tf"]),
		string(files["terraform.tfvars"]),
		string(files["outputs.tf"]),
	}, "\n")
	for _, identifier := range []string{
		target.OCIIAMResource.UserResourceName,
		target.OCIIAMResource.GroupResourceName,
		target.OCIIAMResource.MembershipResourceName,
		target.OCIIAMResource.PolicyResourceName,
	} {
		if strings.Contains(all, identifier) {
			t.Fatalf("target identifier remains after Delete: %s", identifier)
		}
	}
	for _, identifier := range []string{
		remaining.OCIIAMResource.UserResourceName,
		remaining.OCIIAMResource.GroupResourceName,
		remaining.OCIIAMResource.MembershipResourceName,
		remaining.OCIIAMResource.PolicyResourceName,
	} {
		if !strings.Contains(all, identifier) {
			t.Fatalf("remaining set lost identifier %s", identifier)
		}
	}
}

func TestOCIIAMDeleteMissingResourcesIsAtomic(t *testing.T) {
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
			modulePath := iamModulePath(t)
			create := deleteTestCreateRequest(modulePath, "target")
			if err := generator.GenerateAtomically(create); err != nil {
				t.Fatalf("seed OCI IAM Create failed: %v", err)
			}
			before := testutil.SnapshotTerraformFiles(t, modulePath)
			deleteRequest := deleteRequestFor(create)
			test.mutate(deleteRequest.OCIIAMResource)

			err := generator.GenerateAtomically(deleteRequest)
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

func TestOCIIAMDeleteRejectsWrongMembershipAndPolicy(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*models.Request, *models.Request)
		expected string
	}{
		{
			name: "membership",
			mutate: func(
				deleteRequest *models.Request,
				second *models.Request,
			) {
				deleteRequest.OCIIAMResource.MembershipResourceName =
					second.OCIIAMResource.MembershipResourceName
			},
			expected: "is not linked to group",
		},
		{
			name: "policy",
			mutate: func(
				deleteRequest *models.Request,
				second *models.Request,
			) {
				deleteRequest.OCIIAMResource.PolicyResourceName =
					second.OCIIAMResource.PolicyResourceName
			},
			expected: "does not target group",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modulePath := iamModulePath(t)
			first := deleteTestCreateRequest(modulePath, "first")
			second := deleteTestCreateRequest(modulePath, "second")
			for _, request := range []*models.Request{first, second} {
				if err := generator.GenerateAtomically(request); err != nil {
					t.Fatalf("seed OCI IAM Create failed: %v", err)
				}
			}
			before := testutil.SnapshotTerraformFiles(t, modulePath)
			deleteRequest := deleteRequestFor(first)
			test.mutate(deleteRequest, second)

			err := generator.GenerateAtomically(deleteRequest)
			if err == nil || !strings.Contains(err.Error(), test.expected) {
				t.Fatalf("wrong relation returned unexpected error: %v", err)
			}
			testutil.AssertTerraformFilesEqual(
				t,
				before,
				testutil.SnapshotTerraformFiles(t, modulePath),
			)
		})
	}
}

func TestOCIIAMDeleteBlocksSharedUserOrGroup(t *testing.T) {
	tests := []struct {
		name     string
		share    func(*hclwrite.Block, *models.OCIIAMRequest)
		expected string
	}{
		{
			name: "user by another membership",
			share: func(
				membership *hclwrite.Block,
				target *models.OCIIAMRequest,
			) {
				membership.Body().SetAttributeTraversal(
					"user_id",
					common.ResourceTraversal(
						"oci_identity_user",
						target.UserResourceName,
						"id",
					),
				)
			},
			expected: "user %s is referenced by another OCI IAM block",
		},
		{
			name: "group by another membership",
			share: func(
				membership *hclwrite.Block,
				target *models.OCIIAMRequest,
			) {
				membership.Body().SetAttributeTraversal(
					"group_id",
					common.ResourceTraversal(
						"oci_identity_group",
						target.GroupResourceName,
						"id",
					),
				)
			},
			expected: "group %s is referenced by another OCI IAM resource",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modulePath := iamModulePath(t)
			first := deleteTestCreateRequest(modulePath, "first")
			second := deleteTestCreateRequest(modulePath, "second")
			for _, request := range []*models.Request{first, second} {
				if err := generator.GenerateAtomically(request); err != nil {
					t.Fatalf("seed OCI IAM Create failed: %v", err)
				}
			}
			mainPath := filepath.Join(modulePath, "main.tf")
			mainFile, err := common.LoadExistingFile(mainPath)
			if err != nil {
				t.Fatalf("load main.tf fixture: %v", err)
			}
			secondMembership := common.FindBlock(
				mainFile,
				"resource",
				"oci_identity_user_group_membership",
				second.OCIIAMResource.MembershipResourceName,
			)
			if secondMembership == nil {
				t.Fatal("second membership fixture is missing")
			}
			test.share(secondMembership, first.OCIIAMResource)
			writeHCLFixture(t, mainPath, mainFile)
			before := testutil.SnapshotTerraformFiles(t, modulePath)

			err = generator.GenerateAtomically(deleteRequestFor(first))
			expected := strings.ReplaceAll(
				test.expected,
				"%s",
				map[bool]string{
					true:  first.OCIIAMResource.UserResourceName,
					false: first.OCIIAMResource.GroupResourceName,
				}[strings.Contains(test.expected, "user ")],
			)
			if err == nil || !strings.Contains(err.Error(), expected) {
				t.Fatalf("shared identity returned unexpected error: %v", err)
			}
			testutil.AssertTerraformFilesEqual(
				t,
				before,
				testutil.SnapshotTerraformFiles(t, modulePath),
			)
		})
	}
}

func TestOCIIAMDeleteBlocksGroupSharedByAnotherPolicy(t *testing.T) {
	modulePath := iamModulePath(t)
	first := deleteTestCreateRequest(modulePath, "first")
	second := deleteTestCreateRequest(modulePath, "second")
	for _, request := range []*models.Request{first, second} {
		if err := generator.GenerateAtomically(request); err != nil {
			t.Fatalf("seed OCI IAM Create failed: %v", err)
		}
	}
	tfvarsPath := filepath.Join(modulePath, "terraform.tfvars")
	tfvars, err := common.LoadExistingFile(tfvarsPath)
	if err != nil {
		t.Fatalf("load terraform.tfvars fixture: %v", err)
	}
	tfvars.Body().SetAttributeValue(
		second.OCIIAMResource.PolicyResourceName+"_statements",
		cty.ListVal([]cty.Value{cty.StringVal(
			"Allow group " + first.OCIIAMResource.GroupName +
				" to read metrics in compartment stage2026",
		)}),
	)
	writeHCLFixture(t, tfvarsPath, tfvars)
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	err = generator.GenerateAtomically(deleteRequestFor(first))
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"group "+first.OCIIAMResource.GroupResourceName+
				" is referenced by another OCI IAM resource",
		) {
		t.Fatalf("shared policy returned unexpected error: %v", err)
	}
	testutil.AssertTerraformFilesEqual(
		t,
		before,
		testutil.SnapshotTerraformFiles(t, modulePath),
	)
}

func TestOCIIAMDeleteToleratesMissingVariableAndOutput(t *testing.T) {
	tests := []struct {
		name   string
		remove func(*common.TerraformFiles, *models.OCIIAMRequest)
	}{
		{
			name: "variable",
			remove: func(
				files *common.TerraformFiles,
				resource *models.OCIIAMRequest,
			) {
				name := resource.UserResourceName + "_description"
				common.RemoveBlocks(
					files.Variables,
					func(block *hclwrite.Block) bool {
						labels := block.Labels()
						return block.Type() == "variable" &&
							len(labels) == 1 &&
							labels[0] == name
					},
				)
			},
		},
		{
			name: "output",
			remove: func(
				files *common.TerraformFiles,
				resource *models.OCIIAMRequest,
			) {
				name := resource.PolicyResourceName + "_name"
				common.RemoveBlocks(
					files.Outputs,
					func(block *hclwrite.Block) bool {
						labels := block.Labels()
						return block.Type() == "output" &&
							len(labels) == 1 &&
							labels[0] == name
					},
				)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modulePath := iamModulePath(t)
			create := deleteTestCreateRequest(modulePath, "target")
			if err := generator.GenerateAtomically(create); err != nil {
				t.Fatalf("seed OCI IAM Create failed: %v", err)
			}
			files, err := common.LoadExistingTerraformFiles(modulePath)
			if err != nil {
				t.Fatalf("load fixture: %v", err)
			}
			test.remove(files, create.OCIIAMResource)
			writeTerraformFixtures(t, modulePath, files)

			if err := generator.GenerateAtomically(
				deleteRequestFor(create),
			); err != nil {
				t.Fatalf("OCI IAM Delete with missing %s failed: %v", test.name, err)
			}
			after := testutil.SnapshotTerraformFiles(t, modulePath)
			for _, filename := range testutil.TerraformFilenames {
				if strings.Contains(
					string(after[filename]),
					"delete_target",
				) {
					t.Fatalf("%s retained target after tolerant Delete", filename)
				}
			}
		})
	}
}

func TestOCIIAMDeleteBlocksCertainCrossModuleDependency(t *testing.T) {
	root := t.TempDir()
	iamPath := filepath.Join(root, "generated", "oci", "iam")
	computePath := filepath.Join(root, "generated", "oci", "compute")
	create := deleteTestCreateRequest(iamPath, "target")
	if err := generator.GenerateAtomically(create); err != nil {
		t.Fatalf("seed OCI IAM Create failed: %v", err)
	}
	if err := generator.GenerateAtomically(testutil.OCIComputeRequest(
		computePath,
		"oci_vm_iam_dependency_01",
		"oci-vm-iam-dependency-01",
		false,
	)); err != nil {
		t.Fatalf("seed OCI Compute failed: %v", err)
	}
	computeMainPath := filepath.Join(computePath, "main.tf")
	computeMain, err := common.LoadExistingFile(computeMainPath)
	if err != nil {
		t.Fatalf("load compute fixture: %v", err)
	}
	computeMain.Body().SetAttributeTraversal(
		"iam_user_reference",
		common.ResourceTraversal(
			"oci_identity_user",
			create.OCIIAMResource.UserResourceName,
			"id",
		),
	)
	writeHCLFixture(t, computeMainPath, computeMain)
	iamBefore := testutil.SnapshotTerraformFiles(t, iamPath)
	computeBefore := testutil.SnapshotTerraformFiles(t, computePath)

	err = generator.GenerateAtomically(deleteRequestFor(create))
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"Cannot delete OCI IAM set: referenced by another OCI module",
		) {
		t.Fatalf("cross-module dependency returned unexpected error: %v", err)
	}
	testutil.AssertTerraformFilesEqual(
		t,
		iamBefore,
		testutil.SnapshotTerraformFiles(t, iamPath),
	)
	testutil.AssertTerraformFilesEqual(
		t,
		computeBefore,
		testutil.SnapshotTerraformFiles(t, computePath),
	)
}

func TestOCIIAMDeleteKeepsOtherModulesAndGeneratesNoSecrets(t *testing.T) {
	root := t.TempDir()
	iamPath := filepath.Join(root, "generated", "oci", "iam")
	storagePath := filepath.Join(root, "generated", "oci", "storage")
	gcpPath := filepath.Join(root, "generated", "gcp", "compute")
	target := deleteTestCreateRequest(iamPath, "target")
	remaining := deleteTestCreateRequest(iamPath, "remaining")
	for _, request := range []*models.Request{target, remaining} {
		if err := generator.GenerateAtomically(request); err != nil {
			t.Fatalf("seed OCI IAM Create failed: %v", err)
		}
	}
	otherRequests := []*models.Request{
		testutil.OCIStorageRequest(
			storagePath,
			"oci_bucket_iam_delete_isolation_01",
			"oci-bucket-iam-delete-isolation-01",
			"NoPublicAccess",
			"Standard",
			"Enabled",
			true,
		),
		testutil.ComputeRequest(
			"create",
			gcpPath,
			"vm_iam_delete_isolation_01",
			"vm-iam-delete-isolation-01",
			"e2-medium",
		),
	}
	paths := []string{storagePath, gcpPath}
	before := make([]map[string][]byte, len(paths))
	for index, request := range otherRequests {
		if err := generator.GenerateAtomically(request); err != nil {
			t.Fatalf("seed other module failed: %v", err)
		}
		before[index] = testutil.SnapshotTerraformFiles(t, paths[index])
	}

	if err := generator.GenerateAtomically(
		deleteRequestFor(target),
	); err != nil {
		t.Fatalf("OCI IAM Delete failed: %v", err)
	}
	for index, path := range paths {
		testutil.AssertTerraformFilesEqual(
			t,
			before[index],
			testutil.SnapshotTerraformFiles(t, path),
		)
	}
	files := testutil.SnapshotTerraformFiles(t, iamPath)
	content := strings.ToLower(strings.Join([]string{
		string(files["main.tf"]),
		string(files["variables.tf"]),
		string(files["terraform.tfvars"]),
		string(files["outputs.tf"]),
	}, "\n"))
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
			t.Fatalf("OCI IAM Delete contains credential term %q", forbidden)
		}
	}
}

func deleteTestCreateRequest(
	modulePath string,
	suffix string,
) *models.Request {
	groupName := "stage2026-delete-" + suffix + "-group"
	return testutil.OCIIAMRequest(
		modulePath,
		"oci_user_delete_"+suffix+"_01",
		"stage2026-delete-"+suffix+"-user",
		"oci_group_delete_"+suffix+"_01",
		groupName,
		"oci_membership_delete_"+suffix+"_01",
		"oci_policy_delete_"+suffix+"_01",
		"stage2026-delete-"+suffix+"-policy",
		[]string{
			"Allow group " + groupName +
				" to read metrics in compartment stage2026",
		},
	)
}

func deleteRequestFor(create *models.Request) *models.Request {
	resource := create.OCIIAMResource
	return testutil.OCIIAMDeleteRequest(
		create.ModulePath,
		resource.UserResourceName,
		resource.GroupResourceName,
		resource.MembershipResourceName,
		resource.PolicyResourceName,
	)
}

func writeHCLFixture(
	t *testing.T,
	path string,
	file *hclwrite.File,
) {
	t.Helper()
	if err := os.WriteFile(path, common.FormattedBytes(file), 0600); err != nil {
		t.Fatalf("write HCL fixture %s: %v", path, err)
	}
}

func writeTerraformFixtures(
	t *testing.T,
	modulePath string,
	files *common.TerraformFiles,
) {
	t.Helper()
	fixtures := map[string]*hclwrite.File{
		"main.tf":          files.Main,
		"variables.tf":     files.Variables,
		"terraform.tfvars": files.Tfvars,
		"outputs.tf":       files.Outputs,
	}
	for filename, file := range fixtures {
		writeHCLFixture(t, filepath.Join(modulePath, filename), file)
	}
}
