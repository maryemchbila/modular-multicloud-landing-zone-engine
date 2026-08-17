package generator_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"hcl-generator/generator"
	"hcl-generator/generator/internal/testutil"
	"hcl-generator/models"
)

func TestProviderModuleActionRoutingAndIsolation(t *testing.T) {
	root := t.TempDir()
	gcpComputePath := filepath.Join(root, "generated", "gcp", "modules", "compute")
	gcpNetworkPath := filepath.Join(root, "generated", "gcp", "modules", "network")
	gcpStoragePath := filepath.Join(root, "generated", "gcp", "modules", "storage")
	ociComputePath := filepath.Join(root, "generated", "oci", "modules", "compute")

	requests := []*models.Request{
		testutil.ComputeRequest(
			"create",
			gcpComputePath,
			"vm_route_01",
			"vm-route-01",
			"e2-medium",
		),
		testutil.NetworkRequest(
			"create",
			gcpNetworkPath,
			"vpc_route_01",
			"vpc-route-01",
			"subnet_route_01",
			"subnet-route-01",
			"10.210.0.0/24",
			"europe-west1",
		),
		testutil.StorageRequest(
			"create",
			gcpStoragePath,
			"bucket_route_01",
			"stage2026-route-01",
			"EU",
			"STANDARD",
			true,
		),
		testutil.OCIComputeRequest(
			ociComputePath,
			"oci_vm_route_01",
			"oci-vm-route-01",
			false,
		),
	}
	for _, request := range requests {
		if err := generator.GenerateAtomically(request); err != nil {
			t.Fatalf(
				"%s/%s/%s failed: %v",
				request.Provider,
				request.Module,
				request.Action,
				err,
			)
		}
	}

	networkBefore := testutil.SnapshotTerraformFiles(t, gcpNetworkPath)
	storageBefore := testutil.SnapshotTerraformFiles(t, gcpStoragePath)
	ociBefore := testutil.SnapshotTerraformFiles(t, ociComputePath)
	if err := generator.GenerateAtomically(testutil.ComputeRequest(
		"update",
		gcpComputePath,
		"vm_route_01",
		"vm-route-production",
		"e2-standard-2",
	)); err != nil {
		t.Fatalf("GCP Compute Update failed: %v", err)
	}
	testutil.AssertModuleFilesEqual(
		t,
		networkBefore,
		testutil.SnapshotTerraformFiles(t, gcpNetworkPath),
	)
	testutil.AssertModuleFilesEqual(
		t,
		storageBefore,
		testutil.SnapshotTerraformFiles(t, gcpStoragePath),
	)
	testutil.AssertTerraformFilesEqual(
		t,
		ociBefore,
		testutil.SnapshotTerraformFiles(t, ociComputePath),
	)
}

func TestUnsupportedRouteDoesNotCreateTerraformFiles(t *testing.T) {
	modulePath := t.TempDir()
	request := &models.Request{
		Action:     "create",
		Provider:   "oci",
		Module:     "database",
		ModulePath: modulePath,
	}
	err := generator.GenerateAtomically(request)
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"fonctionnalite non implementee : oci / database / create",
		) {
		t.Fatalf("unexpected unsupported-route result: %v", err)
	}

	entries, readErr := os.ReadDir(modulePath)
	if readErr != nil {
		t.Fatalf("read temporary module directory: %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("unsupported route created %d files", len(entries))
	}
}

func TestLegacyPathIsRejectedWithoutWriting(t *testing.T) {
	root := filepath.Join(t.TempDir(), "generated", "gcp")
	legacy := filepath.Join(root, "compute")
	request := testutil.ComputeRequest(
		"create", legacy, "vm_test_26", "vm-test-26", "e2-small",
	)
	if err := generator.GenerateAtomically(request); err == nil {
		t.Fatal("legacy path was accepted")
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy path was created: %v", err)
	}
}

func TestCanonicalModulePathUpdatesRootInSameTransaction(t *testing.T) {
	root := t.TempDir()
	modulePath := filepath.Join(
		root,
		"generated",
		"gcp",
		"modules",
		"compute",
	)
	request := testutil.ComputeRequest(
		"create",
		modulePath,
		"vm_canonical_01",
		"vm-canonical-01",
		"e2-medium",
	)
	if err := generator.GenerateAtomically(request); err != nil {
		t.Fatal(err)
	}
	rootMain := filepath.Join(root, "generated", "gcp", "main.tf")
	content, err := os.ReadFile(rootMain)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), `module "compute"`) ||
		strings.Contains(string(content), `module "network"`) {
		t.Fatalf("unexpected root main.tf:\n%s", content)
	}
	if _, err := os.Stat(filepath.Join(root, "generated", "gcp", "compute")); !os.IsNotExist(err) {
		t.Fatal("canonical generation unexpectedly created the legacy module path")
	}
}

func TestEveryGCPModuleWritesProjectContextInFreshWorkspace(t *testing.T) {
	for _, module := range []string{"compute", "network", "storage", "iam"} {
		t.Run(module, func(t *testing.T) {
			root := t.TempDir()
			modulePath := filepath.Join(
				root, "generated", "gcp", "modules", module,
			)
			request := gcpProjectContextRequest(
				module, "create", modulePath, "example-test-project",
			)
			if err := generator.GenerateAtomically(request); err != nil {
				t.Fatal(err)
			}

			assertRootProjectContext(
				t, modulePath, "example-test-project",
			)
			if _, err := os.Stat(filepath.Join(modulePath, "terraform.tfvars")); !os.IsNotExist(err) {
				t.Fatal("module-local terraform.tfvars was created")
			}
		})
	}
}

func TestEveryGCPModuleReplacesProjectContextIdempotently(t *testing.T) {
	for _, module := range []string{"compute", "network", "storage", "iam"} {
		t.Run(module, func(t *testing.T) {
			modulePath := filepath.Join(
				t.TempDir(), "generated", "gcp", "modules", module,
			)
			create := gcpProjectContextRequest(
				module, "create", modulePath, "project-a",
			)
			if err := generator.GenerateAtomically(create); err != nil {
				t.Fatal(err)
			}
			update := gcpProjectContextRequest(
				module, "update", modulePath, "project-b",
			)
			if err := generator.GenerateAtomically(update); err != nil {
				t.Fatal(err)
			}

			assertRootProjectContext(t, modulePath, "project-b")
			content, err := os.ReadFile(
				testutil.TerraformFilePath(modulePath, "terraform.tfvars"),
			)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(content), `"project-a"`) {
				t.Fatal("old project context remains after update")
			}
			if !strings.Contains(string(content), "_context_01") {
				t.Fatal("module tfvars were not preserved with project context")
			}
		})
	}
}

func gcpProjectContextRequest(
	module string,
	action string,
	modulePath string,
	projectID string,
) *models.Request {
	switch module {
	case "compute":
		request := testutil.ComputeRequest(
			action, modulePath, "vm_context_01", "vm-context-01", "e2-medium",
		)
		request.ProjectID = projectID
		return request
	case "network":
		request := testutil.NetworkRequest(
			action, modulePath, "vpc_context_01", "vpc-context-01",
			"subnet_context_01", "subnet-context-01", "10.92.0.0/24",
			"europe-west1",
		)
		request.ProjectID = projectID
		return request
	case "storage":
		request := testutil.StorageRequest(
			action, modulePath, "bucket_context_01", "example-context-bucket",
			"EU", "STANDARD", true,
		)
		request.ProjectID = projectID
		return request
	case "iam":
		return &models.Request{
			Action: action, Provider: "gcp", Module: "iam",
			ModulePath: modulePath, ProjectID: projectID,
			IAMResource: &models.IAMRequest{
				ResourceName: "sa_context_01", AccountID: "sa-context-01",
				DisplayName: "Service Account Context",
				Description: "Service account used by project-context tests",
				ProjectID:   projectID, Role: "roles/viewer",
			},
		}
	default:
		panic("unsupported GCP module in test: " + module)
	}
}

func assertRootProjectContext(
	t *testing.T,
	modulePath string,
	expectedProjectID string,
) {
	t.Helper()
	content, err := os.ReadFile(
		testutil.TerraformFilePath(modulePath, "terraform.tfvars"),
	)
	if err != nil {
		t.Fatal(err)
	}
	assignment := regexp.MustCompile(
		`(?m)^gcp_project_id\s*=\s*"` +
			regexp.QuoteMeta(expectedProjectID) + `"\s*$`,
	)
	if !assignment.Match(content) {
		t.Fatalf("missing root project context %q:\n%s", expectedProjectID, content)
	}
	key := regexp.MustCompile(`(?m)^gcp_project_id\s*=`)
	if count := len(key.FindAll(content, -1)); count != 1 {
		t.Fatalf("gcp_project_id count = %d, want 1", count)
	}
}

func TestResourceNamesNeverChangeCanonicalDestination(t *testing.T) {
	markers := []string{"test", "inexistante", "delete_b", "demo", "fixture"}
	root := t.TempDir()
	computePath := filepath.Join(root, "generated", "gcp", "modules", "compute")
	for _, marker := range markers {
		resourceName := "vm_" + marker + "_01"
		if marker == "test" {
			resourceName = "vm_test_26"
		}
		request := testutil.ComputeRequest(
			"create",
			computePath,
			resourceName,
			strings.ReplaceAll(resourceName, "_", "-"),
			"e2-medium",
		)
		if err := generator.GenerateAtomically(request); err != nil {
			t.Fatalf("generate %s: %v", resourceName, err)
		}
	}

	mainContent, err := os.ReadFile(filepath.Join(computePath, "main.tf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range markers {
		resourceName := "vm_" + marker + "_01"
		if marker == "test" {
			resourceName = "vm_test_26"
		}
		if count := strings.Count(
			string(mainContent),
			`resource "google_compute_instance" "`+resourceName+`"`,
		); count != 1 {
			t.Fatalf("%s canonical resource count = %d", resourceName, count)
		}
	}
	assertCanonicalRootAndNoLegacy(t, root, "gcp", "compute")
}

func TestEveryProviderModuleUsesCanonicalDestinationForTestName(t *testing.T) {
	tests := []struct {
		name         string
		provider     string
		module       string
		resourceName string
		request      func(string) *models.Request
	}{
		{
			name: "GCP network", provider: "gcp", module: "network",
			resourceName: "network_test_01",
			request: func(path string) *models.Request {
				return testutil.NetworkRequest(
					"create", path, "network_test_01", "network-test-01",
					"subnet_test_01", "subnet-test-01", "10.90.0.0/24", "europe-west1",
				)
			},
		},
		{
			name: "GCP storage", provider: "gcp", module: "storage",
			resourceName: "bucket_test_01",
			request: func(path string) *models.Request {
				return testutil.StorageRequest(
					"create", path, "bucket_test_01", "stage2026-bucket-test-01",
					"EU", "STANDARD", true,
				)
			},
		},
		{
			name: "GCP IAM", provider: "gcp", module: "iam",
			resourceName: "iam_test_01",
			request: func(path string) *models.Request {
				return &models.Request{
					Action: "create", Provider: "gcp", Module: "iam", ModulePath: path,
					ProjectID: "example-test-project",
					IAMResource: &models.IAMRequest{
						ResourceName: "iam_test_01", AccountID: "iam-test-01",
						DisplayName: "IAM test 01", Description: "Canonical path test",
						ProjectID: "example-test-project", Role: "roles/viewer",
					},
				}
			},
		},
		{
			name: "OCI compute", provider: "oci", module: "compute",
			resourceName: "oci_vm_test_01",
			request: func(path string) *models.Request {
				return testutil.OCIComputeRequest(path, "oci_vm_test_01", "oci-vm-test-01", false)
			},
		},
		{
			name: "OCI network", provider: "oci", module: "network",
			resourceName: "oci_network_test_01",
			request: func(path string) *models.Request {
				return testutil.OCINetworkRequest(
					path, "oci_network_test_01", "oci-network-test-01",
					"oci_subnet_test_01", "oci-subnet-test-01", "10.91.0.0/16", "10.91.1.0/24",
					"oci_igw_test_01", "oci-igw-test-01", "oci_rt_test_01", "oci-rt-test-01", false,
				)
			},
		},
		{
			name: "OCI storage", provider: "oci", module: "storage",
			resourceName: "oci_bucket_test_01",
			request: func(path string) *models.Request {
				return testutil.OCIStorageRequest(
					path, "oci_bucket_test_01", "oci-bucket-test-01",
					"NoPublicAccess", "Standard", "Enabled", true,
				)
			},
		},
		{
			name: "OCI IAM", provider: "oci", module: "iam",
			resourceName: "oci_user_test_01",
			request: func(path string) *models.Request {
				return testutil.OCIIAMRequest(
					path, "oci_user_test_01", "oci-user-test-01",
					"oci_group_test_01", "oci-group-test-01", "oci_membership_test_01",
					"oci_policy_test_01", "oci-policy-test-01",
					[]string{"Allow group oci-group-test-01 to read metrics in tenancy"},
				)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			modulePath := filepath.Join(
				root, "generated", test.provider, "modules", test.module,
			)
			if err := generator.GenerateAtomically(test.request(modulePath)); err != nil {
				t.Fatal(err)
			}
			mainContent, err := os.ReadFile(filepath.Join(modulePath, "main.tf"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(mainContent), `"`+test.resourceName+`"`) {
				t.Fatalf("canonical module does not contain %s", test.resourceName)
			}
			assertCanonicalRootAndNoLegacy(t, root, test.provider, test.module)
		})
	}
}

func assertCanonicalRootAndNoLegacy(
	t *testing.T,
	root string,
	provider string,
	module string,
) {
	t.Helper()
	providerRoot := filepath.Join(root, "generated", provider)
	legacy := filepath.Join(providerRoot, module)
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy path exists: %s", legacy)
	}
	rootMain, err := os.ReadFile(filepath.Join(providerRoot, "main.tf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rootMain), `module "`+module+`"`) ||
		!strings.Contains(string(rootMain), `"./modules/`+module+`"`) {
		t.Fatalf("root does not reference canonical %s module:\n%s", module, rootMain)
	}
}
