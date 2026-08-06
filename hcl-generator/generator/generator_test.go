package generator_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hcl-generator/generator"
	"hcl-generator/generator/internal/testutil"
	"hcl-generator/models"
)

func TestProviderModuleActionRoutingAndIsolation(t *testing.T) {
	root := t.TempDir()
	gcpComputePath := filepath.Join(root, "generated", "gcp", "compute")
	gcpNetworkPath := filepath.Join(root, "generated", "gcp", "network")
	gcpStoragePath := filepath.Join(root, "generated", "gcp", "storage")
	ociComputePath := filepath.Join(root, "generated", "oci", "compute")

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
	testutil.AssertTerraformFilesEqual(
		t,
		networkBefore,
		testutil.SnapshotTerraformFiles(t, gcpNetworkPath),
	)
	testutil.AssertTerraformFilesEqual(
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
