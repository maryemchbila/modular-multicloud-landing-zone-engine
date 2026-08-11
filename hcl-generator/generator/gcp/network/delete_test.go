package network_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hcl-generator/generator"
	"hcl-generator/generator/common"
	"hcl-generator/generator/internal/testutil"
	"hcl-generator/models"
	"hcl-generator/validation"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

func TestNetworkDeleteRemovesOnlyTargetPair(t *testing.T) {
	root := filepath.Join(t.TempDir(), "generated", "gcp", "modules")
	modulePath := filepath.Join(root, "network")
	createNetworkDeletePair(t, modulePath, "a", "10.190.0.0/24")
	createNetworkDeletePair(t, modulePath, "b", "10.191.0.0/24")

	if err := generator.GenerateAtomically(testutil.NetworkDeleteRequest(
		modulePath,
		"vpc_delete_a_01",
		"subnet_delete_a_01")); err != nil {
		t.Fatalf("Network Delete failed: %v", err)
	}

	after := testutil.SnapshotTerraformFiles(t, modulePath)
	for _, filename := range testutil.TerraformFilenames {
		if bytes.Contains(after[filename], []byte("delete_a_01")) {
			t.Fatalf("%s still contains the deleted network pair", filename)
		}
		if !bytes.Contains(after[filename], []byte("delete_b_01")) {
			t.Fatalf("%s lost the independent network pair", filename)
		}
		if bytes.Contains(after[filename], []byte("\n\n\n")) {
			t.Fatalf("%s contains excessive blank lines after delete", filename)
		}
	}

	mainContent := string(after["main.tf"])
	if count := strings.Count(
		mainContent,
		`resource "google_compute_network" "vpc_delete_b_01"`,
	); count != 1 {
		t.Fatalf("remaining VPC count = %d, want 1", count)
	}
	if count := strings.Count(
		mainContent,
		`resource "google_compute_subnetwork" "subnet_delete_b_01"`,
	); count != 1 {
		t.Fatalf("remaining subnet count = %d, want 1", count)
	}
	if count := strings.Count(
		string(after["variables.tf"]),
		`variable "`,
	); count != 4 {
		t.Fatalf("remaining variable count = %d, want 4", count)
	}
	if count := len(afterTfvarsKeys(t, after["terraform.tfvars"])); count != 4 {
		t.Fatalf("remaining tfvars count = %d, want 4", count)
	}
	if count := strings.Count(string(after["outputs.tf"]), `output "`); count != 2 {
		t.Fatalf("remaining output count = %d, want 2", count)
	}
}

func TestNetworkDeleteMissingResourcesDoNotModifyFiles(t *testing.T) {
	root := filepath.Join(t.TempDir(), "generated", "gcp", "modules")
	modulePath := filepath.Join(root, "network")
	createNetworkDeletePair(t, modulePath, "test", "10.190.0.0/24")
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	missingVPC := testutil.NetworkDeleteRequest(
		modulePath,
		"vpc_inexistant_999",
		"subnet_delete_test_01")

	err := generator.GenerateAtomically(missingVPC)
	if err == nil ||
		err.Error() != "Network resource not found: vpc_inexistant_999" {
		t.Fatalf("unexpected missing VPC error: %v", err)
	}
	testutil.AssertTerraformFilesEqual(t, before, testutil.SnapshotTerraformFiles(t, modulePath))

	missingSubnet := testutil.NetworkDeleteRequest(
		modulePath,
		"vpc_delete_test_01",
		"subnet_inexistant_999")

	err = generator.GenerateAtomically(missingSubnet)
	if err == nil ||
		err.Error() != "Subnetwork resource not found: subnet_inexistant_999" {
		t.Fatalf("unexpected missing subnet error: %v", err)
	}
	testutil.AssertTerraformFilesEqual(t, before, testutil.SnapshotTerraformFiles(t, modulePath))
}

func TestNetworkDeleteRejectsMismatchedPair(t *testing.T) {
	root := filepath.Join(t.TempDir(), "generated", "gcp", "modules")
	modulePath := filepath.Join(root, "network")
	createNetworkDeletePair(t, modulePath, "a", "10.190.0.0/24")
	createNetworkDeletePair(t, modulePath, "b", "10.191.0.0/24")
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	err := generator.GenerateAtomically(testutil.NetworkDeleteRequest(
		modulePath,
		"vpc_delete_a_01",
		"subnet_delete_b_01"))

	if err == nil ||
		err.Error() !=
			"Subnetwork subnet_delete_b_01 is not linked to network vpc_delete_a_01" {
		t.Fatalf("unexpected mismatched pair error: %v", err)
	}
	testutil.AssertTerraformFilesEqual(t, before, testutil.SnapshotTerraformFiles(t, modulePath))
}

func TestNetworkDeleteBlocksInternalDependency(t *testing.T) {
	root := filepath.Join(t.TempDir(), "generated", "gcp", "modules")
	modulePath := filepath.Join(root, "network")
	createNetworkDeletePair(t, modulePath, "a", "10.190.0.0/24")
	createNetworkDeletePair(t, modulePath, "b", "10.191.0.0/24")

	files, err := common.LoadExistingTerraformFiles(modulePath)
	if err != nil {
		t.Fatalf("load Network fixture: %v", err)
	}
	dependent := common.FindBlock(
		files.Main,
		"resource",
		"google_compute_network",
		"vpc_delete_b_01",
	)
	if dependent == nil {
		t.Fatal("dependent VPC is missing")
	}
	dependent.Body().SetAttributeTraversal(
		"peer_network",
		common.ResourceTraversal(
			"google_compute_network",
			"vpc_delete_a_01",
			"id",
		),
	)
	if err := os.WriteFile(
		filepath.Join(modulePath, "main.tf"),
		common.FormattedBytes(files.Main),
		0o644,
	); err != nil {
		t.Fatalf("write Network dependency fixture: %v", err)
	}
	before := testutil.SnapshotTerraformFiles(t, modulePath)

	err = generator.GenerateAtomically(testutil.NetworkDeleteRequest(
		modulePath,
		"vpc_delete_a_01",
		"subnet_delete_a_01"))

	if err == nil ||
		err.Error() !=
			"Cannot delete network vpc_delete_a_01: resource is referenced by another block" {
		t.Fatalf("unexpected internal dependency error: %v", err)
	}
	testutil.AssertTerraformFilesEqual(t, before, testutil.SnapshotTerraformFiles(t, modulePath))
}

func TestNetworkDeleteBlocksCertainComputeDependency(t *testing.T) {
	root := filepath.Join(t.TempDir(), "generated", "gcp", "modules")
	networkPath := filepath.Join(root, "network")
	computePath := filepath.Join(root, "compute")
	createNetworkDeletePair(t, networkPath, "test", "10.190.0.0/24")
	if err := generator.GenerateAtomically(&models.Request{
		Action:     "create",
		Provider:   "gcp",
		Module:     "compute",
		ModulePath: computePath,
		ComputeResource: &models.ComputeRequest{
			ResourceName: "vm_network_consumer_01",
			Name:         "vm-network-consumer-01",
			MachineType:  "e2-medium",
			Zone:         "europe-west1-b",
			Image:        "debian-cloud/debian-12",
			Network:      "vpc-delete-test-01",
		},
	}); err != nil {
		t.Fatalf("Compute Create failed: %v", err)
	}
	before := testutil.SnapshotTerraformFiles(t, networkPath)

	err := generator.GenerateAtomically(testutil.NetworkDeleteRequest(
		networkPath,
		"vpc_delete_test_01",
		"subnet_delete_test_01"))

	if err == nil ||
		err.Error() !=
			"Cannot delete network vpc_delete_test_01: referenced by Compute configuration" {
		t.Fatalf("unexpected Compute dependency error: %v", err)
	}
	testutil.AssertTerraformFilesEqual(t, before, testutil.SnapshotTerraformFiles(t, networkPath))
}

func TestNetworkDeleteNonRegressionAndModuleIsolation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "generated", "gcp", "modules")
	computePath := filepath.Join(root, "compute")
	networkPath := filepath.Join(root, "network")
	storagePath := filepath.Join(root, "storage")

	for _, resourceName := range []string{"vm_network_delete_01", "vm_network_keep_01"} {
		if err := generator.GenerateAtomically(testutil.ComputeRequest(
			"create",
			computePath,
			resourceName,
			strings.ReplaceAll(resourceName, "_", "-"),
			"e2-medium")); err != nil {
			t.Fatalf("Compute Create %s failed: %v", resourceName, err)
		}
	}
	if err := generator.GenerateAtomically(testutil.ComputeRequest(
		"update",
		computePath,
		"vm_network_keep_01",
		"vm-network-keep-production",
		"e2-standard-2")); err != nil {
		t.Fatalf("Compute Update failed: %v", err)
	}
	if err := generator.GenerateAtomically(testutil.ComputeDeleteRequest(
		computePath,
		"vm_network_delete_01")); err != nil {
		t.Fatalf("Compute Delete failed: %v", err)
	}

	createNetworkDeletePair(t, networkPath, "a", "10.190.0.0/24")
	createNetworkDeletePair(t, networkPath, "b", "10.191.0.0/24")
	if err := generator.GenerateAtomically(testutil.NetworkRequest(
		"update",
		networkPath,
		"vpc_delete_b_01",
		"vpc-delete-b-production",
		"subnet_delete_b_01",
		"subnet-delete-b-production",
		"10.192.0.0/24",
		"europe-west3")); err != nil {
		t.Fatalf("Network Update failed: %v", err)
	}

	if err := generator.GenerateAtomically(testutil.StorageRequest(
		"create",
		storagePath,
		"bucket_network_delete_01",
		"stage2026-network-delete-01",
		"EU",
		"STANDARD",
		true)); err != nil {
		t.Fatalf("Storage Create failed: %v", err)
	}
	if err := generator.GenerateAtomically(testutil.StorageRequest(
		"update",
		storagePath,
		"bucket_network_delete_01",
		"stage2026-network-delete-production",
		"EUROPE-WEST1",
		"COLDLINE",
		false)); err != nil {
		t.Fatalf("Storage Update failed: %v", err)
	}

	computeBefore := testutil.SnapshotTerraformFiles(t, computePath)
	storageBefore := testutil.SnapshotTerraformFiles(t, storagePath)
	if err := generator.GenerateAtomically(testutil.NetworkDeleteRequest(
		networkPath,
		"vpc_delete_a_01",
		"subnet_delete_a_01")); err != nil {
		t.Fatalf("Network Delete failed: %v", err)
	}
	testutil.AssertModuleFilesEqual(
		t,
		computeBefore,
		testutil.SnapshotTerraformFiles(t, computePath))

	testutil.AssertModuleFilesEqual(
		t,
		storageBefore,
		testutil.SnapshotTerraformFiles(t, storagePath))

	createNetworkDeletePair(t, networkPath, "after", "10.193.0.0/24")
	if err := generator.GenerateAtomically(testutil.NetworkRequest(
		"update",
		networkPath,
		"vpc_delete_b_01",
		"vpc-delete-b-final",
		"subnet_delete_b_01",
		"subnet-delete-b-final",
		"10.194.0.0/24",
		"europe-west1")); err != nil {
		t.Fatalf("Network Update after Delete failed: %v", err)
	}
}

func TestNetworkDeleteValidationUsesOnlyIdentifiers(t *testing.T) {
	request := testutil.NetworkDeleteRequest(
		filepath.Join(t.TempDir(), "generated", "gcp", "modules", "network"),
		"vpc_delete_test_01",
		"subnet_delete_test_01")

	if err := validation.ValidateRequest(request); err != nil {
		t.Fatalf("minimal Network Delete validation failed: %v", err)
	}

	request.NetworkResource.SubnetResourceName = "invalid subnet"
	if err := validation.ValidateRequest(request); err == nil {
		t.Fatal("invalid Terraform subnet identifier was accepted")
	}
}

func createNetworkDeletePair(
	t *testing.T,
	modulePath string,
	suffix string,
	cidr string,
) {
	t.Helper()
	if err := generator.GenerateAtomically(testutil.NetworkRequest(
		"create",
		modulePath,
		"vpc_delete_"+suffix+"_01",
		"vpc-delete-"+suffix+"-01",
		"subnet_delete_"+suffix+"_01",
		"subnet-delete-"+suffix+"-01",
		cidr,
		"europe-west1")); err != nil {
		t.Fatalf("Network Create %s failed: %v", suffix, err)
	}
}

func afterTfvarsKeys(t *testing.T, content []byte) []string {
	t.Helper()
	file, diagnostics := hclwrite.ParseConfig(
		content,
		"terraform.tfvars",
		hcl.InitialPos,
	)
	if diagnostics.HasErrors() {
		t.Fatalf("parse terraform.tfvars: %s", diagnostics.Error())
	}
	keys := make([]string, 0, len(file.Body().Attributes()))
	for key := range file.Body().Attributes() {
		keys = append(keys, key)
	}
	return keys
}
