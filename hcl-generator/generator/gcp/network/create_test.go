package network_test

import (
	"bytes"
	"strings"
	"testing"

	"hcl-generator/generator"
	"hcl-generator/generator/internal/testutil"
)

func TestCreateNetwork(t *testing.T) {
	modulePath := t.TempDir()
	request := testutil.NetworkRequest(
		"create",
		modulePath,
		"vpc_test",
		"vpc-test",
		"subnet_test",
		"subnet-test",
		"10.20.0.0/24",
		"europe-west1",
	)
	if err := generator.GenerateAtomically(request); err != nil {
		t.Fatalf("Network Create failed: %v", err)
	}

	beforeDuplicate := testutil.SnapshotTerraformFiles(t, modulePath)
	mainContent := string(beforeDuplicate["main.tf"])
	for _, expected := range []string{
		`resource "google_compute_network" "vpc_test"`,
		`resource "google_compute_subnetwork" "subnet_test"`,
		"network       = google_compute_network.vpc_test.id",
	} {
		if !strings.Contains(mainContent, expected) {
			t.Fatalf("main.tf is missing %q", expected)
		}
	}

	if err := generator.GenerateAtomically(request); err == nil {
		t.Fatal("duplicate Network Create unexpectedly succeeded")
	}
	afterDuplicate := testutil.SnapshotTerraformFiles(t, modulePath)
	for _, filename := range testutil.TerraformFilenames {
		if !bytes.Equal(
			beforeDuplicate[filename],
			afterDuplicate[filename],
		) {
			t.Fatalf("%s changed after duplicate Network Create", filename)
		}
	}
}
