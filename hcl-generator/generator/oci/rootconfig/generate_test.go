package rootconfig_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gcproot "hcl-generator/generator/gcp/rootconfig"
	ocicroot "hcl-generator/generator/oci/rootconfig"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

func TestEnsureOCIRootConfigurationCreatesValidFilesWithTraversal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "generated", "oci")
	if err := ocicroot.EnsureOCIRootConfiguration(root); err != nil {
		t.Fatalf("generation OCI impossible : %v", err)
	}

	versions := parseOCIFile(t, filepath.Join(root, "versions.tf"))
	terraformBlock := findOCIBlock(versions.Body(), "terraform", "")
	if terraformBlock == nil {
		t.Fatal("bloc terraform absent")
	}
	requiredProviders := findOCIBlock(terraformBlock.Body(), "required_providers", "")
	if requiredProviders == nil ||
		requiredProviders.Body().GetAttribute("oci") == nil {
		t.Fatal("required_providers.oci absent")
	}

	providers := parseOCIFile(t, filepath.Join(root, "providers.tf"))
	providerBlock := findOCIBlock(providers.Body(), "provider", "oci")
	if providerBlock == nil {
		t.Fatal(`provider "oci" absent`)
	}
	region := providerBlock.Body().GetAttribute("region")
	if region == nil {
		t.Fatal("region absente")
	}
	traversals := region.Expr().Variables()
	expression := strings.TrimSpace(string(region.Expr().BuildTokens(nil).Bytes()))
	if len(traversals) != 1 || expression != "var.oci_region" {
		t.Fatalf("region n'est pas un traversal : %s", region.Expr().BuildTokens(nil).Bytes())
	}

	variables := parseOCIFile(t, filepath.Join(root, "variables.tf"))
	if countOCIBlocks(variables.Body(), "variable", "oci_region") != 1 {
		t.Fatal("oci_region absente ou dupliquee")
	}
	assertOCINoSecrets(t, root)
}

func TestEnsureOCIRootConfigurationIsIdempotentAndPreservesContent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "generated", "oci")
	writeOCIFile(t, filepath.Join(root, "versions.tf"), `terraform {
  required_version = ">= 1.7.0"
}

locals { keep_versions = true }
`)
	writeOCIFile(t, filepath.Join(root, "providers.tf"), `locals { keep_providers = true }
`)
	writeOCIFile(t, filepath.Join(root, "variables.tf"), `variable "oci_region" {
  type    = string
  default = "us-ashburn-1"
}
`)
	if err := ocicroot.EnsureOCIRootConfiguration(root); err != nil {
		t.Fatal(err)
	}
	before := snapshotOCI(t, root)
	if err := ocicroot.EnsureOCIRootConfiguration(root); err != nil {
		t.Fatal(err)
	}
	after := snapshotOCI(t, root)
	for path, expected := range before {
		if !bytes.Equal(expected, after[path]) {
			t.Fatalf("%s n'est pas idempotent", path)
		}
	}
	for path, values := range map[string][]string{
		filepath.Join(root, "versions.tf"):  {`required_version = ">= 1.7.0"`, "keep_versions"},
		filepath.Join(root, "providers.tf"): {"keep_providers", `provider "oci"`},
		filepath.Join(root, "variables.tf"): {`default = "us-ashburn-1"`},
	} {
		content := string(readOCIFile(t, path))
		for _, value := range values {
			if !strings.Contains(content, value) {
				t.Fatalf("%s ne preserve pas %q", path, value)
			}
		}
	}
	versions := parseOCIFile(t, filepath.Join(root, "versions.tf"))
	terraformBlock := findOCIBlock(versions.Body(), "terraform", "")
	if countOCIBlocks(versions.Body(), "terraform", "") != 1 ||
		countOCIBlocks(terraformBlock.Body(), "required_providers", "") != 1 {
		t.Fatal("configuration OCI dupliquee")
	}
}

func TestEnsureOCIRootConfigurationIsIsolatedFromGCP(t *testing.T) {
	generated := filepath.Join(t.TempDir(), "generated")
	gcpRoot := filepath.Join(generated, "gcp")
	ociRoot := filepath.Join(generated, "oci")
	if err := gcproot.EnsureGCPRootConfiguration(gcpRoot); err != nil {
		t.Fatal(err)
	}
	gcpBefore := snapshotOCI(t, gcpRoot)
	if err := ocicroot.EnsureOCIRootConfiguration(ociRoot); err != nil {
		t.Fatal(err)
	}
	gcpAfter := snapshotOCI(t, gcpRoot)
	for path, expected := range gcpBefore {
		if !bytes.Equal(expected, gcpAfter[path]) {
			t.Fatalf("OCI a modifie %s", path)
		}
	}
	for _, content := range snapshotOCI(t, ociRoot) {
		if bytes.Contains(content, []byte(`provider "google"`)) ||
			bytes.Contains(content, []byte("gcp_project_id")) {
			t.Fatal("la configuration OCI contient des elements GCP")
		}
	}
}

func parseOCIFile(t *testing.T, path string) *hclwrite.File {
	t.Helper()
	content := readOCIFile(t, path)
	file, diagnostics := hclwrite.ParseConfig(content, path, hcl.InitialPos)
	if diagnostics.HasErrors() {
		t.Fatalf("HCL OCI invalide dans %s : %s", path, diagnostics.Error())
	}
	return file
}

func findOCIBlock(body *hclwrite.Body, blockType, label string) *hclwrite.Block {
	for _, block := range body.Blocks() {
		labels := block.Labels()
		if block.Type() == blockType &&
			((label == "" && len(labels) == 0) ||
				(len(labels) == 1 && labels[0] == label)) {
			return block
		}
	}
	return nil
}

func countOCIBlocks(body *hclwrite.Body, blockType, label string) int {
	count := 0
	for _, block := range body.Blocks() {
		labels := block.Labels()
		if block.Type() == blockType &&
			((label == "" && len(labels) == 0) ||
				(len(labels) == 1 && labels[0] == label)) {
			count++
		}
	}
	return count
}

func assertOCINoSecrets(t *testing.T, root string) {
	t.Helper()
	for path, content := range snapshotOCI(t, root) {
		lower := strings.ToLower(string(content))
		for _, forbidden := range []string{
			"private_key", "password", "token", "fingerprint", "client_secret",
		} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("%s contient %q", path, forbidden)
			}
		}
	}
}

func snapshotOCI(t *testing.T, root string) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	for _, name := range []string{"versions.tf", "providers.tf", "variables.tf"} {
		path := filepath.Join(root, name)
		result[path] = readOCIFile(t, path)
	}
	return result
}

func writeOCIFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func readOCIFile(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("lecture de %s impossible : %v", path, err)
	}
	return content
}
