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

func TestEnsureGCPRootConfigurationCreatesValidFilesWithTraversals(t *testing.T) {
	root := filepath.Join(t.TempDir(), "generated", "gcp")
	if err := gcproot.EnsureGCPRootConfiguration(root); err != nil {
		t.Fatalf("generation GCP impossible : %v", err)
	}

	versions := parseFile(t, filepath.Join(root, "versions.tf"))
	if countBlocks(versions.Body(), "terraform", "") != 1 {
		t.Fatal("versions.tf doit contenir exactement un bloc terraform")
	}
	terraformBlock := firstBlock(versions.Body(), "terraform", "")
	requiredProviders := firstBlock(terraformBlock.Body(), "required_providers", "")
	if requiredProviders == nil ||
		requiredProviders.Body().GetAttribute("google") == nil {
		t.Fatal("required_providers.google est absent")
	}

	providers := parseFile(t, filepath.Join(root, "providers.tf"))
	providerBlock := firstBlock(providers.Body(), "provider", "google")
	if providerBlock == nil {
		t.Fatal(`provider "google" est absent`)
	}
	assertTraversal(t, providerBlock, "project", "gcp_project_id")
	assertTraversal(t, providerBlock, "region", "gcp_region")
	assertTraversal(t, providerBlock, "zone", "gcp_zone")

	variables := parseFile(t, filepath.Join(root, "variables.tf"))
	for _, name := range []string{"gcp_project_id", "gcp_region", "gcp_zone"} {
		if countBlocks(variables.Body(), "variable", name) != 1 {
			t.Fatalf("variable %s absente ou dupliquee", name)
		}
	}
	assertNoSecrets(t, root)
}

func TestEnsureGCPRootConfigurationIsIdempotentAndHasNoDuplicates(t *testing.T) {
	root := filepath.Join(t.TempDir(), "generated", "gcp")
	if err := gcproot.EnsureGCPRootConfiguration(root); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, root)
	if err := gcproot.EnsureGCPRootConfiguration(root); err != nil {
		t.Fatal(err)
	}
	after := snapshot(t, root)
	assertSnapshotsEqual(t, before, after)

	versions := parseFile(t, filepath.Join(root, "versions.tf"))
	terraformBlock := firstBlock(versions.Body(), "terraform", "")
	if countBlocks(versions.Body(), "terraform", "") != 1 ||
		countBlocks(terraformBlock.Body(), "required_providers", "") != 1 {
		t.Fatal("blocs terraform ou required_providers dupliques")
	}
	providers := parseFile(t, filepath.Join(root, "providers.tf"))
	if countBlocks(providers.Body(), "provider", "google") != 1 {
		t.Fatal(`provider "google" duplique`)
	}
}

func TestEnsureGCPRootConfigurationPreservesExistingContent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "generated", "gcp")
	writeFile(t, filepath.Join(root, "versions.tf"), `terraform {
  required_version = ">= 1.6.0"
  required_providers {
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

locals { preserved_versions = true }
`)
	writeFile(t, filepath.Join(root, "providers.tf"), `locals { preserved_providers = true }
`)
	writeFile(t, filepath.Join(root, "variables.tf"), `variable "gcp_region" {
  type    = string
  default = "us-central1"
}

variable "application_name" { type = string }
`)

	if err := gcproot.EnsureGCPRootConfiguration(root); err != nil {
		t.Fatal(err)
	}
	assertContains(t, filepath.Join(root, "versions.tf"),
		`required_version = ">= 1.6.0"`, "random", "preserved_versions")
	assertContains(t, filepath.Join(root, "providers.tf"),
		"preserved_providers", `provider "google"`)
	assertContains(t, filepath.Join(root, "variables.tf"),
		`default = "us-central1"`, `variable "application_name"`)
	if bytes.Count(readFile(t, filepath.Join(root, "variables.tf")),
		[]byte(`variable "gcp_region"`)) != 1 {
		t.Fatal("gcp_region a ete dupliquee")
	}
}

func TestEnsureGCPRootConfigurationIsIsolatedFromOCI(t *testing.T) {
	generated := filepath.Join(t.TempDir(), "generated")
	gcpRoot := filepath.Join(generated, "gcp")
	ociRoot := filepath.Join(generated, "oci")
	if err := ocicroot.EnsureOCIRootConfiguration(ociRoot); err != nil {
		t.Fatal(err)
	}
	ociBefore := snapshot(t, ociRoot)
	if err := gcproot.EnsureGCPRootConfiguration(gcpRoot); err != nil {
		t.Fatal(err)
	}
	assertSnapshotsEqual(t, ociBefore, snapshot(t, ociRoot))
	for _, content := range snapshot(t, gcpRoot) {
		if bytes.Contains(content, []byte(`provider "oci"`)) ||
			bytes.Contains(content, []byte("oci_region")) {
			t.Fatal("la configuration GCP contient des elements OCI")
		}
	}
}

func TestEnsureGCPRootConfigurationRejectsDuplicateTerraformBlocks(t *testing.T) {
	root := filepath.Join(t.TempDir(), "generated", "gcp")
	path := filepath.Join(root, "versions.tf")
	original := []byte("terraform {}\nterraform {}\n")
	writeFile(t, path, string(original))
	err := gcproot.EnsureGCPRootConfiguration(root)
	if err == nil || !strings.Contains(err.Error(), "plusieurs blocs terraform") {
		t.Fatalf("erreur explicite attendue, obtenu : %v", err)
	}
	if !bytes.Equal(original, readFile(t, path)) {
		t.Fatal("le fichier invalide a ete modifie")
	}
}

func parseFile(t *testing.T, path string) *hclwrite.File {
	t.Helper()
	content := readFile(t, path)
	file, diagnostics := hclwrite.ParseConfig(content, path, hcl.InitialPos)
	if diagnostics.HasErrors() {
		t.Fatalf("HCL invalide dans %s : %s", path, diagnostics.Error())
	}
	return file
}

func firstBlock(body *hclwrite.Body, blockType string, label string) *hclwrite.Block {
	for _, block := range body.Blocks() {
		if block.Type() != blockType {
			continue
		}
		labels := block.Labels()
		if label == "" && len(labels) == 0 {
			return block
		}
		if len(labels) == 1 && labels[0] == label {
			return block
		}
	}
	return nil
}

func countBlocks(body *hclwrite.Body, blockType string, label string) int {
	count := 0
	for _, block := range body.Blocks() {
		if block.Type() != blockType {
			continue
		}
		labels := block.Labels()
		if (label == "" && len(labels) == 0) ||
			(len(labels) == 1 && labels[0] == label) {
			count++
		}
	}
	return count
}

func assertTraversal(
	t *testing.T,
	block *hclwrite.Block,
	attribute string,
	variable string,
) {
	t.Helper()
	value := block.Body().GetAttribute(attribute)
	if value == nil {
		t.Fatalf("attribut %s absent", attribute)
	}
	variables := value.Expr().Variables()
	expression := strings.TrimSpace(string(value.Expr().BuildTokens(nil).Bytes()))
	if len(variables) != 1 || expression != "var."+variable {
		t.Fatalf("%s n'est pas un traversal var.* : %s", attribute, value.Expr().BuildTokens(nil).Bytes())
	}
	if strings.Contains(expression, `"var.`) {
		t.Fatalf("%s a ete genere comme chaine", attribute)
	}
}

func assertNoSecrets(t *testing.T, root string) {
	t.Helper()
	for path, content := range snapshot(t, root) {
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

func snapshot(t *testing.T, root string) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	for _, name := range []string{"versions.tf", "providers.tf", "variables.tf"} {
		path := filepath.Join(root, name)
		result[path] = readFile(t, path)
	}
	return result
}

func assertSnapshotsEqual(t *testing.T, expected, actual map[string][]byte) {
	t.Helper()
	for path, content := range expected {
		if !bytes.Equal(content, actual[path]) {
			t.Fatalf("%s a change de maniere inattendue", path)
		}
	}
}

func assertContains(t *testing.T, path string, values ...string) {
	t.Helper()
	content := readFile(t, path)
	for _, value := range values {
		if !bytes.Contains(content, []byte(value)) {
			t.Fatalf("%s ne contient pas %q :\n%s", path, value, content)
		}
	}
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("lecture de %s impossible : %v", path, err)
	}
	return content
}
