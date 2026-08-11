package rootmodule_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	gcproot "hcl-generator/generator/gcp/rootmodule"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

func TestEnsureGCPRootModuleCreatesOnlyCanonicalStructure(t *testing.T) {
	root := filepath.Join(t.TempDir(), "generated", "gcp")

	if err := gcproot.EnsureGCPRootModule(root); err != nil {
		t.Fatal(err)
	}
	assertCanonicalGCPFiles(t, root)
	main := parseGCP(t, filepath.Join(root, "main.tf"))
	if len(main.Body().Blocks()) != 0 {
		t.Fatal("an empty canonical module was called")
	}
	for _, moduleName := range []string{"compute", "network", "storage", "iam"} {
		if _, err := os.Stat(filepath.Join(root, moduleName)); !os.IsNotExist(err) {
			t.Fatalf("non-canonical module directory exists: %s", moduleName)
		}
	}

	before := snapshotGCP(t, root)
	if err := gcproot.EnsureGCPRootModule(root); err != nil {
		t.Fatal(err)
	}
	afterSnapshot := snapshotGCP(t, root)
	assertGCPSnapshot(t, before, afterSnapshot)
}

func assertCanonicalGCPFiles(t *testing.T, root string) {
	t.Helper()
	for _, name := range []string{
		"main.tf", "variables.tf", "terraform.tfvars", "outputs.tf",
		"providers.tf", "versions.tf",
	} {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			t.Fatalf("missing root file %s: %v", name, err)
		}
	}
	for _, moduleName := range []string{"compute", "network", "storage", "iam"} {
		for _, name := range []string{"main.tf", "variables.tf", "outputs.tf"} {
			path := filepath.Join(root, "modules", moduleName, name)
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("missing module file %s: %v", path, err)
			}
			parseGCP(t, path)
		}
	}
}

func parseGCP(t *testing.T, path string) *hclwrite.File {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	file, diagnostics := hclwrite.ParseConfig(content, path, hcl.InitialPos)
	if diagnostics.HasErrors() {
		t.Fatalf("invalid HCL in %s: %s", path, diagnostics.Error())
	}
	return file
}

func snapshotGCP(t *testing.T, root string) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			result[path] = content
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return result
}

func assertGCPSnapshot(t *testing.T, expected, actual map[string][]byte) {
	t.Helper()
	if len(expected) != len(actual) {
		t.Fatalf("snapshot size changed: %d != %d", len(expected), len(actual))
	}
	for path, content := range expected {
		if !bytes.Equal(content, actual[path]) {
			t.Fatalf("%s changed on second execution", path)
		}
	}
}
