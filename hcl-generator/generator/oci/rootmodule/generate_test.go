package rootmodule_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	ociroot "hcl-generator/generator/oci/rootmodule"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

func TestEnsureOCIRootModuleCreatesFourEmptyIsolatedModules(t *testing.T) {
	generated := filepath.Join(t.TempDir(), "generated")
	root := filepath.Join(generated, "oci")
	gcpSentinel := filepath.Join(generated, "gcp", "sentinel.tf")
	if err := os.MkdirAll(filepath.Dir(gcpSentinel), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gcpSentinel, []byte("gcp-unchanged\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ociroot.EnsureOCIRootModule(root); err != nil {
		t.Fatal(err)
	}
	for _, moduleName := range []string{"compute", "network", "storage", "iam"} {
		for _, name := range []string{"main.tf", "variables.tf", "outputs.tf"} {
			path := filepath.Join(root, "modules", moduleName, name)
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("missing module file %s: %v", path, err)
			}
			_, diagnostics := hclwrite.ParseConfig(content, path, hcl.InitialPos)
			if diagnostics.HasErrors() {
				t.Fatalf("invalid HCL in %s: %s", path, diagnostics.Error())
			}
		}
	}
	mainContent, err := os.ReadFile(filepath.Join(root, "main.tf"))
	if err != nil {
		t.Fatal(err)
	}
	mainFile, diagnostics := hclwrite.ParseConfig(
		mainContent,
		filepath.Join(root, "main.tf"),
		hcl.InitialPos,
	)
	if diagnostics.HasErrors() || len(mainFile.Body().Blocks()) != 0 {
		t.Fatal("OCI root must not call an empty module")
	}
	gcpAfter, _ := os.ReadFile(gcpSentinel)
	if !bytes.Equal(gcpAfter, []byte("gcp-unchanged\n")) {
		t.Fatal("OCI preparation modified GCP")
	}
}

func TestEnsureOCIRootModulePreservesExistingChildProviderVersion(t *testing.T) {
	root := filepath.Join(t.TempDir(), "generated", "oci")
	modulePath := filepath.Join(root, "modules", "compute")
	if err := os.MkdirAll(modulePath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(modulePath, "main.tf"),
		[]byte("resource \"oci_core_instance\" \"example\" {}\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	versionsPath := filepath.Join(modulePath, "versions.tf")
	versions := []byte(`terraform {
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = "= 8.23.0"
    }
  }
}
`)
	if err := os.WriteFile(versionsPath, versions, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ociroot.EnsureOCIRootModule(root); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(versionsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, versions) {
		t.Fatal("existing child provider version was modified")
	}
}
