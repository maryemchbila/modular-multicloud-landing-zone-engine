package clientpaths

import (
	"path/filepath"
	"testing"
)

func TestBuildClientPaths(t *testing.T) {
	projectRoot := t.TempDir()
	root, err := BuildClientRoot(projectRoot, "example-client", "dev", "gcp")
	if err != nil {
		t.Fatalf("build root: %v", err)
	}
	if root != filepath.Join(
		projectRoot, "runtime", "clients", "example-client", "dev", "gcp",
	) {
		t.Fatalf("unexpected root: %s", root)
	}
	layout, err := BuildClientModulePath(
		projectRoot, "example-client", "prod", "oci", "iam",
	)
	if err != nil {
		t.Fatalf("build module path: %v", err)
	}
	if layout.ModulePath != filepath.Join(
		projectRoot, "runtime", "clients", "example-client", "prod", "oci",
		"modules", "iam",
	) {
		t.Fatalf("unexpected module path: %s", layout.ModulePath)
	}
}

func TestBuildClientPathsRejectsTraversal(t *testing.T) {
	projectRoot := t.TempDir()
	tests := []struct {
		clientID, environment, provider, module string
	}{
		{"../../foo", "dev", "gcp", "compute"},
		{"company/a", "dev", "gcp", "compute"},
		{"company\\a", "dev", "gcp", "compute"},
		{"example-client", "../prod", "gcp", "compute"},
		{"example-client", "dev/../../prod", "gcp", "compute"},
		{"example-client", "dev", "../../", "compute"},
		{"example-client", "dev", "gcp", "../compute"},
	}
	for _, test := range tests {
		if _, err := BuildClientModulePath(
			projectRoot,
			test.clientID,
			test.environment,
			test.provider,
			test.module,
		); err == nil {
			t.Fatalf("unsafe path accepted: %+v", test)
		}
	}
}
