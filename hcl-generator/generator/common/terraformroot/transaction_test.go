package terraformroot_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"hcl-generator/generator/common/terraformroot"
)

func TestCommitPreparedFilesRollsBackEveryCommittedFile(t *testing.T) {
	root := t.TempDir()
	gcpRoot := filepath.Join(root, "gcp")
	ociRoot := filepath.Join(root, "oci")
	if err := os.MkdirAll(gcpRoot, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(ociRoot, 0755); err != nil {
		t.Fatal(err)
	}

	firstPath := filepath.Join(gcpRoot, "versions.tf")
	original := []byte("original\n")
	if err := os.WriteFile(firstPath, original, 0644); err != nil {
		t.Fatal(err)
	}
	invalidTarget := filepath.Join(ociRoot, "versions.tf")
	if err := os.Mkdir(invalidTarget, 0755); err != nil {
		t.Fatal(err)
	}

	err := terraformroot.CommitPreparedFiles(map[string][]byte{
		firstPath:     []byte("replacement\n"),
		invalidTarget: []byte("must not be written\n"),
	})
	if err == nil {
		t.Fatal("la transaction aurait du echouer")
	}
	after, readErr := os.ReadFile(firstPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(after, original) {
		t.Fatalf("rollback incomplet : %q", after)
	}
	if info, statErr := os.Stat(invalidTarget); statErr != nil || !info.IsDir() {
		t.Fatalf("la cible invalide a change : info=%v err=%v", info, statErr)
	}
}
