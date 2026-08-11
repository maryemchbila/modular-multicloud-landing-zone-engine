package validation_test

import (
	"path/filepath"
	"testing"

	"hcl-generator/models"
	"hcl-generator/validation"
)

func TestValidateRequestAcceptsOnlyCanonicalModulePath(t *testing.T) {
	root := t.TempDir()
	newRequest := func(modulePath string) *models.Request {
		request := &models.Request{
			Action:     "create",
			Provider:   "gcp",
			Module:     "compute",
			ModulePath: modulePath,
			ComputeResource: &models.ComputeRequest{
				ResourceName: "vm_path_01",
				Name:         "vm-path-01",
				MachineType:  "e2-medium",
				Zone:         "europe-west1-b",
				Image:        "debian-cloud/debian-12",
				Network:      "default",
			},
		}
		return request
	}

	legacy := filepath.Join(root, "generated", "gcp", "compute")
	if err := validation.ValidateRequest(newRequest(legacy)); err == nil {
		t.Fatal("legacy module path was accepted")
	}

	canonical := filepath.Join(root, "generated", "gcp", "modules", "compute")
	if err := validation.ValidateRequest(newRequest(canonical)); err != nil {
		t.Fatalf("canonical path rejected: %v", err)
	}
}
