package validation_test

import (
	"path/filepath"
	"testing"

	"hcl-generator/models"
	"hcl-generator/validation"
)

func TestValidateRequestAcceptsLegacyAndCanonicalModulePaths(t *testing.T) {
	root := t.TempDir()
	for _, modulePath := range []string{
		filepath.Join(root, "generated", "gcp", "compute"),
		filepath.Join(root, "generated", "gcp", "modules", "compute"),
	} {
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
		if err := validation.ValidateRequest(request); err != nil {
			t.Fatalf("path %s rejected: %v", modulePath, err)
		}
	}
}
