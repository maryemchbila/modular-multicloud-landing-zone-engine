package validation_test

import (
	"path/filepath"
	"strings"
	"testing"

	"hcl-generator/models"
	"hcl-generator/validation"
)

func TestGCPComputeCreateAndUpdateRequireProjectID(t *testing.T) {
	for _, action := range []string{"create", "update"} {
		t.Run(action, func(t *testing.T) {
			request := &models.Request{
				Action: action, Provider: "gcp", Module: "compute",
				ModulePath: filepath.Join(
					t.TempDir(), "generated", "gcp", "modules", "compute",
				),
				ComputeResource: &models.ComputeRequest{
					ResourceName: "vm_project_01",
					Name:         "vm-project-01",
					MachineType:  "e2-medium",
					Zone:         "europe-west1-b",
					Image:        "debian-cloud/debian-12",
					Network:      "default",
				},
			}

			err := validation.ValidateRequest(request)
			if err == nil || !strings.Contains(err.Error(), "project_id") {
				t.Fatalf("missing project_id was not rejected: %v", err)
			}
		})
	}
}
