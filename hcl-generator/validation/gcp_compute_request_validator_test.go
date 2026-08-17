package validation_test

import (
	"path/filepath"
	"strings"
	"testing"

	"hcl-generator/models"
	"hcl-generator/validation"
)

func TestEveryGCPModuleActionRequiresProjectID(t *testing.T) {
	for _, module := range []string{"compute", "network", "storage", "iam"} {
		for _, action := range []string{"create", "update", "delete"} {
			t.Run(module+"/"+action, func(t *testing.T) {
				request := &models.Request{
					Action: action, Provider: "gcp", Module: module,
					ModulePath: filepath.Join(
						t.TempDir(), "generated", "gcp", "modules", module,
					),
				}

				err := validation.ValidateRequest(request)
				if err == nil || !strings.Contains(err.Error(), "project_id") {
					t.Fatalf("missing project_id was not rejected: %v", err)
				}
			})
		}
	}
}
