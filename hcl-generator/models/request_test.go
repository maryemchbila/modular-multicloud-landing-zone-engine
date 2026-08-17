package models_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"hcl-generator/models"
)

func TestEveryGCPModuleParsesTopLevelProjectID(t *testing.T) {
	for _, module := range []string{"compute", "network", "storage", "iam"} {
		t.Run(module, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "request.json")
			payload := fmt.Sprintf(
				`{"action":"create","provider":"gcp","module":%q,`+
					`"module_path":"generated/gcp/modules/%s",`+
					`"project_id":"example-test-project","resource":{}}`,
				module,
				module,
			)
			if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
				t.Fatal(err)
			}

			request, err := models.LoadRequest(path)
			if err != nil {
				t.Fatal(err)
			}
			if request.ProjectID != "example-test-project" {
				t.Fatalf("ProjectID = %q", request.ProjectID)
			}
		})
	}
}
