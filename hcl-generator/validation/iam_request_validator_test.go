package validation

import (
	"path/filepath"
	"strings"
	"testing"

	"hcl-generator/models"
)

func TestValidateIAMRequest(t *testing.T) {
	valid := validIAMRequest(t)
	if err := ValidateRequest(valid); err != nil {
		t.Fatalf("valid IAM request rejected: %v", err)
	}
	valid.Action = "update"
	if err := ValidateRequest(valid); err != nil {
		t.Fatalf("valid IAM Update request rejected: %v", err)
	}

	for _, role := range []string{"roles/owner", "roles/editor"} {
		t.Run(role, func(t *testing.T) {
			request := validIAMRequest(t)
			request.IAMResource.Role = role
			err := ValidateRequest(request)
			if err == nil || !strings.Contains(err.Error(), role) {
				t.Fatalf("forbidden role returned unexpected error: %v", err)
			}
		})
	}

	malformed := validIAMRequest(t)
	malformed.Action = "update"
	malformed.IAMResource.Role = "logging.logWriter"
	err := ValidateRequest(malformed)
	if err == nil || err.Error() != "Le rôle IAM doit commencer par roles/" {
		t.Fatalf("malformed role returned unexpected error: %v", err)
	}
}

func TestValidateIAMDeleteUsesOnlyResourceName(t *testing.T) {
	request := validIAMRequest(t)
	request.Action = "delete"
	request.IAMResource = &models.IAMRequest{
		ResourceName: "sa_logging_01",
	}
	if err := ValidateRequest(request); err != nil {
		t.Fatalf("minimal IAM Delete request rejected: %v", err)
	}

	request.IAMResource.ResourceName = "1-invalid"
	err := ValidateRequest(request)
	if err == nil || !strings.Contains(err.Error(), "identifiant Terraform") {
		t.Fatalf("invalid IAM Delete identifier returned unexpected error: %v", err)
	}
}

func TestValidateIAMRejectsWrongPath(t *testing.T) {
	request := validIAMRequest(t)
	request.ModulePath = filepath.Join(
		t.TempDir(),
		"generated",
		"gcp",
		"modules",
		"compute",
	)
	err := ValidateRequest(request)
	if err == nil || !strings.Contains(err.Error(), "generated/gcp/modules/iam") {
		t.Fatalf("wrong IAM path returned unexpected error: %v", err)
	}
}

func validIAMRequest(t *testing.T) *models.Request {
	t.Helper()
	return &models.Request{
		Action:     "create",
		Provider:   "gcp",
		Module:     "iam",
		ModulePath: filepath.Join(t.TempDir(), "generated", "gcp", "modules", "iam"),
		IAMResource: &models.IAMRequest{
			ResourceName: "sa_logging_01",
			AccountID:    "sa-logging-01",
			DisplayName:  "Service Account Logging 01",
			Description:  "Compte de service pour les journaux",
			ProjectID:    "stage2026-project",
			Role:         "roles/logging.logWriter",
		},
	}
}
