package validation

import (
	"path/filepath"
	"strings"
	"testing"

	"hcl-generator/models"
)

func TestValidateOCIIAMCreate(t *testing.T) {
	request := validOCIIAMRequest(t)
	if err := ValidateRequest(request); err != nil {
		t.Fatalf("valid OCI IAM request rejected: %v", err)
	}
}

func TestValidateOCIIAMRejectsInvalidIdentifiers(t *testing.T) {
	invalidIdentifiers := []string{
		"oci-user-01",
		"01_oci_user",
		"oci user 01",
	}
	fields := []struct {
		name   string
		mutate func(*models.OCIIAMRequest, string)
	}{
		{
			name: "user",
			mutate: func(resource *models.OCIIAMRequest, value string) {
				resource.UserResourceName = value
			},
		},
		{
			name: "group",
			mutate: func(resource *models.OCIIAMRequest, value string) {
				resource.GroupResourceName = value
			},
		},
		{
			name: "membership",
			mutate: func(resource *models.OCIIAMRequest, value string) {
				resource.MembershipResourceName = value
			},
		},
		{
			name: "policy",
			mutate: func(resource *models.OCIIAMRequest, value string) {
				resource.PolicyResourceName = value
			},
		},
	}
	for _, field := range fields {
		for _, invalid := range invalidIdentifiers {
			t.Run(field.name+"/"+invalid, func(t *testing.T) {
				request := validOCIIAMRequest(t)
				field.mutate(request.OCIIAMResource, invalid)
				err := ValidateRequest(request)
				if err == nil ||
					!strings.Contains(err.Error(), "identifiant Terraform OCI IAM") {
					t.Fatalf("invalid identifier %q returned unexpected error: %v", invalid, err)
				}
			})
		}
	}
}

func TestValidateOCIIAMRejectsDuplicateIdentifiers(t *testing.T) {
	request := validOCIIAMRequest(t)
	request.OCIIAMResource.PolicyResourceName =
		request.OCIIAMResource.UserResourceName
	err := ValidateRequest(request)
	if err == nil || !strings.Contains(err.Error(), "doivent etre differents") {
		t.Fatalf("duplicate identifiers returned unexpected error: %v", err)
	}
}

func TestValidateOCIIAMRejectsInvalidOCIDsAndPath(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*models.Request)
		expected string
	}{
		{
			name: "tenancy OCID",
			mutate: func(request *models.Request) {
				request.OCIIAMResource.TenancyOCID =
					"ocid1.compartment.oc1..invalid"
			},
			expected: "ocid1.tenancy.",
		},
		{
			name: "policy compartment OCID",
			mutate: func(request *models.Request) {
				request.OCIIAMResource.PolicyCompartmentID =
					"ocid1.user.oc1..invalid"
			},
			expected: "ocid1.tenancy. ou ocid1.compartment.",
		},
		{
			name: "dedicated output path",
			mutate: func(request *models.Request) {
				request.ModulePath = filepath.Join(
					t.TempDir(),
					"generated",
					"oci",
					"compute",
				)
			},
			expected: "generated/oci/iam",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validOCIIAMRequest(t)
			test.mutate(request)
			err := ValidateRequest(request)
			if err == nil || !strings.Contains(err.Error(), test.expected) {
				t.Fatalf("invalid request returned unexpected error: %v", err)
			}
		})
	}
}

func TestValidateOCIIAMRejectsUnsafePolicyStatements(t *testing.T) {
	valid := "Allow group stage2026-observability-group to read metrics in compartment stage2026"
	tests := []struct {
		name       string
		statements []string
		expected   string
	}{
		{
			name:       "empty list",
			statements: []string{},
			expected:   "at least one",
		},
		{
			name:       "empty statement",
			statements: []string{"   "},
			expected:   "empty values",
		},
		{
			name:       "wrong verb",
			statements: []string{"Permit group stage2026-observability-group to read metrics in tenancy"},
			expected:   "start with 'Allow'",
		},
		{
			name:       "wrong group",
			statements: []string{"Allow group another-group to read metrics in tenancy"},
			expected:   "configured group",
		},
		{
			name:       "any user",
			statements: []string{"Allow any-user to read objects in tenancy"},
			expected:   "any-user",
		},
		{
			name:       "manage all resources in tenancy",
			statements: []string{"Allow group stage2026-observability-group to manage all-resources in tenancy"},
			expected:   "too permissive",
		},
		{
			name:       "duplicate",
			statements: []string{valid, valid},
			expected:   "duplicates",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validOCIIAMRequest(t)
			request.OCIIAMResource.PolicyStatements = test.statements
			err := ValidateRequest(request)
			if err == nil || !strings.Contains(err.Error(), test.expected) {
				t.Fatalf("invalid policy returned unexpected error: %v", err)
			}
		})
	}
}

func TestValidateOCIIAMSupportsCRUD(t *testing.T) {
	update := validOCIIAMRequest(t)
	update.Action = "update"
	if err := ValidateRequest(update); err != nil {
		t.Fatalf("valid OCI IAM Update rejected: %v", err)
	}

	deleteRequest := validOCIIAMRequest(t)
	deleteRequest.Action = "delete"
	deleteRequest.OCIIAMResource = &models.OCIIAMRequest{
		UserResourceName:       "oci_user_delete_test_01",
		GroupResourceName:      "oci_group_delete_test_01",
		MembershipResourceName: "oci_membership_delete_test_01",
		PolicyResourceName:     "oci_policy_delete_test_01",
	}
	if err := ValidateRequest(deleteRequest); err != nil {
		t.Fatalf("valid OCI IAM Delete rejected: %v", err)
	}
}

func TestValidateOCIIAMDeleteRequiresOnlyFourIdentifiers(t *testing.T) {
	request := validOCIIAMRequest(t)
	request.Action = "delete"
	request.OCIIAMResource = &models.OCIIAMRequest{
		UserResourceName:       "oci_user_delete_test_01",
		GroupResourceName:      "oci_group_delete_test_01",
		MembershipResourceName: "oci_membership_delete_test_01",
		PolicyResourceName:     "oci_policy_delete_test_01",
	}
	if err := ValidateRequest(request); err != nil {
		t.Fatalf("minimal OCI IAM Delete rejected: %v", err)
	}

	tests := []struct {
		name     string
		mutate   func(*models.OCIIAMRequest)
		expected string
	}{
		{
			name: "missing user",
			mutate: func(resource *models.OCIIAMRequest) {
				resource.UserResourceName = " "
			},
			expected: "resource.user_resource_name",
		},
		{
			name: "invalid group",
			mutate: func(resource *models.OCIIAMRequest) {
				resource.GroupResourceName = "oci-group-delete"
			},
			expected: "identifiant Terraform OCI IAM",
		},
		{
			name: "duplicate identifiers",
			mutate: func(resource *models.OCIIAMRequest) {
				resource.PolicyResourceName = resource.UserResourceName
			},
			expected: "doivent etre differents",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := *request.OCIIAMResource
			deleteRequest := *request
			deleteRequest.OCIIAMResource = &candidate
			test.mutate(deleteRequest.OCIIAMResource)
			err := ValidateRequest(&deleteRequest)
			if err == nil || !strings.Contains(err.Error(), test.expected) {
				t.Fatalf("invalid Delete returned unexpected error: %v", err)
			}
		})
	}
}

func validOCIIAMRequest(t *testing.T) *models.Request {
	t.Helper()
	return &models.Request{
		Action:   "create",
		Provider: "oci",
		Module:   "iam",
		ModulePath: filepath.Join(
			t.TempDir(),
			"generated",
			"oci",
			"iam",
		),
		OCIIAMResource: &models.OCIIAMRequest{
			TenancyOCID:            "ocid1.tenancy.oc1..exampleuniqueID",
			UserResourceName:       "oci_user_observability_01",
			UserName:               "stage2026-observability-user",
			UserDescription:        "Utilisateur OCI pour l'observabilite",
			GroupResourceName:      "oci_group_observability_01",
			GroupName:              "stage2026-observability-group",
			GroupDescription:       "Groupe OCI pour l'observabilite",
			MembershipResourceName: "oci_membership_observability_01",
			PolicyResourceName:     "oci_policy_observability_01",
			PolicyName:             "stage2026-observability-policy",
			PolicyDescription:      "Politique OCI minimale",
			PolicyCompartmentID:    "ocid1.compartment.oc1..exampleuniqueID",
			PolicyStatements: []string{
				"Allow group stage2026-observability-group to read metrics in compartment stage2026",
			},
		},
	}
}
