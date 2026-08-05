package validation

import (
	"path/filepath"
	"strings"
	"testing"

	"hcl-generator/models"
)

func TestValidateOCIStorageCreate(t *testing.T) {
	if err := ValidateRequest(validOCIStorageRequest(t)); err != nil {
		t.Fatalf("valid OCI Storage request rejected: %v", err)
	}
}

func TestValidateOCIStorageUpdate(t *testing.T) {
	request := validOCIStorageRequest(t)
	request.Action = "update"
	if err := ValidateRequest(request); err != nil {
		t.Fatalf("valid OCI Storage Update rejected: %v", err)
	}
}

func TestValidateOCIStorageRejectsInvalidValuesBeforeGeneration(
	t *testing.T,
) {
	tests := []struct {
		name     string
		mutate   func(*models.OCIStorageRequest)
		expected string
	}{
		{
			name: "invalid access type",
			mutate: func(resource *models.OCIStorageRequest) {
				resource.AccessType = "PublicReadWrite"
			},
			expected: "access_type",
		},
		{
			name: "invalid storage tier",
			mutate: func(resource *models.OCIStorageRequest) {
				resource.StorageTier = "Coldline"
			},
			expected: "storage_tier",
		},
		{
			name: "invalid versioning",
			mutate: func(resource *models.OCIStorageRequest) {
				resource.Versioning = "Active"
			},
			expected: "versioning",
		},
		{
			name: "invalid compartment OCID",
			mutate: func(resource *models.OCIStorageRequest) {
				resource.CompartmentID = "compartment-invalid"
			},
			expected: "ocid1.compartment.",
		},
		{
			name: "missing boolean",
			mutate: func(resource *models.OCIStorageRequest) {
				resource.ObjectEventsEnabled = nil
			},
			expected: "object_events_enabled",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validOCIStorageRequest(t)
			test.mutate(request.OCIStorageResource)
			err := ValidateRequest(request)
			if err == nil || !strings.Contains(err.Error(), test.expected) {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestValidateOCIStorageRejectsWrongPath(
	t *testing.T,
) {
	request := validOCIStorageRequest(t)
	request.ModulePath = filepath.Join(
		t.TempDir(),
		"generated",
		"oci",
		"compute",
	)
	err := ValidateRequest(request)
	if err == nil || !strings.Contains(err.Error(), "generated/oci/storage") {
		t.Fatalf("unexpected path validation error: %v", err)
	}

}

func TestValidateOCIStorageDeleteRequiresOnlyResourceName(t *testing.T) {
	request := validOCIStorageRequest(t)
	request.Action = "delete"
	request.OCIStorageResource = &models.OCIStorageRequest{
		ResourceName: "oci_bucket_delete_test_01",
	}
	if err := ValidateRequest(request); err != nil {
		t.Fatalf("valid OCI Storage Delete rejected: %v", err)
	}

	for _, resourceName := range []string{"", "999 invalid"} {
		request.OCIStorageResource.ResourceName = resourceName
		if err := ValidateRequest(request); err == nil {
			t.Fatalf("invalid resource_name %q was accepted", resourceName)
		}
	}
}

func validOCIStorageRequest(t *testing.T) *models.Request {
	t.Helper()
	objectEventsEnabled := true
	return &models.Request{
		Action:   "create",
		Provider: "oci",
		Module:   "storage",
		ModulePath: filepath.Join(
			t.TempDir(),
			"generated",
			"oci",
			"storage",
		),
		OCIStorageResource: &models.OCIStorageRequest{
			ResourceName:        "oci_bucket_test_01",
			CompartmentID:       "ocid1.compartment.oc1..exampleuniqueID",
			Namespace:           "exampletenancy",
			Name:                "oci-bucket-test-01",
			AccessType:          "NoPublicAccess",
			StorageTier:         "Standard",
			Versioning:          "Enabled",
			ObjectEventsEnabled: &objectEventsEnabled,
		},
	}
}
