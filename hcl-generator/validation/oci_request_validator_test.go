package validation

import (
	"path/filepath"
	"strings"
	"testing"

	"hcl-generator/models"
)

func TestValidateOCIComputeCreate(t *testing.T) {
	request := validOCIComputeRequest(t)
	if err := ValidateRequest(request); err != nil {
		t.Fatalf("valid OCI Compute request rejected: %v", err)
	}
}

func TestValidateOCIComputeUpdate(t *testing.T) {
	request := validOCIComputeRequest(t)
	request.Action = "update"
	if err := ValidateRequest(request); err != nil {
		t.Fatalf("valid OCI Compute Update rejected: %v", err)
	}
}

func TestValidateOCIComputeDeleteRequiresOnlyResourceName(t *testing.T) {
	request := validOCIComputeRequest(t)
	request.Action = "delete"
	request.OCIComputeResource = &models.OCIComputeRequest{
		ResourceName: "oci_vm_delete_test_01",
	}
	if err := ValidateRequest(request); err != nil {
		t.Fatalf("valid OCI Compute Delete rejected: %v", err)
	}

	for _, resourceName := range []string{"", "999_invalid"} {
		request.OCIComputeResource.ResourceName = resourceName
		if err := ValidateRequest(request); err == nil {
			t.Fatalf("invalid resource_name %q was accepted", resourceName)
		}
	}
}

func TestValidateOCIRejectsUnimplementedRoutes(t *testing.T) {
	tests := []struct {
		module string
		action string
	}{
		{module: "database", action: "delete"},
	}
	for _, test := range tests {
		t.Run(test.module+"/"+test.action, func(t *testing.T) {
			request := validOCIComputeRequest(t)
			request.Module = test.module
			request.Action = test.action
			err := ValidateRequest(request)
			if err == nil ||
				!strings.Contains(err.Error(), "fonctionnalite non implementee") {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestValidateOCIComputeRejectsInvalidOCIDs(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*models.OCIComputeRequest)
		expected string
	}{
		{
			name: "compartment",
			mutate: func(resource *models.OCIComputeRequest) {
				resource.CompartmentID = "compartment-test"
			},
			expected: "ocid1.compartment.",
		},
		{
			name: "subnet",
			mutate: func(resource *models.OCIComputeRequest) {
				resource.SubnetID = "subnet-test"
			},
			expected: "ocid1.subnet.",
		},
		{
			name: "image",
			mutate: func(resource *models.OCIComputeRequest) {
				resource.ImageID = "image-test"
			},
			expected: "ocid1.image.",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validOCIComputeRequest(t)
			test.mutate(request.OCIComputeResource)
			err := ValidateRequest(request)
			if err == nil || !strings.Contains(err.Error(), test.expected) {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestValidateOCIComputeRequiresBooleanAndDedicatedPath(t *testing.T) {
	request := validOCIComputeRequest(t)
	request.OCIComputeResource.AssignPublicIP = nil
	err := ValidateRequest(request)
	if err == nil || !strings.Contains(err.Error(), "assign_public_ip") {
		t.Fatalf("missing boolean returned unexpected error: %v", err)
	}

	request = validOCIComputeRequest(t)
	request.ModulePath = filepath.Join(
		t.TempDir(),
		"generated",
		"gcp",
		"compute",
	)
	err = ValidateRequest(request)
	if err == nil || !strings.Contains(err.Error(), "generated/oci/compute") {
		t.Fatalf("wrong OCI path returned unexpected error: %v", err)
	}
}

func validOCIComputeRequest(t *testing.T) *models.Request {
	t.Helper()
	assignPublicIP := false
	return &models.Request{
		Action:   "create",
		Provider: "oci",
		Module:   "compute",
		ModulePath: filepath.Join(
			t.TempDir(),
			"generated",
			"oci",
			"compute",
		),
		OCIComputeResource: &models.OCIComputeRequest{
			ResourceName:       "oci_vm_test_01",
			DisplayName:        "oci-vm-test-01",
			AvailabilityDomain: "Uocm:EU-FRANKFURT-1-AD-1",
			CompartmentID: "ocid1.compartment.oc1.." +
				"exampleuniqueID",
			Shape: "VM.Standard.E4.Flex",
			SubnetID: "ocid1.subnet.oc1.eu-frankfurt-1." +
				"exampleuniqueID",
			ImageID: "ocid1.image.oc1.eu-frankfurt-1." +
				"exampleuniqueID",
			AssignPublicIP: &assignPublicIP,
		},
	}
}
