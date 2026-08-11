package validation

import (
	"path/filepath"
	"strings"
	"testing"

	"hcl-generator/models"
)

func TestValidateOCINetworkCreate(t *testing.T) {
	request := validOCINetworkRequest(t)
	if err := ValidateRequest(request); err != nil {
		t.Fatalf("valid OCI Network request rejected: %v", err)
	}
}

func TestValidateOCINetworkUpdate(t *testing.T) {
	request := validOCINetworkRequest(t)
	request.Action = "update"
	if err := ValidateRequest(request); err != nil {
		t.Fatalf("valid OCI Network Update rejected: %v", err)
	}
}

func TestValidateOCINetworkRejectsInvalidNetworkData(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*models.OCINetworkRequest)
		expected string
	}{
		{
			name: "invalid compartment",
			mutate: func(resource *models.OCINetworkRequest) {
				resource.CompartmentID = "compartment-invalid"
			},
			expected: "ocid1.compartment.",
		},
		{
			name: "invalid VCN CIDR",
			mutate: func(resource *models.OCINetworkRequest) {
				resource.VCNCIDR = "10.500.0.0/16"
			},
			expected: "vcn_cidr",
		},
		{
			name: "subnet outside VCN",
			mutate: func(resource *models.OCINetworkRequest) {
				resource.VCNCIDR = "10.50.0.0/16"
				resource.SubnetCIDR = "10.60.1.0/24"
			},
			expected: "doit appartenir au CIDR du VCN",
		},
		{
			name: "subnet not more specific",
			mutate: func(resource *models.OCINetworkRequest) {
				resource.SubnetCIDR = "10.30.0.0/16"
			},
			expected: "doit etre plus specifique",
		},
		{
			name: "missing boolean",
			mutate: func(resource *models.OCINetworkRequest) {
				resource.ProhibitPublicIPOnVNIC = nil
			},
			expected: "prohibit_public_ip_on_vnic",
		},
		{
			name: "invalid VCN DNS label",
			mutate: func(resource *models.OCINetworkRequest) {
				resource.DNSLabel = "vcn-test"
			},
			expected: "resource.dns_label",
		},
		{
			name: "invalid subnet DNS label",
			mutate: func(resource *models.OCINetworkRequest) {
				resource.SubnetDNSLabel = "01subnet"
			},
			expected: "resource.subnet_dns_label",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validOCINetworkRequest(t)
			test.mutate(request.OCINetworkResource)
			err := ValidateRequest(request)
			if err == nil || !strings.Contains(err.Error(), test.expected) {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestValidateOCINetworkRejectsInvalidIdentifiersAndPath(t *testing.T) {
	request := validOCINetworkRequest(t)
	request.OCINetworkResource.InternetGatewayResourceName = "999 invalid"
	err := ValidateRequest(request)
	if err == nil || !strings.Contains(
		err.Error(),
		"internet_gateway_resource_name",
	) {
		t.Fatalf("unexpected identifier validation error: %v", err)
	}

	request = validOCINetworkRequest(t)
	request.ModulePath = filepath.Join(
		t.TempDir(),
		"generated",
		"oci",
		"modules",
		"compute",
	)
	err = ValidateRequest(request)
	if err == nil || !strings.Contains(err.Error(), "generated/oci/modules/network") {
		t.Fatalf("unexpected path validation error: %v", err)
	}
}

func TestValidateOCINetworkDeleteRequiresOnlyIdentifiers(t *testing.T) {
	request := validOCINetworkRequest(t)
	request.Action = "delete"
	request.OCINetworkResource = &models.OCINetworkRequest{
		ResourceName:                "oci_vcn_delete_test_01",
		SubnetResourceName:          "oci_subnet_delete_test_01",
		InternetGatewayResourceName: "oci_igw_delete_test_01",
		RouteTableResourceName:      "oci_rt_delete_test_01",
	}
	if err := ValidateRequest(request); err != nil {
		t.Fatalf("valid OCI Network Delete rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*models.OCINetworkRequest)
	}{
		{
			name: "missing VCN",
			mutate: func(resource *models.OCINetworkRequest) {
				resource.ResourceName = ""
			},
		},
		{
			name: "invalid subnet",
			mutate: func(resource *models.OCINetworkRequest) {
				resource.SubnetResourceName = "999 invalid"
			},
		},
		{
			name: "missing Internet Gateway",
			mutate: func(resource *models.OCINetworkRequest) {
				resource.InternetGatewayResourceName = ""
			},
		},
		{
			name: "invalid Route Table",
			mutate: func(resource *models.OCINetworkRequest) {
				resource.RouteTableResourceName = "invalid route table"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			copy := *request.OCINetworkResource
			test.mutate(&copy)
			invalid := *request
			invalid.OCINetworkResource = &copy
			if err := ValidateRequest(&invalid); err == nil {
				t.Fatal("invalid OCI Network Delete was accepted")
			}
		})
	}
}

func validOCINetworkRequest(t *testing.T) *models.Request {
	t.Helper()
	prohibitPublicIP := false
	return &models.Request{
		Action:   "create",
		Provider: "oci",
		Module:   "network",
		ModulePath: filepath.Join(
			t.TempDir(),
			"generated",
			"oci",
			"modules",
			"network",
		),
		OCINetworkResource: &models.OCINetworkRequest{
			ResourceName:                "oci_vcn_test_01",
			DisplayName:                 "oci-vcn-test-01",
			CompartmentID:               "ocid1.compartment.oc1..exampleuniqueID",
			VCNCIDR:                     "10.30.0.0/16",
			DNSLabel:                    "vcntest01",
			SubnetResourceName:          "oci_subnet_test_01",
			SubnetDisplayName:           "oci-subnet-test-01",
			SubnetCIDR:                  "10.30.1.0/24",
			SubnetDNSLabel:              "subtest01",
			AvailabilityDomain:          "Uocm:EU-FRANKFURT-1-AD-1",
			ProhibitPublicIPOnVNIC:      &prohibitPublicIP,
			InternetGatewayResourceName: "oci_igw_test_01",
			InternetGatewayDisplayName:  "oci-igw-test-01",
			RouteTableResourceName:      "oci_rt_test_01",
			RouteTableDisplayName:       "oci-rt-test-01",
		},
	}
}
