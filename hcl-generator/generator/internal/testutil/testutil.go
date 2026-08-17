package testutil

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"hcl-generator/models"
)

var TerraformFilenames = []string{
	"main.tf",
	"variables.tf",
	"terraform.tfvars",
	"outputs.tf",
}

func CanonicalModulePath(t testing.TB, provider, module string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "generated", provider, "modules", module)
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("create canonical module path: %v", err)
	}
	return path
}

func SnapshotTerraformFiles(
	t testing.TB,
	modulePath string,
) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte, len(TerraformFilenames))
	for _, filename := range TerraformFilenames {
		content, err := os.ReadFile(TerraformFilePath(modulePath, filename))
		if err != nil {
			t.Fatalf("read %s: %v", filename, err)
		}
		result[filename] = content
	}
	return result
}

func TerraformFilePath(modulePath, filename string) string {
	if filename == "terraform.tfvars" &&
		filepath.Base(filepath.Dir(filepath.Clean(modulePath))) == "modules" {
		return filepath.Join(filepath.Dir(filepath.Dir(modulePath)), filename)
	}
	return filepath.Join(modulePath, filename)
}

func AssertTerraformFilesEqual(
	t testing.TB,
	before map[string][]byte,
	after map[string][]byte,
) {
	t.Helper()
	for _, filename := range TerraformFilenames {
		if !bytes.Equal(before[filename], after[filename]) {
			t.Fatalf("%s changed unexpectedly", filename)
		}
	}
}

func AssertModuleFilesEqual(
	t testing.TB,
	before map[string][]byte,
	after map[string][]byte,
) {
	t.Helper()
	for _, filename := range []string{"main.tf", "variables.tf", "outputs.tf"} {
		if !bytes.Equal(before[filename], after[filename]) {
			t.Fatalf("%s changed unexpectedly", filename)
		}
	}
}

func ComputeRequest(
	action string,
	modulePath string,
	resourceName string,
	name string,
	machineType string,
) *models.Request {
	return &models.Request{
		Action:     action,
		Provider:   "gcp",
		Module:     "compute",
		ModulePath: modulePath,
		ProjectID:  "example-test-project",
		ComputeResource: &models.ComputeRequest{
			ResourceName: resourceName,
			Name:         name,
			MachineType:  machineType,
			Zone:         "europe-west1-b",
			Image:        "debian-cloud/debian-12",
			Network:      "default",
		},
	}
}

func ComputeDeleteRequest(
	modulePath string,
	resourceName string,
) *models.Request {
	return &models.Request{
		Action:     "delete",
		Provider:   "gcp",
		Module:     "compute",
		ModulePath: modulePath,
		ProjectID:  "example-test-project",
		ComputeResource: &models.ComputeRequest{
			ResourceName: resourceName,
		},
	}
}

func NetworkRequest(
	action string,
	modulePath string,
	resourceName string,
	name string,
	subnetResourceName string,
	subnetName string,
	cidr string,
	region string,
) *models.Request {
	return &models.Request{
		Action:     action,
		Provider:   "gcp",
		Module:     "network",
		ModulePath: modulePath,
		ProjectID:  "example-test-project",
		NetworkResource: &models.NetworkRequest{
			ResourceName:       resourceName,
			Name:               name,
			SubnetResourceName: subnetResourceName,
			SubnetName:         subnetName,
			CIDR:               cidr,
			Region:             region,
		},
	}
}

func NetworkDeleteRequest(
	modulePath string,
	resourceName string,
	subnetResourceName string,
) *models.Request {
	return &models.Request{
		Action:     "delete",
		Provider:   "gcp",
		Module:     "network",
		ModulePath: modulePath,
		ProjectID:  "example-test-project",
		NetworkResource: &models.NetworkRequest{
			ResourceName:       resourceName,
			SubnetResourceName: subnetResourceName,
		},
	}
}

func StorageRequest(
	action string,
	modulePath string,
	resourceName string,
	name string,
	location string,
	storageClass string,
	uniformAccess bool,
) *models.Request {
	return &models.Request{
		Action:     action,
		Provider:   "gcp",
		Module:     "storage",
		ModulePath: modulePath,
		ProjectID:  "example-test-project",
		StorageResource: &models.StorageRequest{
			ResourceName:             resourceName,
			Name:                     name,
			Location:                 location,
			StorageClass:             storageClass,
			UniformBucketLevelAccess: &uniformAccess,
		},
	}
}

func StorageDeleteRequest(
	modulePath string,
	resourceName string,
) *models.Request {
	return &models.Request{
		Action:     "delete",
		Provider:   "gcp",
		Module:     "storage",
		ModulePath: modulePath,
		ProjectID:  "example-test-project",
		StorageResource: &models.StorageRequest{
			ResourceName: resourceName,
		},
	}
}

func OCIComputeRequest(
	modulePath string,
	resourceName string,
	displayName string,
	assignPublicIP bool,
) *models.Request {
	return OCIComputeActionRequest(
		"create",
		modulePath,
		resourceName,
		displayName,
		assignPublicIP,
	)
}

func OCIComputeActionRequest(
	action string,
	modulePath string,
	resourceName string,
	displayName string,
	assignPublicIP bool,
) *models.Request {
	return &models.Request{
		Action:     action,
		Provider:   "oci",
		Module:     "compute",
		ModulePath: modulePath,
		OCIComputeResource: &models.OCIComputeRequest{
			ResourceName:       resourceName,
			DisplayName:        displayName,
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

func OCIComputeDeleteRequest(
	modulePath string,
	resourceName string,
) *models.Request {
	return &models.Request{
		Action:     "delete",
		Provider:   "oci",
		Module:     "compute",
		ModulePath: modulePath,
		OCIComputeResource: &models.OCIComputeRequest{
			ResourceName: resourceName,
		},
	}
}

func OCINetworkRequest(
	modulePath string,
	resourceName string,
	displayName string,
	subnetResourceName string,
	subnetDisplayName string,
	vcnCIDR string,
	subnetCIDR string,
	internetGatewayResourceName string,
	internetGatewayDisplayName string,
	routeTableResourceName string,
	routeTableDisplayName string,
	prohibitPublicIPOnVNIC bool,
) *models.Request {
	return &models.Request{
		Action:     "create",
		Provider:   "oci",
		Module:     "network",
		ModulePath: modulePath,
		OCINetworkResource: &models.OCINetworkRequest{
			ResourceName:                resourceName,
			DisplayName:                 displayName,
			CompartmentID:               "ocid1.compartment.oc1..exampleuniqueID",
			VCNCIDR:                     vcnCIDR,
			DNSLabel:                    "vcntest01",
			SubnetResourceName:          subnetResourceName,
			SubnetDisplayName:           subnetDisplayName,
			SubnetCIDR:                  subnetCIDR,
			SubnetDNSLabel:              "subtest01",
			AvailabilityDomain:          "Uocm:EU-FRANKFURT-1-AD-1",
			ProhibitPublicIPOnVNIC:      &prohibitPublicIPOnVNIC,
			InternetGatewayResourceName: internetGatewayResourceName,
			InternetGatewayDisplayName:  internetGatewayDisplayName,
			RouteTableResourceName:      routeTableResourceName,
			RouteTableDisplayName:       routeTableDisplayName,
		},
	}
}

func OCIStorageRequest(
	modulePath string,
	resourceName string,
	name string,
	accessType string,
	storageTier string,
	versioning string,
	objectEventsEnabled bool,
) *models.Request {
	return &models.Request{
		Action:     "create",
		Provider:   "oci",
		Module:     "storage",
		ModulePath: modulePath,
		OCIStorageResource: &models.OCIStorageRequest{
			ResourceName:        resourceName,
			CompartmentID:       "ocid1.compartment.oc1..exampleuniqueID",
			Namespace:           "exampletenancy",
			Name:                name,
			AccessType:          accessType,
			StorageTier:         storageTier,
			Versioning:          versioning,
			ObjectEventsEnabled: &objectEventsEnabled,
		},
	}
}

func OCIStorageDeleteRequest(
	modulePath string,
	resourceName string,
) *models.Request {
	return &models.Request{
		Action:     "delete",
		Provider:   "oci",
		Module:     "storage",
		ModulePath: modulePath,
		OCIStorageResource: &models.OCIStorageRequest{
			ResourceName: resourceName,
		},
	}
}

func OCIIAMRequest(
	modulePath string,
	userResourceName string,
	userName string,
	groupResourceName string,
	groupName string,
	membershipResourceName string,
	policyResourceName string,
	policyName string,
	policyStatements []string,
) *models.Request {
	return OCIIAMActionRequest(
		"create",
		modulePath,
		userResourceName,
		userName,
		groupResourceName,
		groupName,
		membershipResourceName,
		policyResourceName,
		policyName,
		policyStatements,
	)
}

func OCIIAMActionRequest(
	action string,
	modulePath string,
	userResourceName string,
	userName string,
	groupResourceName string,
	groupName string,
	membershipResourceName string,
	policyResourceName string,
	policyName string,
	policyStatements []string,
) *models.Request {
	return &models.Request{
		Action:     action,
		Provider:   "oci",
		Module:     "iam",
		ModulePath: modulePath,
		OCIIAMResource: &models.OCIIAMRequest{
			TenancyOCID:            "ocid1.tenancy.oc1..exampleuniqueID",
			UserResourceName:       userResourceName,
			UserName:               userName,
			UserDescription:        "Utilisateur OCI de test",
			GroupResourceName:      groupResourceName,
			GroupName:              groupName,
			GroupDescription:       "Groupe OCI de test",
			MembershipResourceName: membershipResourceName,
			PolicyResourceName:     policyResourceName,
			PolicyName:             policyName,
			PolicyDescription:      "Politique OCI de test",
			PolicyCompartmentID: "ocid1.compartment.oc1.." +
				"exampleuniqueID",
			PolicyStatements: policyStatements,
		},
	}
}

func OCIIAMDeleteRequest(
	modulePath string,
	userResourceName string,
	groupResourceName string,
	membershipResourceName string,
	policyResourceName string,
) *models.Request {
	return &models.Request{
		Action:     "delete",
		Provider:   "oci",
		Module:     "iam",
		ModulePath: modulePath,
		OCIIAMResource: &models.OCIIAMRequest{
			UserResourceName:       userResourceName,
			GroupResourceName:      groupResourceName,
			MembershipResourceName: membershipResourceName,
			PolicyResourceName:     policyResourceName,
		},
	}
}
