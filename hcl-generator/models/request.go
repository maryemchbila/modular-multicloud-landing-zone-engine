package models

import (
	"encoding/json"
	"fmt"
	"os"
)

type Request struct {
	Action             string             `json:"action"`
	Provider           string             `json:"provider"`
	Module             string             `json:"module"`
	ModulePath         string             `json:"module_path"`
	ComputeResource    *ComputeRequest    `json:"-"`
	NetworkResource    *NetworkRequest    `json:"-"`
	StorageResource    *StorageRequest    `json:"-"`
	IAMResource        *IAMRequest        `json:"-"`
	OCIComputeResource *OCIComputeRequest `json:"-"`
	OCINetworkResource *OCINetworkRequest `json:"-"`
	OCIStorageResource *OCIStorageRequest `json:"-"`
	OCIIAMResource     *OCIIAMRequest     `json:"-"`
}

type ComputeRequest struct {
	ResourceName string `json:"resource_name"`
	Name         string `json:"name"`
	MachineType  string `json:"machine_type"`
	Zone         string `json:"zone"`
	Image        string `json:"image"`
	Network      string `json:"network"`
}

type NetworkRequest struct {
	ResourceName       string `json:"resource_name"`
	Name               string `json:"name"`
	SubnetResourceName string `json:"subnet_resource_name"`
	SubnetName         string `json:"subnet_name"`
	CIDR               string `json:"cidr"`
	Region             string `json:"region"`
}

type StorageRequest struct {
	ResourceName             string `json:"resource_name"`
	Name                     string `json:"name"`
	Location                 string `json:"location"`
	StorageClass             string `json:"storage_class"`
	UniformBucketLevelAccess *bool  `json:"uniform_bucket_level_access"`
}

type IAMRequest struct {
	ResourceName string `json:"resource_name"`
	AccountID    string `json:"account_id"`
	DisplayName  string `json:"display_name"`
	Description  string `json:"description"`
	ProjectID    string `json:"project_id"`
	Role         string `json:"role"`
}

type OCIComputeRequest struct {
	ResourceName       string `json:"resource_name"`
	DisplayName        string `json:"display_name"`
	AvailabilityDomain string `json:"availability_domain"`
	CompartmentID      string `json:"compartment_id"`
	Shape              string `json:"shape"`
	SubnetID           string `json:"subnet_id"`
	ImageID            string `json:"image_id"`
	AssignPublicIP     *bool  `json:"assign_public_ip"`
}

type OCINetworkRequest struct {
	ResourceName                string `json:"resource_name"`
	DisplayName                 string `json:"display_name"`
	CompartmentID               string `json:"compartment_id"`
	VCNCIDR                     string `json:"vcn_cidr"`
	DNSLabel                    string `json:"dns_label"`
	SubnetResourceName          string `json:"subnet_resource_name"`
	SubnetDisplayName           string `json:"subnet_display_name"`
	SubnetCIDR                  string `json:"subnet_cidr"`
	SubnetDNSLabel              string `json:"subnet_dns_label"`
	AvailabilityDomain          string `json:"availability_domain"`
	ProhibitPublicIPOnVNIC      *bool  `json:"prohibit_public_ip_on_vnic"`
	InternetGatewayResourceName string `json:"internet_gateway_resource_name"`
	InternetGatewayDisplayName  string `json:"internet_gateway_display_name"`
	RouteTableResourceName      string `json:"route_table_resource_name"`
	RouteTableDisplayName       string `json:"route_table_display_name"`
}

type OCIStorageRequest struct {
	ResourceName        string `json:"resource_name"`
	CompartmentID       string `json:"compartment_id"`
	Namespace           string `json:"namespace"`
	Name                string `json:"name"`
	AccessType          string `json:"access_type"`
	StorageTier         string `json:"storage_tier"`
	Versioning          string `json:"versioning"`
	ObjectEventsEnabled *bool  `json:"object_events_enabled"`
}

type OCIIAMRequest struct {
	TenancyOCID            string   `json:"tenancy_ocid"`
	UserResourceName       string   `json:"user_resource_name"`
	UserName               string   `json:"user_name"`
	UserDescription        string   `json:"user_description"`
	GroupResourceName      string   `json:"group_resource_name"`
	GroupName              string   `json:"group_name"`
	GroupDescription       string   `json:"group_description"`
	MembershipResourceName string   `json:"membership_resource_name"`
	PolicyResourceName     string   `json:"policy_resource_name"`
	PolicyName             string   `json:"policy_name"`
	PolicyDescription      string   `json:"policy_description"`
	PolicyCompartmentID    string   `json:"policy_compartment_id"`
	PolicyStatements       []string `json:"policy_statements"`
}

func LoadRequest(path string) (*Request, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("impossible de lire %s : %w", path, err)
	}

	var request Request
	if err := json.Unmarshal(content, &request); err != nil {
		return nil, fmt.Errorf("JSON invalide dans %s : %w", path, err)
	}

	var envelope struct {
		Resource json.RawMessage `json:"resource"`
	}
	if err := json.Unmarshal(content, &envelope); err != nil {
		return nil, fmt.Errorf("ressource invalide dans %s : %w", path, err)
	}

	switch request.Provider + "/" + request.Module {
	case "gcp/compute":
		var resource ComputeRequest
		if err := json.Unmarshal(envelope.Resource, &resource); err != nil {
			return nil, fmt.Errorf("ressource compute invalide dans %s : %w", path, err)
		}
		request.ComputeResource = &resource
	case "gcp/network":
		var resource NetworkRequest
		if err := json.Unmarshal(envelope.Resource, &resource); err != nil {
			return nil, fmt.Errorf("ressource network invalide dans %s : %w", path, err)
		}
		request.NetworkResource = &resource
	case "gcp/storage":
		var resource StorageRequest
		if err := json.Unmarshal(envelope.Resource, &resource); err != nil {
			return nil, fmt.Errorf("ressource storage invalide dans %s : %w", path, err)
		}
		request.StorageResource = &resource
	case "gcp/iam":
		var resource IAMRequest
		if err := json.Unmarshal(envelope.Resource, &resource); err != nil {
			return nil, fmt.Errorf("ressource iam invalide dans %s : %w", path, err)
		}
		request.IAMResource = &resource
	case "oci/compute":
		var resource OCIComputeRequest
		if err := json.Unmarshal(envelope.Resource, &resource); err != nil {
			return nil, fmt.Errorf(
				"ressource OCI compute invalide dans %s : %w",
				path,
				err,
			)
		}
		request.OCIComputeResource = &resource
	case "oci/network":
		var resource OCINetworkRequest
		if err := json.Unmarshal(envelope.Resource, &resource); err != nil {
			return nil, fmt.Errorf(
				"ressource OCI network invalide dans %s : %w",
				path,
				err,
			)
		}
		request.OCINetworkResource = &resource
	case "oci/storage":
		var resource OCIStorageRequest
		if err := json.Unmarshal(envelope.Resource, &resource); err != nil {
			return nil, fmt.Errorf(
				"ressource OCI storage invalide dans %s : %w",
				path,
				err,
			)
		}
		request.OCIStorageResource = &resource
	case "oci/iam":
		var resource OCIIAMRequest
		if err := json.Unmarshal(envelope.Resource, &resource); err != nil {
			return nil, fmt.Errorf(
				"ressource OCI IAM invalide dans %s : %w",
				path,
				err,
			)
		}
		request.OCIIAMResource = &resource
	}

	return &request, nil
}
