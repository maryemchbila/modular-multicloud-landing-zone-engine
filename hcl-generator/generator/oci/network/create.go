package network

import (
	"fmt"

	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

const (
	vcnResourceType             = "oci_core_vcn"
	subnetResourceType          = "oci_core_subnet"
	internetGatewayResourceType = "oci_core_internet_gateway"
	routeTableResourceType      = "oci_core_route_table"
)

func ApplyCreate(files *common.TerraformFiles, request *models.Request) error {
	resource := request.OCINetworkResource
	if resource == nil {
		return fmt.Errorf("ressource OCI network manquante")
	}
	if resource.ProhibitPublicIPOnVNIC == nil {
		return fmt.Errorf(
			"champ obligatoire manquant : resource.prohibit_public_ip_on_vnic",
		)
	}
	if err := checkCreateDuplicates(files, resource); err != nil {
		return err
	}

	addMainResources(files.Main, resource)
	addVariables(files.Variables, resource)
	addTfvars(files.Tfvars, resource)
	addOutputs(files.Outputs, resource)
	return nil
}

func checkCreateDuplicates(
	files *common.TerraformFiles,
	resource *models.OCINetworkRequest,
) error {
	resources := []struct {
		resourceType string
		resourceName string
	}{
		{vcnResourceType, resource.ResourceName},
		{subnetResourceType, resource.SubnetResourceName},
		{
			internetGatewayResourceType,
			resource.InternetGatewayResourceName,
		},
		{routeTableResourceType, resource.RouteTableResourceName},
	}
	for _, candidate := range resources {
		if common.BlockExists(
			files.Main,
			"resource",
			candidate.resourceType,
			candidate.resourceName,
		) {
			return fmt.Errorf(
				"doublon OCI network : resource %q %q existe deja",
				candidate.resourceType,
				candidate.resourceName,
			)
		}
	}

	for _, name := range variableNames(resource) {
		if common.BlockExists(files.Variables, "variable", name) {
			return fmt.Errorf(
				"doublon OCI network : variable %q existe deja",
				name,
			)
		}
		if common.AttributeExists(files.Tfvars, name) {
			return fmt.Errorf(
				"doublon OCI network : valeur tfvars %q existe deja",
				name,
			)
		}
	}

	for _, name := range outputNames(resource) {
		if common.BlockExists(files.Outputs, "output", name) {
			return fmt.Errorf(
				"doublon OCI network : output %q existe deja",
				name,
			)
		}
	}
	return nil
}

func addMainResources(
	file *hclwrite.File,
	resource *models.OCINetworkRequest,
) {
	vcn := hclwrite.NewBlock(
		"resource",
		[]string{vcnResourceType, resource.ResourceName},
	)
	vcn.Body().SetAttributeTraversal(
		"compartment_id",
		common.VarTraversal(resource.ResourceName+"_compartment_id"),
	)
	vcn.Body().SetAttributeTraversal(
		"cidr_block",
		common.VarTraversal(resource.ResourceName+"_cidr_block"),
	)
	vcn.Body().SetAttributeTraversal(
		"display_name",
		common.VarTraversal(resource.ResourceName+"_display_name"),
	)
	vcn.Body().SetAttributeTraversal(
		"dns_label",
		common.VarTraversal(resource.ResourceName+"_dns_label"),
	)
	common.AppendBlock(file, vcn)

	internetGateway := hclwrite.NewBlock(
		"resource",
		[]string{
			internetGatewayResourceType,
			resource.InternetGatewayResourceName,
		},
	)
	internetGateway.Body().SetAttributeTraversal(
		"compartment_id",
		common.VarTraversal(resource.ResourceName+"_compartment_id"),
	)
	internetGateway.Body().SetAttributeTraversal(
		"vcn_id",
		common.ResourceTraversal(
			vcnResourceType,
			resource.ResourceName,
			"id",
		),
	)
	internetGateway.Body().SetAttributeTraversal(
		"display_name",
		common.VarTraversal(
			resource.InternetGatewayResourceName+"_display_name",
		),
	)
	internetGateway.Body().SetAttributeValue("enabled", cty.BoolVal(true))
	common.AppendBlock(file, internetGateway)

	routeTable := hclwrite.NewBlock(
		"resource",
		[]string{routeTableResourceType, resource.RouteTableResourceName},
	)
	routeTable.Body().SetAttributeTraversal(
		"compartment_id",
		common.VarTraversal(resource.ResourceName+"_compartment_id"),
	)
	routeTable.Body().SetAttributeTraversal(
		"vcn_id",
		common.ResourceTraversal(
			vcnResourceType,
			resource.ResourceName,
			"id",
		),
	)
	routeTable.Body().SetAttributeTraversal(
		"display_name",
		common.VarTraversal(resource.RouteTableResourceName+"_display_name"),
	)
	routeRule := hclwrite.NewBlock("route_rules", nil)
	routeRule.Body().SetAttributeValue(
		"destination",
		cty.StringVal("0.0.0.0/0"),
	)
	routeRule.Body().SetAttributeValue(
		"destination_type",
		cty.StringVal("CIDR_BLOCK"),
	)
	routeRule.Body().SetAttributeTraversal(
		"network_entity_id",
		common.ResourceTraversal(
			internetGatewayResourceType,
			resource.InternetGatewayResourceName,
			"id",
		),
	)
	routeTable.Body().AppendNewline()
	routeTable.Body().AppendBlock(routeRule)
	common.AppendBlock(file, routeTable)

	subnet := hclwrite.NewBlock(
		"resource",
		[]string{subnetResourceType, resource.SubnetResourceName},
	)
	subnet.Body().SetAttributeTraversal(
		"compartment_id",
		common.VarTraversal(resource.ResourceName+"_compartment_id"),
	)
	subnet.Body().SetAttributeTraversal(
		"vcn_id",
		common.ResourceTraversal(
			vcnResourceType,
			resource.ResourceName,
			"id",
		),
	)
	subnet.Body().SetAttributeTraversal(
		"cidr_block",
		common.VarTraversal(resource.SubnetResourceName+"_cidr_block"),
	)
	subnet.Body().SetAttributeTraversal(
		"display_name",
		common.VarTraversal(resource.SubnetResourceName+"_display_name"),
	)
	subnet.Body().SetAttributeTraversal(
		"dns_label",
		common.VarTraversal(resource.SubnetResourceName+"_dns_label"),
	)
	subnet.Body().SetAttributeTraversal(
		"availability_domain",
		common.VarTraversal(
			resource.SubnetResourceName+"_availability_domain",
		),
	)
	subnet.Body().SetAttributeTraversal(
		"route_table_id",
		common.ResourceTraversal(
			routeTableResourceType,
			resource.RouteTableResourceName,
			"id",
		),
	)
	subnet.Body().SetAttributeTraversal(
		"prohibit_public_ip_on_vnic",
		common.VarTraversal(
			resource.SubnetResourceName+"_prohibit_public_ip_on_vnic",
		),
	)
	common.AppendBlock(file, subnet)
}
