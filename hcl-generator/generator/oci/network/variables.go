package network

import (
	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

type variableDefinition struct {
	name        string
	description string
	typeName    string
}

func variableDefinitions(
	resource *models.OCINetworkRequest,
) []variableDefinition {
	return []variableDefinition{
		{
			resource.ResourceName + "_compartment_id",
			"OCID du compartiment OCI",
			"string",
		},
		{
			resource.ResourceName + "_cidr_block",
			"CIDR du VCN OCI",
			"string",
		},
		{
			resource.ResourceName + "_display_name",
			"Nom affiché du VCN OCI",
			"string",
		},
		{
			resource.ResourceName + "_dns_label",
			"Label DNS du VCN OCI",
			"string",
		},
		{
			resource.SubnetResourceName + "_cidr_block",
			"CIDR du subnet OCI",
			"string",
		},
		{
			resource.SubnetResourceName + "_display_name",
			"Nom affiché du subnet OCI",
			"string",
		},
		{
			resource.SubnetResourceName + "_dns_label",
			"Label DNS du subnet OCI",
			"string",
		},
		{
			resource.SubnetResourceName + "_availability_domain",
			"Availability Domain du subnet OCI",
			"string",
		},
		{
			resource.SubnetResourceName + "_prohibit_public_ip_on_vnic",
			"Interdit les adresses IP publiques sur les VNIC du subnet",
			"bool",
		},
		{
			resource.InternetGatewayResourceName + "_display_name",
			"Nom affiché de l'Internet Gateway OCI",
			"string",
		},
		{
			resource.RouteTableResourceName + "_display_name",
			"Nom affiché de la route table OCI",
			"string",
		},
	}
}

func variableNames(resource *models.OCINetworkRequest) []string {
	definitions := variableDefinitions(resource)
	names := make([]string, 0, len(definitions))
	for _, definition := range definitions {
		names = append(names, definition.name)
	}
	return names
}

func addVariables(
	file *hclwrite.File,
	resource *models.OCINetworkRequest,
) {
	for _, definition := range variableDefinitions(resource) {
		block := hclwrite.NewBlock("variable", []string{definition.name})
		block.Body().SetAttributeValue(
			"description",
			cty.StringVal(definition.description),
		)
		block.Body().SetAttributeTraversal(
			"type",
			common.TypeTraversal(definition.typeName),
		)
		common.AppendBlock(file, block)
	}
}
