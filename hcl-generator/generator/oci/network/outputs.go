package network

import (
	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

type outputDefinition struct {
	name         string
	description  string
	resourceType string
	resourceName string
}

func outputDefinitions(
	resource *models.OCINetworkRequest,
) []outputDefinition {
	return []outputDefinition{
		{
			resource.ResourceName + "_id",
			"OCID du VCN OCI",
			vcnResourceType,
			resource.ResourceName,
		},
		{
			resource.SubnetResourceName + "_id",
			"OCID du subnet OCI",
			subnetResourceType,
			resource.SubnetResourceName,
		},
		{
			resource.InternetGatewayResourceName + "_id",
			"OCID de l'Internet Gateway OCI",
			internetGatewayResourceType,
			resource.InternetGatewayResourceName,
		},
		{
			resource.RouteTableResourceName + "_id",
			"OCID de la route table OCI",
			routeTableResourceType,
			resource.RouteTableResourceName,
		},
	}
}

func outputNames(resource *models.OCINetworkRequest) []string {
	definitions := outputDefinitions(resource)
	names := make([]string, 0, len(definitions))
	for _, definition := range definitions {
		names = append(names, definition.name)
	}
	return names
}

func addOutputs(
	file *hclwrite.File,
	resource *models.OCINetworkRequest,
) {
	for _, definition := range outputDefinitions(resource) {
		block := hclwrite.NewBlock("output", []string{definition.name})
		block.Body().SetAttributeValue(
			"description",
			cty.StringVal(definition.description),
		)
		block.Body().SetAttributeTraversal(
			"value",
			common.ResourceTraversal(
				definition.resourceType,
				definition.resourceName,
				"id",
			),
		)
		common.AppendBlock(file, block)
	}
}
