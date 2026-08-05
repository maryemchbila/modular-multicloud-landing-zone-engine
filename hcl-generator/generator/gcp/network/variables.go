package network

import (
	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

func networkVariableNames(resource *models.NetworkRequest) []string {
	return []string{
		resource.ResourceName + "_name",
		resource.SubnetResourceName + "_name",
		resource.SubnetResourceName + "_cidr",
		resource.SubnetResourceName + "_region",
	}
}

func addVariables(
	file *hclwrite.File,
	resource *models.NetworkRequest,
) {
	variables := []struct {
		name        string
		description string
	}{
		{resource.ResourceName + "_name", "Nom du VPC GCP"},
		{resource.SubnetResourceName + "_name", "Nom du subnet GCP"},
		{resource.SubnetResourceName + "_cidr", "Plage CIDR du subnet"},
		{resource.SubnetResourceName + "_region", "Région du subnet GCP"},
	}

	for _, variable := range variables {
		if common.BlockExists(file, "variable", variable.name) {
			continue
		}
		block := hclwrite.NewBlock("variable", []string{variable.name})
		block.Body().SetAttributeValue(
			"description",
			cty.StringVal(variable.description),
		)
		block.Body().SetAttributeTraversal(
			"type",
			common.TypeTraversal("string"),
		)
		common.AppendBlock(file, block)
	}
}
