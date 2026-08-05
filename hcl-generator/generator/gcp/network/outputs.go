package network

import (
	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

func addOutputs(
	file *hclwrite.File,
	resource *models.NetworkRequest,
) {
	outputs := []struct {
		name         string
		description  string
		resourceType string
		resourceName string
	}{
		{
			resource.ResourceName + "_id",
			"Identifiant du VPC GCP",
			"google_compute_network",
			resource.ResourceName,
		},
		{
			resource.SubnetResourceName + "_id",
			"Identifiant du subnet GCP",
			"google_compute_subnetwork",
			resource.SubnetResourceName,
		},
	}

	for _, output := range outputs {
		block := hclwrite.NewBlock("output", []string{output.name})
		block.Body().SetAttributeValue(
			"description",
			cty.StringVal(output.description),
		)
		block.Body().SetAttributeTraversal(
			"value",
			common.ResourceTraversal(
				output.resourceType,
				output.resourceName,
				"id",
			),
		)
		common.AppendBlock(file, block)
	}
}
