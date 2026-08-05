package storage

import (
	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

func addOutputs(file *hclwrite.File, resource *models.StorageRequest) {
	outputs := []struct {
		name        string
		description string
		attribute   string
	}{
		{
			resource.ResourceName + "_id",
			"Identifiant du bucket GCS",
			"id",
		},
		{
			resource.ResourceName + "_url",
			"URL du bucket GCS",
			"url",
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
				"google_storage_bucket",
				resource.ResourceName,
				output.attribute,
			),
		)
		common.AppendBlock(file, block)
	}
}
