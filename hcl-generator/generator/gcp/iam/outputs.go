package iam

import (
	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

func outputNames(resourceName string) []string {
	return []string{
		resourceName + "_email",
		resourceName + "_name",
		resourceName + "_unique_id",
	}
}

func addOutputs(file *hclwrite.File, resource *models.IAMRequest) {
	outputs := []struct {
		name        string
		description string
		attribute   string
	}{
		{
			resource.ResourceName + "_email",
			"Adresse email du compte de service GCP",
			"email",
		},
		{
			resource.ResourceName + "_name",
			"Nom complet du compte de service GCP",
			"name",
		},
		{
			resource.ResourceName + "_unique_id",
			"Identifiant unique du compte de service GCP",
			"unique_id",
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
				serviceAccountResourceType,
				resource.ResourceName,
				output.attribute,
			),
		)
		common.AppendBlock(file, block)
	}
}
