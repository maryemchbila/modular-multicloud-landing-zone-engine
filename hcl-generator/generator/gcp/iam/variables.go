package iam

import (
	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

func variableNames(resourceName string) []string {
	return []string{
		resourceName + "_account_id",
		resourceName + "_display_name",
		resourceName + "_description",
		resourceName + "_project_id",
		resourceName + "_role",
	}
}

func addVariables(file *hclwrite.File, resource *models.IAMRequest) {
	variables := []struct {
		name        string
		description string
	}{
		{
			resource.ResourceName + "_account_id",
			"Identifiant du compte de service GCP",
		},
		{
			resource.ResourceName + "_display_name",
			"Nom affiché du compte de service GCP",
		},
		{
			resource.ResourceName + "_description",
			"Description du compte de service GCP",
		},
		{
			resource.ResourceName + "_project_id",
			"Identifiant du projet GCP",
		},
		{
			resource.ResourceName + "_role",
			"Rôle IAM attribué au compte de service",
		},
	}

	for _, variable := range variables {
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
