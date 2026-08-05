package iam

import (
	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

type variableDefinition struct {
	name        string
	description string
	listType    bool
}

func variableDefinitions(
	resource *models.OCIIAMRequest,
) []variableDefinition {
	return []variableDefinition{
		{
			resource.UserResourceName + "_tenancy_ocid",
			"OCID du tenancy contenant l'utilisateur OCI",
			false,
		},
		{
			resource.UserResourceName + "_name",
			"Nom de l'utilisateur OCI",
			false,
		},
		{
			resource.UserResourceName + "_description",
			"Description de l'utilisateur OCI",
			false,
		},
		{
			resource.GroupResourceName + "_tenancy_ocid",
			"OCID du tenancy contenant le groupe OCI",
			false,
		},
		{
			resource.GroupResourceName + "_name",
			"Nom du groupe OCI",
			false,
		},
		{
			resource.GroupResourceName + "_description",
			"Description du groupe OCI",
			false,
		},
		{
			resource.PolicyResourceName + "_compartment_id",
			"OCID du tenancy ou compartiment contenant la politique OCI",
			false,
		},
		{
			resource.PolicyResourceName + "_name",
			"Nom de la politique OCI",
			false,
		},
		{
			resource.PolicyResourceName + "_description",
			"Description de la politique OCI",
			false,
		},
		{
			resource.PolicyResourceName + "_statements",
			"Déclarations de la politique OCI IAM",
			true,
		},
	}
}

func variableNames(resource *models.OCIIAMRequest) []string {
	definitions := variableDefinitions(resource)
	names := make([]string, 0, len(definitions))
	for _, definition := range definitions {
		names = append(names, definition.name)
	}
	return names
}

func addVariables(file *hclwrite.File, resource *models.OCIIAMRequest) {
	for _, definition := range variableDefinitions(resource) {
		block := hclwrite.NewBlock("variable", []string{definition.name})
		block.Body().SetAttributeValue(
			"description",
			cty.StringVal(definition.description),
		)
		if definition.listType {
			block.Body().SetAttributeRaw(
				"type",
				hclwrite.TokensForFunctionCall(
					"list",
					hclwrite.TokensForIdentifier("string"),
				),
			)
		} else {
			block.Body().SetAttributeTraversal(
				"type",
				common.TypeTraversal("string"),
			)
		}
		common.AppendBlock(file, block)
	}
}
