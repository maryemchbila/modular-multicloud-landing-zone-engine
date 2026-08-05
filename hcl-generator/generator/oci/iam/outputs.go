package iam

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
	attribute    string
}

func outputDefinitions(resource *models.OCIIAMRequest) []outputDefinition {
	return []outputDefinition{
		{
			resource.UserResourceName + "_id",
			"OCID de l'utilisateur OCI",
			userResourceType,
			resource.UserResourceName,
			"id",
		},
		{
			resource.UserResourceName + "_name",
			"Nom de l'utilisateur OCI",
			userResourceType,
			resource.UserResourceName,
			"name",
		},
		{
			resource.GroupResourceName + "_id",
			"OCID du groupe OCI",
			groupResourceType,
			resource.GroupResourceName,
			"id",
		},
		{
			resource.GroupResourceName + "_name",
			"Nom du groupe OCI",
			groupResourceType,
			resource.GroupResourceName,
			"name",
		},
		{
			resource.MembershipResourceName + "_id",
			"Identifiant de l'association utilisateur-groupe OCI",
			membershipResourceType,
			resource.MembershipResourceName,
			"id",
		},
		{
			resource.PolicyResourceName + "_id",
			"OCID de la politique OCI",
			policyResourceType,
			resource.PolicyResourceName,
			"id",
		},
		{
			resource.PolicyResourceName + "_name",
			"Nom de la politique OCI",
			policyResourceType,
			resource.PolicyResourceName,
			"name",
		},
	}
}

func outputNames(resource *models.OCIIAMRequest) []string {
	definitions := outputDefinitions(resource)
	names := make([]string, 0, len(definitions))
	for _, definition := range definitions {
		names = append(names, definition.name)
	}
	return names
}

func addOutputs(file *hclwrite.File, resource *models.OCIIAMRequest) {
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
				definition.attribute,
			),
		)
		common.AppendBlock(file, block)
	}
}
