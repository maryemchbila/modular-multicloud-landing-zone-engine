package storage

import (
	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

func storageVariableNames(resourceName string) []string {
	return []string{
		resourceName + "_name",
		resourceName + "_location",
		resourceName + "_storage_class",
		resourceName + "_uniform_bucket_level_access",
	}
}

func addVariables(file *hclwrite.File, resource *models.StorageRequest) {
	variables := []struct {
		name        string
		description string
		typeName    string
	}{
		{resource.ResourceName + "_name", "Nom du bucket GCS", "string"},
		{resource.ResourceName + "_location", "Localisation du bucket GCS", "string"},
		{resource.ResourceName + "_storage_class", "Classe de stockage du bucket GCS", "string"},
		{
			resource.ResourceName + "_uniform_bucket_level_access",
			"Active Uniform Bucket Level Access",
			"bool",
		},
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
			common.TypeTraversal(variable.typeName),
		)
		common.AppendBlock(file, block)
	}
}
