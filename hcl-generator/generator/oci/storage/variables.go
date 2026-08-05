package storage

import (
	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

type variableDefinition struct {
	suffix      string
	description string
	typeName    string
}

var storageVariableDefinitions = []variableDefinition{
	{
		"compartment_id",
		"OCID du compartiment OCI contenant le bucket",
		"string",
	},
	{"namespace", "Namespace OCI Object Storage", "string"},
	{"name", "Nom du bucket OCI Object Storage", "string"},
	{"access_type", "Niveau d'accès du bucket OCI", "string"},
	{"storage_tier", "Classe de stockage du bucket OCI", "string"},
	{"versioning", "État du versioning du bucket OCI", "string"},
	{
		"object_events_enabled",
		"Active les événements OCI Object Storage",
		"bool",
	},
}

func variableNames(resource *models.OCIStorageRequest) []string {
	names := make([]string, 0, len(storageVariableDefinitions))
	for _, definition := range storageVariableDefinitions {
		names = append(
			names,
			resource.ResourceName+"_"+definition.suffix,
		)
	}
	return names
}

func addVariables(
	file *hclwrite.File,
	resource *models.OCIStorageRequest,
) {
	for _, definition := range storageVariableDefinitions {
		name := resource.ResourceName + "_" + definition.suffix
		block := hclwrite.NewBlock("variable", []string{name})
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
