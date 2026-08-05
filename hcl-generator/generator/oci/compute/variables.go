package compute

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

var variableDefinitions = []variableDefinition{
	{"display_name", "Nom affiché de l'instance OCI", "string"},
	{"availability_domain", "Availability Domain OCI", "string"},
	{"compartment_id", "OCID du compartiment OCI", "string"},
	{"shape", "Shape de l'instance OCI", "string"},
	{"subnet_id", "OCID du subnet OCI", "string"},
	{"image_id", "OCID de l'image OCI", "string"},
	{
		"assign_public_ip",
		"Autorise une adresse IP publique sur le VNIC",
		"bool",
	},
}

func variableNames(resourceName string) []string {
	names := make([]string, 0, len(variableDefinitions))
	for _, definition := range variableDefinitions {
		names = append(names, resourceName+"_"+definition.suffix)
	}
	return names
}

func addVariables(
	file *hclwrite.File,
	resource *models.OCIComputeRequest,
) {
	for _, definition := range variableDefinitions {
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
