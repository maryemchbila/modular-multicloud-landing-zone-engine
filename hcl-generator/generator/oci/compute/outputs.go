package compute

import (
	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

type outputDefinition struct {
	suffix      string
	description string
	attribute   string
}

var outputDefinitions = []outputDefinition{
	{"id", "OCID de l'instance OCI", "id"},
	{"display_name", "Nom affiché de l'instance OCI", "display_name"},
	{"private_ip", "Adresse IP privée de l'instance OCI", "private_ip"},
	{"public_ip", "Adresse IP publique de l'instance OCI", "public_ip"},
}

func outputNames(resourceName string) []string {
	names := make([]string, 0, len(outputDefinitions))
	for _, definition := range outputDefinitions {
		names = append(names, resourceName+"_"+definition.suffix)
	}
	return names
}

func addOutputs(
	file *hclwrite.File,
	resource *models.OCIComputeRequest,
) {
	for _, definition := range outputDefinitions {
		block := hclwrite.NewBlock(
			"output",
			[]string{resource.ResourceName + "_" + definition.suffix},
		)
		block.Body().SetAttributeValue(
			"description",
			cty.StringVal(definition.description),
		)
		block.Body().SetAttributeTraversal(
			"value",
			common.ResourceTraversal(
				instanceResourceType,
				resource.ResourceName,
				definition.attribute,
			),
		)
		common.AppendBlock(file, block)
	}
}
