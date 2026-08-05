package compute

import (
	"strings"

	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

func variableNames(resourceName string) []string {
	return []string{
		resourceName + "_name",
		resourceName + "_machine_type",
		resourceName + "_zone",
		resourceName + "_image",
		resourceName + "_network",
	}
}

func addVariables(
	file *hclwrite.File,
	resource *models.ComputeRequest,
) {
	for _, name := range variableNames(resource.ResourceName) {
		addStringVariable(file, name)
	}
}

func addStringVariable(
	file *hclwrite.File,
	name string,
) {
	if common.BlockExists(file, "variable", name) {
		return
	}

	block := hclwrite.NewBlock(
		"variable",
		[]string{name},
	)
	block.Body().SetAttributeValue(
		"description",
		cty.StringVal(variableDescription(name)),
	)
	block.Body().SetAttributeTraversal(
		"type",
		common.TypeTraversal("string"),
	)

	common.AppendBlock(file, block)
}

func variableDescription(name string) string {
	switch {
	case strings.HasSuffix(name, "_machine_type"):
		return "Type de machine GCP"
	case strings.HasSuffix(name, "_zone"):
		return "Zone GCP"
	case strings.HasSuffix(name, "_image"):
		return "Image de démarrage GCP"
	case strings.HasSuffix(name, "_network"):
		return "Réseau VPC GCP"
	default:
		return "Nom de la VM GCP"
	}
}
