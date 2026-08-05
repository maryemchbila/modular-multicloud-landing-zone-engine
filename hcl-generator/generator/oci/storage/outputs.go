package storage

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

var storageOutputDefinitions = []outputDefinition{
	{"id", "Identifiant du bucket OCI", "id"},
	{"name", "Nom du bucket OCI", "name"},
	{"namespace", "Namespace du bucket OCI", "namespace"},
	{"etag", "ETag du bucket OCI", "etag"},
}

func outputNames(resource *models.OCIStorageRequest) []string {
	names := make([]string, 0, len(storageOutputDefinitions))
	for _, definition := range storageOutputDefinitions {
		names = append(
			names,
			resource.ResourceName+"_"+definition.suffix,
		)
	}
	return names
}

func addOutputs(
	file *hclwrite.File,
	resource *models.OCIStorageRequest,
) {
	for _, definition := range storageOutputDefinitions {
		name := resource.ResourceName + "_" + definition.suffix
		block := hclwrite.NewBlock("output", []string{name})
		block.Body().SetAttributeValue(
			"description",
			cty.StringVal(definition.description),
		)
		block.Body().SetAttributeTraversal(
			"value",
			common.ResourceTraversal(
				bucketResourceType,
				resource.ResourceName,
				definition.attribute,
			),
		)
		common.AppendBlock(file, block)
	}
}
