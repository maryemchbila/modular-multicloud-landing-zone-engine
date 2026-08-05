package compute

import (
	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

func addOutputs(
	file *hclwrite.File,
	request *models.Request,
) {
	resourceName := request.ComputeResource.ResourceName
	addOutput(
		file,
		resourceName+"_id",
		request,
		"id",
	)
	addOutput(
		file,
		resourceName+"_name",
		request,
		"name",
	)
}

func outputNames(resourceName string) []string {
	return []string{
		resourceName + "_id",
		resourceName + "_name",
	}
}

func addOutput(
	file *hclwrite.File,
	outputName string,
	request *models.Request,
	attribute string,
) {
	if common.BlockExists(file, "output", outputName) {
		return
	}

	block := hclwrite.NewBlock(
		"output",
		[]string{outputName},
	)
	block.Body().SetAttributeTraversal(
		"value",
		common.ResourceTraversal(
			"google_compute_instance",
			request.ComputeResource.ResourceName,
			attribute,
		),
	)

	common.AppendBlock(file, block)
}
