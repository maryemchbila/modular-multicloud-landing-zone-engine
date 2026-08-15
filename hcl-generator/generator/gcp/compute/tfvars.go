package compute

import (
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

func addTfvars(
	file *hclwrite.File,
	request *models.Request,
) {
	body := file.Body()
	resource := request.ComputeResource

	if request.ProjectID != "" {
		body.SetAttributeValue(
			"gcp_project_id",
			cty.StringVal(request.ProjectID),
		)
	}

	body.SetAttributeValue(
		resource.ResourceName+"_name",
		cty.StringVal(resource.Name),
	)
	body.SetAttributeValue(
		resource.ResourceName+"_machine_type",
		cty.StringVal(resource.MachineType),
	)
	body.SetAttributeValue(
		resource.ResourceName+"_zone",
		cty.StringVal(resource.Zone),
	)
	body.SetAttributeValue(
		resource.ResourceName+"_image",
		cty.StringVal(resource.Image),
	)
	body.SetAttributeValue(
		resource.ResourceName+"_network",
		cty.StringVal(resource.Network),
	)
}
