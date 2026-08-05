package compute

import (
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

func addTfvars(
	file *hclwrite.File,
	resource *models.OCIComputeRequest,
) {
	body := file.Body()
	prefix := resource.ResourceName + "_"

	body.SetAttributeValue(
		prefix+"display_name",
		cty.StringVal(resource.DisplayName),
	)
	body.SetAttributeValue(
		prefix+"availability_domain",
		cty.StringVal(resource.AvailabilityDomain),
	)
	body.SetAttributeValue(
		prefix+"compartment_id",
		cty.StringVal(resource.CompartmentID),
	)
	body.SetAttributeValue(
		prefix+"shape",
		cty.StringVal(resource.Shape),
	)
	body.SetAttributeValue(
		prefix+"subnet_id",
		cty.StringVal(resource.SubnetID),
	)
	body.SetAttributeValue(
		prefix+"image_id",
		cty.StringVal(resource.ImageID),
	)
	body.SetAttributeValue(
		prefix+"assign_public_ip",
		cty.BoolVal(*resource.AssignPublicIP),
	)
}
