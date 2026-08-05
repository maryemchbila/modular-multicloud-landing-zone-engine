package network

import (
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

func addTfvars(
	file *hclwrite.File,
	resource *models.NetworkRequest,
) {
	body := file.Body()
	body.SetAttributeValue(
		resource.ResourceName+"_name",
		cty.StringVal(resource.Name),
	)
	body.SetAttributeValue(
		resource.SubnetResourceName+"_name",
		cty.StringVal(resource.SubnetName),
	)
	body.SetAttributeValue(
		resource.SubnetResourceName+"_cidr",
		cty.StringVal(resource.CIDR),
	)
	body.SetAttributeValue(
		resource.SubnetResourceName+"_region",
		cty.StringVal(resource.Region),
	)
}
