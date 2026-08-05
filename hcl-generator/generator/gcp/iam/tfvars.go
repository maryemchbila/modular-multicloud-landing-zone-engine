package iam

import (
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

func addTfvars(file *hclwrite.File, resource *models.IAMRequest) {
	body := file.Body()
	body.SetAttributeValue(
		resource.ResourceName+"_account_id",
		cty.StringVal(resource.AccountID),
	)
	body.SetAttributeValue(
		resource.ResourceName+"_display_name",
		cty.StringVal(resource.DisplayName),
	)
	body.SetAttributeValue(
		resource.ResourceName+"_description",
		cty.StringVal(resource.Description),
	)
	body.SetAttributeValue(
		resource.ResourceName+"_project_id",
		cty.StringVal(resource.ProjectID),
	)
	body.SetAttributeValue(
		resource.ResourceName+"_role",
		cty.StringVal(resource.Role),
	)
}
