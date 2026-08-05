package iam

import (
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

func addTfvars(file *hclwrite.File, resource *models.OCIIAMRequest) {
	body := file.Body()
	values := []struct {
		name  string
		value string
	}{
		{resource.UserResourceName + "_tenancy_ocid", resource.TenancyOCID},
		{resource.UserResourceName + "_name", resource.UserName},
		{
			resource.UserResourceName + "_description",
			resource.UserDescription,
		},
		{resource.GroupResourceName + "_tenancy_ocid", resource.TenancyOCID},
		{resource.GroupResourceName + "_name", resource.GroupName},
		{
			resource.GroupResourceName + "_description",
			resource.GroupDescription,
		},
		{
			resource.PolicyResourceName + "_compartment_id",
			resource.PolicyCompartmentID,
		},
		{resource.PolicyResourceName + "_name", resource.PolicyName},
		{
			resource.PolicyResourceName + "_description",
			resource.PolicyDescription,
		},
	}
	for _, entry := range values {
		body.SetAttributeValue(entry.name, cty.StringVal(entry.value))
	}

	statements := make([]cty.Value, 0, len(resource.PolicyStatements))
	for _, statement := range resource.PolicyStatements {
		statements = append(statements, cty.StringVal(statement))
	}
	body.SetAttributeValue(
		resource.PolicyResourceName+"_statements",
		cty.ListVal(statements),
	)
}
