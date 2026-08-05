package iam

import (
	"fmt"

	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

// ApplyUpdate replaces the final local values of one existing service account
// and its IAM membership. Changing account_id is allowed here, but Terraform
// may replace the service account during a future plan/apply.
func ApplyUpdate(files *common.TerraformFiles, request *models.Request) error {
	resource := request.IAMResource
	if resource == nil {
		return fmt.Errorf("ressource iam manquante")
	}

	serviceAccount := common.FindBlock(
		files.Main,
		"resource",
		serviceAccountResourceType,
		resource.ResourceName,
	)
	if serviceAccount == nil {
		return fmt.Errorf(
			"IAM service account not found: %s",
			resource.ResourceName,
		)
	}

	roleBindingName := resource.ResourceName + "_role"
	roleBinding := common.FindBlock(
		files.Main,
		"resource",
		projectIAMMemberType,
		roleBindingName,
	)
	if roleBinding == nil {
		return fmt.Errorf("IAM role binding not found: %s", roleBindingName)
	}

	if err := validateUpdateStructure(
		files,
		serviceAccount,
		roleBinding,
		resource.ResourceName,
	); err != nil {
		return err
	}

	addTfvars(files.Tfvars, resource)
	return nil
}

func validateUpdateStructure(
	files *common.TerraformFiles,
	serviceAccount *hclwrite.Block,
	roleBinding *hclwrite.Block,
	resourceName string,
) error {
	for _, attribute := range []string{
		"account_id",
		"display_name",
		"description",
		"project",
	} {
		if serviceAccount.Body().GetAttribute(attribute) == nil {
			return fmt.Errorf(
				"IAM service account %s is missing required attribute: %s",
				resourceName,
				attribute,
			)
		}
	}

	for _, attribute := range []string{"project", "role", "member"} {
		if roleBinding.Body().GetAttribute(attribute) == nil {
			return fmt.Errorf(
				"IAM role binding %s_role is missing required attribute: %s",
				resourceName,
				attribute,
			)
		}
	}

	for _, name := range variableNames(resourceName) {
		if !common.BlockExists(files.Variables, "variable", name) {
			return fmt.Errorf("IAM variable not found: %s", name)
		}
		if !common.AttributeExists(files.Tfvars, name) {
			return fmt.Errorf("IAM tfvars value not found: %s", name)
		}
	}

	for _, name := range outputNames(resourceName) {
		if !common.BlockExists(files.Outputs, "output", name) {
			return fmt.Errorf("IAM output not found: %s", name)
		}
	}

	return nil
}
