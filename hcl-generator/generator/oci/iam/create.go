package iam

import (
	"bytes"
	"fmt"

	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

const (
	groupResourceType      = "oci_identity_group"
	userResourceType       = "oci_identity_user"
	membershipResourceType = "oci_identity_user_group_membership"
	policyResourceType     = "oci_identity_policy"
)

func ApplyCreate(files *common.TerraformFiles, request *models.Request) error {
	resource := request.OCIIAMResource
	if resource == nil {
		return fmt.Errorf("ressource OCI IAM manquante")
	}
	if len(resource.PolicyStatements) == 0 {
		return fmt.Errorf(
			"OCI IAM policy statements cannot be empty; must contain at least one value.",
		)
	}
	if err := checkCreateDuplicates(files, resource); err != nil {
		return err
	}

	addMainResources(files.Main, resource)
	addVariables(files.Variables, resource)
	addTfvars(files.Tfvars, resource)
	addOutputs(files.Outputs, resource)
	return nil
}

func checkCreateDuplicates(
	files *common.TerraformFiles,
	resource *models.OCIIAMRequest,
) error {
	resources := []struct {
		resourceType string
		resourceName string
	}{
		{groupResourceType, resource.GroupResourceName},
		{userResourceType, resource.UserResourceName},
		{membershipResourceType, resource.MembershipResourceName},
		{policyResourceType, resource.PolicyResourceName},
	}
	for _, candidate := range resources {
		if common.BlockExists(
			files.Main,
			"resource",
			candidate.resourceType,
			candidate.resourceName,
		) {
			return fmt.Errorf(
				"doublon OCI IAM : resource %q %q existe deja",
				candidate.resourceType,
				candidate.resourceName,
			)
		}
	}

	for _, name := range variableNames(resource) {
		if common.BlockExists(files.Variables, "variable", name) {
			return fmt.Errorf(
				"doublon OCI IAM : variable %q existe deja",
				name,
			)
		}
		if common.AttributeExists(files.Tfvars, name) {
			return fmt.Errorf(
				"doublon OCI IAM : valeur tfvars %q existe deja",
				name,
			)
		}
	}
	for _, name := range outputNames(resource) {
		if common.BlockExists(files.Outputs, "output", name) {
			return fmt.Errorf(
				"doublon OCI IAM : output %q existe deja",
				name,
			)
		}
	}

	for _, candidate := range []struct {
		resourceType string
		suffix       string
		field        string
		value        string
	}{
		{userResourceType, "_name", "user_name", resource.UserName},
		{groupResourceType, "_name", "group_name", resource.GroupName},
		{policyResourceType, "_name", "policy_name", resource.PolicyName},
	} {
		for _, block := range files.Main.Body().Blocks() {
			if block.Type() != "resource" ||
				len(block.Labels()) != 2 ||
				block.Labels()[0] != candidate.resourceType {
				continue
			}
			name := block.Labels()[1] + candidate.suffix
			value, ok := literalStringAttribute(files.Tfvars, name)
			if ok && value == candidate.value {
				return fmt.Errorf(
					"doublon OCI IAM : %s %q existe deja",
					candidate.field,
					candidate.value,
				)
			}
		}
	}
	return nil
}

func literalStringAttribute(
	file *hclwrite.File,
	name string,
) (string, bool) {
	attribute := file.Body().GetAttribute(name)
	if attribute == nil {
		return "", false
	}
	expression, diagnostics := hclsyntax.ParseExpression(
		bytes.TrimSpace(attribute.Expr().BuildTokens(nil).Bytes()),
		"terraform.tfvars",
		hcl.InitialPos,
	)
	if diagnostics.HasErrors() {
		return "", false
	}
	value, diagnostics := expression.Value(nil)
	if diagnostics.HasErrors() ||
		!value.IsKnown() ||
		value.IsNull() ||
		value.Type() != cty.String {
		return "", false
	}
	return value.AsString(), true
}

func addMainResources(
	file *hclwrite.File,
	resource *models.OCIIAMRequest,
) {
	group := hclwrite.NewBlock(
		"resource",
		[]string{groupResourceType, resource.GroupResourceName},
	)
	group.Body().SetAttributeTraversal(
		"compartment_id",
		common.VarTraversal(resource.GroupResourceName+"_tenancy_ocid"),
	)
	group.Body().SetAttributeTraversal(
		"name",
		common.VarTraversal(resource.GroupResourceName+"_name"),
	)
	group.Body().SetAttributeTraversal(
		"description",
		common.VarTraversal(resource.GroupResourceName+"_description"),
	)
	common.AppendBlock(file, group)

	user := hclwrite.NewBlock(
		"resource",
		[]string{userResourceType, resource.UserResourceName},
	)
	user.Body().SetAttributeTraversal(
		"compartment_id",
		common.VarTraversal(resource.UserResourceName+"_tenancy_ocid"),
	)
	user.Body().SetAttributeTraversal(
		"name",
		common.VarTraversal(resource.UserResourceName+"_name"),
	)
	user.Body().SetAttributeTraversal(
		"description",
		common.VarTraversal(resource.UserResourceName+"_description"),
	)
	common.AppendBlock(file, user)

	membership := hclwrite.NewBlock(
		"resource",
		[]string{membershipResourceType, resource.MembershipResourceName},
	)
	membership.Body().SetAttributeTraversal(
		"group_id",
		common.ResourceTraversal(
			groupResourceType,
			resource.GroupResourceName,
			"id",
		),
	)
	membership.Body().SetAttributeTraversal(
		"user_id",
		common.ResourceTraversal(
			userResourceType,
			resource.UserResourceName,
			"id",
		),
	)
	common.AppendBlock(file, membership)

	policy := hclwrite.NewBlock(
		"resource",
		[]string{policyResourceType, resource.PolicyResourceName},
	)
	for _, attribute := range []string{
		"compartment_id",
		"name",
		"description",
		"statements",
	} {
		policy.Body().SetAttributeTraversal(
			attribute,
			common.VarTraversal(
				resource.PolicyResourceName+"_"+attribute,
			),
		)
	}
	common.AppendBlock(file, policy)
}
