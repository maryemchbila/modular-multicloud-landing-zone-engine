package iam

import (
	"fmt"
	"strings"

	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

// ApplyUpdate replaces only the final tfvars values of one complete existing
// OCI IAM logical set. Resource identities, relations, declarations and
// outputs remain unchanged.
func ApplyUpdate(files *common.TerraformFiles, request *models.Request) error {
	resource := request.OCIIAMResource
	if resource == nil {
		return fmt.Errorf("ressource OCI IAM manquante")
	}

	group, err := requireIAMResource(
		files.Main,
		groupResourceType,
		resource.GroupResourceName,
		"OCI IAM group resource not found",
	)
	if err != nil {
		return err
	}
	user, err := requireIAMResource(
		files.Main,
		userResourceType,
		resource.UserResourceName,
		"OCI IAM user resource not found",
	)
	if err != nil {
		return err
	}
	membership, err := requireIAMResource(
		files.Main,
		membershipResourceType,
		resource.MembershipResourceName,
		"OCI IAM membership resource not found",
	)
	if err != nil {
		return err
	}
	policy, err := requireIAMResource(
		files.Main,
		policyResourceType,
		resource.PolicyResourceName,
		"OCI IAM policy resource not found",
	)
	if err != nil {
		return err
	}

	if err := verifyIAMMainTraversals(
		group,
		user,
		membership,
		policy,
		resource,
	); err != nil {
		return err
	}
	if err := verifyIAMUpdateDeclarations(files, resource); err != nil {
		return err
	}
	if err := checkUpdatedActualNameDuplicates(files, resource); err != nil {
		return err
	}

	addTfvars(files.Tfvars, resource)
	return nil
}

func requireIAMResource(
	file *hclwrite.File,
	resourceType string,
	resourceName string,
	notFoundMessage string,
) (*hclwrite.Block, error) {
	blocks := findIAMBlocks(
		file,
		"resource",
		resourceType,
		resourceName,
	)
	if len(blocks) == 0 {
		return nil, fmt.Errorf("%s: %s", notFoundMessage, resourceName)
	}
	if len(blocks) != 1 {
		return nil, fmt.Errorf(
			"OCI IAM resource missing or duplicated: %s.%s",
			resourceType,
			resourceName,
		)
	}
	return blocks[0], nil
}

func verifyIAMMainTraversals(
	group *hclwrite.Block,
	user *hclwrite.Block,
	membership *hclwrite.Block,
	policy *hclwrite.Block,
	resource *models.OCIIAMRequest,
) error {
	resources := []struct {
		block      *hclwrite.Block
		display    string
		name       string
		attributes map[string]string
	}{
		{
			block:   group,
			display: "group",
			name:    resource.GroupResourceName,
			attributes: map[string]string{
				"compartment_id": "var." +
					resource.GroupResourceName + "_tenancy_ocid",
				"name": "var." + resource.GroupResourceName + "_name",
				"description": "var." +
					resource.GroupResourceName + "_description",
			},
		},
		{
			block:   user,
			display: "user",
			name:    resource.UserResourceName,
			attributes: map[string]string{
				"compartment_id": "var." +
					resource.UserResourceName + "_tenancy_ocid",
				"name": "var." + resource.UserResourceName + "_name",
				"description": "var." +
					resource.UserResourceName + "_description",
			},
		},
		{
			block:   policy,
			display: "policy",
			name:    resource.PolicyResourceName,
			attributes: map[string]string{
				"compartment_id": "var." +
					resource.PolicyResourceName + "_compartment_id",
				"name": "var." + resource.PolicyResourceName + "_name",
				"description": "var." +
					resource.PolicyResourceName + "_description",
				"statements": "var." +
					resource.PolicyResourceName + "_statements",
			},
		},
	}
	for _, candidate := range resources {
		for attribute, expected := range candidate.attributes {
			if !iamAttributeEqualsTraversal(
				candidate.block.Body(),
				attribute,
				expected,
			) {
				return fmt.Errorf(
					"OCI IAM %s resource %s has invalid traversal for %s: expected %s",
					candidate.display,
					candidate.name,
					attribute,
					expected,
				)
			}
		}
	}

	expectedGroup := groupResourceType + "." +
		resource.GroupResourceName + ".id"
	if !iamAttributeEqualsTraversal(
		membership.Body(),
		"group_id",
		expectedGroup,
	) {
		return fmt.Errorf(
			"OCI IAM membership %s is not linked to group %s",
			resource.MembershipResourceName,
			resource.GroupResourceName,
		)
	}
	expectedUser := userResourceType + "." +
		resource.UserResourceName + ".id"
	if !iamAttributeEqualsTraversal(
		membership.Body(),
		"user_id",
		expectedUser,
	) {
		return fmt.Errorf(
			"OCI IAM membership %s is not linked to user %s",
			resource.MembershipResourceName,
			resource.UserResourceName,
		)
	}
	return nil
}

func verifyIAMUpdateDeclarations(
	files *common.TerraformFiles,
	resource *models.OCIIAMRequest,
) error {
	for _, name := range variableNames(resource) {
		blocks := findIAMBlocks(files.Variables, "variable", name)
		if len(blocks) != 1 {
			return fmt.Errorf(
				"OCI IAM variable missing or duplicated: %s",
				name,
			)
		}
		if name == resource.PolicyResourceName+"_statements" &&
			!iamAttributeEqualsTraversal(
				blocks[0].Body(),
				"type",
				"list(string)",
			) {
			return fmt.Errorf(
				"OCI IAM policy statements variable must use type list(string): %s",
				name,
			)
		}
		if !common.AttributeExists(files.Tfvars, name) {
			return fmt.Errorf("OCI IAM tfvar not found: %s", name)
		}
	}

	for _, definition := range outputDefinitions(resource) {
		blocks := findIAMBlocks(
			files.Outputs,
			"output",
			definition.name,
		)
		if len(blocks) != 1 {
			return fmt.Errorf(
				"OCI IAM output missing or duplicated: %s",
				definition.name,
			)
		}
		expected := definition.resourceType + "." +
			definition.resourceName + "." + definition.attribute
		if !iamAttributeEqualsTraversal(
			blocks[0].Body(),
			"value",
			expected,
		) {
			return fmt.Errorf(
				"OCI IAM output %s has invalid traversal: expected %s",
				definition.name,
				expected,
			)
		}
	}
	return nil
}

func checkUpdatedActualNameDuplicates(
	files *common.TerraformFiles,
	resource *models.OCIIAMRequest,
) error {
	for _, candidate := range []struct {
		resourceType string
		currentName  string
		field        string
		value        string
	}{
		{
			userResourceType,
			resource.UserResourceName,
			"user_name",
			resource.UserName,
		},
		{
			groupResourceType,
			resource.GroupResourceName,
			"group_name",
			resource.GroupName,
		},
		{
			policyResourceType,
			resource.PolicyResourceName,
			"policy_name",
			resource.PolicyName,
		},
	} {
		for _, block := range files.Main.Body().Blocks() {
			labels := block.Labels()
			if block.Type() != "resource" ||
				len(labels) != 2 ||
				labels[0] != candidate.resourceType ||
				labels[1] == candidate.currentName {
				continue
			}
			value, ok := literalStringAttribute(
				files.Tfvars,
				labels[1]+"_name",
			)
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

func findIAMBlocks(
	file *hclwrite.File,
	blockType string,
	expectedLabels ...string,
) []*hclwrite.Block {
	var matches []*hclwrite.Block
	for _, block := range file.Body().Blocks() {
		if block.Type() != blockType {
			continue
		}
		labels := block.Labels()
		if len(labels) != len(expectedLabels) {
			continue
		}
		match := true
		for index := range labels {
			if labels[index] != expectedLabels[index] {
				match = false
				break
			}
		}
		if match {
			matches = append(matches, block)
		}
	}
	return matches
}

func iamAttributeEqualsTraversal(
	body *hclwrite.Body,
	attributeName string,
	expected string,
) bool {
	attribute := body.GetAttribute(attributeName)
	if attribute == nil {
		return false
	}
	actual := strings.TrimSpace(
		string(attribute.Expr().BuildTokens(nil).Bytes()),
	)
	return actual == expected
}
