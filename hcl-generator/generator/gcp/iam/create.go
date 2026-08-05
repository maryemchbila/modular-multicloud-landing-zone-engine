package iam

import (
	"fmt"

	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

const (
	serviceAccountResourceType = "google_service_account"
	projectIAMMemberType       = "google_project_iam_member"
)

func ApplyCreate(files *common.TerraformFiles, request *models.Request) error {
	resource := request.IAMResource
	if resource == nil {
		return fmt.Errorf("ressource iam manquante")
	}

	if err := checkDuplicates(files, resource); err != nil {
		return err
	}

	addMainResources(files.Main, resource)
	addVariables(files.Variables, resource)
	addTfvars(files.Tfvars, resource)
	addOutputs(files.Outputs, resource)
	return nil
}

func checkDuplicates(
	files *common.TerraformFiles,
	resource *models.IAMRequest,
) error {
	resources := []struct {
		resourceType string
		resourceName string
	}{
		{serviceAccountResourceType, resource.ResourceName},
		{projectIAMMemberType, resource.ResourceName + "_role"},
	}
	for _, candidate := range resources {
		if common.BlockExists(
			files.Main,
			"resource",
			candidate.resourceType,
			candidate.resourceName,
		) {
			return fmt.Errorf(
				"doublon iam : resource %q %q existe deja",
				candidate.resourceType,
				candidate.resourceName,
			)
		}
	}

	for _, name := range variableNames(resource.ResourceName) {
		if common.BlockExists(files.Variables, "variable", name) {
			return fmt.Errorf("doublon iam : variable %q existe deja", name)
		}
		if common.AttributeExists(files.Tfvars, name) {
			return fmt.Errorf("doublon iam : valeur tfvars %q existe deja", name)
		}
	}

	for _, name := range outputNames(resource.ResourceName) {
		if common.BlockExists(files.Outputs, "output", name) {
			return fmt.Errorf("doublon iam : output %q existe deja", name)
		}
	}

	return nil
}

func addMainResources(file *hclwrite.File, resource *models.IAMRequest) {
	serviceAccount := hclwrite.NewBlock(
		"resource",
		[]string{serviceAccountResourceType, resource.ResourceName},
	)
	serviceAccountBody := serviceAccount.Body()
	serviceAccountBody.SetAttributeTraversal(
		"account_id",
		common.VarTraversal(resource.ResourceName+"_account_id"),
	)
	serviceAccountBody.SetAttributeTraversal(
		"display_name",
		common.VarTraversal(resource.ResourceName+"_display_name"),
	)
	serviceAccountBody.SetAttributeTraversal(
		"description",
		common.VarTraversal(resource.ResourceName+"_description"),
	)
	serviceAccountBody.SetAttributeTraversal(
		"project",
		common.VarTraversal(resource.ResourceName+"_project_id"),
	)
	common.AppendBlock(file, serviceAccount)

	iamMember := hclwrite.NewBlock(
		"resource",
		[]string{projectIAMMemberType, resource.ResourceName + "_role"},
	)
	iamMemberBody := iamMember.Body()
	iamMemberBody.SetAttributeTraversal(
		"project",
		common.VarTraversal(resource.ResourceName+"_project_id"),
	)
	iamMemberBody.SetAttributeTraversal(
		"role",
		common.VarTraversal(resource.ResourceName+"_role"),
	)
	iamMemberBody.SetAttributeRaw(
		"member",
		serviceAccountMemberTokens(resource.ResourceName),
	)
	common.AppendBlock(file, iamMember)
}

func serviceAccountMemberTokens(resourceName string) hclwrite.Tokens {
	tokens := hclwrite.Tokens{
		{
			Type:  hclsyntax.TokenOQuote,
			Bytes: []byte(`"`),
		},
		{
			Type:  hclsyntax.TokenQuotedLit,
			Bytes: []byte("serviceAccount:"),
		},
		{
			Type:  hclsyntax.TokenTemplateInterp,
			Bytes: []byte("${"),
		},
	}
	tokens = append(
		tokens,
		hclwrite.TokensForTraversal(
			common.ResourceTraversal(
				serviceAccountResourceType,
				resourceName,
				"email",
			),
		)...,
	)
	return append(
		tokens,
		&hclwrite.Token{
			Type:  hclsyntax.TokenTemplateSeqEnd,
			Bytes: []byte("}"),
		},
		&hclwrite.Token{
			Type:  hclsyntax.TokenCQuote,
			Bytes: []byte(`"`),
		},
	)
}
