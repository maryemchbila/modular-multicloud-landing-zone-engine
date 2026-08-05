package storage

import (
	"fmt"
	"strings"

	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

const storageResourceType = "google_storage_bucket"

var legacyStorageVariableNames = map[string]struct{}{
	"name":                        {},
	"location":                    {},
	"storage_class":               {},
	"uniform_bucket_level_access": {},
}

// ApplyUpdate updates one existing bucket without changing its Terraform
// resource label or creating outputs.
func ApplyUpdate(files *common.TerraformFiles, request *models.Request) error {
	resource := request.StorageResource
	if resource == nil {
		return fmt.Errorf("ressource storage manquante")
	}
	if resource.UniformBucketLevelAccess == nil {
		return fmt.Errorf(
			"champ obligatoire manquant : resource.uniform_bucket_level_access",
		)
	}

	block := common.FindBlock(
		files.Main,
		"resource",
		storageResourceType,
		resource.ResourceName,
	)
	if block == nil {
		return fmt.Errorf("Storage resource not found: %s", resource.ResourceName)
	}

	if err := updateStorageVariableReferences(block, resource.ResourceName); err != nil {
		return err
	}

	addVariables(files.Variables, resource)
	addTfvars(files.Tfvars, resource)
	removeUnusedLegacyStorageVariables(files)
	return nil
}

func updateStorageVariableReferences(
	resourceBlock *hclwrite.Block,
	resourceName string,
) error {
	body := resourceBlock.Body()
	attributes := []struct {
		attribute string
		suffix    string
	}{
		{"name", "_name"},
		{"location", "_location"},
		{"storage_class", "_storage_class"},
		{
			"uniform_bucket_level_access",
			"_uniform_bucket_level_access",
		},
	}

	for _, candidate := range attributes {
		if body.GetAttribute(candidate.attribute) == nil {
			return fmt.Errorf(
				"Storage resource %s is missing required attribute: %s",
				resourceName,
				candidate.attribute,
			)
		}
	}

	for _, candidate := range attributes {
		body.SetAttributeTraversal(
			candidate.attribute,
			common.VarTraversal(resourceName+candidate.suffix),
		)
	}
	return nil
}

func removeUnusedLegacyStorageVariables(files *common.TerraformFiles) {
	if bodyUsesLegacyStorageVariables(files.Main.Body()) {
		return
	}

	for _, block := range files.Variables.Body().Blocks() {
		if block.Type() != "variable" || len(block.Labels()) != 1 {
			continue
		}
		if _, legacy := legacyStorageVariableNames[block.Labels()[0]]; legacy {
			files.Variables.Body().RemoveBlock(block)
		}
	}

	for name := range legacyStorageVariableNames {
		files.Tfvars.Body().RemoveAttribute(name)
	}
}

func bodyUsesLegacyStorageVariables(body *hclwrite.Body) bool {
	for _, attribute := range body.Attributes() {
		for _, traversal := range attribute.Expr().Variables() {
			if isLegacyStorageVariableTraversal(traversal) {
				return true
			}
		}
	}

	for _, block := range body.Blocks() {
		if bodyUsesLegacyStorageVariables(block.Body()) {
			return true
		}
	}
	return false
}

func isLegacyStorageVariableTraversal(traversal *hclwrite.Traversal) bool {
	nameTraversal := strings.TrimSpace(
		string(traversal.BuildTokens(nil).Bytes()),
	)
	for name := range legacyStorageVariableNames {
		if nameTraversal == "var."+name {
			return true
		}
	}
	return false
}
