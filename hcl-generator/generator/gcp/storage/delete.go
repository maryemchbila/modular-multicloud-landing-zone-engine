package storage

import (
	"fmt"
	"strings"

	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

// ApplyDelete removes one existing bucket and only its associated variables,
// tfvars and outputs from the local Terraform configuration.
func ApplyDelete(files *common.TerraformFiles, request *models.Request) error {
	resource := request.StorageResource
	if resource == nil {
		return fmt.Errorf("ressource storage manquante")
	}
	resourceName := resource.ResourceName

	target := common.FindBlock(
		files.Main,
		"resource",
		storageResourceType,
		resourceName,
	)
	if target == nil {
		return fmt.Errorf("Storage resource not found: %s", resourceName)
	}

	if storageResourceReferencedByAnotherBlock(
		files.Main,
		target,
		resourceName,
	) {
		return fmt.Errorf(
			"Cannot delete Storage resource %s: referenced by another block",
			resourceName,
		)
	}

	common.RemoveBlocks(files.Main, func(block *hclwrite.Block) bool {
		return block == target
	})

	names := storageVariableNames(resourceName)
	nameSet := make(map[string]struct{}, len(names))
	for _, name := range names {
		nameSet[name] = struct{}{}
	}
	common.RemoveBlocks(files.Variables, func(block *hclwrite.Block) bool {
		if block.Type() != "variable" || len(block.Labels()) != 1 {
			return false
		}
		_, belongsToTarget := nameSet[block.Labels()[0]]
		return belongsToTarget
	})
	common.RemoveAttributes(files.Tfvars, names)

	common.RemoveBlocks(files.Outputs, func(block *hclwrite.Block) bool {
		return block.Type() == "output" &&
			len(block.Labels()) == 1 &&
			strings.HasPrefix(block.Labels()[0], resourceName+"_")
	})

	return compactDeletedStorageFiles(files)
}

func storageResourceReferencedByAnotherBlock(
	file *hclwrite.File,
	target *hclwrite.Block,
	resourceName string,
) bool {
	for _, block := range file.Body().Blocks() {
		if block == target {
			continue
		}
		if bodyReferencesStorageResource(block.Body(), resourceName) {
			return true
		}
	}
	return false
}

func bodyReferencesStorageResource(
	body *hclwrite.Body,
	resourceName string,
) bool {
	for _, attribute := range body.Attributes() {
		for _, traversal := range attribute.Expr().Variables() {
			value := strings.TrimSpace(
				string(traversal.BuildTokens(nil).Bytes()),
			)
			prefix := storageResourceType + "." + resourceName
			if value == prefix || strings.HasPrefix(value, prefix+".") {
				return true
			}
		}
	}
	for _, block := range body.Blocks() {
		if bodyReferencesStorageResource(block.Body(), resourceName) {
			return true
		}
	}
	return false
}

func compactDeletedStorageFiles(files *common.TerraformFiles) error {
	targets := []struct {
		name string
		file **hclwrite.File
	}{
		{"main.tf", &files.Main},
		{"variables.tf", &files.Variables},
		{"terraform.tfvars", &files.Tfvars},
		{"outputs.tf", &files.Outputs},
	}
	for _, target := range targets {
		compacted, err := common.CompactFile(*target.file, target.name)
		if err != nil {
			return err
		}
		*target.file = compacted
	}
	return nil
}
