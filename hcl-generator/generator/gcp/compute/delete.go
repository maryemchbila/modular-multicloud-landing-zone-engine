package compute

import (
	"fmt"
	"strings"

	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

// ApplyDelete removes one existing Compute resource and only its associated
// variables, tfvars and outputs.
func ApplyDelete(files *common.TerraformFiles, request *models.Request) error {
	resource := request.ComputeResource
	if resource == nil {
		return fmt.Errorf("ressource compute manquante")
	}
	resourceName := resource.ResourceName

	target := common.FindBlock(
		files.Main,
		"resource",
		computeResourceType,
		resourceName,
	)
	if target == nil {
		return fmt.Errorf("Compute resource not found: %s", resourceName)
	}

	if referencedByAnotherMainBlock(files.Main, target, resourceName) {
		return fmt.Errorf(
			"Cannot delete Compute resource %s: referenced by another block",
			resourceName,
		)
	}

	common.RemoveBlocks(files.Main, func(block *hclwrite.Block) bool {
		return block == target
	})

	names := variableNames(resourceName)
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
		if block.Type() != "output" || len(block.Labels()) != 1 {
			return false
		}
		if strings.HasPrefix(block.Labels()[0], resourceName+"_") {
			return true
		}
		return bodyReferencesComputeResource(block.Body(), resourceName)
	})

	return compactDeletedComputeFiles(files)
}

func referencedByAnotherMainBlock(
	file *hclwrite.File,
	target *hclwrite.Block,
	resourceName string,
) bool {
	for _, block := range file.Body().Blocks() {
		if block == target {
			continue
		}
		if bodyReferencesComputeResource(block.Body(), resourceName) {
			return true
		}
	}
	return false
}

func bodyReferencesComputeResource(
	body *hclwrite.Body,
	resourceName string,
) bool {
	for _, attribute := range body.Attributes() {
		for _, traversal := range attribute.Expr().Variables() {
			if isComputeResourceTraversal(traversal, resourceName) {
				return true
			}
		}
	}
	for _, block := range body.Blocks() {
		if bodyReferencesComputeResource(block.Body(), resourceName) {
			return true
		}
	}
	return false
}

func isComputeResourceTraversal(
	traversal *hclwrite.Traversal,
	resourceName string,
) bool {
	value := strings.TrimSpace(string(traversal.BuildTokens(nil).Bytes()))
	prefix := computeResourceType + "." + resourceName
	return value == prefix || strings.HasPrefix(value, prefix+".")
}

func compactDeletedComputeFiles(files *common.TerraformFiles) error {
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
