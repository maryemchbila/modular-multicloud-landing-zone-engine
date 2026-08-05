package network

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"

	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// ApplyDelete removes one linked VPC/subnet pair and only their associated
// variables, tfvars and outputs.
func ApplyDelete(files *common.TerraformFiles, request *models.Request) error {
	resource := request.NetworkResource
	if resource == nil {
		return fmt.Errorf("ressource network manquante")
	}

	networkBlock := common.FindBlock(
		files.Main,
		"resource",
		networkResourceType,
		resource.ResourceName,
	)
	if networkBlock == nil {
		return fmt.Errorf("Network resource not found: %s", resource.ResourceName)
	}
	subnetworkBlock := common.FindBlock(
		files.Main,
		"resource",
		subnetworkResourceType,
		resource.SubnetResourceName,
	)
	if subnetworkBlock == nil {
		return fmt.Errorf(
			"Subnetwork resource not found: %s",
			resource.SubnetResourceName,
		)
	}

	if !subnetworkIsLinkedToNetwork(
		subnetworkBlock,
		resource.ResourceName,
	) {
		return fmt.Errorf(
			"Subnetwork %s is not linked to network %s",
			resource.SubnetResourceName,
			resource.ResourceName,
		)
	}
	if networkReferencedByAnotherBlock(
		files.Main,
		networkBlock,
		subnetworkBlock,
		resource,
	) {
		return fmt.Errorf(
			"Cannot delete network %s: resource is referenced by another block",
			resource.ResourceName,
		)
	}

	referencedByCompute, err := networkReferencedByComputeConfiguration(
		request,
		files.Tfvars,
	)
	if err != nil {
		return err
	}
	if referencedByCompute {
		return fmt.Errorf(
			"Cannot delete network %s: referenced by Compute configuration",
			resource.ResourceName,
		)
	}

	common.RemoveBlocks(files.Main, func(block *hclwrite.Block) bool {
		return block == networkBlock || block == subnetworkBlock
	})

	names := networkVariableNames(resource)
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
		outputName := block.Labels()[0]
		if strings.HasPrefix(outputName, resource.ResourceName+"_") ||
			strings.HasPrefix(outputName, resource.SubnetResourceName+"_") {
			return true
		}
		return bodyReferencesNetworkResource(block.Body(), resource)
	})

	return compactDeletedNetworkFiles(files)
}

func subnetworkIsLinkedToNetwork(
	subnetworkBlock *hclwrite.Block,
	networkName string,
) bool {
	attribute := subnetworkBlock.Body().GetAttribute("network")
	if attribute == nil {
		return false
	}
	traversals := attribute.Expr().Variables()
	if len(traversals) != 1 {
		return false
	}
	return traversalValue(traversals[0]) ==
		networkResourceType+"."+networkName+".id"
}

func networkReferencedByAnotherBlock(
	file *hclwrite.File,
	networkBlock *hclwrite.Block,
	subnetworkBlock *hclwrite.Block,
	resource *models.NetworkRequest,
) bool {
	for _, block := range file.Body().Blocks() {
		if block == networkBlock || block == subnetworkBlock {
			continue
		}
		if bodyReferencesNetworkResource(block.Body(), resource) {
			return true
		}
	}
	return false
}

func bodyReferencesNetworkResource(
	body *hclwrite.Body,
	resource *models.NetworkRequest,
) bool {
	for _, attribute := range body.Attributes() {
		for _, traversal := range attribute.Expr().Variables() {
			if traversalReferencesNetworkResource(traversal, resource) {
				return true
			}
		}
	}
	for _, block := range body.Blocks() {
		if bodyReferencesNetworkResource(block.Body(), resource) {
			return true
		}
	}
	return false
}

func traversalReferencesNetworkResource(
	traversal *hclwrite.Traversal,
	resource *models.NetworkRequest,
) bool {
	value := traversalValue(traversal)
	prefixes := []string{
		networkResourceType + "." + resource.ResourceName,
		subnetworkResourceType + "." + resource.SubnetResourceName,
	}
	for _, prefix := range prefixes {
		if value == prefix || strings.HasPrefix(value, prefix+".") {
			return true
		}
	}
	return false
}

func traversalValue(traversal *hclwrite.Traversal) string {
	return strings.TrimSpace(string(traversal.BuildTokens(nil).Bytes()))
}

func networkReferencedByComputeConfiguration(
	request *models.Request,
	networkTfvars *hclwrite.File,
) (bool, error) {
	computePath := filepath.Join(
		filepath.Dir(request.ModulePath),
		"compute",
	)
	computeMain, err := common.LoadOrCreateFile(
		filepath.Join(computePath, "main.tf"),
	)
	if err != nil {
		return false, fmt.Errorf(
			"impossible d'inspecter les dependances Compute : %w",
			err,
		)
	}
	resource := request.NetworkResource
	if bodyReferencesNetworkResource(computeMain.Body(), resource) {
		return true, nil
	}

	computeTfvars, err := common.LoadOrCreateFile(
		filepath.Join(computePath, "terraform.tfvars"),
	)
	if err != nil {
		return false, fmt.Errorf(
			"impossible d'inspecter les dependances Compute : %w",
			err,
		)
	}
	certainNames := map[string]struct{}{
		resource.ResourceName: {},
	}
	if value, ok := literalStringAttribute(
		networkTfvars.Body().GetAttribute(resource.ResourceName + "_name"),
	); ok {
		certainNames[value] = struct{}{}
	}

	for name, attribute := range computeTfvars.Body().Attributes() {
		if !strings.HasSuffix(name, "_network") {
			continue
		}
		value, ok := literalStringAttribute(attribute)
		if !ok {
			continue
		}
		if _, certain := certainNames[value]; certain {
			return true, nil
		}
	}
	return false, nil
}

func literalStringAttribute(attribute *hclwrite.Attribute) (string, bool) {
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

func compactDeletedNetworkFiles(files *common.TerraformFiles) error {
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
