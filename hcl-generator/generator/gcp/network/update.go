package network

import (
	"fmt"
	"strings"

	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

const (
	networkResourceType    = "google_compute_network"
	subnetworkResourceType = "google_compute_subnetwork"
)

var legacyNetworkVariableNames = map[string]struct{}{
	"name":        {},
	"subnet_name": {},
	"cidr":        {},
	"region":      {},
}

// ApplyUpdate updates one existing VPC and its existing subnet. Both resources
// are located before any in-memory mutation so a missing resource changes
// nothing.
func ApplyUpdate(files *common.TerraformFiles, request *models.Request) error {
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

	if err := updateNetworkVariableReferences(
		networkBlock,
		subnetworkBlock,
		resource,
	); err != nil {
		return err
	}

	addVariables(files.Variables, resource)
	addTfvars(files.Tfvars, resource)
	removeUnusedLegacyNetworkVariables(files)
	return nil
}

func updateNetworkVariableReferences(
	networkBlock *hclwrite.Block,
	subnetworkBlock *hclwrite.Block,
	resource *models.NetworkRequest,
) error {
	if networkBlock.Body().GetAttribute("name") == nil {
		return missingNetworkAttribute(resource.ResourceName, "name")
	}

	subnetworkBody := subnetworkBlock.Body()
	for _, attribute := range []string{"name", "ip_cidr_range", "region", "network"} {
		if subnetworkBody.GetAttribute(attribute) == nil {
			return missingSubnetworkAttribute(
				resource.SubnetResourceName,
				attribute,
			)
		}
	}

	networkBlock.Body().SetAttributeTraversal(
		"name",
		common.VarTraversal(resource.ResourceName+"_name"),
	)
	subnetworkBody.SetAttributeTraversal(
		"name",
		common.VarTraversal(resource.SubnetResourceName+"_name"),
	)
	subnetworkBody.SetAttributeTraversal(
		"ip_cidr_range",
		common.VarTraversal(resource.SubnetResourceName+"_cidr"),
	)
	subnetworkBody.SetAttributeTraversal(
		"region",
		common.VarTraversal(resource.SubnetResourceName+"_region"),
	)
	subnetworkBody.SetAttributeTraversal(
		"network",
		common.ResourceTraversal(
			networkResourceType,
			resource.ResourceName,
			"id",
		),
	)
	return nil
}

func missingNetworkAttribute(resourceName string, attribute string) error {
	return fmt.Errorf(
		"Network resource %s is missing required attribute: %s",
		resourceName,
		attribute,
	)
}

func missingSubnetworkAttribute(resourceName string, attribute string) error {
	return fmt.Errorf(
		"Subnetwork resource %s is missing required attribute: %s",
		resourceName,
		attribute,
	)
}

func removeUnusedLegacyNetworkVariables(files *common.TerraformFiles) {
	if bodyUsesLegacyNetworkVariables(files.Main.Body()) {
		return
	}

	for _, block := range files.Variables.Body().Blocks() {
		if block.Type() != "variable" || len(block.Labels()) != 1 {
			continue
		}
		if _, legacy := legacyNetworkVariableNames[block.Labels()[0]]; legacy {
			files.Variables.Body().RemoveBlock(block)
		}
	}

	for name := range legacyNetworkVariableNames {
		files.Tfvars.Body().RemoveAttribute(name)
	}
}

func bodyUsesLegacyNetworkVariables(body *hclwrite.Body) bool {
	for _, attribute := range body.Attributes() {
		for _, traversal := range attribute.Expr().Variables() {
			if isLegacyNetworkVariableTraversal(traversal) {
				return true
			}
		}
	}

	for _, block := range body.Blocks() {
		if bodyUsesLegacyNetworkVariables(block.Body()) {
			return true
		}
	}
	return false
}

func isLegacyNetworkVariableTraversal(traversal *hclwrite.Traversal) bool {
	nameTraversal := strings.TrimSpace(
		string(traversal.BuildTokens(nil).Bytes()),
	)
	for name := range legacyNetworkVariableNames {
		if nameTraversal == "var."+name {
			return true
		}
	}
	return false
}
