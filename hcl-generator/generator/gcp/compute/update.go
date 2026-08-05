package compute

import (
	"fmt"
	"strings"

	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

const computeResourceType = "google_compute_instance"

var legacyComputeVariableNames = map[string]struct{}{
	"name":         {},
	"machine_type": {},
	"zone":         {},
	"image":        {},
	"network":      {},
}

// ApplyUpdate updates one existing Compute resource. Legacy Compute resources
// using shared variables are migrated to resource-scoped variables so that
// updating one VM cannot change the values used by another VM.
func ApplyUpdate(files *common.TerraformFiles, request *models.Request) error {
	resource := request.ComputeResource
	if resource == nil {
		return fmt.Errorf("ressource compute manquante")
	}

	block := common.FindBlock(
		files.Main,
		"resource",
		computeResourceType,
		resource.ResourceName,
	)
	if block == nil {
		return fmt.Errorf("Compute resource not found: %s", resource.ResourceName)
	}

	if err := updateResourceVariableReferences(block, resource.ResourceName); err != nil {
		return err
	}

	ensureUpdateVariables(files.Variables, resource.ResourceName)
	addTfvars(files.Tfvars, request)
	removeUnusedLegacyComputeVariables(files)
	return nil
}

func updateResourceVariableReferences(
	resourceBlock *hclwrite.Block,
	resourceName string,
) error {
	body := resourceBlock.Body()
	if body.GetAttribute("name") == nil {
		return missingComputeAttribute(resourceName, "name")
	}
	if body.GetAttribute("machine_type") == nil {
		return missingComputeAttribute(resourceName, "machine_type")
	}
	if body.GetAttribute("zone") == nil {
		return missingComputeAttribute(resourceName, "zone")
	}

	bootDisk, err := requireSingleNestedBlock(body, "boot_disk", resourceName)
	if err != nil {
		return err
	}
	initializeParams, err := requireSingleNestedBlock(
		bootDisk.Body(),
		"initialize_params",
		resourceName,
	)
	if err != nil {
		return err
	}
	if initializeParams.Body().GetAttribute("image") == nil {
		return missingComputeAttribute(resourceName, "boot_disk.initialize_params.image")
	}

	networkInterface, err := requireSingleNestedBlock(
		body,
		"network_interface",
		resourceName,
	)
	if err != nil {
		return err
	}
	if networkInterface.Body().GetAttribute("network") == nil {
		return missingComputeAttribute(resourceName, "network_interface.network")
	}

	body.SetAttributeTraversal(
		"name",
		common.VarTraversal(resourceName+"_name"),
	)
	body.SetAttributeTraversal(
		"machine_type",
		common.VarTraversal(resourceName+"_machine_type"),
	)
	body.SetAttributeTraversal(
		"zone",
		common.VarTraversal(resourceName+"_zone"),
	)
	initializeParams.Body().SetAttributeTraversal(
		"image",
		common.VarTraversal(resourceName+"_image"),
	)
	networkInterface.Body().SetAttributeTraversal(
		"network",
		common.VarTraversal(resourceName+"_network"),
	)

	return nil
}

func requireSingleNestedBlock(
	body *hclwrite.Body,
	blockType string,
	resourceName string,
) (*hclwrite.Block, error) {
	var found *hclwrite.Block
	for _, block := range body.Blocks() {
		if block.Type() != blockType {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf(
				"Compute resource %s has multiple %s blocks; update is ambiguous",
				resourceName,
				blockType,
			)
		}
		found = block
	}
	if found == nil {
		return nil, fmt.Errorf(
			"Compute resource %s is missing required block: %s",
			resourceName,
			blockType,
		)
	}
	return found, nil
}

func missingComputeAttribute(resourceName string, attribute string) error {
	return fmt.Errorf(
		"Compute resource %s is missing required attribute: %s",
		resourceName,
		attribute,
	)
}

func ensureUpdateVariables(file *hclwrite.File, resourceName string) {
	for _, name := range variableNames(resourceName) {
		addStringVariable(file, name)
	}
}

// removeUnusedLegacyComputeVariables removes the old shared declarations and
// values only after every reference in main.tf has been migrated.
func removeUnusedLegacyComputeVariables(files *common.TerraformFiles) {
	if bodyUsesLegacyComputeVariables(files.Main.Body()) {
		return
	}

	for _, block := range files.Variables.Body().Blocks() {
		if block.Type() != "variable" || len(block.Labels()) != 1 {
			continue
		}
		if _, legacy := legacyComputeVariableNames[block.Labels()[0]]; legacy {
			files.Variables.Body().RemoveBlock(block)
		}
	}

	for name := range legacyComputeVariableNames {
		files.Tfvars.Body().RemoveAttribute(name)
	}
}

func bodyUsesLegacyComputeVariables(body *hclwrite.Body) bool {
	for _, attribute := range body.Attributes() {
		for _, traversal := range attribute.Expr().Variables() {
			if isLegacyComputeVariableTraversal(traversal) {
				return true
			}
		}
	}

	for _, block := range body.Blocks() {
		if bodyUsesLegacyComputeVariables(block.Body()) {
			return true
		}
	}
	return false
}

func isLegacyComputeVariableTraversal(traversal *hclwrite.Traversal) bool {
	nameTraversal := strings.TrimSpace(
		string(traversal.BuildTokens(nil).Bytes()),
	)
	for name := range legacyComputeVariableNames {
		if nameTraversal == "var."+name {
			return true
		}
	}
	return false
}
