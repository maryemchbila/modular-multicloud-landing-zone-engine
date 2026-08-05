package compute

import (
	"fmt"

	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

// ApplyUpdate updates the final values of one existing OCI Compute instance.
// The Terraform resource, variable declarations and outputs are deliberately
// left unchanged.
func ApplyUpdate(files *common.TerraformFiles, request *models.Request) error {
	resource := request.OCIComputeResource
	if resource == nil {
		return fmt.Errorf("ressource OCI compute manquante")
	}
	if resource.AssignPublicIP == nil {
		return fmt.Errorf(
			"champ obligatoire manquant : resource.assign_public_ip",
		)
	}

	if common.FindBlock(
		files.Main,
		"resource",
		instanceResourceType,
		resource.ResourceName,
	) == nil {
		return fmt.Errorf(
			"OCI Compute resource not found: %s",
			resource.ResourceName,
		)
	}

	for _, name := range variableNames(resource.ResourceName) {
		if countBlocks(files.Variables, "variable", name) != 1 {
			return fmt.Errorf(
				"OCI Compute variable missing or duplicated: %s",
				name,
			)
		}
		if !common.AttributeExists(files.Tfvars, name) {
			return fmt.Errorf("OCI Compute tfvar not found: %s", name)
		}
	}

	addTfvars(files.Tfvars, resource)
	return nil
}

func countBlocks(
	file *hclwrite.File,
	blockType string,
	expectedLabels ...string,
) int {
	count := 0
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
			count++
		}
	}
	return count
}
