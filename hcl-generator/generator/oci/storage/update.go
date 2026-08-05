package storage

import (
	"fmt"
	"strings"

	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

// ApplyUpdate changes only the final tfvars values of an existing OCI Object
// Storage bucket. Its resource identity, declarations and outputs stay intact.
func ApplyUpdate(files *common.TerraformFiles, request *models.Request) error {
	resource := request.OCIStorageResource
	if resource == nil {
		return fmt.Errorf("ressource OCI storage manquante")
	}
	if resource.ObjectEventsEnabled == nil {
		return fmt.Errorf(
			"champ obligatoire manquant : resource.object_events_enabled",
		)
	}

	buckets := findStorageBlocks(
		files.Main,
		"resource",
		bucketResourceType,
		resource.ResourceName,
	)
	if len(buckets) == 0 {
		return fmt.Errorf(
			"OCI Storage resource not found: %s",
			resource.ResourceName,
		)
	}
	if len(buckets) != 1 {
		return fmt.Errorf(
			"OCI Storage resource missing or duplicated: %s.%s",
			bucketResourceType,
			resource.ResourceName,
		)
	}
	if err := verifyStorageTraversals(buckets[0], resource); err != nil {
		return err
	}
	if err := verifyStorageUpdateDeclarations(files, resource); err != nil {
		return err
	}

	addTfvars(files.Tfvars, resource)
	return nil
}

func verifyStorageTraversals(
	bucket *hclwrite.Block,
	resource *models.OCIStorageRequest,
) error {
	for _, definition := range storageVariableDefinitions {
		expected := "var." + resource.ResourceName + "_" + definition.suffix
		attribute := bucket.Body().GetAttribute(definition.suffix)
		if attribute == nil {
			return fmt.Errorf(
				"OCI Storage resource %s is missing required attribute: %s",
				resource.ResourceName,
				definition.suffix,
			)
		}
		actual := strings.TrimSpace(
			string(attribute.Expr().BuildTokens(nil).Bytes()),
		)
		if actual != expected {
			return fmt.Errorf(
				"OCI Storage resource %s has invalid traversal for %s: expected %s",
				resource.ResourceName,
				definition.suffix,
				expected,
			)
		}
	}
	return nil
}

func verifyStorageUpdateDeclarations(
	files *common.TerraformFiles,
	resource *models.OCIStorageRequest,
) error {
	for _, name := range variableNames(resource) {
		if len(findStorageBlocks(
			files.Variables,
			"variable",
			name,
		)) != 1 {
			return fmt.Errorf(
				"OCI Storage variable missing or duplicated: %s",
				name,
			)
		}
		if !common.AttributeExists(files.Tfvars, name) {
			return fmt.Errorf("OCI Storage tfvar not found: %s", name)
		}
	}
	for _, name := range outputNames(resource) {
		if len(findStorageBlocks(files.Outputs, "output", name)) != 1 {
			return fmt.Errorf(
				"OCI Storage output missing or duplicated: %s",
				name,
			)
		}
	}
	return nil
}

func findStorageBlocks(
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
		matched := true
		for index := range labels {
			if labels[index] != expectedLabels[index] {
				matched = false
				break
			}
		}
		if matched {
			matches = append(matches, block)
		}
	}
	return matches
}
