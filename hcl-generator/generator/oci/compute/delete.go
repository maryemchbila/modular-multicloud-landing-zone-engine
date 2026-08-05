package compute

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

var otherOCIModules = []string{"network", "storage", "iam"}

// ApplyDelete removes one OCI Compute instance and only its local Terraform
// variables, tfvars and outputs.
func ApplyDelete(files *common.TerraformFiles, request *models.Request) error {
	resource := request.OCIComputeResource
	if resource == nil {
		return fmt.Errorf("ressource OCI compute manquante")
	}
	resourceName := resource.ResourceName

	target := common.FindBlock(
		files.Main,
		"resource",
		instanceResourceType,
		resourceName,
	)
	if target == nil {
		return fmt.Errorf(
			"OCI Compute resource not found: %s",
			resourceName,
		)
	}
	if countBlocks(
		files.Main,
		"resource",
		instanceResourceType,
		resourceName,
	) != 1 {
		return fmt.Errorf(
			"OCI Compute resource duplicated: %s",
			resourceName,
		)
	}

	if referencedByAnotherOCIComputeBlock(
		files.Main,
		target,
		resourceName,
	) {
		return fmt.Errorf(
			"Cannot delete OCI Compute resource %s: referenced by another block",
			resourceName,
		)
	}

	referenced, err := referencedByAnotherOCIModule(
		request.ModulePath,
		resourceName,
	)
	if err != nil {
		return err
	}
	if referenced {
		return fmt.Errorf(
			"Cannot delete OCI Compute resource %s: referenced by another OCI module",
			resourceName,
		)
	}

	common.RemoveBlocks(files.Main, func(block *hclwrite.Block) bool {
		return block == target
	})

	variableNameSet := make(map[string]struct{})
	for _, name := range variableNames(resourceName) {
		variableNameSet[name] = struct{}{}
	}
	common.RemoveBlocks(files.Variables, func(block *hclwrite.Block) bool {
		if block.Type() != "variable" || len(block.Labels()) != 1 {
			return false
		}
		_, belongsToTarget := variableNameSet[block.Labels()[0]]
		return belongsToTarget
	})
	common.RemoveAttributes(files.Tfvars, variableNames(resourceName))

	outputPrefix := resourceName + "_"
	common.RemoveBlocks(files.Outputs, func(block *hclwrite.Block) bool {
		return block.Type() == "output" &&
			len(block.Labels()) == 1 &&
			strings.HasPrefix(block.Labels()[0], outputPrefix)
	})

	return compactDeletedOCIComputeFiles(files)
}

func referencedByAnotherOCIComputeBlock(
	file *hclwrite.File,
	target *hclwrite.Block,
	resourceName string,
) bool {
	for _, block := range file.Body().Blocks() {
		if block == target {
			continue
		}
		if bodyReferencesOCICompute(block.Body(), resourceName, false) {
			return true
		}
	}
	return false
}

// Cross-module detection intentionally recognizes only explicit HCL
// traversals. String literals and dynamically constructed references are not
// treated as dependencies because they cannot be identified with certainty.
func referencedByAnotherOCIModule(
	computeModulePath string,
	resourceName string,
) (bool, error) {
	ociRoot := filepath.Dir(filepath.Clean(computeModulePath))
	for _, moduleName := range otherOCIModules {
		modulePath := filepath.Join(ociRoot, moduleName)
		info, err := os.Stat(modulePath)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf(
				"impossible d'inspecter le module OCI %s : %w",
				moduleName,
				err,
			)
		}
		if !info.IsDir() {
			return false, fmt.Errorf(
				"le module OCI %s n'est pas un dossier : %s",
				moduleName,
				modulePath,
			)
		}

		referenced := false
		err = filepath.WalkDir(
			modulePath,
			func(path string, entry fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if entry.IsDir() {
					if path != modulePath &&
						strings.HasPrefix(entry.Name(), ".") {
						return filepath.SkipDir
					}
					return nil
				}
				if filepath.Ext(entry.Name()) != ".tf" {
					return nil
				}

				file, loadErr := common.LoadExistingFile(path)
				if loadErr != nil {
					return loadErr
				}
				if bodyReferencesOCICompute(
					file.Body(),
					resourceName,
					true,
				) {
					referenced = true
					return filepath.SkipAll
				}
				return nil
			},
		)
		if err != nil {
			return false, fmt.Errorf(
				"impossible d'inspecter le module OCI %s : %w",
				moduleName,
				err,
			)
		}
		if referenced {
			return true, nil
		}
	}
	return false, nil
}

func bodyReferencesOCICompute(
	body *hclwrite.Body,
	resourceName string,
	includeOutputs bool,
) bool {
	for _, attribute := range body.Attributes() {
		for _, traversal := range attribute.Expr().Variables() {
			if traversalReferencesOCICompute(
				traversal,
				resourceName,
				includeOutputs,
			) {
				return true
			}
		}
	}
	for _, block := range body.Blocks() {
		if bodyReferencesOCICompute(
			block.Body(),
			resourceName,
			includeOutputs,
		) {
			return true
		}
	}
	return false
}

func traversalReferencesOCICompute(
	traversal *hclwrite.Traversal,
	resourceName string,
	includeOutputs bool,
) bool {
	value := strings.TrimSpace(string(traversal.BuildTokens(nil).Bytes()))
	resourcePrefix := instanceResourceType + "." + resourceName
	if value == resourcePrefix ||
		strings.HasPrefix(value, resourcePrefix+".") {
		return true
	}
	if !includeOutputs {
		return false
	}
	for _, outputName := range outputNames(resourceName) {
		if value == outputName || strings.HasSuffix(value, "."+outputName) {
			return true
		}
	}
	return false
}

func compactDeletedOCIComputeFiles(files *common.TerraformFiles) error {
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
