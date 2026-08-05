package storage

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

var storageDependencyModules = []string{"compute", "network", "iam"}

// ApplyDelete removes one OCI Object Storage bucket and only its associated
// local Terraform declarations. It never performs a cloud operation.
func ApplyDelete(files *common.TerraformFiles, request *models.Request) error {
	resource := request.OCIStorageResource
	if resource == nil {
		return fmt.Errorf("ressource OCI storage manquante")
	}
	resourceName := resource.ResourceName

	targets := findStorageBlocks(
		files.Main,
		"resource",
		bucketResourceType,
		resourceName,
	)
	if len(targets) == 0 {
		return fmt.Errorf(
			"OCI Storage resource not found: %s",
			resourceName,
		)
	}
	if len(targets) != 1 {
		return fmt.Errorf(
			"OCI Storage resource duplicated: %s",
			resourceName,
		)
	}
	target := targets[0]

	if referencedByAnotherOCIStorageBlock(
		files.Main,
		target,
		resourceName,
	) {
		return fmt.Errorf(
			"Cannot delete OCI Storage resource %s: referenced by another OCI Storage block",
			resourceName,
		)
	}
	referenced, err := storageReferencedByAnotherOCIModule(
		request.ModulePath,
		resourceName,
	)
	if err != nil {
		return err
	}
	if referenced {
		return fmt.Errorf(
			"Cannot delete OCI Storage resource %s: referenced by another OCI module",
			resourceName,
		)
	}

	names := variableNames(resource)
	for _, name := range names {
		if len(findStorageBlocks(
			files.Variables,
			"variable",
			name,
		)) == 0 {
			fmt.Printf(
				"Avertissement OCI Storage : variable absente : %s\n",
				name,
			)
		}
		if !common.AttributeExists(files.Tfvars, name) {
			fmt.Printf(
				"Avertissement OCI Storage : tfvar absent : %s\n",
				name,
			)
		}
	}

	common.RemoveBlocks(files.Main, func(block *hclwrite.Block) bool {
		return block == target
	})

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

	outputPrefix := resourceName + "_"
	common.RemoveBlocks(files.Outputs, func(block *hclwrite.Block) bool {
		return block.Type() == "output" &&
			len(block.Labels()) == 1 &&
			strings.HasPrefix(block.Labels()[0], outputPrefix)
	})

	return compactDeletedOCIStorageFiles(files)
}

func referencedByAnotherOCIStorageBlock(
	file *hclwrite.File,
	target *hclwrite.Block,
	resourceName string,
) bool {
	for _, block := range file.Body().Blocks() {
		if block == target {
			continue
		}
		if bodyReferencesOCIStorage(
			block.Body(),
			resourceName,
			false,
		) {
			return true
		}
	}
	return false
}

// Cross-module detection deliberately accepts only explicit HCL traversals
// to the bucket resource, a module output or a remote-state output. Literal
// strings and dynamically assembled references are intentionally ignored.
func storageReferencedByAnotherOCIModule(
	storageModulePath string,
	resourceName string,
) (bool, error) {
	ociRoot := filepath.Dir(filepath.Clean(storageModulePath))
	for _, moduleName := range storageDependencyModules {
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
				if bodyReferencesOCIStorage(
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

func bodyReferencesOCIStorage(
	body *hclwrite.Body,
	resourceName string,
	includeOutputs bool,
) bool {
	for _, attribute := range body.Attributes() {
		for _, traversal := range attribute.Expr().Variables() {
			if traversalReferencesOCIStorage(
				traversal,
				resourceName,
				includeOutputs,
			) {
				return true
			}
		}
	}
	for _, block := range body.Blocks() {
		if bodyReferencesOCIStorage(
			block.Body(),
			resourceName,
			includeOutputs,
		) {
			return true
		}
	}
	return false
}

func traversalReferencesOCIStorage(
	traversal *hclwrite.Traversal,
	resourceName string,
	includeOutputs bool,
) bool {
	value := strings.TrimSpace(string(traversal.BuildTokens(nil).Bytes()))
	resourcePrefix := bucketResourceType + "." + resourceName
	if value == resourcePrefix ||
		strings.HasPrefix(value, resourcePrefix+".") {
		return true
	}
	if !includeOutputs {
		return false
	}
	resource := &models.OCIStorageRequest{ResourceName: resourceName}
	for _, outputName := range outputNames(resource) {
		outputSuffix := "." + outputName
		if (strings.HasPrefix(value, "module.") ||
			strings.Contains(value, ".outputs.")) &&
			strings.HasSuffix(value, outputSuffix) {
			return true
		}
	}
	return false
}

func compactDeletedOCIStorageFiles(
	files *common.TerraformFiles,
) error {
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
