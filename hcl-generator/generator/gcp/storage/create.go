package storage

import (
	"fmt"

	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

func ApplyCreate(files *common.TerraformFiles, request *models.Request) error {
	resource := request.StorageResource
	if resource == nil {
		return fmt.Errorf("ressource storage manquante")
	}

	if err := checkDuplicates(files, resource); err != nil {
		return err
	}

	addMainResource(files.Main, resource)
	addVariables(files.Variables, resource)
	addTfvars(files.Tfvars, resource)
	addOutputs(files.Outputs, resource)
	return nil
}

func checkDuplicates(
	files *common.TerraformFiles,
	resource *models.StorageRequest,
) error {
	if common.BlockExists(
		files.Main,
		"resource",
		"google_storage_bucket",
		resource.ResourceName,
	) {
		return fmt.Errorf(
			"doublon storage : resource %q %q existe deja",
			"google_storage_bucket",
			resource.ResourceName,
		)
	}

	for _, name := range storageVariableNames(resource.ResourceName) {
		if common.BlockExists(files.Variables, "variable", name) {
			return fmt.Errorf("doublon storage : variable %q existe deja", name)
		}
		if common.AttributeExists(files.Tfvars, name) {
			return fmt.Errorf("doublon storage : valeur tfvars %q existe deja", name)
		}
	}

	outputNames := []string{
		resource.ResourceName + "_id",
		resource.ResourceName + "_url",
	}
	for _, name := range outputNames {
		if common.BlockExists(files.Outputs, "output", name) {
			return fmt.Errorf("doublon storage : output %q existe deja", name)
		}
	}

	return nil
}

func addMainResource(file *hclwrite.File, resource *models.StorageRequest) {
	block := hclwrite.NewBlock(
		"resource",
		[]string{"google_storage_bucket", resource.ResourceName},
	)
	body := block.Body()
	body.SetAttributeTraversal(
		"name",
		common.VarTraversal(resource.ResourceName+"_name"),
	)
	body.SetAttributeTraversal(
		"location",
		common.VarTraversal(resource.ResourceName+"_location"),
	)
	body.SetAttributeTraversal(
		"storage_class",
		common.VarTraversal(resource.ResourceName+"_storage_class"),
	)
	body.SetAttributeTraversal(
		"uniform_bucket_level_access",
		common.VarTraversal(resource.ResourceName+"_uniform_bucket_level_access"),
	)
	common.AppendBlock(file, block)
}
