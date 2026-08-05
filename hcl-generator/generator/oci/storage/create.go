package storage

import (
	"fmt"

	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

const bucketResourceType = "oci_objectstorage_bucket"

func ApplyCreate(files *common.TerraformFiles, request *models.Request) error {
	resource := request.OCIStorageResource
	if resource == nil {
		return fmt.Errorf("ressource OCI storage manquante")
	}
	if resource.ObjectEventsEnabled == nil {
		return fmt.Errorf(
			"champ obligatoire manquant : resource.object_events_enabled",
		)
	}
	if err := checkCreateDuplicates(files, resource); err != nil {
		return err
	}

	addMainResource(files.Main, resource)
	addVariables(files.Variables, resource)
	addTfvars(files.Tfvars, resource)
	addOutputs(files.Outputs, resource)
	return nil
}

func checkCreateDuplicates(
	files *common.TerraformFiles,
	resource *models.OCIStorageRequest,
) error {
	if common.BlockExists(
		files.Main,
		"resource",
		bucketResourceType,
		resource.ResourceName,
	) {
		return fmt.Errorf(
			"doublon OCI storage : resource %q %q existe deja",
			bucketResourceType,
			resource.ResourceName,
		)
	}
	for _, name := range variableNames(resource) {
		if common.BlockExists(files.Variables, "variable", name) {
			return fmt.Errorf(
				"doublon OCI storage : variable %q existe deja",
				name,
			)
		}
		if common.AttributeExists(files.Tfvars, name) {
			return fmt.Errorf(
				"doublon OCI storage : valeur tfvars %q existe deja",
				name,
			)
		}
	}
	for _, name := range outputNames(resource) {
		if common.BlockExists(files.Outputs, "output", name) {
			return fmt.Errorf(
				"doublon OCI storage : output %q existe deja",
				name,
			)
		}
	}
	return nil
}

func addMainResource(
	file *hclwrite.File,
	resource *models.OCIStorageRequest,
) {
	block := hclwrite.NewBlock(
		"resource",
		[]string{bucketResourceType, resource.ResourceName},
	)
	for _, attribute := range []string{
		"compartment_id",
		"namespace",
		"name",
		"access_type",
		"storage_tier",
		"versioning",
		"object_events_enabled",
	} {
		block.Body().SetAttributeTraversal(
			attribute,
			common.VarTraversal(resource.ResourceName+"_"+attribute),
		)
	}
	common.AppendBlock(file, block)
}
