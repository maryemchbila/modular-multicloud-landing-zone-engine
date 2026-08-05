package compute

import (
	"fmt"

	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

const instanceResourceType = "oci_core_instance"

func ApplyCreate(files *common.TerraformFiles, request *models.Request) error {
	resource := request.OCIComputeResource
	if resource == nil {
		return fmt.Errorf("ressource OCI compute manquante")
	}
	if resource.AssignPublicIP == nil {
		return fmt.Errorf(
			"champ obligatoire manquant : resource.assign_public_ip",
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
	resource *models.OCIComputeRequest,
) error {
	if common.BlockExists(
		files.Main,
		"resource",
		instanceResourceType,
		resource.ResourceName,
	) {
		return fmt.Errorf(
			"doublon OCI compute : resource %q %q existe deja",
			instanceResourceType,
			resource.ResourceName,
		)
	}

	for _, name := range variableNames(resource.ResourceName) {
		if common.BlockExists(files.Variables, "variable", name) {
			return fmt.Errorf(
				"doublon OCI compute : variable %q existe deja",
				name,
			)
		}
		if common.AttributeExists(files.Tfvars, name) {
			return fmt.Errorf(
				"doublon OCI compute : valeur tfvars %q existe deja",
				name,
			)
		}
	}

	for _, name := range outputNames(resource.ResourceName) {
		if common.BlockExists(files.Outputs, "output", name) {
			return fmt.Errorf(
				"doublon OCI compute : output %q existe deja",
				name,
			)
		}
	}

	return nil
}

func addMainResource(
	file *hclwrite.File,
	resource *models.OCIComputeRequest,
) {
	resourceName := resource.ResourceName
	block := hclwrite.NewBlock(
		"resource",
		[]string{instanceResourceType, resourceName},
	)
	body := block.Body()
	body.SetAttributeTraversal(
		"availability_domain",
		common.VarTraversal(resourceName+"_availability_domain"),
	)
	body.SetAttributeTraversal(
		"compartment_id",
		common.VarTraversal(resourceName+"_compartment_id"),
	)
	body.SetAttributeTraversal(
		"display_name",
		common.VarTraversal(resourceName+"_display_name"),
	)
	body.SetAttributeTraversal(
		"shape",
		common.VarTraversal(resourceName+"_shape"),
	)

	vnicBlock := hclwrite.NewBlock("create_vnic_details", nil)
	vnicBlock.Body().SetAttributeTraversal(
		"subnet_id",
		common.VarTraversal(resourceName+"_subnet_id"),
	)
	vnicBlock.Body().SetAttributeTraversal(
		"assign_public_ip",
		common.VarTraversal(resourceName+"_assign_public_ip"),
	)
	body.AppendNewline()
	body.AppendBlock(vnicBlock)

	sourceBlock := hclwrite.NewBlock("source_details", nil)
	sourceBlock.Body().SetAttributeValue(
		"source_type",
		cty.StringVal("image"),
	)
	sourceBlock.Body().SetAttributeTraversal(
		"source_id",
		common.VarTraversal(resourceName+"_image_id"),
	)
	body.AppendNewline()
	body.AppendBlock(sourceBlock)

	common.AppendBlock(file, block)
}
