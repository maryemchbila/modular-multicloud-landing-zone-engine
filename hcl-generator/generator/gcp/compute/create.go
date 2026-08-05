package compute

import (
	"fmt"

	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

func ApplyCreate(files *common.TerraformFiles, request *models.Request) error {
	if request.ComputeResource == nil {
		return fmt.Errorf("ressource compute manquante")
	}
	if err := checkCreateDuplicates(files, request.ComputeResource); err != nil {
		return err
	}
	if err := addMainResource(files.Main, request); err != nil {
		return err
	}
	addVariables(files.Variables, request.ComputeResource)
	addTfvars(files.Tfvars, request)
	addOutputs(files.Outputs, request)
	return nil
}

func checkCreateDuplicates(
	files *common.TerraformFiles,
	resource *models.ComputeRequest,
) error {
	if common.BlockExists(
		files.Main,
		"resource",
		"google_compute_instance",
		resource.ResourceName,
	) {
		return fmt.Errorf(
			"doublon compute : resource %q %q existe deja",
			"google_compute_instance",
			resource.ResourceName,
		)
	}

	for _, name := range variableNames(resource.ResourceName) {
		if common.BlockExists(files.Variables, "variable", name) {
			return fmt.Errorf("doublon compute : variable %q existe deja", name)
		}
		if common.AttributeExists(files.Tfvars, name) {
			return fmt.Errorf("doublon compute : valeur tfvars %q existe deja", name)
		}
	}

	for _, name := range outputNames(resource.ResourceName) {
		if common.BlockExists(files.Outputs, "output", name) {
			return fmt.Errorf("doublon compute : output %q existe deja", name)
		}
	}

	return nil
}

func addMainResource(
	file *hclwrite.File,
	request *models.Request,
) error {
	if request.ComputeResource == nil {
		return fmt.Errorf("ressource compute manquante")
	}
	resource := request.ComputeResource
	resourceType := "google_compute_instance"
	resourceName := resource.ResourceName

	block := hclwrite.NewBlock(
		"resource",
		[]string{resourceType, resourceName},
	)
	body := block.Body()

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

	bootDiskBlock := hclwrite.NewBlock(
		"boot_disk",
		nil,
	)
	initializeParamsBlock := hclwrite.NewBlock(
		"initialize_params",
		nil,
	)
	initializeParamsBlock.Body().SetAttributeTraversal(
		"image",
		common.VarTraversal(resourceName+"_image"),
	)
	bootDiskBlock.Body().AppendBlock(initializeParamsBlock)
	body.AppendNewline()
	body.AppendBlock(bootDiskBlock)

	networkInterfaceBlock := hclwrite.NewBlock(
		"network_interface",
		nil,
	)
	networkInterfaceBlock.Body().SetAttributeTraversal(
		"network",
		common.VarTraversal(resourceName+"_network"),
	)
	body.AppendNewline()
	body.AppendBlock(networkInterfaceBlock)

	common.AppendBlock(file, block)
	return nil
}
