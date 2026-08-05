package network

import (
	"fmt"

	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

func ApplyCreate(files *common.TerraformFiles, request *models.Request) error {
	resource := request.NetworkResource
	if resource == nil {
		return fmt.Errorf("ressource network manquante")
	}

	if err := checkDuplicates(
		files.Main,
		files.Variables,
		files.Tfvars,
		files.Outputs,
		resource,
	); err != nil {
		return err
	}

	addMainResources(files.Main, resource)
	addVariables(files.Variables, resource)
	addTfvars(files.Tfvars, resource)
	addOutputs(files.Outputs, resource)
	return nil
}

func checkDuplicates(
	mainFile *hclwrite.File,
	variablesFile *hclwrite.File,
	tfvarsFile *hclwrite.File,
	outputsFile *hclwrite.File,
	resource *models.NetworkRequest,
) error {
	resourceBlocks := []struct {
		resourceType string
		resourceName string
	}{
		{"google_compute_network", resource.ResourceName},
		{"google_compute_subnetwork", resource.SubnetResourceName},
	}
	for _, candidate := range resourceBlocks {
		if common.BlockExists(
			mainFile,
			"resource",
			candidate.resourceType,
			candidate.resourceName,
		) {
			return fmt.Errorf(
				"doublon network : resource %q %q existe deja",
				candidate.resourceType,
				candidate.resourceName,
			)
		}
	}

	for _, name := range networkVariableNames(resource) {
		if common.BlockExists(variablesFile, "variable", name) {
			return fmt.Errorf("doublon network : variable %q existe deja", name)
		}
		if common.AttributeExists(tfvarsFile, name) {
			return fmt.Errorf("doublon network : valeur tfvars %q existe deja", name)
		}
	}

	outputNames := []string{
		resource.ResourceName + "_id",
		resource.SubnetResourceName + "_id",
	}
	for _, name := range outputNames {
		if common.BlockExists(outputsFile, "output", name) {
			return fmt.Errorf("doublon network : output %q existe deja", name)
		}
	}

	return nil
}

func addMainResources(
	file *hclwrite.File,
	resource *models.NetworkRequest,
) {
	networkBlock := hclwrite.NewBlock(
		"resource",
		[]string{"google_compute_network", resource.ResourceName},
	)
	networkBlock.Body().SetAttributeTraversal(
		"name",
		common.VarTraversal(resource.ResourceName+"_name"),
	)
	networkBlock.Body().SetAttributeValue(
		"auto_create_subnetworks",
		cty.BoolVal(false),
	)
	common.AppendBlock(file, networkBlock)

	subnetBlock := hclwrite.NewBlock(
		"resource",
		[]string{"google_compute_subnetwork", resource.SubnetResourceName},
	)
	subnetBlock.Body().SetAttributeTraversal(
		"name",
		common.VarTraversal(resource.SubnetResourceName+"_name"),
	)
	subnetBlock.Body().SetAttributeTraversal(
		"ip_cidr_range",
		common.VarTraversal(resource.SubnetResourceName+"_cidr"),
	)
	subnetBlock.Body().SetAttributeTraversal(
		"region",
		common.VarTraversal(resource.SubnetResourceName+"_region"),
	)
	subnetBlock.Body().SetAttributeTraversal(
		"network",
		common.ResourceTraversal(
			"google_compute_network",
			resource.ResourceName,
			"id",
		),
	)
	common.AppendBlock(file, subnetBlock)
}
