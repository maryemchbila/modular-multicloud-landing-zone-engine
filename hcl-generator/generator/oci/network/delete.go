package network

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"hcl-generator/generator/common"
	commonroot "hcl-generator/generator/common/rootmodule"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// ApplyDelete removes one complete, linked OCI Network group and only its
// associated variables, tfvars and outputs.
func ApplyDelete(files *common.TerraformFiles, request *models.Request) error {
	resource := request.OCINetworkResource
	if resource == nil {
		return fmt.Errorf("ressource OCI network manquante")
	}

	vcn, err := requireNetworkResource(
		files.Main,
		vcnResourceType,
		resource.ResourceName,
		"OCI VCN resource not found",
	)
	if err != nil {
		return err
	}
	subnet, err := requireNetworkResource(
		files.Main,
		subnetResourceType,
		resource.SubnetResourceName,
		"OCI Subnet resource not found",
	)
	if err != nil {
		return err
	}
	internetGateway, err := requireNetworkResource(
		files.Main,
		internetGatewayResourceType,
		resource.InternetGatewayResourceName,
		"OCI Internet Gateway resource not found",
	)
	if err != nil {
		return err
	}
	routeTable, err := requireNetworkResource(
		files.Main,
		routeTableResourceType,
		resource.RouteTableResourceName,
		"OCI Route Table resource not found",
	)
	if err != nil {
		return err
	}

	if err := verifyDeleteRelations(
		vcn,
		subnet,
		internetGateway,
		routeTable,
		resource,
	); err != nil {
		return err
	}

	targets := map[*hclwrite.Block]struct{}{
		vcn:             {},
		subnet:          {},
		internetGateway: {},
		routeTable:      {},
	}
	if referencedByAnotherNetworkBlock(
		files.Main,
		targets,
		resource,
	) {
		return fmt.Errorf(
			"Cannot delete OCI Network %s: referenced by another OCI Network block",
			resource.ResourceName,
		)
	}
	rootReferenced, err := commonroot.ModuleOutputsReferencedByAnotherModule(
		request.ModulePath,
		"network",
		[]string{
			resource.ResourceName + "_id",
			resource.SubnetResourceName + "_id",
			resource.InternetGatewayResourceName + "_id",
			resource.RouteTableResourceName + "_id",
		},
	)
	if err != nil {
		return err
	}
	if rootReferenced {
		return fmt.Errorf(
			"Cannot delete OCI Network %s: referenced by another root module",
			resource.ResourceName,
		)
	}

	referencedByCompute, err := subnetReferencedByOCICompute(
		request.ModulePath,
		resource.SubnetResourceName,
	)
	if err != nil {
		return err
	}
	if referencedByCompute {
		return fmt.Errorf(
			"Cannot delete OCI Network %s: subnet %s is referenced by OCI Compute configuration",
			resource.ResourceName,
			resource.SubnetResourceName,
		)
	}

	names := variableNames(resource)
	for _, name := range names {
		if len(findBlocks(files.Variables, "variable", name)) == 0 {
			fmt.Printf(
				"Avertissement OCI Network : variable absente : %s\n",
				name,
			)
		}
		if !common.AttributeExists(files.Tfvars, name) {
			fmt.Printf(
				"Avertissement OCI Network : tfvar absent : %s\n",
				name,
			)
		}
	}

	// Logical dependency order: subnet, route table, Internet Gateway, VCN.
	removeExactBlock(files.Main, subnet)
	removeExactBlock(files.Main, routeTable)
	removeExactBlock(files.Main, internetGateway)
	removeExactBlock(files.Main, vcn)

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

	outputPrefixes := []string{
		resource.ResourceName + "_",
		resource.SubnetResourceName + "_",
		resource.InternetGatewayResourceName + "_",
		resource.RouteTableResourceName + "_",
	}
	common.RemoveBlocks(files.Outputs, func(block *hclwrite.Block) bool {
		if block.Type() != "output" || len(block.Labels()) != 1 {
			return false
		}
		for _, prefix := range outputPrefixes {
			if strings.HasPrefix(block.Labels()[0], prefix) {
				return true
			}
		}
		return false
	})

	return compactDeletedOCINetworkFiles(files)
}

func verifyDeleteRelations(
	vcn *hclwrite.Block,
	subnet *hclwrite.Block,
	internetGateway *hclwrite.Block,
	routeTable *hclwrite.Block,
	resource *models.OCINetworkRequest,
) error {
	vcnID := traversalText(
		vcnResourceType,
		resource.ResourceName,
		"id",
	)
	routeTableID := traversalText(
		routeTableResourceType,
		resource.RouteTableResourceName,
		"id",
	)
	internetGatewayID := traversalText(
		internetGatewayResourceType,
		resource.InternetGatewayResourceName,
		"id",
	)

	if !attributeEqualsTraversal(subnet.Body(), "vcn_id", vcnID) {
		return fmt.Errorf(
			"OCI Subnet %s is not linked to VCN %s",
			resource.SubnetResourceName,
			resource.ResourceName,
		)
	}
	if !attributeEqualsTraversal(routeTable.Body(), "vcn_id", vcnID) {
		return fmt.Errorf(
			"OCI Route Table %s is not linked to VCN %s",
			resource.RouteTableResourceName,
			resource.ResourceName,
		)
	}
	if !attributeEqualsTraversal(
		internetGateway.Body(),
		"vcn_id",
		vcnID,
	) {
		return fmt.Errorf(
			"OCI Internet Gateway %s is not linked to VCN %s",
			resource.InternetGatewayResourceName,
			resource.ResourceName,
		)
	}
	if !attributeEqualsTraversal(
		subnet.Body(),
		"route_table_id",
		routeTableID,
	) {
		return fmt.Errorf(
			"OCI Subnet %s is not linked to Route Table %s",
			resource.SubnetResourceName,
			resource.RouteTableResourceName,
		)
	}

	routeRules := findNestedBlocks(routeTable.Body(), "route_rules")
	if len(routeRules) != 1 ||
		!attributeEqualsTraversal(
			routeRules[0].Body(),
			"network_entity_id",
			internetGatewayID,
		) {
		return fmt.Errorf(
			"OCI Route Table %s is not linked to Internet Gateway %s",
			resource.RouteTableResourceName,
			resource.InternetGatewayResourceName,
		)
	}
	return nil
}

func referencedByAnotherNetworkBlock(
	file *hclwrite.File,
	targets map[*hclwrite.Block]struct{},
	resource *models.OCINetworkRequest,
) bool {
	for _, block := range file.Body().Blocks() {
		if _, target := targets[block]; target {
			continue
		}
		if bodyReferencesOCINetwork(block.Body(), resource) {
			return true
		}
	}
	return false
}

func bodyReferencesOCINetwork(
	body *hclwrite.Body,
	resource *models.OCINetworkRequest,
) bool {
	for _, attribute := range body.Attributes() {
		for _, traversal := range attribute.Expr().Variables() {
			if traversalReferencesOCINetwork(traversal, resource) {
				return true
			}
		}
	}
	for _, block := range body.Blocks() {
		if bodyReferencesOCINetwork(block.Body(), resource) {
			return true
		}
	}
	return false
}

func traversalReferencesOCINetwork(
	traversal *hclwrite.Traversal,
	resource *models.OCINetworkRequest,
) bool {
	value := strings.TrimSpace(
		string(traversal.BuildTokens(nil).Bytes()),
	)
	prefixes := []string{
		vcnResourceType + "." + resource.ResourceName,
		subnetResourceType + "." + resource.SubnetResourceName,
		internetGatewayResourceType + "." +
			resource.InternetGatewayResourceName,
		routeTableResourceType + "." + resource.RouteTableResourceName,
	}
	for _, prefix := range prefixes {
		if value == prefix || strings.HasPrefix(value, prefix+".") {
			return true
		}
	}
	return false
}

// OCI Compute dependencies are blocked only when they are certain: an
// explicit traversal to the target subnet, or a *_subnet_id literal equal to
// its Terraform address/name. Arbitrary OCIDs cannot be correlated reliably
// with a Terraform logical name and are intentionally ignored.
func subnetReferencedByOCICompute(
	networkModulePath string,
	subnetResourceName string,
) (bool, error) {
	computePath := filepath.Join(
		filepath.Dir(filepath.Clean(networkModulePath)),
		"compute",
	)
	info, err := os.Stat(computePath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf(
			"impossible d'inspecter les dependances OCI Compute : %w",
			err,
		)
	}
	if !info.IsDir() {
		return false, fmt.Errorf(
			"le module OCI Compute n'est pas un dossier : %s",
			computePath,
		)
	}

	computeMain, err := common.LoadOrCreateFile(
		filepath.Join(computePath, "main.tf"),
	)
	if err != nil {
		return false, fmt.Errorf(
			"impossible d'inspecter OCI Compute main.tf : %w",
			err,
		)
	}
	if bodyReferencesOCISubnet(
		computeMain.Body(),
		subnetResourceName,
	) {
		return true, nil
	}

	computeTfvars, err := common.LoadOrCreateFile(
		filepath.Join(computePath, "terraform.tfvars"),
	)
	if err != nil {
		return false, fmt.Errorf(
			"impossible d'inspecter OCI Compute terraform.tfvars : %w",
			err,
		)
	}
	certainValues := map[string]struct{}{
		subnetResourceName: {},
		subnetResourceType + "." + subnetResourceName:         {},
		subnetResourceType + "." + subnetResourceName + ".id": {},
	}
	for name, attribute := range computeTfvars.Body().Attributes() {
		if !strings.HasSuffix(name, "_subnet_id") {
			continue
		}
		value, ok := literalStringValue(attribute)
		if !ok {
			continue
		}
		if _, certain := certainValues[value]; certain {
			return true, nil
		}
	}
	return false, nil
}

func bodyReferencesOCISubnet(
	body *hclwrite.Body,
	subnetResourceName string,
) bool {
	prefix := subnetResourceType + "." + subnetResourceName
	for _, attribute := range body.Attributes() {
		for _, traversal := range attribute.Expr().Variables() {
			value := strings.TrimSpace(
				string(traversal.BuildTokens(nil).Bytes()),
			)
			if value == prefix || strings.HasPrefix(value, prefix+".") {
				return true
			}
		}
	}
	for _, block := range body.Blocks() {
		if bodyReferencesOCISubnet(block.Body(), subnetResourceName) {
			return true
		}
	}
	return false
}

func literalStringValue(
	attribute *hclwrite.Attribute,
) (string, bool) {
	if attribute == nil {
		return "", false
	}
	expression, diagnostics := hclsyntax.ParseExpression(
		bytes.TrimSpace(attribute.Expr().BuildTokens(nil).Bytes()),
		"terraform.tfvars",
		hcl.InitialPos,
	)
	if diagnostics.HasErrors() {
		return "", false
	}
	value, diagnostics := expression.Value(nil)
	if diagnostics.HasErrors() ||
		!value.IsKnown() ||
		value.IsNull() ||
		value.Type() != cty.String {
		return "", false
	}
	return value.AsString(), true
}

func removeExactBlock(file *hclwrite.File, target *hclwrite.Block) {
	common.RemoveBlocks(file, func(block *hclwrite.Block) bool {
		return block == target
	})
}

func compactDeletedOCINetworkFiles(
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
