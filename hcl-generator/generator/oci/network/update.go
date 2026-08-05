package network

import (
	"fmt"
	"strings"

	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

// ApplyUpdate updates only the final tfvars values of one existing OCI
// network. Resource identities, declarations, traversals and outputs remain
// unchanged.
func ApplyUpdate(files *common.TerraformFiles, request *models.Request) error {
	resource := request.OCINetworkResource
	if resource == nil {
		return fmt.Errorf("ressource OCI network manquante")
	}
	if resource.ProhibitPublicIPOnVNIC == nil {
		return fmt.Errorf(
			"champ obligatoire manquant : resource.prohibit_public_ip_on_vnic",
		)
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

	if err := verifyNetworkTraversals(
		vcn,
		subnet,
		internetGateway,
		routeTable,
		resource,
	); err != nil {
		return err
	}
	if err := verifyUpdateDeclarations(files, resource); err != nil {
		return err
	}

	addTfvars(files.Tfvars, resource)
	return nil
}

func requireNetworkResource(
	file *hclwrite.File,
	resourceType string,
	resourceName string,
	notFoundMessage string,
) (*hclwrite.Block, error) {
	blocks := findBlocks(file, "resource", resourceType, resourceName)
	if len(blocks) == 0 {
		return nil, fmt.Errorf("%s: %s", notFoundMessage, resourceName)
	}
	if len(blocks) != 1 {
		return nil, fmt.Errorf(
			"OCI Network resource missing or duplicated: %s.%s",
			resourceType,
			resourceName,
		)
	}
	return blocks[0], nil
}

func verifyNetworkTraversals(
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
			"OCI subnet %s is not linked to VCN %s",
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
			"OCI subnet %s is not linked to Route Table %s",
			resource.SubnetResourceName,
			resource.RouteTableResourceName,
		)
	}

	routeRules := findNestedBlocks(routeTable.Body(), "route_rules")
	if len(routeRules) != 1 {
		return fmt.Errorf(
			"OCI Route Table %s has missing or duplicated route_rules",
			resource.RouteTableResourceName,
		)
	}
	if !attributeEqualsTraversal(
		routeRules[0].Body(),
		"network_entity_id",
		internetGatewayID,
	) {
		return fmt.Errorf(
			"OCI Route Table %s default route is not linked to Internet Gateway %s",
			resource.RouteTableResourceName,
			resource.InternetGatewayResourceName,
		)
	}

	expected := []struct {
		block     *hclwrite.Block
		attribute string
		traversal string
	}{
		{
			vcn,
			"compartment_id",
			"var." + resource.ResourceName + "_compartment_id",
		},
		{
			vcn,
			"cidr_block",
			"var." + resource.ResourceName + "_cidr_block",
		},
		{
			vcn,
			"display_name",
			"var." + resource.ResourceName + "_display_name",
		},
		{
			vcn,
			"dns_label",
			"var." + resource.ResourceName + "_dns_label",
		},
		{
			internetGateway,
			"compartment_id",
			"var." + resource.ResourceName + "_compartment_id",
		},
		{
			internetGateway,
			"display_name",
			"var." + resource.InternetGatewayResourceName + "_display_name",
		},
		{
			routeTable,
			"compartment_id",
			"var." + resource.ResourceName + "_compartment_id",
		},
		{
			routeTable,
			"display_name",
			"var." + resource.RouteTableResourceName + "_display_name",
		},
		{
			subnet,
			"compartment_id",
			"var." + resource.ResourceName + "_compartment_id",
		},
		{
			subnet,
			"cidr_block",
			"var." + resource.SubnetResourceName + "_cidr_block",
		},
		{
			subnet,
			"display_name",
			"var." + resource.SubnetResourceName + "_display_name",
		},
		{
			subnet,
			"dns_label",
			"var." + resource.SubnetResourceName + "_dns_label",
		},
		{
			subnet,
			"availability_domain",
			"var." + resource.SubnetResourceName + "_availability_domain",
		},
		{
			subnet,
			"prohibit_public_ip_on_vnic",
			"var." + resource.SubnetResourceName +
				"_prohibit_public_ip_on_vnic",
		},
	}
	for _, candidate := range expected {
		if !attributeEqualsTraversal(
			candidate.block.Body(),
			candidate.attribute,
			candidate.traversal,
		) {
			labels := candidate.block.Labels()
			return fmt.Errorf(
				"OCI Network resource %s.%s has invalid traversal for %s: expected %s",
				labels[0],
				labels[1],
				candidate.attribute,
				candidate.traversal,
			)
		}
	}
	return nil
}

func verifyUpdateDeclarations(
	files *common.TerraformFiles,
	resource *models.OCINetworkRequest,
) error {
	for _, name := range variableNames(resource) {
		if len(findBlocks(files.Variables, "variable", name)) != 1 {
			return fmt.Errorf(
				"OCI Network variable missing or duplicated: %s",
				name,
			)
		}
		if !common.AttributeExists(files.Tfvars, name) {
			return fmt.Errorf("OCI Network tfvar not found: %s", name)
		}
	}
	for _, name := range outputNames(resource) {
		if len(findBlocks(files.Outputs, "output", name)) != 1 {
			return fmt.Errorf(
				"OCI Network output missing or duplicated: %s",
				name,
			)
		}
	}
	return nil
}

func findBlocks(
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
		match := true
		for index := range labels {
			if labels[index] != expectedLabels[index] {
				match = false
				break
			}
		}
		if match {
			matches = append(matches, block)
		}
	}
	return matches
}

func findNestedBlocks(
	body *hclwrite.Body,
	blockType string,
) []*hclwrite.Block {
	var matches []*hclwrite.Block
	for _, block := range body.Blocks() {
		if block.Type() == blockType {
			matches = append(matches, block)
		}
	}
	return matches
}

func attributeEqualsTraversal(
	body *hclwrite.Body,
	attributeName string,
	expected string,
) bool {
	attribute := body.GetAttribute(attributeName)
	if attribute == nil {
		return false
	}
	actual := strings.TrimSpace(
		string(attribute.Expr().BuildTokens(nil).Bytes()),
	)
	return actual == expected
}

func traversalText(
	resourceType string,
	resourceName string,
	attribute string,
) string {
	return resourceType + "." + resourceName + "." + attribute
}
