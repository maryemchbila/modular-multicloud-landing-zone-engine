package network

import (
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

func addTfvars(
	file *hclwrite.File,
	resource *models.OCINetworkRequest,
) {
	body := file.Body()
	body.SetAttributeValue(
		resource.ResourceName+"_compartment_id",
		cty.StringVal(resource.CompartmentID),
	)
	body.SetAttributeValue(
		resource.ResourceName+"_cidr_block",
		cty.StringVal(resource.VCNCIDR),
	)
	body.SetAttributeValue(
		resource.ResourceName+"_display_name",
		cty.StringVal(resource.DisplayName),
	)
	body.SetAttributeValue(
		resource.ResourceName+"_dns_label",
		cty.StringVal(resource.DNSLabel),
	)
	body.SetAttributeValue(
		resource.SubnetResourceName+"_cidr_block",
		cty.StringVal(resource.SubnetCIDR),
	)
	body.SetAttributeValue(
		resource.SubnetResourceName+"_display_name",
		cty.StringVal(resource.SubnetDisplayName),
	)
	body.SetAttributeValue(
		resource.SubnetResourceName+"_dns_label",
		cty.StringVal(resource.SubnetDNSLabel),
	)
	body.SetAttributeValue(
		resource.SubnetResourceName+"_availability_domain",
		cty.StringVal(resource.AvailabilityDomain),
	)
	body.SetAttributeValue(
		resource.SubnetResourceName+"_prohibit_public_ip_on_vnic",
		cty.BoolVal(*resource.ProhibitPublicIPOnVNIC),
	)
	body.SetAttributeValue(
		resource.InternetGatewayResourceName+"_display_name",
		cty.StringVal(resource.InternetGatewayDisplayName),
	)
	body.SetAttributeValue(
		resource.RouteTableResourceName+"_display_name",
		cty.StringVal(resource.RouteTableDisplayName),
	)
}
