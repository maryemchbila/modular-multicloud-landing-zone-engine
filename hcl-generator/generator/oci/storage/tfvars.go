package storage

import (
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

func addTfvars(
	file *hclwrite.File,
	resource *models.OCIStorageRequest,
) {
	prefix := resource.ResourceName + "_"
	body := file.Body()
	body.SetAttributeValue(
		prefix+"compartment_id",
		cty.StringVal(resource.CompartmentID),
	)
	body.SetAttributeValue(
		prefix+"namespace",
		cty.StringVal(resource.Namespace),
	)
	body.SetAttributeValue(prefix+"name", cty.StringVal(resource.Name))
	body.SetAttributeValue(
		prefix+"access_type",
		cty.StringVal(resource.AccessType),
	)
	body.SetAttributeValue(
		prefix+"storage_tier",
		cty.StringVal(resource.StorageTier),
	)
	body.SetAttributeValue(
		prefix+"versioning",
		cty.StringVal(resource.Versioning),
	)
	body.SetAttributeValue(
		prefix+"object_events_enabled",
		cty.BoolVal(*resource.ObjectEventsEnabled),
	)
}
