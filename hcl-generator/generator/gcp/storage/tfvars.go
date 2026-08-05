package storage

import (
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

func addTfvars(file *hclwrite.File, resource *models.StorageRequest) {
	body := file.Body()
	body.SetAttributeValue(
		resource.ResourceName+"_name",
		cty.StringVal(resource.Name),
	)
	body.SetAttributeValue(
		resource.ResourceName+"_location",
		cty.StringVal(resource.Location),
	)
	body.SetAttributeValue(
		resource.ResourceName+"_storage_class",
		cty.StringVal(resource.StorageClass),
	)
	body.SetAttributeValue(
		resource.ResourceName+"_uniform_bucket_level_access",
		cty.BoolVal(*resource.UniformBucketLevelAccess),
	)
}
