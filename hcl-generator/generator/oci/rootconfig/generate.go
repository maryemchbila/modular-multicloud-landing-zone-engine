package rootconfig

import (
	"fmt"
	"path/filepath"

	"hcl-generator/generator/common/terraformroot"

	"github.com/hashicorp/hcl/v2"
)

const (
	TerraformConstraint = ">= 1.5.7"
	ProviderConstraint  = "= 8.23.0"
)

func EnsureOCIRootConfiguration(modulePath string) error {
	prepared, err := PrepareOCIRootConfiguration(modulePath)
	if err != nil {
		return err
	}
	return terraformroot.CommitPreparedFiles(prepared)
}

func PrepareOCIRootConfiguration(
	modulePath string,
) (map[string][]byte, error) {
	if filepath.Base(filepath.Clean(modulePath)) != "oci" {
		return nil, fmt.Errorf(
			"le chemin racine OCI doit se terminer par oci : %s",
			modulePath,
		)
	}
	return terraformroot.PrepareRootConfiguration(
		modulePath,
		terraformroot.Configuration{
			TerraformConstraint: TerraformConstraint,
			ProviderName:        "oci",
			ProviderSource:      "oracle/oci",
			ProviderConstraint:  ProviderConstraint,
			ProviderAttributes: map[string]hcl.Traversal{
				"region": variableTraversal("oci_region"),
			},
			Variables: []terraformroot.VariableDefinition{
				{
					Name:        "oci_region",
					Description: "Region Oracle Cloud Infrastructure par defaut",
					Default:     stringPointer("eu-frankfurt-1"),
				},
			},
		},
	)
}

func variableTraversal(name string) hcl.Traversal {
	return hcl.Traversal{
		hcl.TraverseRoot{Name: "var"},
		hcl.TraverseAttr{Name: name},
	}
}

func stringPointer(value string) *string {
	return &value
}
