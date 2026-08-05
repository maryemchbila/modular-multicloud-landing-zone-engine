package rootconfig

import (
	"fmt"
	"path/filepath"

	"hcl-generator/generator/common/terraformroot"

	"github.com/hashicorp/hcl/v2"
)

const (
	TerraformConstraint = ">= 1.5.7"
	ProviderConstraint  = "~> 7.0"
)

func EnsureGCPRootConfiguration(modulePath string) error {
	prepared, err := PrepareGCPRootConfiguration(modulePath)
	if err != nil {
		return err
	}
	return terraformroot.CommitPreparedFiles(prepared)
}

func PrepareGCPRootConfiguration(
	modulePath string,
) (map[string][]byte, error) {
	if filepath.Base(filepath.Clean(modulePath)) != "gcp" {
		return nil, fmt.Errorf(
			"le chemin racine GCP doit se terminer par gcp : %s",
			modulePath,
		)
	}
	return terraformroot.PrepareRootConfiguration(
		modulePath,
		terraformroot.Configuration{
			TerraformConstraint: TerraformConstraint,
			ProviderName:        "google",
			ProviderSource:      "hashicorp/google",
			ProviderConstraint:  ProviderConstraint,
			ProviderAttributes: map[string]hcl.Traversal{
				"project": variableTraversal("gcp_project_id"),
				"region":  variableTraversal("gcp_region"),
				"zone":    variableTraversal("gcp_zone"),
			},
			Variables: []terraformroot.VariableDefinition{
				{
					Name:        "gcp_project_id",
					Description: "Identifiant du projet Google Cloud",
				},
				{
					Name:        "gcp_region",
					Description: "Region Google Cloud par defaut",
					Default:     stringPointer("europe-west1"),
				},
				{
					Name:        "gcp_zone",
					Description: "Zone Google Cloud par defaut",
					Default:     stringPointer("europe-west1-b"),
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
