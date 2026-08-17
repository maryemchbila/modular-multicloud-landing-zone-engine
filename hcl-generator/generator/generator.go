package generator

import (
	"fmt"
	"os"
	"path/filepath"

	"hcl-generator/generator/common"
	commonroot "hcl-generator/generator/common/rootmodule"
	gcpcompute "hcl-generator/generator/gcp/compute"
	gcpiam "hcl-generator/generator/gcp/iam"
	gcpnetwork "hcl-generator/generator/gcp/network"
	gcprootmodule "hcl-generator/generator/gcp/rootmodule"
	gcpstorage "hcl-generator/generator/gcp/storage"
	ocicompute "hcl-generator/generator/oci/compute"
	ociiam "hcl-generator/generator/oci/iam"
	ocinetwork "hcl-generator/generator/oci/network"
	ocimodule "hcl-generator/generator/oci/rootmodule"
	ocistorage "hcl-generator/generator/oci/storage"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

type actionHandler func(*common.TerraformFiles, *models.Request) error

type routeKey struct {
	provider string
	module   string
	action   string
}

var actionHandlers = map[routeKey]actionHandler{
	{"gcp", "compute", "create"}: gcpcompute.ApplyCreate,
	{"gcp", "compute", "update"}: gcpcompute.ApplyUpdate,
	{"gcp", "compute", "delete"}: gcpcompute.ApplyDelete,
	{"gcp", "network", "create"}: gcpnetwork.ApplyCreate,
	{"gcp", "network", "update"}: gcpnetwork.ApplyUpdate,
	{"gcp", "network", "delete"}: gcpnetwork.ApplyDelete,
	{"gcp", "storage", "create"}: gcpstorage.ApplyCreate,
	{"gcp", "storage", "update"}: gcpstorage.ApplyUpdate,
	{"gcp", "storage", "delete"}: gcpstorage.ApplyDelete,
	{"gcp", "iam", "create"}:     gcpiam.ApplyCreate,
	{"gcp", "iam", "update"}:     gcpiam.ApplyUpdate,
	{"gcp", "iam", "delete"}:     gcpiam.ApplyDelete,
	{"oci", "compute", "create"}: ocicompute.ApplyCreate,
	{"oci", "compute", "update"}: ocicompute.ApplyUpdate,
	{"oci", "compute", "delete"}: ocicompute.ApplyDelete,
	{"oci", "network", "create"}: ocinetwork.ApplyCreate,
	{"oci", "network", "update"}: ocinetwork.ApplyUpdate,
	{"oci", "network", "delete"}: ocinetwork.ApplyDelete,
	{"oci", "storage", "create"}: ocistorage.ApplyCreate,
	{"oci", "storage", "update"}: ocistorage.ApplyUpdate,
	{"oci", "storage", "delete"}: ocistorage.ApplyDelete,
	{"oci", "iam", "create"}:     ociiam.ApplyCreate,
	{"oci", "iam", "update"}:     ociiam.ApplyUpdate,
	{"oci", "iam", "delete"}:     ociiam.ApplyDelete,
}

func GenerateAtomically(
	request *models.Request,
) error {
	handler, supported := actionHandlers[routeKey{
		provider: request.Provider,
		module:   request.Module,
		action:   request.Action,
	}]
	if !supported {
		return fmt.Errorf(
			"fonctionnalite non implementee : %s / %s / %s",
			request.Provider,
			request.Module,
			request.Action,
		)
	}

	layout, err := commonroot.ResolveModulePath(
		request.ModulePath,
		request.Provider,
		request.Module,
	)
	if err != nil {
		return err
	}

	if request.Action == "create" {
		if err := os.MkdirAll(request.ModulePath, 0755); err != nil {
			return fmt.Errorf("impossible de creer le dossier %s : %w", request.ModulePath, err)
		}
	} else {
		info, err := os.Stat(request.ModulePath)
		if err != nil {
			return fmt.Errorf("impossible d'ouvrir le dossier %s : %w", request.ModulePath, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("module_path n'est pas un dossier : %s", request.ModulePath)
		}
	}

	files, err := common.LoadTerraformFiles(request.ModulePath)
	if err != nil {
		return err
	}
	if request.Provider == "gcp" {
		writeGCPProjectContext(files.Tfvars, request.ProjectID)
	}

	if err := handler(files, request); err != nil {
		return err
	}

	tfvarsPath := filepath.Join(layout.ProviderRoot, "terraform.tfvars")
	modulePrepared := map[string][]byte{
		filepath.Join(request.ModulePath, "main.tf"):      common.FormattedBytes(files.Main),
		filepath.Join(request.ModulePath, "variables.tf"): common.FormattedBytes(files.Variables),
		tfvarsPath: common.FormattedBytes(files.Tfvars),
		filepath.Join(request.ModulePath, "outputs.tf"): common.FormattedBytes(files.Outputs),
	}
	var transactionDirectories []string

	for path, content := range modulePrepared {
		if err := common.ValidatePreparedFile(filepath.Base(path), content); err != nil {
			return err
		}
	}

	var rootPlan commonroot.Plan
	switch request.Provider {
	case "gcp":
		rootPlan, err = gcprootmodule.PrepareGCPRootModule(
			layout.ProviderRoot,
			modulePrepared,
		)
	case "oci":
		rootPlan, err = ocimodule.PrepareOCIRootModule(
			layout.ProviderRoot,
			modulePrepared,
		)
	default:
		return fmt.Errorf("provider racine non supporte : %s", request.Provider)
	}
	if err != nil {
		return err
	}
	if rootPlan.Report.HasConflicts() {
		return fmt.Errorf(
			"conflits dans le root module %s : %v",
			request.Provider,
			rootPlan.Report.Conflicts,
		)
	}
	for path, content := range rootPlan.Prepared {
		modulePrepared[path] = content
	}
	transactionDirectories = rootPlan.Directories

	if len(transactionDirectories) > 0 {
		return commonroot.CommitPreparedFiles(
			modulePrepared,
			transactionDirectories,
		)
	}
	return common.CommitFilePathsAtomically(modulePrepared)
}

func writeGCPProjectContext(file *hclwrite.File, projectID string) {
	file.Body().SetAttributeValue(
		"gcp_project_id",
		cty.StringVal(projectID),
	)
}
