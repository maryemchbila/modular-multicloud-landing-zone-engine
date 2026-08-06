package rootmodule

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

var ModuleNames = []string{"compute", "network", "storage", "iam"}

type ModuleLayout struct {
	ProviderRoot string
	ModulesRoot  string
	ModulePath   string
	Legacy       bool
}

// ResolveModulePath reconnait les deux conventions autorisees :
// generated/<provider>/<module> et generated/<provider>/modules/<module>.
func ResolveModulePath(modulePath, provider, moduleName string) (ModuleLayout, error) {
	cleaned := filepath.Clean(modulePath)
	if filepath.Base(cleaned) != moduleName {
		return ModuleLayout{}, invalidModulePath(modulePath, provider, moduleName)
	}

	parent := filepath.Dir(cleaned)
	if filepath.Base(parent) == provider &&
		filepath.Base(filepath.Dir(parent)) == "generated" {
		return ModuleLayout{
			ProviderRoot: parent,
			ModulesRoot:  filepath.Join(parent, "modules"),
			ModulePath:   cleaned,
			Legacy:       true,
		}, nil
	}

	if filepath.Base(parent) == "modules" {
		providerRoot := filepath.Dir(parent)
		if filepath.Base(providerRoot) == provider &&
			filepath.Base(filepath.Dir(providerRoot)) == "generated" {
			return ModuleLayout{
				ProviderRoot: providerRoot,
				ModulesRoot:  parent,
				ModulePath:   cleaned,
				Legacy:       false,
			}, nil
		}
	}
	return ModuleLayout{}, invalidModulePath(modulePath, provider, moduleName)
}

func invalidModulePath(path, provider, moduleName string) error {
	return fmt.Errorf(
		"module_path %s/%s doit cibler generated/%s/%s ou generated/%s/modules/%s : %s",
		provider,
		moduleName,
		provider,
		moduleName,
		provider,
		moduleName,
		path,
	)
}

func ValidatePreparedFiles(prepared map[string][]byte) error {
	for path, content := range prepared {
		if filepath.Base(path) == "terraform.tfvars" && len(content) == 0 {
			continue
		}
		_, diagnostics := hclwrite.ParseConfig(content, path, hcl.InitialPos)
		if diagnostics.HasErrors() {
			return fmt.Errorf("HCL invalide pour %s : %s", path, diagnostics.Error())
		}
	}
	return nil
}

func isSensitiveName(name string) bool {
	lower := strings.ToLower(name)
	for _, marker := range []string{
		"private_key", "private-key", "password", "token",
		"fingerprint", "client_secret", "client-secret", "secret",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func blocksByTypeAndLabel(
	body *hclwrite.Body,
	blockType string,
	label string,
) []*hclwrite.Block {
	var result []*hclwrite.Block
	for _, block := range body.Blocks() {
		labels := block.Labels()
		if block.Type() == blockType && len(labels) == 1 && labels[0] == label {
			result = append(result, block)
		}
	}
	return result
}

func appendBlock(body *hclwrite.Body, block *hclwrite.Block) {
	if len(body.Attributes()) > 0 || len(body.Blocks()) > 0 {
		body.AppendNewline()
	}
	body.AppendBlock(block)
	body.AppendNewline()
}
