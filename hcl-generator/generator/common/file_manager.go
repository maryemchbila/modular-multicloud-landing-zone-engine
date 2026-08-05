package common

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

func LoadTerraformFiles(basePath string) (*TerraformFiles, error) {
	return loadTerraformFiles(basePath, LoadOrCreateFile)
}

func LoadExistingTerraformFiles(basePath string) (*TerraformFiles, error) {
	return loadTerraformFiles(basePath, LoadExistingFile)
}

func loadTerraformFiles(
	basePath string,
	loader func(string) (*hclwrite.File, error),
) (*TerraformFiles, error) {
	mainFile, err := loader(filepath.Join(basePath, "main.tf"))
	if err != nil {
		return nil, err
	}

	variablesFile, err := loader(filepath.Join(basePath, "variables.tf"))
	if err != nil {
		return nil, err
	}

	tfvarsFile, err := loader(filepath.Join(basePath, "terraform.tfvars"))
	if err != nil {
		return nil, err
	}

	outputsFile, err := loader(filepath.Join(basePath, "outputs.tf"))
	if err != nil {
		return nil, err
	}

	return &TerraformFiles{
		Main:      mainFile,
		Variables: variablesFile,
		Tfvars:    tfvarsFile,
		Outputs:   outputsFile,
	}, nil
}

func LoadExistingFile(path string) (*hclwrite.File, error) {
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("fichier Terraform requis introuvable : %s", path)
	}
	if err != nil {
		return nil, err
	}
	return parseFile(content, path)
}

func LoadOrCreateFile(path string) (*hclwrite.File, error) {
	content, err := os.ReadFile(path)

	if errors.Is(err, os.ErrNotExist) {
		return hclwrite.NewEmptyFile(), nil
	}

	if err != nil {
		return nil, err
	}

	return parseFile(content, path)
}

func parseFile(content []byte, path string) (*hclwrite.File, error) {
	file, diagnostics := hclwrite.ParseConfig(
		content,
		path,
		hcl.InitialPos,
	)

	if diagnostics.HasErrors() {
		return nil, fmt.Errorf(
			"le fichier %s contient des erreurs HCL : %s",
			path,
			diagnostics.Error(),
		)
	}

	return file, nil
}
