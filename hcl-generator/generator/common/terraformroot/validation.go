package terraformroot

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

func ValidatePreparedFiles(prepared map[string][]byte) error {
	for path, content := range prepared {
		_, diagnostics := hclwrite.ParseConfig(content, path, hcl.InitialPos)
		if diagnostics.HasErrors() {
			return fmt.Errorf(
				"HCL invalide pour %s : %s",
				path,
				diagnostics.Error(),
			)
		}
	}
	return nil
}

func loadOrCreateFile(path string) (*hclwrite.File, error) {
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return hclwrite.NewEmptyFile(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("impossible de lire %s : %w", path, err)
	}
	file, diagnostics := hclwrite.ParseConfig(content, path, hcl.InitialPos)
	if diagnostics.HasErrors() {
		return nil, fmt.Errorf(
			"le fichier existant %s contient du HCL invalide : %s",
			path,
			diagnostics.Error(),
		)
	}
	return file, nil
}

func formattedBytes(file *hclwrite.File) []byte {
	content := hclwrite.Format(file.Bytes())
	for bytes.Contains(content, []byte("\n\n\n")) {
		content = bytes.ReplaceAll(content, []byte("\n\n\n"), []byte("\n\n"))
	}
	return append(bytes.TrimSpace(content), '\n')
}

func validateConfiguration(configuration Configuration) error {
	required := map[string]string{
		"terraformConstraint": configuration.TerraformConstraint,
		"providerName":        configuration.ProviderName,
		"providerSource":      configuration.ProviderSource,
		"providerConstraint":  configuration.ProviderConstraint,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("configuration racine invalide : %s est vide", field)
		}
	}
	for name, traversal := range configuration.ProviderAttributes {
		if strings.TrimSpace(name) == "" || len(traversal) == 0 {
			return fmt.Errorf(
				"configuration racine invalide : attribut provider %q sans traversal",
				name,
			)
		}
	}
	for _, variable := range configuration.Variables {
		if strings.TrimSpace(variable.Name) == "" {
			return fmt.Errorf("configuration racine invalide : variable sans nom")
		}
	}
	return nil
}
