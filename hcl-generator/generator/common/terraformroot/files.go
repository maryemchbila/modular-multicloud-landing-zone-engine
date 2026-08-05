package terraformroot

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

type VariableDefinition struct {
	Name        string
	Description string
	Default     *string
}

type Configuration struct {
	TerraformConstraint string
	ProviderName        string
	ProviderSource      string
	ProviderConstraint  string
	ProviderAttributes  map[string]hcl.Traversal
	Variables           []VariableDefinition
}

// PrepareRootConfiguration charge les fichiers existants, applique uniquement
// les ajouts manquants en memoire et retourne un ensemble HCL valide pret a
// etre ecrit dans une transaction unique.
func PrepareRootConfiguration(
	modulePath string,
	configuration Configuration,
) (map[string][]byte, error) {
	if err := validateConfiguration(configuration); err != nil {
		return nil, err
	}

	versionsPath := filepath.Join(modulePath, "versions.tf")
	versionsFile, err := loadOrCreateFile(versionsPath)
	if err != nil {
		return nil, err
	}
	if err := ensureTerraformVersion(
		versionsFile,
		versionsPath,
		configuration.TerraformConstraint,
		configuration.ProviderName,
		configuration.ProviderSource,
		configuration.ProviderConstraint,
	); err != nil {
		return nil, err
	}

	providersPath := filepath.Join(modulePath, "providers.tf")
	providersFile, err := loadOrCreateFile(providersPath)
	if err != nil {
		return nil, err
	}
	if err := ensureProvider(
		providersFile,
		providersPath,
		configuration.ProviderName,
		configuration.ProviderAttributes,
	); err != nil {
		return nil, err
	}

	variablesPath := filepath.Join(modulePath, "variables.tf")
	variablesFile, err := loadOrCreateFile(variablesPath)
	if err != nil {
		return nil, err
	}
	if err := ensureVariables(
		variablesFile,
		variablesPath,
		configuration.Variables,
	); err != nil {
		return nil, err
	}

	prepared := map[string][]byte{
		versionsPath:  formattedBytes(versionsFile),
		providersPath: formattedBytes(providersFile),
		variablesPath: formattedBytes(variablesFile),
	}
	if err := ValidatePreparedFiles(prepared); err != nil {
		return nil, err
	}
	return prepared, nil
}

// EnsureTerraformVersionFile fusionne le bloc terraform et la declaration du
// provider requis dans versions.tf, sans dupliquer les elements existants.
func EnsureTerraformVersionFile(
	modulePath string,
	terraformConstraint string,
	providerName string,
	providerSource string,
	providerConstraint string,
) error {
	path := filepath.Join(modulePath, "versions.tf")
	file, err := loadOrCreateFile(path)
	if err != nil {
		return err
	}
	if err := ensureTerraformVersion(
		file,
		path,
		terraformConstraint,
		providerName,
		providerSource,
		providerConstraint,
	); err != nil {
		return err
	}
	return validateAndCommit(map[string][]byte{path: formattedBytes(file)})
}

// EnsureProviderBlock fusionne un bloc provider dans providers.tf. Les
// expressions var.* sont fournies comme traversals HCL par l'appelant.
func EnsureProviderBlock(
	modulePath string,
	providerName string,
	attributes map[string]hcl.Traversal,
) error {
	path := filepath.Join(modulePath, "providers.tf")
	file, err := loadOrCreateFile(path)
	if err != nil {
		return err
	}
	if err := ensureProvider(file, path, providerName, attributes); err != nil {
		return err
	}
	return validateAndCommit(map[string][]byte{path: formattedBytes(file)})
}

func ensureTerraformVersion(
	file *hclwrite.File,
	path string,
	terraformConstraint string,
	providerName string,
	providerSource string,
	providerConstraint string,
) error {
	terraformBlocks := blocksByType(file.Body(), "terraform")
	if len(terraformBlocks) > 1 {
		return fmt.Errorf("plusieurs blocs terraform existent dans %s", path)
	}

	var terraformBlock *hclwrite.Block
	if len(terraformBlocks) == 0 {
		terraformBlock = hclwrite.NewBlock("terraform", nil)
		appendBlock(file.Body(), terraformBlock)
	} else {
		terraformBlock = terraformBlocks[0]
	}
	if terraformBlock.Body().GetAttribute("required_version") == nil {
		terraformBlock.Body().SetAttributeValue(
			"required_version",
			cty.StringVal(terraformConstraint),
		)
	}

	requiredProviderBlocks := blocksByType(
		terraformBlock.Body(),
		"required_providers",
	)
	if len(requiredProviderBlocks) > 1 {
		return fmt.Errorf(
			"plusieurs blocs required_providers existent dans %s",
			path,
		)
	}
	var requiredProviders *hclwrite.Block
	if len(requiredProviderBlocks) == 0 {
		requiredProviders = hclwrite.NewBlock("required_providers", nil)
		appendBlock(terraformBlock.Body(), requiredProviders)
	} else {
		requiredProviders = requiredProviderBlocks[0]
	}
	if requiredProviders.Body().GetAttribute(providerName) == nil {
		requiredProviders.Body().SetAttributeValue(
			providerName,
			cty.ObjectVal(map[string]cty.Value{
				"source":  cty.StringVal(providerSource),
				"version": cty.StringVal(providerConstraint),
			}),
		)
	}
	return nil
}

func ensureProvider(
	file *hclwrite.File,
	path string,
	providerName string,
	attributes map[string]hcl.Traversal,
) error {
	matching := blocksByTypeAndLabel(file.Body(), "provider", providerName)
	if len(matching) > 1 {
		return fmt.Errorf(
			"plusieurs blocs provider %q existent dans %s",
			providerName,
			path,
		)
	}

	var providerBlock *hclwrite.Block
	if len(matching) == 0 {
		providerBlock = hclwrite.NewBlock("provider", []string{providerName})
		appendBlock(file.Body(), providerBlock)
	} else {
		providerBlock = matching[0]
	}

	names := make([]string, 0, len(attributes))
	for name := range attributes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if providerBlock.Body().GetAttribute(name) == nil {
			providerBlock.Body().SetAttributeTraversal(name, attributes[name])
		}
	}
	return nil
}

func ensureVariables(
	file *hclwrite.File,
	path string,
	variables []VariableDefinition,
) error {
	for _, variable := range variables {
		matching := blocksByTypeAndLabel(file.Body(), "variable", variable.Name)
		if len(matching) > 1 {
			return fmt.Errorf(
				"variable %q dupliquee dans %s",
				variable.Name,
				path,
			)
		}
		if len(matching) == 1 {
			continue
		}

		block := hclwrite.NewBlock("variable", []string{variable.Name})
		block.Body().SetAttributeValue(
			"description",
			cty.StringVal(variable.Description),
		)
		block.Body().SetAttributeTraversal(
			"type",
			hcl.Traversal{hcl.TraverseRoot{Name: "string"}},
		)
		if variable.Default != nil {
			block.Body().SetAttributeValue(
				"default",
				cty.StringVal(*variable.Default),
			)
		}
		appendBlock(file.Body(), block)
	}
	return nil
}

func blocksByType(body *hclwrite.Body, blockType string) []*hclwrite.Block {
	result := make([]*hclwrite.Block, 0)
	for _, block := range body.Blocks() {
		if block.Type() == blockType {
			result = append(result, block)
		}
	}
	return result
}

func blocksByTypeAndLabel(
	body *hclwrite.Body,
	blockType string,
	label string,
) []*hclwrite.Block {
	result := make([]*hclwrite.Block, 0)
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

func validateAndCommit(prepared map[string][]byte) error {
	if err := ValidatePreparedFiles(prepared); err != nil {
		return err
	}
	return CommitPreparedFiles(prepared)
}
