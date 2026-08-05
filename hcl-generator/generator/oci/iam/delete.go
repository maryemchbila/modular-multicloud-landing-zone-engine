package iam

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"hcl-generator/generator/common"
	"hcl-generator/models"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

var iamDependencyModules = []string{"compute", "network", "storage"}

// ApplyDelete removes one complete linked OCI IAM set from local Terraform
// code. It never invokes Terraform or OCI.
func ApplyDelete(files *common.TerraformFiles, request *models.Request) error {
	resource := request.OCIIAMResource
	if resource == nil {
		return fmt.Errorf("ressource OCI IAM manquante")
	}

	user, err := requireIAMResource(
		files.Main,
		userResourceType,
		resource.UserResourceName,
		"OCI IAM user resource not found",
	)
	if err != nil {
		return err
	}
	group, err := requireIAMResource(
		files.Main,
		groupResourceType,
		resource.GroupResourceName,
		"OCI IAM group resource not found",
	)
	if err != nil {
		return err
	}
	membership, err := requireIAMResource(
		files.Main,
		membershipResourceType,
		resource.MembershipResourceName,
		"OCI IAM membership resource not found",
	)
	if err != nil {
		return err
	}
	policy, err := requireIAMResource(
		files.Main,
		policyResourceType,
		resource.PolicyResourceName,
		"OCI IAM policy resource not found",
	)
	if err != nil {
		return err
	}

	if err := verifyDeleteMembership(membership, resource); err != nil {
		return err
	}
	groupName, err := verifyDeletePolicy(files, policy, resource)
	if err != nil {
		return err
	}
	if err := verifyInternalIAMDependencies(
		files,
		user,
		group,
		membership,
		policy,
		resource,
		groupName,
	); err != nil {
		return err
	}
	referenced, err := iamSetReferencedByAnotherOCIModule(
		request.ModulePath,
		resource,
	)
	if err != nil {
		return err
	}
	if referenced {
		return fmt.Errorf(
			"Cannot delete OCI IAM set: referenced by another OCI module",
		)
	}

	variables := variableNames(resource)
	for _, name := range variables {
		if len(findIAMBlocks(files.Variables, "variable", name)) == 0 {
			fmt.Printf(
				"Avertissement OCI IAM : variable absente : %s\n",
				name,
			)
		}
		if !common.AttributeExists(files.Tfvars, name) {
			fmt.Printf(
				"Avertissement OCI IAM : tfvar absent : %s\n",
				name,
			)
		}
	}
	for _, name := range outputNames(resource) {
		if len(findIAMBlocks(files.Outputs, "output", name)) == 0 {
			fmt.Printf(
				"Avertissement OCI IAM : output absent : %s\n",
				name,
			)
		}
	}

	// Preserve the logical dependency order even though all four files are
	// committed together atomically.
	removeIAMBlock(files.Main, membership)
	removeIAMBlock(files.Main, policy)
	removeIAMBlock(files.Main, user)
	removeIAMBlock(files.Main, group)

	variableSet := make(map[string]struct{}, len(variables))
	for _, name := range variables {
		variableSet[name] = struct{}{}
	}
	common.RemoveBlocks(files.Variables, func(block *hclwrite.Block) bool {
		labels := block.Labels()
		if block.Type() != "variable" || len(labels) != 1 {
			return false
		}
		_, belongsToTarget := variableSet[labels[0]]
		return belongsToTarget
	})
	common.RemoveAttributes(files.Tfvars, variables)

	outputPrefixes := []string{
		resource.UserResourceName + "_",
		resource.GroupResourceName + "_",
		resource.MembershipResourceName + "_",
		resource.PolicyResourceName + "_",
	}
	common.RemoveBlocks(files.Outputs, func(block *hclwrite.Block) bool {
		labels := block.Labels()
		if block.Type() != "output" || len(labels) != 1 {
			return false
		}
		for _, prefix := range outputPrefixes {
			if strings.HasPrefix(labels[0], prefix) {
				return true
			}
		}
		return false
	})

	return compactDeletedOCIIAMFiles(files)
}

func verifyDeleteMembership(
	membership *hclwrite.Block,
	resource *models.OCIIAMRequest,
) error {
	expectedGroup := groupResourceType + "." +
		resource.GroupResourceName + ".id"
	if !iamAttributeEqualsTraversal(
		membership.Body(),
		"group_id",
		expectedGroup,
	) {
		return fmt.Errorf(
			"OCI IAM membership %s is not linked to group %s",
			resource.MembershipResourceName,
			resource.GroupResourceName,
		)
	}
	expectedUser := userResourceType + "." +
		resource.UserResourceName + ".id"
	if !iamAttributeEqualsTraversal(
		membership.Body(),
		"user_id",
		expectedUser,
	) {
		return fmt.Errorf(
			"OCI IAM membership %s is not linked to user %s",
			resource.MembershipResourceName,
			resource.UserResourceName,
		)
	}
	return nil
}

func verifyDeletePolicy(
	files *common.TerraformFiles,
	policy *hclwrite.Block,
	resource *models.OCIIAMRequest,
) (string, error) {
	expectedStatements := "var." +
		resource.PolicyResourceName + "_statements"
	if !iamAttributeEqualsTraversal(
		policy.Body(),
		"statements",
		expectedStatements,
	) {
		return "", fmt.Errorf(
			"OCI IAM policy %s has invalid statements traversal",
			resource.PolicyResourceName,
		)
	}

	groupName, ok := literalStringAttribute(
		files.Tfvars,
		resource.GroupResourceName+"_name",
	)
	if !ok || strings.TrimSpace(groupName) == "" {
		return "", fmt.Errorf(
			"OCI IAM group name tfvar not found or invalid: %s_name",
			resource.GroupResourceName,
		)
	}
	statements, ok := literalStringListAttribute(
		files.Tfvars,
		resource.PolicyResourceName+"_statements",
	)
	if !ok {
		return "", fmt.Errorf(
			"OCI IAM policy statements tfvar not found or invalid: %s_statements",
			resource.PolicyResourceName,
		)
	}
	if !statementsTargetGroup(statements, groupName) {
		return "", fmt.Errorf(
			"OCI IAM policy %s does not target group %s",
			resource.PolicyResourceName,
			resource.GroupResourceName,
		)
	}
	return groupName, nil
}

func verifyInternalIAMDependencies(
	files *common.TerraformFiles,
	user *hclwrite.Block,
	group *hclwrite.Block,
	membership *hclwrite.Block,
	policy *hclwrite.Block,
	resource *models.OCIIAMRequest,
	groupName string,
) error {
	targets := map[*hclwrite.Block]struct{}{
		user:       {},
		group:      {},
		membership: {},
		policy:     {},
	}
	userPrefix := userResourceType + "." + resource.UserResourceName
	groupPrefix := groupResourceType + "." + resource.GroupResourceName
	for _, block := range files.Main.Body().Blocks() {
		if _, targeted := targets[block]; targeted {
			continue
		}
		if bodyReferencesTraversalPrefix(block.Body(), userPrefix) {
			return fmt.Errorf(
				"Cannot delete OCI IAM set: user %s is referenced by another OCI IAM block",
				resource.UserResourceName,
			)
		}
		if bodyReferencesTraversalPrefix(block.Body(), groupPrefix) {
			return fmt.Errorf(
				"Cannot delete OCI IAM set: group %s is referenced by another OCI IAM resource",
				resource.GroupResourceName,
			)
		}
	}

	for _, block := range files.Main.Body().Blocks() {
		labels := block.Labels()
		if block.Type() != "resource" ||
			len(labels) != 2 ||
			labels[0] != policyResourceType ||
			block == policy {
			continue
		}
		statements, ok := literalStringListAttribute(
			files.Tfvars,
			labels[1]+"_statements",
		)
		if ok && statementsTargetGroup(statements, groupName) {
			return fmt.Errorf(
				"Cannot delete OCI IAM set: group %s is referenced by another OCI IAM resource",
				resource.GroupResourceName,
			)
		}
	}
	return nil
}

func iamSetReferencedByAnotherOCIModule(
	iamModulePath string,
	resource *models.OCIIAMRequest,
) (bool, error) {
	ociRoot := filepath.Dir(filepath.Clean(iamModulePath))
	for _, moduleName := range iamDependencyModules {
		modulePath := filepath.Join(ociRoot, moduleName)
		info, err := os.Stat(modulePath)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf(
				"impossible d'inspecter le module OCI %s : %w",
				moduleName,
				err,
			)
		}
		if !info.IsDir() {
			return false, fmt.Errorf(
				"le module OCI %s n'est pas un dossier : %s",
				moduleName,
				modulePath,
			)
		}

		referenced := false
		err = filepath.WalkDir(
			modulePath,
			func(path string, entry fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if entry.IsDir() {
					if path != modulePath &&
						strings.HasPrefix(entry.Name(), ".") {
						return filepath.SkipDir
					}
					return nil
				}
				if filepath.Ext(entry.Name()) != ".tf" &&
					!strings.HasSuffix(entry.Name(), ".tfvars") {
					return nil
				}
				file, loadErr := common.LoadExistingFile(path)
				if loadErr != nil {
					return loadErr
				}
				if bodyReferencesOCIIAMSet(file.Body(), resource) {
					referenced = true
					return filepath.SkipAll
				}
				return nil
			},
		)
		if err != nil {
			return false, fmt.Errorf(
				"impossible d'inspecter le module OCI %s : %w",
				moduleName,
				err,
			)
		}
		if referenced {
			return true, nil
		}
	}
	return false, nil
}

func bodyReferencesOCIIAMSet(
	body *hclwrite.Body,
	resource *models.OCIIAMRequest,
) bool {
	resourcePrefixes := []string{
		userResourceType + "." + resource.UserResourceName,
		groupResourceType + "." + resource.GroupResourceName,
		policyResourceType + "." + resource.PolicyResourceName,
	}
	outputs := outputNames(resource)
	for _, attribute := range body.Attributes() {
		for _, traversal := range attribute.Expr().Variables() {
			value := ociIAMTraversalValue(traversal)
			for _, prefix := range resourcePrefixes {
				if value == prefix ||
					strings.HasPrefix(value, prefix+".") {
					return true
				}
			}
			for _, output := range outputs {
				if (strings.HasPrefix(value, "module.") ||
					strings.Contains(value, ".outputs.")) &&
					strings.HasSuffix(value, "."+output) {
					return true
				}
			}
		}
	}
	for _, block := range body.Blocks() {
		if bodyReferencesOCIIAMSet(block.Body(), resource) {
			return true
		}
	}
	return false
}

func bodyReferencesTraversalPrefix(
	body *hclwrite.Body,
	prefix string,
) bool {
	for _, attribute := range body.Attributes() {
		for _, traversal := range attribute.Expr().Variables() {
			value := ociIAMTraversalValue(traversal)
			if value == prefix || strings.HasPrefix(value, prefix+".") {
				return true
			}
		}
	}
	for _, block := range body.Blocks() {
		if bodyReferencesTraversalPrefix(block.Body(), prefix) {
			return true
		}
	}
	return false
}

func literalStringListAttribute(
	file *hclwrite.File,
	name string,
) ([]string, bool) {
	attribute := file.Body().GetAttribute(name)
	if attribute == nil {
		return nil, false
	}
	expression, diagnostics := hclsyntax.ParseExpression(
		bytes.TrimSpace(attribute.Expr().BuildTokens(nil).Bytes()),
		"terraform.tfvars",
		hcl.InitialPos,
	)
	if diagnostics.HasErrors() {
		return nil, false
	}
	value, diagnostics := expression.Value(nil)
	if diagnostics.HasErrors() ||
		!value.IsKnown() ||
		value.IsNull() ||
		(!value.Type().IsListType() && !value.Type().IsTupleType()) {
		return nil, false
	}
	result := make([]string, 0, value.LengthInt())
	iterator := value.ElementIterator()
	for iterator.Next() {
		_, item := iterator.Element()
		if !item.IsKnown() ||
			item.IsNull() ||
			item.Type() != cty.String {
			return nil, false
		}
		result = append(result, item.AsString())
	}
	return result, true
}

func ociIAMTraversalValue(traversal *hclwrite.Traversal) string {
	return strings.TrimSpace(string(traversal.BuildTokens(nil).Bytes()))
}

func statementsTargetGroup(statements []string, groupName string) bool {
	for _, statement := range statements {
		words := strings.Fields(statement)
		if len(words) >= 3 &&
			strings.EqualFold(words[0], "Allow") &&
			strings.EqualFold(words[1], "group") &&
			words[2] == groupName {
			return true
		}
	}
	return false
}

func removeIAMBlock(file *hclwrite.File, target *hclwrite.Block) {
	common.RemoveBlocks(file, func(block *hclwrite.Block) bool {
		return block == target
	})
}

func compactDeletedOCIIAMFiles(files *common.TerraformFiles) error {
	targets := []struct {
		name string
		file **hclwrite.File
	}{
		{"main.tf", &files.Main},
		{"variables.tf", &files.Variables},
		{"terraform.tfvars", &files.Tfvars},
		{"outputs.tf", &files.Outputs},
	}
	for _, target := range targets {
		compacted, err := common.CompactFile(*target.file, target.name)
		if err != nil {
			return err
		}
		*target.file = compacted
	}
	return nil
}
