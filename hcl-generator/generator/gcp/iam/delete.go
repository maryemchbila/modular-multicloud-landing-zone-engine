package iam

import (
	"bytes"
	"fmt"
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

// ApplyDelete removes one linked IAM binding/service-account pair and only its
// associated local variables, tfvars and outputs.
func ApplyDelete(files *common.TerraformFiles, request *models.Request) error {
	resource := request.IAMResource
	if resource == nil {
		return fmt.Errorf("ressource iam manquante")
	}
	resourceName := resource.ResourceName

	serviceAccount := common.FindBlock(
		files.Main,
		"resource",
		serviceAccountResourceType,
		resourceName,
	)
	if serviceAccount == nil {
		return fmt.Errorf("IAM service account not found: %s", resourceName)
	}

	roleBindingName := resourceName + "_role"
	roleBinding := common.FindBlock(
		files.Main,
		"resource",
		projectIAMMemberType,
		roleBindingName,
	)
	if roleBinding == nil {
		return fmt.Errorf("IAM role binding not found: %s", roleBindingName)
	}

	if !roleBindingIsLinkedToServiceAccount(roleBinding, resourceName) {
		return fmt.Errorf(
			"IAM role binding %s is not linked to service account %s",
			roleBindingName,
			resourceName,
		)
	}

	if iamResourceReferencedByAnotherBlock(
		files.Main,
		serviceAccount,
		roleBinding,
		resourceName,
	) {
		return fmt.Errorf(
			"Cannot delete IAM resource %s: referenced by another block",
			resourceName,
		)
	}

	referencedByAnotherModule, err := iamResourceReferencedByAnotherModule(
		request,
		files.Tfvars,
		resourceName,
	)
	if err != nil {
		return err
	}
	if referencedByAnotherModule {
		return fmt.Errorf(
			"Cannot delete IAM resource %s: referenced by another module",
			resourceName,
		)
	}

	// Remove the dependent binding before its service account.
	common.RemoveBlocks(files.Main, func(block *hclwrite.Block) bool {
		return block == roleBinding
	})
	common.RemoveBlocks(files.Main, func(block *hclwrite.Block) bool {
		return block == serviceAccount
	})

	variableNames := variableNames(resourceName)
	variableSet := make(map[string]struct{}, len(variableNames))
	for _, name := range variableNames {
		variableSet[name] = struct{}{}
	}
	common.RemoveBlocks(files.Variables, func(block *hclwrite.Block) bool {
		if block.Type() != "variable" || len(block.Labels()) != 1 {
			return false
		}
		_, belongsToTarget := variableSet[block.Labels()[0]]
		return belongsToTarget
	})
	common.RemoveAttributes(files.Tfvars, variableNames)

	targetOutputs := outputNames(resourceName)
	outputSet := make(map[string]struct{}, len(targetOutputs))
	for _, name := range targetOutputs {
		outputSet[name] = struct{}{}
	}
	common.RemoveBlocks(files.Outputs, func(block *hclwrite.Block) bool {
		if block.Type() != "output" || len(block.Labels()) != 1 {
			return false
		}
		name := block.Labels()[0]
		if !strings.HasPrefix(name, resourceName+"_") {
			return false
		}
		_, belongsToTarget := outputSet[name]
		return belongsToTarget
	})

	return compactDeletedIAMFiles(files)
}

func roleBindingIsLinkedToServiceAccount(
	roleBinding *hclwrite.Block,
	resourceName string,
) bool {
	member := roleBinding.Body().GetAttribute("member")
	if member == nil {
		return false
	}
	traversals := member.Expr().Variables()
	if len(traversals) != 1 {
		return false
	}
	return iamTraversalValue(traversals[0]) ==
		serviceAccountResourceType+"."+resourceName+".email"
}

func iamResourceReferencedByAnotherBlock(
	file *hclwrite.File,
	serviceAccount *hclwrite.Block,
	roleBinding *hclwrite.Block,
	resourceName string,
) bool {
	for _, block := range file.Body().Blocks() {
		if block == serviceAccount || block == roleBinding {
			continue
		}
		if bodyReferencesIAMResource(block.Body(), resourceName) {
			return true
		}
	}
	return false
}

func bodyReferencesIAMResource(
	body *hclwrite.Body,
	resourceName string,
) bool {
	for _, attribute := range body.Attributes() {
		for _, traversal := range attribute.Expr().Variables() {
			if traversalReferencesIAMResource(traversal, resourceName) {
				return true
			}
		}
	}
	for _, block := range body.Blocks() {
		if bodyReferencesIAMResource(block.Body(), resourceName) {
			return true
		}
	}
	return false
}

func traversalReferencesIAMResource(
	traversal *hclwrite.Traversal,
	resourceName string,
) bool {
	value := iamTraversalValue(traversal)
	prefixes := []string{
		serviceAccountResourceType + "." + resourceName,
		projectIAMMemberType + "." + resourceName + "_role",
	}
	for _, prefix := range prefixes {
		if value == prefix || strings.HasPrefix(value, prefix+".") {
			return true
		}
	}
	return false
}

func iamTraversalValue(traversal *hclwrite.Traversal) string {
	return strings.TrimSpace(string(traversal.BuildTokens(nil).Bytes()))
}

func iamResourceReferencedByAnotherModule(
	request *models.Request,
	iamTfvars *hclwrite.File,
	resourceName string,
) (bool, error) {
	email := iamServiceAccountEmail(iamTfvars, resourceName)
	generatedPath := filepath.Dir(request.ModulePath)

	for _, moduleName := range []string{"compute", "network", "storage"} {
		modulePath := filepath.Join(generatedPath, moduleName)
		entries, err := os.ReadDir(modulePath)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf(
				"impossible d'inspecter les dependances du module %s : %w",
				moduleName,
				err,
			)
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			filename := entry.Name()
			if filepath.Ext(filename) != ".tf" &&
				!strings.HasSuffix(filename, ".tfvars") {
				continue
			}
			file, err := common.LoadExistingFile(
				filepath.Join(modulePath, filename),
			)
			if err != nil {
				return false, fmt.Errorf(
					"impossible d'inspecter les dependances du module %s : %w",
					moduleName,
					err,
				)
			}
			if bodyReferencesIAMIdentity(
				file.Body(),
				resourceName,
				email,
			) {
				return true, nil
			}
		}
	}
	return false, nil
}

func bodyReferencesIAMIdentity(
	body *hclwrite.Body,
	resourceName string,
	email string,
) bool {
	for name, attribute := range body.Attributes() {
		for _, traversal := range attribute.Expr().Variables() {
			if traversalReferencesIAMResource(traversal, resourceName) {
				return true
			}
		}

		if email != "" && iamIdentityAttributeName(name) {
			if value, ok := iamLiteralStringAttribute(attribute); ok &&
				(value == email || value == "serviceAccount:"+email) {
				return true
			}
		}
	}
	for _, block := range body.Blocks() {
		if bodyReferencesIAMIdentity(block.Body(), resourceName, email) {
			return true
		}
	}
	return false
}

func iamIdentityAttributeName(name string) bool {
	lowerName := strings.ToLower(name)
	return strings.Contains(lowerName, "service_account") ||
		strings.Contains(lowerName, "email") ||
		strings.Contains(lowerName, "identity") ||
		strings.Contains(lowerName, "member")
}

func iamServiceAccountEmail(
	tfvars *hclwrite.File,
	resourceName string,
) string {
	accountID, accountOK := iamLiteralStringAttribute(
		tfvars.Body().GetAttribute(resourceName + "_account_id"),
	)
	projectID, projectOK := iamLiteralStringAttribute(
		tfvars.Body().GetAttribute(resourceName + "_project_id"),
	)
	if !accountOK || !projectOK || accountID == "" || projectID == "" {
		return ""
	}
	return accountID + "@" + projectID + ".iam.gserviceaccount.com"
}

func iamLiteralStringAttribute(
	attribute *hclwrite.Attribute,
) (string, bool) {
	if attribute == nil {
		return "", false
	}
	expression, diagnostics := hclsyntax.ParseExpression(
		bytes.TrimSpace(attribute.Expr().BuildTokens(nil).Bytes()),
		"terraform.tfvars",
		hcl.InitialPos,
	)
	if diagnostics.HasErrors() {
		return "", false
	}
	value, diagnostics := expression.Value(nil)
	if diagnostics.HasErrors() ||
		!value.IsKnown() ||
		value.IsNull() ||
		value.Type() != cty.String {
		return "", false
	}
	return value.AsString(), true
}

func compactDeletedIAMFiles(files *common.TerraformFiles) error {
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
