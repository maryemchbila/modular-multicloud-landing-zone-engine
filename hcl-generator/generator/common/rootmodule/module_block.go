package rootmodule

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// EnsureModuleBlock ajoute un appel de module idempotent. Une expression
// existante differente est un conflit et n'est jamais ecrasee silencieusement.
func EnsureModuleBlock(
	file *hclwrite.File,
	moduleName string,
	source string,
	attributes map[string]hcl.Traversal,
) error {
	matches := blocksByTypeAndLabel(file.Body(), "module", moduleName)
	if len(matches) > 1 {
		return fmt.Errorf("plusieurs blocs module %q existent", moduleName)
	}

	var block *hclwrite.Block
	if len(matches) == 0 {
		block = hclwrite.NewBlock("module", []string{moduleName})
		block.Body().SetAttributeValue("source", cty.StringVal(source))
		appendBlock(file.Body(), block)
	} else {
		block = matches[0]
		existingSource := block.Body().GetAttribute("source")
		if existingSource == nil ||
			!bytes.Equal(
				normalizeExpression(existingSource.Expr().BuildTokens(nil).Bytes()),
				normalizeExpression(hclwrite.TokensForValue(cty.StringVal(source)).Bytes()),
			) {
			return fmt.Errorf("source conflictuelle pour module %q", moduleName)
		}
	}

	names := make([]string, 0, len(attributes))
	for name := range attributes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		expected := hclwrite.TokensForTraversal(attributes[name]).Bytes()
		existing := block.Body().GetAttribute(name)
		if existing == nil {
			block.Body().SetAttributeTraversal(name, attributes[name])
			continue
		}
		if !bytes.Equal(
			normalizeExpression(existing.Expr().BuildTokens(nil).Bytes()),
			normalizeExpression(expected),
		) {
			return fmt.Errorf(
				"attribut %q conflictuel dans module %q",
				name,
				moduleName,
			)
		}
	}
	return nil
}

func normalizeExpression(content []byte) []byte {
	return bytes.Join(bytes.Fields(content), nil)
}
