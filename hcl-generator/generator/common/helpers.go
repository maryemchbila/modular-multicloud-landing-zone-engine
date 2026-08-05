package common

import (
	"bytes"
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

func BlockExists(
	file *hclwrite.File,
	blockType string,
	expectedLabels ...string,
) bool {
	return FindBlock(file, blockType, expectedLabels...) != nil
}

func FindBlock(
	file *hclwrite.File,
	blockType string,
	expectedLabels ...string,
) *hclwrite.Block {
	for _, block := range file.Body().Blocks() {
		if block.Type() != blockType {
			continue
		}

		labels := block.Labels()
		if len(labels) != len(expectedLabels) {
			continue
		}

		match := true
		for index := range labels {
			if labels[index] != expectedLabels[index] {
				match = false
				break
			}
		}
		if match {
			return block
		}
	}

	return nil
}

func AttributeExists(file *hclwrite.File, name string) bool {
	return file.Body().GetAttribute(name) != nil
}

func RemoveBlocks(
	file *hclwrite.File,
	shouldRemove func(*hclwrite.Block) bool,
) int {
	removed := 0
	for _, block := range file.Body().Blocks() {
		if shouldRemove(block) {
			file.Body().RemoveBlock(block)
			removed++
		}
	}
	return removed
}

func RemoveAttributes(file *hclwrite.File, names []string) int {
	removed := 0
	for _, name := range names {
		if file.Body().GetAttribute(name) != nil {
			file.Body().RemoveAttribute(name)
			removed++
		}
	}
	return removed
}

func AppendBlock(file *hclwrite.File, block *hclwrite.Block) {
	body := file.Body()
	if len(body.Blocks()) > 0 || len(body.Attributes()) > 0 {
		body.AppendNewline()
	}
	body.AppendBlock(block)
	body.AppendNewline()
}

func VarTraversal(variableName string) hcl.Traversal {
	return hcl.Traversal{
		hcl.TraverseRoot{Name: "var"},
		hcl.TraverseAttr{Name: variableName},
	}
}

func TypeTraversal(typeName string) hcl.Traversal {
	return hcl.Traversal{hcl.TraverseRoot{Name: typeName}}
}

func ResourceTraversal(
	resourceType string,
	resourceName string,
	attribute string,
) hcl.Traversal {
	return hcl.Traversal{
		hcl.TraverseRoot{Name: resourceType},
		hcl.TraverseAttr{Name: resourceName},
		hcl.TraverseAttr{Name: attribute},
	}
}

func FormattedBytes(file *hclwrite.File) []byte {
	return hclwrite.Format(file.Bytes())
}

// CompactFile removes excessive blank lines left by AST block removal, then
// reparses the result so subsequent operations continue to use a valid AST.
func CompactFile(file *hclwrite.File, filename string) (*hclwrite.File, error) {
	content := FormattedBytes(file)
	for bytes.Contains(content, []byte("\n\n\n")) {
		content = bytes.ReplaceAll(content, []byte("\n\n\n"), []byte("\n\n"))
	}
	content = append(bytes.TrimSpace(content), '\n')
	compacted, diagnostics := hclwrite.ParseConfig(
		content,
		filename,
		hcl.InitialPos,
	)
	if diagnostics.HasErrors() {
		return nil, fmt.Errorf(
			"impossible de compacter %s : %s",
			filename,
			diagnostics.Error(),
		)
	}
	return compacted, nil
}

func ValidatePreparedFile(filename string, content []byte) error {
	_, diagnostics := hclwrite.ParseConfig(
		content,
		filename,
		hcl.InitialPos,
	)
	if diagnostics.HasErrors() {
		return fmt.Errorf(
			"contenu HCL invalide pour %s : %s",
			filename,
			diagnostics.Error(),
		)
	}
	return nil
}
