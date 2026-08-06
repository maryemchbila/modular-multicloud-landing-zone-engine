package rootmodule

import "github.com/hashicorp/hcl/v2"

func VariableTraversal(name string) hcl.Traversal {
	return hcl.Traversal{
		hcl.TraverseRoot{Name: "var"},
		hcl.TraverseAttr{Name: name},
	}
}

func ModuleOutputTraversal(moduleName, outputName string) hcl.Traversal {
	return hcl.Traversal{
		hcl.TraverseRoot{Name: "module"},
		hcl.TraverseAttr{Name: moduleName},
		hcl.TraverseAttr{Name: outputName},
	}
}
