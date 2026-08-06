package rootmodule

import (
	commonroot "hcl-generator/generator/common/rootmodule"
	ociconfig "hcl-generator/generator/oci/rootconfig"
)

// AnalyzeOCIMigration produit uniquement la projection de la phase B.
func AnalyzeOCIMigration(rootPath string) (commonroot.Plan, error) {
	base, err := ociconfig.PrepareOCIRootConfiguration(rootPath)
	if err != nil {
		return commonroot.Plan{}, err
	}
	plan, err := commonroot.AnalyzeMigration(rootPath, "oci", base)
	if err != nil {
		return commonroot.Plan{}, err
	}
	commonroot.AddPreparedFiles(&plan, base)
	return plan, nil
}
