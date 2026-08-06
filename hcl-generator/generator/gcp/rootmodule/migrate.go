package rootmodule

import (
	commonroot "hcl-generator/generator/common/rootmodule"
	gcprootconfig "hcl-generator/generator/gcp/rootconfig"
)

// AnalyzeGCPMigration produit uniquement la projection de la phase B.
// L'application destructive de cette projection n'appartient pas a la phase A.
func AnalyzeGCPMigration(rootPath string) (commonroot.Plan, error) {
	base, err := gcprootconfig.PrepareGCPRootConfiguration(rootPath)
	if err != nil {
		return commonroot.Plan{}, err
	}
	plan, err := commonroot.AnalyzeMigration(rootPath, "gcp", base)
	if err != nil {
		return commonroot.Plan{}, err
	}
	commonroot.AddPreparedFiles(&plan, base)
	return plan, nil
}

func PrepareGCPFilteredMigration(rootPath string) (commonroot.Plan, error) {
	base, err := gcprootconfig.PrepareGCPRootConfiguration(rootPath)
	if err != nil {
		return commonroot.Plan{}, err
	}
	plan, err := commonroot.PrepareFilteredMigration(rootPath, "gcp", base)
	if err != nil {
		return commonroot.Plan{}, err
	}
	commonroot.AddPreparedFiles(&plan, base)
	return plan, nil
}
