package rootmodule

import (
	"fmt"
	"path/filepath"

	commonroot "hcl-generator/generator/common/rootmodule"
	ociconfig "hcl-generator/generator/oci/rootconfig"
)

func EnsureOCIRootModule(rootPath string) error {
	plan, err := PrepareOCIRootModule(rootPath, nil)
	if err != nil {
		return err
	}
	if plan.Report.HasConflicts() {
		return fmt.Errorf("configuration racine OCI en conflit : %v", plan.Report.Conflicts)
	}
	return commonroot.CommitPreparedFiles(plan.Prepared, plan.Directories)
}

func PrepareOCIRootModule(
	rootPath string,
	overlays map[string][]byte,
) (commonroot.Plan, error) {
	if filepath.Base(filepath.Clean(rootPath)) != "oci" {
		return commonroot.Plan{}, fmt.Errorf(
			"le chemin racine OCI doit se terminer par oci : %s",
			rootPath,
		)
	}
	base, err := ociconfig.PrepareOCIRootConfiguration(rootPath)
	if err != nil {
		return commonroot.Plan{}, err
	}
	combined := mergeOverlays(base, overlays)
	plan, err := commonroot.PrepareRootModule(rootPath, "oci", combined)
	if err != nil {
		return commonroot.Plan{}, err
	}
	commonroot.AddPreparedFiles(&plan, base)
	return plan, nil
}

func mergeOverlays(base, extra map[string][]byte) map[string][]byte {
	result := make(map[string][]byte, len(base)+len(extra))
	for path, content := range base {
		result[filepath.Clean(path)] = content
	}
	for path, content := range extra {
		result[filepath.Clean(path)] = content
	}
	return result
}
