package rootmodule

import (
	"fmt"
	"path/filepath"

	commonroot "hcl-generator/generator/common/rootmodule"
	gcprootconfig "hcl-generator/generator/gcp/rootconfig"
)

func EnsureGCPRootModule(rootPath string) error {
	plan, err := PrepareGCPRootModule(rootPath, nil)
	if err != nil {
		return err
	}
	if plan.Report.HasConflicts() {
		return fmt.Errorf("configuration racine GCP en conflit : %v", plan.Report.Conflicts)
	}
	return commonroot.CommitPreparedFiles(plan.Prepared, plan.Directories)
}

func PrepareGCPRootModule(
	rootPath string,
	overlays map[string][]byte,
) (commonroot.Plan, error) {
	if filepath.Base(filepath.Clean(rootPath)) != "gcp" {
		return commonroot.Plan{}, fmt.Errorf(
			"le chemin racine GCP doit se terminer par gcp : %s",
			rootPath,
		)
	}
	base, err := gcprootconfig.PrepareGCPRootConfiguration(rootPath)
	if err != nil {
		return commonroot.Plan{}, err
	}
	combined := mergeOverlays(base, overlays)
	plan, err := commonroot.PrepareRootModule(rootPath, "gcp", combined)
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
