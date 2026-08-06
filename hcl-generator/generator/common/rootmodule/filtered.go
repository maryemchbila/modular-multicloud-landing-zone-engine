package rootmodule

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

var fixtureMarkers = []string{
	"test", "clean_test", "migration_test", "modular_test",
	"inexistante", "delete_b",
}

// PrepareFilteredMigration moves only functional blocks into canonical
// modules. Fixture blocks and all of their inputs/outputs remain in legacy
// files. The returned plan is entirely in memory.
func PrepareFilteredMigration(
	rootPath string,
	provider string,
	baseOverlays map[string][]byte,
) (Plan, error) {
	rootPath = filepath.Clean(rootPath)
	overlays := cloneContents(baseOverlays)
	legacyPrepared := make(map[string][]byte)
	report := MigrationReport{Provider: provider, RootPath: rootPath}

	for _, moduleName := range ModuleNames {
		legacyPath := filepath.Join(rootPath, moduleName)
		targetPath := filepath.Join(rootPath, "modules", moduleName)
		if info, statErr := os.Stat(legacyPath); os.IsNotExist(statErr) {
			continue
		} else if statErr != nil {
			return Plan{}, fmt.Errorf("impossible d'inspecter %s : %w", legacyPath, statErr)
		} else if !info.IsDir() {
			return Plan{}, fmt.Errorf("le chemin historique n'est pas un dossier : %s", legacyPath)
		}
		legacyMain, err := loadFile(filepath.Join(legacyPath, "main.tf"), nil)
		if err != nil {
			return Plan{}, err
		}
		legacyVariables, err := loadFile(filepath.Join(legacyPath, "variables.tf"), nil)
		if err != nil {
			return Plan{}, err
		}
		legacyTfvars, err := loadFile(filepath.Join(legacyPath, "terraform.tfvars"), nil)
		if err != nil {
			return Plan{}, err
		}
		legacyOutputs, err := loadFile(filepath.Join(legacyPath, "outputs.tf"), nil)
		if err != nil {
			return Plan{}, err
		}

		targetMain, err := loadFile(filepath.Join(targetPath, "main.tf"), overlays)
		if err != nil {
			return Plan{}, err
		}
		targetVariables, err := loadFile(filepath.Join(targetPath, "variables.tf"), overlays)
		if err != nil {
			return Plan{}, err
		}
		targetTfvars := hclwrite.NewEmptyFile()
		targetOutputs, err := loadFile(filepath.Join(targetPath, "outputs.tf"), overlays)
		if err != nil {
			return Plan{}, err
		}

		functionalAddresses := make(map[string]struct{})
		fixtureAddresses := make(map[string]struct{})
		functionalVariables := make(map[string]struct{})
		fixtureVariables := make(map[string]struct{})
		for _, block := range append([]*hclwrite.Block(nil), legacyMain.Body().Blocks()...) {
			if block.Type() != "resource" || len(block.Labels()) != 2 {
				continue
			}
			address := block.Labels()[0] + "." + block.Labels()[1]
			if isFixtureLabel(block.Labels()[1]) {
				fixtureAddresses[address] = struct{}{}
				collectVariableNames(block, fixtureVariables)
				report.IgnoredValues = append(report.IgnoredValues,
					moduleName+":"+address+" (fixture conservee)")
				continue
			}
			functionalAddresses[address] = struct{}{}
			collectVariableNames(block, functionalVariables)
			if err := appendUniqueBlock(targetMain, block); err != nil {
				report.Conflicts = append(report.Conflicts,
					moduleName+":"+address+": "+err.Error())
				continue
			}
			legacyMain.Body().RemoveBlock(block)
			report.ResourcesToMove = append(report.ResourcesToMove, moduleName+":"+address)
		}

		for name := range functionalVariables {
			if _, shared := fixtureVariables[name]; shared {
				report.Conflicts = append(report.Conflicts,
					"variable partagee par fixture et ressource fonctionnelle: "+moduleName+"."+name)
			}
		}
		for _, block := range append([]*hclwrite.Block(nil), legacyVariables.Body().Blocks()...) {
			if block.Type() != "variable" || len(block.Labels()) != 1 {
				continue
			}
			name := block.Labels()[0]
			if _, move := functionalVariables[name]; !move {
				continue
			}
			if _, shared := fixtureVariables[name]; shared {
				continue
			}
			if err := appendUniqueBlock(targetVariables, block); err != nil {
				report.Conflicts = append(report.Conflicts,
					moduleName+"."+name+": "+err.Error())
				continue
			}
			legacyVariables.Body().RemoveBlock(block)
		}

		for name, attribute := range legacyTfvars.Body().Attributes() {
			if _, move := functionalVariables[name]; !move {
				continue
			}
			if _, shared := fixtureVariables[name]; shared {
				continue
			}
			if isSensitiveName(name) {
				report.Conflicts = append(report.Conflicts,
					"variable sensible refusee: "+moduleName+".<nom masque>")
				continue
			}
			targetTfvars.Body().SetAttributeRaw(name, attribute.Expr().BuildTokens(nil))
			legacyTfvars.Body().RemoveAttribute(name)
		}

		for _, block := range append([]*hclwrite.Block(nil), legacyOutputs.Body().Blocks()...) {
			if block.Type() != "output" || len(block.Labels()) != 1 {
				continue
			}
			functional, fixture := outputOwners(block, functionalAddresses, fixtureAddresses)
			if functional && fixture {
				report.Conflicts = append(report.Conflicts,
					"output partage par fixture et ressource fonctionnelle: "+moduleName+"."+block.Labels()[0])
				continue
			}
			if !functional {
				continue
			}
			if err := appendUniqueBlock(targetOutputs, block); err != nil {
				report.Conflicts = append(report.Conflicts,
					moduleName+"."+block.Labels()[0]+": "+err.Error())
				continue
			}
			legacyOutputs.Body().RemoveBlock(block)
		}

		legacyPrepared[filepath.Join(legacyPath, "main.tf")] = formatted(legacyMain)
		legacyPrepared[filepath.Join(legacyPath, "variables.tf")] = formatted(legacyVariables)
		legacyPrepared[filepath.Join(legacyPath, "terraform.tfvars")] = formatted(legacyTfvars)
		legacyPrepared[filepath.Join(legacyPath, "outputs.tf")] = formatted(legacyOutputs)
		overlays[filepath.Join(targetPath, "main.tf")] = formatted(targetMain)
		overlays[filepath.Join(targetPath, "variables.tf")] = formatted(targetVariables)
		overlays[filepath.Join(targetPath, "terraform.tfvars")] = formatted(targetTfvars)
		overlays[filepath.Join(targetPath, "outputs.tf")] = formatted(targetOutputs)
	}

	plan, err := PrepareRootModule(rootPath, provider, overlays)
	if err != nil {
		return Plan{}, err
	}
	for path, content := range legacyPrepared {
		plan.Prepared[path] = content
	}
	plan.Report.ResourcesToMove = append(plan.Report.ResourcesToMove, report.ResourcesToMove...)
	plan.Report.IgnoredValues = append(plan.Report.IgnoredValues, report.IgnoredValues...)
	plan.Report.Conflicts = append(plan.Report.Conflicts, report.Conflicts...)
	plan.Report.FilesToCreate = nil
	plan.Report.FilesToModify = nil
	classifyFiles(plan.Prepared, &plan.Report)
	plan.Report.normalize()
	return plan, nil
}

func isFixtureLabel(label string) bool {
	lower := strings.ToLower(label)
	for _, marker := range fixtureMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func collectVariableNames(block *hclwrite.Block, destination map[string]struct{}) {
	for _, traversal := range bodyTraversals(block.Body()) {
		if strings.HasPrefix(traversal, "var.") && strings.Count(traversal, ".") == 1 {
			destination[strings.TrimPrefix(traversal, "var.")] = struct{}{}
		}
	}
}

func appendUniqueBlock(target *hclwrite.File, source *hclwrite.Block) error {
	labels := source.Labels()
	if len(labels) == 0 {
		return fmt.Errorf("bloc sans label non supporte")
	}
	var existing []*hclwrite.Block
	for _, candidate := range target.Body().Blocks() {
		if candidate.Type() != source.Type() || len(candidate.Labels()) != len(labels) {
			continue
		}
		match := true
		for index, label := range labels {
			if candidate.Labels()[index] != label {
				match = false
				break
			}
		}
		if match {
			existing = append(existing, candidate)
		}
	}
	if len(existing) > 1 {
		return fmt.Errorf("bloc cible duplique")
	}
	if len(existing) == 1 {
		if !bytes.Equal(
			normalizeExpression(existing[0].BuildTokens(nil).Bytes()),
			normalizeExpression(source.BuildTokens(nil).Bytes()),
		) {
			return fmt.Errorf("bloc cible conflictuel")
		}
		return nil
	}
	clone, err := cloneBlock(source)
	if err != nil {
		return err
	}
	appendBlock(target.Body(), clone)
	return nil
}

func outputOwners(
	block *hclwrite.Block,
	functional map[string]struct{},
	fixtures map[string]struct{},
) (bool, bool) {
	functionalOwner, fixtureOwner := false, false
	for _, traversal := range bodyTraversals(block.Body()) {
		parts := strings.Split(traversal, ".")
		if len(parts) < 2 {
			continue
		}
		address := parts[0] + "." + parts[1]
		if _, ok := functional[address]; ok {
			functionalOwner = true
		}
		if _, ok := fixtures[address]; ok {
			fixtureOwner = true
		}
	}
	return functionalOwner, fixtureOwner
}
