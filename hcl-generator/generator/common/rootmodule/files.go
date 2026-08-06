package rootmodule

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

type MigrationReport struct {
	Provider          string
	RootPath          string
	FilesToCreate     []string
	FilesToModify     []string
	FilesToMove       []string
	ModuleBlocksToAdd []string
	ResourcesToMove   []string
	VariablesToMerge  []string
	OutputsToAdd      []string
	Dependencies      []string
	IgnoredValues     []string
	Conflicts         []string
}

type Plan struct {
	Prepared    map[string][]byte
	Directories []string
	Report      MigrationReport
}

type moduleInfo struct {
	name      string
	path      string
	main      *hclwrite.File
	variables *hclwrite.File
	tfvars    *hclwrite.File
	outputs   *hclwrite.File
	useful    bool
}

// AddPreparedFiles complete un plan avec des fichiers de configuration deja
// prepares (par exemple versions.tf et providers.tf) sans ecraser les fichiers
// racine enrichis par le plan de modules.
func AddPreparedFiles(plan *Plan, extra map[string][]byte) {
	for path, content := range extra {
		cleaned := filepath.Clean(path)
		if _, present := plan.Prepared[cleaned]; !present {
			plan.Prepared[cleaned] = content
		}
	}
	plan.Report.FilesToCreate = nil
	plan.Report.FilesToModify = nil
	classifyFiles(plan.Prepared, &plan.Report)
	plan.Report.normalize()
}

// EnsureModuleDirectory prepare les trois fichiers HCL d'un sous-module. Il
// ne cree jamais d'appel de module tant que le contenu reste vide.
func EnsureModuleDirectory(rootPath, moduleName string) error {
	if !validModuleName(moduleName) {
		return fmt.Errorf("nom de module non supporte : %s", moduleName)
	}
	modulePath := filepath.Join(rootPath, "modules", moduleName)
	prepared := make(map[string][]byte)
	for _, filename := range []string{"main.tf", "variables.tf", "outputs.tf"} {
		path := filepath.Join(modulePath, filename)
		content, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			prepared[path] = nil
			continue
		}
		if err != nil {
			return fmt.Errorf("impossible de lire %s : %w", path, err)
		}
		prepared[path] = content
	}
	return CommitPreparedFiles(prepared, []string{modulePath})
}

// PrepareRootModule construit en memoire une racine Terraform a partir des
// sous-modules canoniques. overlays permet d'inclure les changements d'une
// operation Create/Update/Delete dans la meme transaction.
func PrepareRootModule(
	rootPath string,
	provider string,
	overlays map[string][]byte,
) (Plan, error) {
	rootPath = filepath.Clean(rootPath)
	report := MigrationReport{Provider: provider, RootPath: rootPath}
	prepared := make(map[string][]byte)
	directories := []string{rootPath, filepath.Join(rootPath, "modules")}

	rootMain, err := loadFile(filepath.Join(rootPath, "main.tf"), overlays)
	if err != nil {
		return Plan{}, err
	}
	rootVariables, err := loadFile(filepath.Join(rootPath, "variables.tf"), overlays)
	if err != nil {
		return Plan{}, err
	}
	rootTfvars, err := loadFile(filepath.Join(rootPath, "terraform.tfvars"), overlays)
	if err != nil {
		return Plan{}, err
	}
	rootOutputs, err := loadFile(filepath.Join(rootPath, "outputs.tf"), overlays)
	if err != nil {
		return Plan{}, err
	}

	infos := make(map[string]*moduleInfo)
	for _, moduleName := range ModuleNames {
		modulePath := filepath.Join(rootPath, "modules", moduleName)
		directories = append(directories, modulePath)
		info, loadErr := loadModuleInfo(moduleName, modulePath, overlays)
		if loadErr != nil {
			return Plan{}, loadErr
		}
		infos[moduleName] = info
		prepared[filepath.Join(modulePath, "main.tf")] = formatted(info.main)
		prepared[filepath.Join(modulePath, "variables.tf")] = formatted(info.variables)
		prepared[filepath.Join(modulePath, "outputs.tf")] = formatted(info.outputs)
	}

	dependencies := detectNetworkDependencies(provider, infos, &report)
	report.Dependencies = append(report.Dependencies, detectInternalDependencies(infos)...)

	rootVariableOwners := make(map[string]string)
	rootOutputOwners := make(map[string]string)
	for _, moduleName := range ModuleNames {
		info := infos[moduleName]
		if !info.useful {
			continue
		}

		attributes := make(map[string]hcl.Traversal)
		variables := labeledBlocks(info.variables.Body(), "variable")
		for _, variable := range variables {
			name := variable.Labels()[0]
			variableAlreadyPresent := len(blocksByTypeAndLabel(
				rootVariables.Body(),
				"variable",
				name,
			)) == 1
			if owner, duplicate := rootVariableOwners[name]; duplicate && owner != moduleName {
				report.Conflicts = append(report.Conflicts,
					fmt.Sprintf("variable %s declaree par %s et %s", name, owner, moduleName))
				continue
			}
			rootVariableOwners[name] = moduleName
			if dependency, ok := dependencies[moduleName][name]; ok {
				attributes[name] = dependency
			} else {
				attributes[name] = VariableTraversal(name)
				if err := ensureClonedVariable(rootVariables, variable, name); err != nil {
					report.Conflicts = append(report.Conflicts, err.Error())
				} else if !variableAlreadyPresent {
					reportedName := moduleName + "." + name
					if isSensitiveName(name) {
						reportedName = moduleName + ".<nom masque>"
					}
					report.VariablesToMerge = append(report.VariablesToMerge, reportedName)
				}
			}
		}

		mergeTfvars(rootTfvars, info, dependencies[moduleName], &report)
		moduleAlreadyPresent := len(blocksByTypeAndLabel(
			rootMain.Body(),
			"module",
			moduleName,
		)) == 1
		if err := EnsureModuleBlock(
			rootMain,
			moduleName,
			"./modules/"+moduleName,
			attributes,
		); err != nil {
			report.Conflicts = append(report.Conflicts, err.Error())
		} else if !moduleAlreadyPresent {
			report.ModuleBlocksToAdd = append(report.ModuleBlocksToAdd, moduleName)
		}

		for _, output := range labeledBlocks(info.outputs.Body(), "output") {
			name := output.Labels()[0]
			outputAlreadyPresent := len(blocksByTypeAndLabel(
				rootOutputs.Body(),
				"output",
				name,
			)) == 1
			if owner, duplicate := rootOutputOwners[name]; duplicate && owner != moduleName {
				report.Conflicts = append(report.Conflicts,
					fmt.Sprintf("output %s declare par %s et %s", name, owner, moduleName))
				continue
			}
			rootOutputOwners[name] = moduleName
			if err := ensureRootOutput(rootOutputs, moduleName, name); err != nil {
				report.Conflicts = append(report.Conflicts, err.Error())
			} else if !outputAlreadyPresent {
				report.OutputsToAdd = append(report.OutputsToAdd, moduleName+"."+name)
			}
		}
	}

	prepared[filepath.Join(rootPath, "main.tf")] = formatted(rootMain)
	prepared[filepath.Join(rootPath, "variables.tf")] = formatted(rootVariables)
	prepared[filepath.Join(rootPath, "terraform.tfvars")] = formatted(rootTfvars)
	prepared[filepath.Join(rootPath, "outputs.tf")] = formatted(rootOutputs)

	if err := ValidatePreparedFiles(prepared); err != nil {
		return Plan{}, err
	}
	classifyFiles(prepared, &report)
	report.normalize()
	return Plan{Prepared: prepared, Directories: directories, Report: report}, nil
}

// AnalyzeMigration projette la phase B en memoire. Les fichiers historiques
// restent intacts et aucune valeur tfvars n'est incluse dans le rapport.
func AnalyzeMigration(
	rootPath string,
	provider string,
	baseOverlays map[string][]byte,
) (Plan, error) {
	overlays := cloneContents(baseOverlays)
	report := MigrationReport{Provider: provider, RootPath: filepath.Clean(rootPath)}
	for _, moduleName := range ModuleNames {
		legacyPath := filepath.Join(rootPath, moduleName)
		targetPath := filepath.Join(rootPath, "modules", moduleName)
		for _, filename := range []string{
			"main.tf", "variables.tf", "terraform.tfvars", "outputs.tf",
		} {
			sourcePath := filepath.Join(legacyPath, filename)
			content, err := os.ReadFile(sourcePath)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return Plan{}, fmt.Errorf("impossible de lire %s : %w", sourcePath, err)
			}
			target := filepath.Join(targetPath, filename)
			if existing, readErr := os.ReadFile(target); readErr == nil &&
				len(bytes.TrimSpace(existing)) > 0 &&
				!bytes.Equal(hclwrite.Format(existing), hclwrite.Format(content)) {
				report.Conflicts = append(report.Conflicts,
					fmt.Sprintf("%s et %s contiennent des configurations differentes", sourcePath, target))
				continue
			} else if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
				return Plan{}, readErr
			}
			overlays[target] = content
			report.FilesToMove = append(report.FilesToMove, sourcePath+" -> "+target)
		}
		collectLegacyInventory(legacyPath, moduleName, &report)
	}

	plan, err := PrepareRootModule(rootPath, provider, overlays)
	if err != nil {
		return Plan{}, err
	}
	plan.Report.FilesToMove = append(plan.Report.FilesToMove, report.FilesToMove...)
	plan.Report.ResourcesToMove = append(plan.Report.ResourcesToMove, report.ResourcesToMove...)
	plan.Report.Conflicts = append(plan.Report.Conflicts, report.Conflicts...)
	plan.Report.normalize()
	return plan, nil
}

func (report MigrationReport) HasConflicts() bool {
	return len(report.Conflicts) > 0
}

func (report MigrationReport) WriteTo(writer io.Writer) {
	fmt.Fprintf(writer, "Provider: %s\nRacine: %s\n", report.Provider, report.RootPath)
	writeReportSection(writer, "Fichiers a creer", report.FilesToCreate)
	writeReportSection(writer, "Fichiers a modifier", report.FilesToModify)
	writeReportSection(writer, "Fichiers a deplacer en phase B", report.FilesToMove)
	writeReportSection(writer, "Blocs module a ajouter", report.ModuleBlocksToAdd)
	writeReportSection(writer, "Ressources a deplacer", report.ResourcesToMove)
	writeReportSection(writer, "Variables a fusionner", report.VariablesToMerge)
	writeReportSection(writer, "Outputs a ajouter", report.OutputsToAdd)
	writeReportSection(writer, "Dependances detectees", report.Dependencies)
	writeReportSection(writer, "Valeurs ignorees", report.IgnoredValues)
	writeReportSection(writer, "Conflits", report.Conflicts)
}

func writeReportSection(writer io.Writer, title string, values []string) {
	fmt.Fprintf(writer, "%s (%d):\n", title, len(values))
	if len(values) == 0 {
		fmt.Fprintln(writer, "  - aucun")
		return
	}
	for _, value := range values {
		fmt.Fprintln(writer, "  - "+value)
	}
}

func loadModuleInfo(
	name string,
	path string,
	overlays map[string][]byte,
) (*moduleInfo, error) {
	mainFile, err := loadFile(filepath.Join(path, "main.tf"), overlays)
	if err != nil {
		return nil, err
	}
	variables, err := loadFile(filepath.Join(path, "variables.tf"), overlays)
	if err != nil {
		return nil, err
	}
	tfvars, err := loadFile(filepath.Join(path, "terraform.tfvars"), overlays)
	if err != nil {
		return nil, err
	}
	outputs, err := loadFile(filepath.Join(path, "outputs.tf"), overlays)
	if err != nil {
		return nil, err
	}
	return &moduleInfo{
		name: name, path: path, main: mainFile, variables: variables,
		tfvars: tfvars, outputs: outputs, useful: hasUsefulConfiguration(mainFile),
	}, nil
}

func loadFile(path string, overlays map[string][]byte) (*hclwrite.File, error) {
	path = filepath.Clean(path)
	content, present := overlays[path]
	if !present {
		var err error
		content, err = os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return hclwrite.NewEmptyFile(), nil
		}
		if err != nil {
			return nil, fmt.Errorf("impossible de lire %s : %w", path, err)
		}
	}
	if len(bytes.TrimSpace(content)) == 0 {
		return hclwrite.NewEmptyFile(), nil
	}
	file, diagnostics := hclwrite.ParseConfig(content, path, hcl.InitialPos)
	if diagnostics.HasErrors() {
		return nil, fmt.Errorf("HCL invalide dans %s : %s", path, diagnostics.Error())
	}
	return file, nil
}

func hasUsefulConfiguration(file *hclwrite.File) bool {
	for _, block := range file.Body().Blocks() {
		switch block.Type() {
		case "resource", "data", "module", "locals", "import", "moved":
			return true
		}
	}
	return false
}

func labeledBlocks(body *hclwrite.Body, blockType string) []*hclwrite.Block {
	var result []*hclwrite.Block
	for _, block := range body.Blocks() {
		if block.Type() == blockType && len(block.Labels()) == 1 {
			result = append(result, block)
		}
	}
	return result
}

func ensureClonedVariable(
	root *hclwrite.File,
	source *hclwrite.Block,
	name string,
) error {
	matches := blocksByTypeAndLabel(root.Body(), "variable", name)
	if len(matches) > 1 {
		return fmt.Errorf("variable racine %s dupliquee", name)
	}
	if len(matches) == 1 {
		if !bytes.Equal(variableType(matches[0]), variableType(source)) {
			return fmt.Errorf("type conflictuel pour la variable racine %s", name)
		}
		return nil
	}
	clone, err := cloneBlock(source)
	if err != nil {
		return err
	}
	appendBlock(root.Body(), clone)
	return nil
}

func variableType(block *hclwrite.Block) []byte {
	attribute := block.Body().GetAttribute("type")
	if attribute == nil {
		return nil
	}
	return normalizeExpression(attribute.Expr().BuildTokens(nil).Bytes())
}

func cloneBlock(source *hclwrite.Block) (*hclwrite.Block, error) {
	file, diagnostics := hclwrite.ParseConfig(
		source.BuildTokens(nil).Bytes(),
		"cloned-block.tf",
		hcl.InitialPos,
	)
	if diagnostics.HasErrors() || len(file.Body().Blocks()) != 1 {
		return nil, fmt.Errorf("impossible de cloner le bloc HCL")
	}
	return file.Body().Blocks()[0], nil
}

func mergeTfvars(
	root *hclwrite.File,
	info *moduleInfo,
	dependencies map[string]hcl.Traversal,
	report *MigrationReport,
) {
	declared := make(map[string]struct{})
	for _, block := range labeledBlocks(info.variables.Body(), "variable") {
		declared[block.Labels()[0]] = struct{}{}
	}
	for name, attribute := range info.tfvars.Body().Attributes() {
		qualified := info.name + "." + name
		if _, ok := declared[name]; !ok {
			report.IgnoredValues = append(report.IgnoredValues, qualified+" (variable non declaree)")
			continue
		}
		if _, wired := dependencies[name]; wired {
			report.IgnoredValues = append(report.IgnoredValues, qualified+" (remplacee par une dependance module)")
			continue
		}
		if isSensitiveName(name) {
			report.IgnoredValues = append(report.IgnoredValues,
				info.name+".<nom masque> (valeur potentiellement sensible)")
			continue
		}
		existing := root.Body().GetAttribute(name)
		value := attribute.Expr().BuildTokens(nil)
		if existing == nil {
			root.Body().SetAttributeRaw(name, value)
			continue
		}
		if !bytes.Equal(
			normalizeExpression(existing.Expr().BuildTokens(nil).Bytes()),
			normalizeExpression(value.Bytes()),
		) {
			report.Conflicts = append(report.Conflicts,
				"valeur terraform.tfvars conflictuelle pour "+name)
		}
	}
}

func ensureRootOutput(root *hclwrite.File, moduleName, outputName string) error {
	matches := blocksByTypeAndLabel(root.Body(), "output", outputName)
	expected := hclwrite.TokensForTraversal(
		ModuleOutputTraversal(moduleName, outputName),
	).Bytes()
	if len(matches) > 1 {
		return fmt.Errorf("output racine %s duplique", outputName)
	}
	if len(matches) == 1 {
		value := matches[0].Body().GetAttribute("value")
		if value == nil || !bytes.Equal(
			normalizeExpression(value.Expr().BuildTokens(nil).Bytes()),
			normalizeExpression(expected),
		) {
			return fmt.Errorf("output racine %s conflictuel", outputName)
		}
		return nil
	}
	block := hclwrite.NewBlock("output", []string{outputName})
	block.Body().SetAttributeTraversal(
		"value",
		ModuleOutputTraversal(moduleName, outputName),
	)
	appendBlock(root.Body(), block)
	return nil
}

func detectNetworkDependencies(
	provider string,
	infos map[string]*moduleInfo,
	report *MigrationReport,
) map[string]map[string]hcl.Traversal {
	result := make(map[string]map[string]hcl.Traversal)
	for _, name := range ModuleNames {
		result[name] = make(map[string]hcl.Traversal)
	}
	network := infos["network"]
	compute := infos["compute"]
	if network == nil || compute == nil || !network.useful || !compute.useful {
		return result
	}

	outputByAddress := make(map[string]string)
	for _, output := range labeledBlocks(network.outputs.Body(), "output") {
		value := output.Body().GetAttribute("value")
		if value == nil {
			continue
		}
		variables := value.Expr().Variables()
		if len(variables) == 1 {
			address := strings.TrimSpace(string(variables[0].BuildTokens(nil).Bytes()))
			outputByAddress[address] = output.Labels()[0]
		}
	}

	aliases := make(map[string][]string)
	for address, output := range outputByAddress {
		parts := strings.Split(address, ".")
		if len(parts) < 3 {
			continue
		}
		resourceType, label := parts[0], parts[1]
		if provider == "gcp" && resourceType != "google_compute_network" {
			continue
		}
		if provider == "oci" && resourceType != "oci_core_subnet" {
			continue
		}
		for _, alias := range []string{label, resourceType + "." + label, address} {
			aliases[alias] = append(aliases[alias], output)
		}
		if nameAttribute := network.tfvars.Body().GetAttribute(label + "_name"); nameAttribute != nil {
			if value, ok := literalString(nameAttribute); ok {
				aliases[value] = append(aliases[value], output)
			}
		}
	}

	for name, attribute := range compute.tfvars.Body().Attributes() {
		eligible := (provider == "gcp" && strings.HasSuffix(name, "_network")) ||
			(provider == "oci" && strings.HasSuffix(name, "_subnet_id"))
		if !eligible {
			continue
		}
		value, ok := literalString(attribute)
		if !ok {
			continue
		}
		matches := uniqueStrings(aliases[value])
		if len(matches) > 1 {
			report.Conflicts = append(report.Conflicts,
				"dependance reseau ambigue pour compute."+name)
			continue
		}
		if len(matches) == 1 {
			result["compute"][name] = ModuleOutputTraversal("network", matches[0])
			report.Dependencies = append(report.Dependencies,
				"compute."+name+" -> module.network."+matches[0])
		}
	}
	return result
}

func literalString(attribute *hclwrite.Attribute) (string, bool) {
	expression, diagnostics := hclsyntax.ParseExpression(
		bytes.TrimSpace(attribute.Expr().BuildTokens(nil).Bytes()),
		"terraform.tfvars",
		hcl.InitialPos,
	)
	if diagnostics.HasErrors() {
		return "", false
	}
	value, diagnostics := expression.Value(nil)
	if diagnostics.HasErrors() || !value.IsKnown() || value.IsNull() || value.Type() != cty.String {
		return "", false
	}
	return value.AsString(), true
}

func detectInternalDependencies(infos map[string]*moduleInfo) []string {
	var result []string
	for _, moduleName := range ModuleNames {
		info := infos[moduleName]
		known := make(map[string]struct{})
		for _, block := range info.main.Body().Blocks() {
			if block.Type() == "resource" && len(block.Labels()) == 2 {
				known[block.Labels()[0]+"."+block.Labels()[1]] = struct{}{}
			}
		}
		for _, block := range info.main.Body().Blocks() {
			if block.Type() != "resource" || len(block.Labels()) != 2 {
				continue
			}
			owner := block.Labels()[0] + "." + block.Labels()[1]
			for _, reference := range bodyTraversals(block.Body()) {
				parts := strings.Split(reference, ".")
				if len(parts) < 2 {
					continue
				}
				target := parts[0] + "." + parts[1]
				if _, ok := known[target]; ok && target != owner {
					result = append(result, moduleName+": "+owner+" -> "+target)
				}
			}
		}
	}
	return uniqueStrings(result)
}

func bodyTraversals(body *hclwrite.Body) []string {
	var result []string
	for _, attribute := range body.Attributes() {
		for _, traversal := range attribute.Expr().Variables() {
			result = append(result,
				strings.TrimSpace(string(traversal.BuildTokens(nil).Bytes())))
		}
	}
	for _, block := range body.Blocks() {
		result = append(result, bodyTraversals(block.Body())...)
	}
	return result
}

func collectLegacyInventory(path, moduleName string, report *MigrationReport) {
	mainFile, err := loadFile(filepath.Join(path, "main.tf"), nil)
	if err == nil {
		for _, block := range mainFile.Body().Blocks() {
			if block.Type() == "resource" && len(block.Labels()) == 2 {
				report.ResourcesToMove = append(report.ResourcesToMove,
					moduleName+":"+block.Labels()[0]+"."+block.Labels()[1])
			}
		}
	}
}

func classifyFiles(prepared map[string][]byte, report *MigrationReport) {
	for path, content := range prepared {
		existing, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			report.FilesToCreate = append(report.FilesToCreate, path)
			continue
		}
		if err == nil && !bytes.Equal(existing, content) {
			report.FilesToModify = append(report.FilesToModify, path)
		}
	}
}

func formatted(file *hclwrite.File) []byte {
	content := hclwrite.Format(file.Bytes())
	return append(bytes.TrimSpace(content), newlineIfNotEmpty(content)...)
}

func newlineIfNotEmpty(content []byte) []byte {
	if len(bytes.TrimSpace(content)) == 0 {
		return nil
	}
	return []byte{'\n'}
}

func cloneContents(source map[string][]byte) map[string][]byte {
	result := make(map[string][]byte, len(source))
	for path, content := range source {
		result[filepath.Clean(path)] = append([]byte(nil), content...)
	}
	return result
}

func validModuleName(name string) bool {
	for _, candidate := range ModuleNames {
		if name == candidate {
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func (report *MigrationReport) normalize() {
	report.FilesToCreate = uniqueStrings(report.FilesToCreate)
	report.FilesToModify = uniqueStrings(report.FilesToModify)
	report.FilesToMove = uniqueStrings(report.FilesToMove)
	report.ModuleBlocksToAdd = uniqueStrings(report.ModuleBlocksToAdd)
	report.ResourcesToMove = uniqueStrings(report.ResourcesToMove)
	report.VariablesToMerge = uniqueStrings(report.VariablesToMerge)
	report.OutputsToAdd = uniqueStrings(report.OutputsToAdd)
	report.Dependencies = uniqueStrings(report.Dependencies)
	report.IgnoredValues = uniqueStrings(report.IgnoredValues)
	report.Conflicts = uniqueStrings(report.Conflicts)
}
