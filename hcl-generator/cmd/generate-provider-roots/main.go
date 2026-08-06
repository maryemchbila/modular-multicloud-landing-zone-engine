package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	commonroot "hcl-generator/generator/common/rootmodule"
	gcproot "hcl-generator/generator/gcp/rootmodule"
	ociroot "hcl-generator/generator/oci/rootmodule"
)

func main() {
	output := flag.String(
		"output",
		"generated",
		"repertoire generated contenant les racines gcp et oci",
	)
	dryRun := flag.Bool(
		"dry-run",
		false,
		"analyse la migration sans modifier aucun fichier ni repertoire",
	)
	migrateFiltered := flag.Bool(
		"migrate-filtered",
		false,
		"applique atomiquement la migration filtree de phase B",
	)
	flag.Parse()
	if *dryRun && *migrateFiltered {
		fmt.Fprintln(os.Stderr, "--dry-run et --migrate-filtered sont incompatibles")
		os.Exit(2)
	}
	if *dryRun {
		if err := printDryRun(*output); err != nil {
			fmt.Fprintf(os.Stderr, "dry-run impossible : %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *migrateFiltered {
		if err := applyFilteredMigration(*output); err != nil {
			fmt.Fprintf(os.Stderr, "migration filtree impossible : %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := gcproot.EnsureGCPRootModule(
		filepath.Join(*output, "gcp"),
	); err != nil {
		fmt.Fprintf(os.Stderr, "generation de la racine GCP impossible : %v\n", err)
		os.Exit(1)
	}
	if err := ociroot.EnsureOCIRootModule(
		filepath.Join(*output, "oci"),
	); err != nil {
		fmt.Fprintf(os.Stderr, "generation de la racine OCI impossible : %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("phase A preparee dans %s ; aucune ressource historique deplacee\n", *output)
}

func applyFilteredMigration(output string) error {
	gcpPlan, err := gcproot.PrepareGCPFilteredMigration(filepath.Join(output, "gcp"))
	if err != nil {
		return err
	}
	ociPlan, err := ociroot.PrepareOCIFilteredMigration(filepath.Join(output, "oci"))
	if err != nil {
		return err
	}
	if gcpPlan.Report.HasConflicts() || ociPlan.Report.HasConflicts() {
		return fmt.Errorf(
			"conflits detectes avant ecriture: GCP=%v OCI=%v",
			gcpPlan.Report.Conflicts,
			ociPlan.Report.Conflicts,
		)
	}
	if err := validateFilteredCounts(gcpPlan, 12, 32, 18); err != nil {
		return fmt.Errorf("projection GCP refusee: %w", err)
	}
	if err := validateFilteredCounts(ociPlan, 5, 18, 8); err != nil {
		return fmt.Errorf("projection OCI refusee: %w", err)
	}
	prepared := make(map[string][]byte, len(gcpPlan.Prepared)+len(ociPlan.Prepared))
	for path, content := range gcpPlan.Prepared {
		prepared[path] = content
	}
	for path, content := range ociPlan.Prepared {
		prepared[path] = content
	}
	directories := append(append([]string(nil), gcpPlan.Directories...), ociPlan.Directories...)
	if err := commonroot.CommitPreparedFiles(prepared, directories); err != nil {
		return err
	}
	fmt.Println("=== GCP MIGRATION FILTREE ===")
	gcpPlan.Report.WriteTo(os.Stdout)
	fmt.Println("\n=== OCI MIGRATION FILTREE ===")
	ociPlan.Report.WriteTo(os.Stdout)
	return nil
}

func validateFilteredCounts(
	plan commonroot.Plan,
	resources int,
	variables int,
	outputs int,
) error {
	resourcesToMove := len(plan.Report.ResourcesToMove)
	if (resourcesToMove != resources && resourcesToMove != 0) ||
		len(plan.Report.VariablesToMerge) != variables ||
		len(plan.Report.OutputsToAdd) != outputs {
		return fmt.Errorf(
			"comptages inattendus: ressources=%d variables=%d outputs=%d",
			resourcesToMove,
			len(plan.Report.VariablesToMerge),
			len(plan.Report.OutputsToAdd),
		)
	}
	return nil
}

func printDryRun(output string) error {
	plans := []struct {
		name string
		plan func(string) error
	}{
		{
			name: "GCP",
			plan: func(path string) error {
				plan, err := gcproot.AnalyzeGCPMigration(path)
				if err != nil {
					return err
				}
				plan.Report.WriteTo(os.Stdout)
				return nil
			},
		},
		{
			name: "OCI",
			plan: func(path string) error {
				plan, err := ociroot.AnalyzeOCIMigration(path)
				if err != nil {
					return err
				}
				plan.Report.WriteTo(os.Stdout)
				return nil
			},
		},
	}
	for index, candidate := range plans {
		if index > 0 {
			fmt.Println()
		}
		fmt.Printf("=== %s DRY-RUN ===\n", candidate.name)
		if err := candidate.plan(
			filepath.Join(output, strings.ToLower(candidate.name)),
		); err != nil {
			return err
		}
	}
	return nil
}
