package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	flag.Parse()
	if *dryRun {
		if err := printDryRun(*output); err != nil {
			fmt.Fprintf(os.Stderr, "dry-run impossible : %v\n", err)
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
