package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	gcproot "hcl-generator/generator/gcp/rootmodule"
	ociroot "hcl-generator/generator/oci/rootmodule"
)

func main() {
	output := flag.String(
		"output",
		"generated",
		"repertoire generated contenant les racines gcp et oci",
	)
	flag.Parse()

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
	fmt.Printf("racines canoniques preparees dans %s\n", *output)
}
