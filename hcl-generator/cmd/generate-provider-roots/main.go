package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	gcproot "hcl-generator/generator/gcp/rootconfig"
	ocicroot "hcl-generator/generator/oci/rootconfig"
)

func main() {
	output := flag.String(
		"output",
		"generated",
		"repertoire generated contenant les racines gcp et oci",
	)
	flag.Parse()

	if err := gcproot.EnsureGCPRootConfiguration(
		filepath.Join(*output, "gcp"),
	); err != nil {
		fmt.Fprintf(os.Stderr, "generation de la racine GCP impossible : %v\n", err)
		os.Exit(1)
	}
	if err := ocicroot.EnsureOCIRootConfiguration(
		filepath.Join(*output, "oci"),
	); err != nil {
		fmt.Fprintf(os.Stderr, "generation de la racine OCI impossible : %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("fichiers racine GCP et OCI generes dans %s\n", *output)
}
