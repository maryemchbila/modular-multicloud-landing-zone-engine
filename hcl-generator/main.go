package main

import (
	"fmt"
	"os"
	"path/filepath"

	"hcl-generator/generator"
	"hcl-generator/models"
	"hcl-generator/validation"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println(
			"Usage : go run . request.json",
		)
		os.Exit(1)
	}

	requestPath := os.Args[1]

	fmt.Println("1. Lecture de la demande utilisateur...")

	request, err := models.LoadRequest(requestPath)
	if err != nil {
		exitWithError(
			"Erreur de lecture",
			err,
		)
	}

	fmt.Println("2. Validation de la demande...")

	if err := validation.ValidateRequest(request); err != nil {
		exitWithError(
			"Demande invalide",
			err,
		)
	}

	fmt.Println("3. Génération des fichiers Terraform...")

	if err := generator.GenerateAtomically(request); err != nil {
		exitWithError(
			"Échec de la génération",
			err,
		)
	}

	fmt.Println()
	if request.Action == "delete" &&
		request.Provider == "gcp" &&
		request.Module == "storage" {
		fmt.Println("Terraform code deleted locally. No cloud resource was destroyed.")
		fmt.Println()
	}
	fmt.Println("Génération terminée avec succès.")
	fmt.Println("Fichiers créés ou mis à jour :")
	fmt.Println(
		"-",
		filepath.Join(request.ModulePath, "main.tf"),
	)
	fmt.Println(
		"-",
		filepath.Join(request.ModulePath, "variables.tf"),
	)
	fmt.Println(
		"-",
		filepath.Join(request.ModulePath, "terraform.tfvars"),
	)
	fmt.Println(
		"-",
		filepath.Join(request.ModulePath, "outputs.tf"),
	)
}

func exitWithError(
	message string,
	err error,
) {
	fmt.Printf("%s : %v\n", message, err)
	os.Exit(1)
}
