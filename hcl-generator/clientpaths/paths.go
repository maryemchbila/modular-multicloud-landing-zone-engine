package clientpaths

import (
	"fmt"
	"path/filepath"
	"strings"

	"hcl-generator/clientcontext"
)

var validProviders = map[string]struct{}{"gcp": {}, "oci": {}}
var validModules = map[string]struct{}{
	"compute": {}, "network": {}, "storage": {}, "iam": {},
}

var clientAwareRoutes = map[string]struct{}{
	"gcp/compute/create": {},
	"gcp/compute/update": {},
	"gcp/compute/delete": {},
	"gcp/iam/create":     {},
	"gcp/iam/update":     {},
	"gcp/iam/delete":     {},
	"gcp/network/create": {},
	"gcp/network/update": {},
	"gcp/network/delete": {},
	"gcp/storage/create": {},
	"gcp/storage/update": {},
	"gcp/storage/delete": {},
	"oci/compute/create": {},
	"oci/compute/update": {},
	"oci/compute/delete": {},
	"oci/iam/create":     {},
	"oci/iam/update":     {},
	"oci/iam/delete":     {},
	"oci/network/create": {},
	"oci/network/update": {},
	"oci/network/delete": {},
	"oci/storage/create": {},
	"oci/storage/update": {},
	"oci/storage/delete": {},
}

type Layout struct {
	RuntimeRoot  string
	ProviderRoot string
	ModulesRoot  string
	ModulePath   string
}

func IsClientAwareRoute(provider, module, action string) bool {
	_, enabled := clientAwareRoutes[provider+"/"+module+"/"+action]
	return enabled
}

func ProjectRootFromWorkingDirectory(workingDirectory string) (string, error) {
	current, err := filepath.Abs(workingDirectory)
	if err != nil {
		return "", fmt.Errorf("repertoire de travail invalide : %w", err)
	}
	for {
		if filepath.Base(current) == "hcl-generator" {
			return filepath.Dir(current), nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf(
				"racine hcl-generator introuvable depuis %s",
				workingDirectory,
			)
		}
		current = parent
	}
}

func BuildClientRoot(
	projectRoot, clientID, environment, provider string,
) (string, error) {
	if err := clientcontext.Validate(clientID, environment); err != nil {
		return "", err
	}
	if _, valid := validProviders[provider]; !valid {
		return "", fmt.Errorf("provider invalide : %q", provider)
	}
	runtimeRoot, err := filepath.Abs(
		filepath.Join(projectRoot, "runtime", "clients"),
	)
	if err != nil {
		return "", fmt.Errorf("racine runtime invalide : %w", err)
	}
	providerRoot := filepath.Join(runtimeRoot, clientID, environment, provider)
	if err := ensureStrictlyUnder(runtimeRoot, providerRoot); err != nil {
		return "", err
	}
	return providerRoot, nil
}

func BuildClientModulePath(
	projectRoot, clientID, environment, provider, module string,
) (Layout, error) {
	providerRoot, err := BuildClientRoot(
		projectRoot, clientID, environment, provider,
	)
	if err != nil {
		return Layout{}, err
	}
	if _, valid := validModules[module]; !valid {
		return Layout{}, fmt.Errorf("module invalide : %q", module)
	}
	runtimeRoot := filepath.Join(projectRoot, "runtime", "clients")
	modulePath := filepath.Join(providerRoot, "modules", module)
	if err := ensureStrictlyUnder(runtimeRoot, modulePath); err != nil {
		return Layout{}, err
	}
	return Layout{
		RuntimeRoot:  filepath.Clean(runtimeRoot),
		ProviderRoot: providerRoot,
		ModulesRoot:  filepath.Join(providerRoot, "modules"),
		ModulePath:   modulePath,
	}, nil
}

func ensureStrictlyUnder(root, candidate string) error {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	absoluteCandidate, err := filepath.Abs(candidate)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(absoluteRoot, absoluteCandidate)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf(
			"chemin %s hors de runtime/clients : %s",
			candidate,
			absoluteRoot,
		)
	}
	return nil
}
