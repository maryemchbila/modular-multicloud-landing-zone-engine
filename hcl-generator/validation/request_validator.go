package validation

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	commonroot "hcl-generator/generator/common/rootmodule"
	"hcl-generator/models"
)

var terraformIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)
var ociIAMIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var ociDNSLabel = regexp.MustCompile(`^[a-z][a-z0-9]{0,14}$`)

var validStorageClasses = map[string]struct{}{
	"STANDARD": {},
	"NEARLINE": {},
	"COLDLINE": {},
	"ARCHIVE":  {},
}

var validOCIStorageAccessTypes = map[string]struct{}{
	"NoPublicAccess":        {},
	"ObjectRead":            {},
	"ObjectReadWithoutList": {},
}

var validOCIStorageTiers = map[string]struct{}{
	"Standard": {},
	"Archive":  {},
}

var validOCIStorageVersioning = map[string]struct{}{
	"Enabled":  {},
	"Disabled": {},
}

func ValidateRequest(request *models.Request) error {
	if request == nil {
		return fmt.Errorf("la demande est vide")
	}

	if request.Action != "create" &&
		request.Action != "update" &&
		request.Action != "delete" {
		return fmt.Errorf(
			"action non supportee %q : seules create, update et delete sont reconnues",
			request.Action,
		)
	}

	if strings.TrimSpace(request.ModulePath) == "" {
		return fmt.Errorf("champ obligatoire manquant : module_path")
	}

	switch request.Provider {
	case "gcp":
		return validateGCPRequest(request)
	case "oci":
		return validateOCIRequest(request)
	default:
		return fmt.Errorf(
			"provider non supporte %q : seuls gcp et oci sont supportes",
			request.Provider,
		)
	}
}

func validateGCPRequest(request *models.Request) error {
	request.ProjectID = strings.TrimSpace(request.ProjectID)
	if request.ProjectID == "" {
		return fmt.Errorf("champ obligatoire manquant : project_id")
	}

	if request.Action == "update" &&
		request.Module != "compute" &&
		request.Module != "iam" &&
		request.Module != "network" &&
		request.Module != "storage" {
		return fmt.Errorf(
			"fonctionnalite non implementee : %s / %s / %s",
			request.Provider,
			request.Module,
			request.Action,
		)
	}

	if request.Action == "delete" &&
		request.Module != "compute" &&
		request.Module != "iam" &&
		request.Module != "network" &&
		request.Module != "storage" {
		return fmt.Errorf(
			"fonctionnalite non implementee : %s / %s / %s",
			request.Provider,
			request.Module,
			request.Action,
		)
	}

	if err := validateModulePath(request.ModulePath, "gcp", request.Module); err != nil {
		return err
	}

	switch request.Module {
	case "compute":
		return validateComputeRequest(request)
	case "network":
		return validateNetworkRequest(request)
	case "storage":
		return validateStorageRequest(request)
	case "iam":
		return validateIAMRequest(request)
	default:
		return fmt.Errorf(
			"module non supporte %q : seuls compute, network, storage et iam sont supportes",
			request.Module,
		)
	}
}

func validateOCIRequest(request *models.Request) error {
	if request.Module == "iam" {
		if request.Action != "create" &&
			request.Action != "update" &&
			request.Action != "delete" {
			return fmt.Errorf(
				"fonctionnalite non implementee : %s / %s / %s",
				request.Provider,
				request.Module,
				request.Action,
			)
		}
		if err := validateModulePath(
			request.ModulePath,
			"oci",
			"iam",
		); err != nil {
			return err
		}
		if request.Action == "delete" {
			return validateOCIIAMDeleteRequest(request)
		}
		return validateOCIIAMRequest(request)
	}

	if request.Module == "storage" {
		if request.Action != "create" &&
			request.Action != "update" &&
			request.Action != "delete" {
			return fmt.Errorf(
				"fonctionnalite non implementee : %s / %s / %s",
				request.Provider,
				request.Module,
				request.Action,
			)
		}
		if err := validateModulePath(
			request.ModulePath,
			"oci",
			"storage",
		); err != nil {
			return err
		}
		if request.Action == "delete" {
			return validateOCIStorageDeleteRequest(request)
		}
		return validateOCIStorageRequest(request)
	}

	if request.Module == "network" {
		if err := validateModulePath(
			request.ModulePath,
			"oci",
			"network",
		); err != nil {
			return err
		}
		switch request.Action {
		case "create", "update":
			return validateOCINetworkRequest(request)
		case "delete":
			return validateOCINetworkDeleteRequest(request)
		default:
			return fmt.Errorf(
				"fonctionnalite non implementee : %s / %s / %s",
				request.Provider,
				request.Module,
				request.Action,
			)
		}
	}

	if request.Module != "compute" ||
		(request.Action != "create" &&
			request.Action != "update" &&
			request.Action != "delete") {
		return fmt.Errorf(
			"fonctionnalite non implementee : %s / %s / %s",
			request.Provider,
			request.Module,
			request.Action,
		)
	}
	if err := validateModulePath(request.ModulePath, "oci", "compute"); err != nil {
		return err
	}

	resource := request.OCIComputeResource
	if resource == nil {
		return fmt.Errorf("ressource OCI compute manquante")
	}
	if request.Action == "delete" {
		if strings.TrimSpace(resource.ResourceName) == "" {
			return fmt.Errorf(
				"champ obligatoire manquant : resource.resource_name",
			)
		}
		if !terraformIdentifier.MatchString(resource.ResourceName) {
			return fmt.Errorf(
				"resource.resource_name n'est pas un identifiant Terraform valide : %q",
				resource.ResourceName,
			)
		}
		return nil
	}
	required := map[string]string{
		"resource.resource_name":       resource.ResourceName,
		"resource.display_name":        resource.DisplayName,
		"resource.availability_domain": resource.AvailabilityDomain,
		"resource.compartment_id":      resource.CompartmentID,
		"resource.shape":               resource.Shape,
		"resource.subnet_id":           resource.SubnetID,
		"resource.image_id":            resource.ImageID,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("champ obligatoire manquant : %s", field)
		}
	}
	if !terraformIdentifier.MatchString(resource.ResourceName) {
		return fmt.Errorf(
			"resource.resource_name n'est pas un identifiant Terraform valide : %q",
			resource.ResourceName,
		)
	}
	if !strings.HasPrefix(resource.CompartmentID, "ocid1.compartment.") {
		return fmt.Errorf(
			"resource.compartment_id doit commencer par ocid1.compartment.",
		)
	}
	if !strings.HasPrefix(resource.SubnetID, "ocid1.subnet.") {
		return fmt.Errorf(
			"resource.subnet_id doit commencer par ocid1.subnet.",
		)
	}
	if !strings.HasPrefix(resource.ImageID, "ocid1.image.") {
		return fmt.Errorf(
			"resource.image_id doit commencer par ocid1.image.",
		)
	}
	if resource.AssignPublicIP == nil {
		return fmt.Errorf(
			"champ obligatoire manquant : resource.assign_public_ip",
		)
	}
	return nil
}

func validateOCIIAMDeleteRequest(request *models.Request) error {
	resource := request.OCIIAMResource
	if resource == nil {
		return fmt.Errorf("ressource OCI IAM manquante")
	}

	identifiers := []struct {
		field string
		value string
	}{
		{"resource.user_resource_name", resource.UserResourceName},
		{"resource.group_resource_name", resource.GroupResourceName},
		{
			"resource.membership_resource_name",
			resource.MembershipResourceName,
		},
		{"resource.policy_resource_name", resource.PolicyResourceName},
	}
	seen := make(map[string]string, len(identifiers))
	for _, identifier := range identifiers {
		identifier.value = strings.TrimSpace(identifier.value)
		if identifier.value == "" {
			return fmt.Errorf(
				"champ obligatoire manquant : %s",
				identifier.field,
			)
		}
		if !ociIAMIdentifier.MatchString(identifier.value) {
			return fmt.Errorf(
				"%s n'est pas un identifiant Terraform OCI IAM valide : %q",
				identifier.field,
				identifier.value,
			)
		}
		if previous, duplicate := seen[identifier.value]; duplicate {
			return fmt.Errorf(
				"%s et %s doivent etre differents",
				previous,
				identifier.field,
			)
		}
		seen[identifier.value] = identifier.field
	}
	resource.UserResourceName = strings.TrimSpace(resource.UserResourceName)
	resource.GroupResourceName = strings.TrimSpace(resource.GroupResourceName)
	resource.MembershipResourceName = strings.TrimSpace(
		resource.MembershipResourceName,
	)
	resource.PolicyResourceName = strings.TrimSpace(
		resource.PolicyResourceName,
	)
	return nil
}

func validateOCIIAMRequest(request *models.Request) error {
	resource := request.OCIIAMResource
	if resource == nil {
		return fmt.Errorf("ressource OCI IAM manquante")
	}

	resource.TenancyOCID = strings.TrimSpace(resource.TenancyOCID)
	resource.UserResourceName = strings.TrimSpace(resource.UserResourceName)
	resource.UserName = strings.TrimSpace(resource.UserName)
	resource.UserDescription = strings.TrimSpace(resource.UserDescription)
	resource.GroupResourceName = strings.TrimSpace(resource.GroupResourceName)
	resource.GroupName = strings.TrimSpace(resource.GroupName)
	resource.GroupDescription = strings.TrimSpace(resource.GroupDescription)
	resource.MembershipResourceName = strings.TrimSpace(
		resource.MembershipResourceName,
	)
	resource.PolicyResourceName = strings.TrimSpace(
		resource.PolicyResourceName,
	)
	resource.PolicyName = strings.TrimSpace(resource.PolicyName)
	resource.PolicyDescription = strings.TrimSpace(
		resource.PolicyDescription,
	)
	resource.PolicyCompartmentID = strings.TrimSpace(
		resource.PolicyCompartmentID,
	)

	required := map[string]string{
		"resource.tenancy_ocid":             resource.TenancyOCID,
		"resource.user_resource_name":       resource.UserResourceName,
		"resource.user_name":                resource.UserName,
		"resource.user_description":         resource.UserDescription,
		"resource.group_resource_name":      resource.GroupResourceName,
		"resource.group_name":               resource.GroupName,
		"resource.group_description":        resource.GroupDescription,
		"resource.membership_resource_name": resource.MembershipResourceName,
		"resource.policy_resource_name":     resource.PolicyResourceName,
		"resource.policy_name":              resource.PolicyName,
		"resource.policy_description":       resource.PolicyDescription,
		"resource.policy_compartment_id":    resource.PolicyCompartmentID,
	}
	for field, value := range required {
		if value == "" {
			return fmt.Errorf("champ obligatoire manquant : %s", field)
		}
	}

	identifiers := []struct {
		field string
		value string
	}{
		{"resource.user_resource_name", resource.UserResourceName},
		{"resource.group_resource_name", resource.GroupResourceName},
		{
			"resource.membership_resource_name",
			resource.MembershipResourceName,
		},
		{"resource.policy_resource_name", resource.PolicyResourceName},
	}
	seen := make(map[string]string, len(identifiers))
	for _, identifier := range identifiers {
		if !ociIAMIdentifier.MatchString(identifier.value) {
			return fmt.Errorf(
				"%s n'est pas un identifiant Terraform OCI IAM valide : %q",
				identifier.field,
				identifier.value,
			)
		}
		if previous, duplicate := seen[identifier.value]; duplicate {
			return fmt.Errorf(
				"%s et %s doivent etre differents",
				previous,
				identifier.field,
			)
		}
		seen[identifier.value] = identifier.field
	}

	if !strings.HasPrefix(resource.TenancyOCID, "ocid1.tenancy.") {
		return fmt.Errorf(
			"Le Tenancy OCID doit commencer par ocid1.tenancy.",
		)
	}
	if !strings.HasPrefix(
		resource.PolicyCompartmentID,
		"ocid1.tenancy.",
	) && !strings.HasPrefix(
		resource.PolicyCompartmentID,
		"ocid1.compartment.",
	) {
		return fmt.Errorf(
			"resource.policy_compartment_id doit commencer par ocid1.tenancy. ou ocid1.compartment.",
		)
	}
	if len(resource.PolicyStatements) == 0 {
		return fmt.Errorf(
			"OCI IAM policy statements cannot be empty; must contain at least one value.",
		)
	}

	normalizedStatements := make([]string, 0, len(resource.PolicyStatements))
	statementSet := make(map[string]struct{}, len(resource.PolicyStatements))
	for _, rawStatement := range resource.PolicyStatements {
		statement := strings.TrimSpace(rawStatement)
		if statement == "" {
			return fmt.Errorf(
				"OCI IAM policy statements cannot contain empty values.",
			)
		}
		if _, duplicate := statementSet[statement]; duplicate {
			return fmt.Errorf(
				"OCI IAM policy statements cannot contain duplicates: %s",
				statement,
			)
		}
		statementSet[statement] = struct{}{}
		words := strings.Fields(statement)
		if len(words) == 0 || !strings.EqualFold(words[0], "Allow") {
			return fmt.Errorf(
				"OCI IAM policy statement must start with 'Allow': %s",
				statement,
			)
		}
		normalized := strings.ToLower(strings.Join(words, " "))
		if strings.HasPrefix(normalized, "allow any-user ") ||
			normalized == "allow any-user" {
			return fmt.Errorf(
				"OCI IAM policy using any-user is not allowed in the current security profile.",
			)
		}
		if strings.Contains(normalized, "manage all-resources") &&
			strings.Contains(normalized, "in tenancy") {
			return fmt.Errorf(
				"OCI IAM policy is too permissive and is blocked by the security policy: %s",
				statement,
			)
		}
		if len(words) < 3 ||
			!strings.EqualFold(words[1], "group") ||
			words[2] != resource.GroupName {
			return fmt.Errorf(
				"OCI IAM policy statement does not target the configured group: %s",
				resource.GroupName,
			)
		}
		normalizedStatements = append(normalizedStatements, statement)
	}
	resource.PolicyStatements = normalizedStatements
	return nil
}

func validateOCIStorageDeleteRequest(request *models.Request) error {
	resource := request.OCIStorageResource
	if resource == nil {
		return fmt.Errorf("ressource OCI storage manquante")
	}
	if strings.TrimSpace(resource.ResourceName) == "" {
		return fmt.Errorf(
			"champ obligatoire manquant : resource.resource_name",
		)
	}
	if !terraformIdentifier.MatchString(resource.ResourceName) {
		return fmt.Errorf(
			"resource.resource_name n'est pas un identifiant Terraform valide : %q",
			resource.ResourceName,
		)
	}
	return nil
}

func validateOCIStorageRequest(request *models.Request) error {
	resource := request.OCIStorageResource
	if resource == nil {
		return fmt.Errorf("ressource OCI storage manquante")
	}

	required := map[string]string{
		"resource.resource_name":  resource.ResourceName,
		"resource.compartment_id": resource.CompartmentID,
		"resource.namespace":      resource.Namespace,
		"resource.name":           resource.Name,
		"resource.access_type":    resource.AccessType,
		"resource.storage_tier":   resource.StorageTier,
		"resource.versioning":     resource.Versioning,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("champ obligatoire manquant : %s", field)
		}
	}
	if !terraformIdentifier.MatchString(resource.ResourceName) {
		return fmt.Errorf(
			"resource.resource_name n'est pas un identifiant Terraform valide : %q",
			resource.ResourceName,
		)
	}
	if !strings.HasPrefix(resource.CompartmentID, "ocid1.compartment.") {
		return fmt.Errorf(
			"resource.compartment_id doit commencer par ocid1.compartment.",
		)
	}
	if _, valid := validOCIStorageAccessTypes[resource.AccessType]; !valid {
		return fmt.Errorf(
			"resource.access_type doit valoir NoPublicAccess, ObjectRead ou ObjectReadWithoutList",
		)
	}
	if _, valid := validOCIStorageTiers[resource.StorageTier]; !valid {
		return fmt.Errorf(
			"resource.storage_tier doit valoir Standard ou Archive",
		)
	}
	if _, valid := validOCIStorageVersioning[resource.Versioning]; !valid {
		return fmt.Errorf(
			"resource.versioning doit valoir Enabled ou Disabled",
		)
	}
	if resource.ObjectEventsEnabled == nil {
		return fmt.Errorf(
			"champ obligatoire manquant : resource.object_events_enabled",
		)
	}
	return nil
}

func validateOCINetworkDeleteRequest(request *models.Request) error {
	resource := request.OCINetworkResource
	if resource == nil {
		return fmt.Errorf("ressource OCI network manquante")
	}

	identifiers := []struct {
		field string
		value string
	}{
		{"resource.resource_name", resource.ResourceName},
		{
			"resource.subnet_resource_name",
			resource.SubnetResourceName,
		},
		{
			"resource.internet_gateway_resource_name",
			resource.InternetGatewayResourceName,
		},
		{
			"resource.route_table_resource_name",
			resource.RouteTableResourceName,
		},
	}
	seen := make(map[string]string, len(identifiers))
	for _, identifier := range identifiers {
		if strings.TrimSpace(identifier.value) == "" {
			return fmt.Errorf(
				"champ obligatoire manquant : %s",
				identifier.field,
			)
		}
		if !terraformIdentifier.MatchString(identifier.value) {
			return fmt.Errorf(
				"%s n'est pas un identifiant Terraform valide : %q",
				identifier.field,
				identifier.value,
			)
		}
		if previous, duplicate := seen[identifier.value]; duplicate {
			return fmt.Errorf(
				"%s et %s doivent etre differents",
				previous,
				identifier.field,
			)
		}
		seen[identifier.value] = identifier.field
	}
	return nil
}

func validateOCINetworkRequest(request *models.Request) error {
	resource := request.OCINetworkResource
	if resource == nil {
		return fmt.Errorf("ressource OCI network manquante")
	}

	required := map[string]string{
		"resource.resource_name":                  resource.ResourceName,
		"resource.display_name":                   resource.DisplayName,
		"resource.compartment_id":                 resource.CompartmentID,
		"resource.vcn_cidr":                       resource.VCNCIDR,
		"resource.dns_label":                      resource.DNSLabel,
		"resource.subnet_resource_name":           resource.SubnetResourceName,
		"resource.subnet_display_name":            resource.SubnetDisplayName,
		"resource.subnet_cidr":                    resource.SubnetCIDR,
		"resource.subnet_dns_label":               resource.SubnetDNSLabel,
		"resource.availability_domain":            resource.AvailabilityDomain,
		"resource.internet_gateway_resource_name": resource.InternetGatewayResourceName,
		"resource.internet_gateway_display_name":  resource.InternetGatewayDisplayName,
		"resource.route_table_resource_name":      resource.RouteTableResourceName,
		"resource.route_table_display_name":       resource.RouteTableDisplayName,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("champ obligatoire manquant : %s", field)
		}
	}

	identifiers := map[string]string{
		"resource.resource_name":                  resource.ResourceName,
		"resource.subnet_resource_name":           resource.SubnetResourceName,
		"resource.internet_gateway_resource_name": resource.InternetGatewayResourceName,
		"resource.route_table_resource_name":      resource.RouteTableResourceName,
	}
	seen := make(map[string]string, len(identifiers))
	for field, value := range identifiers {
		if !terraformIdentifier.MatchString(value) {
			return fmt.Errorf(
				"%s n'est pas un identifiant Terraform valide : %q",
				field,
				value,
			)
		}
		if previousField, duplicate := seen[value]; duplicate {
			return fmt.Errorf(
				"%s et %s doivent etre differents",
				previousField,
				field,
			)
		}
		seen[value] = field
	}

	if !strings.HasPrefix(resource.CompartmentID, "ocid1.compartment.") {
		return fmt.Errorf(
			"resource.compartment_id doit commencer par ocid1.compartment.",
		)
	}
	if resource.ProhibitPublicIPOnVNIC == nil {
		return fmt.Errorf(
			"champ obligatoire manquant : resource.prohibit_public_ip_on_vnic",
		)
	}
	for field, value := range map[string]string{
		"resource.dns_label":        resource.DNSLabel,
		"resource.subnet_dns_label": resource.SubnetDNSLabel,
	} {
		if !ociDNSLabel.MatchString(value) {
			return fmt.Errorf(
				"%s doit commencer par une lettre minuscule, contenir uniquement des lettres minuscules et des chiffres, et avoir au plus 15 caracteres",
				field,
			)
		}
	}

	vcnIP, vcnNetwork, err := net.ParseCIDR(resource.VCNCIDR)
	if err != nil ||
		vcnIP.To4() == nil ||
		!vcnIP.Equal(vcnNetwork.IP) {
		return fmt.Errorf(
			"resource.vcn_cidr n'est pas un CIDR IPv4 valide : %q",
			resource.VCNCIDR,
		)
	}
	subnetIP, subnetNetwork, err := net.ParseCIDR(resource.SubnetCIDR)
	if err != nil ||
		subnetIP.To4() == nil ||
		!subnetIP.Equal(subnetNetwork.IP) {
		return fmt.Errorf(
			"resource.subnet_cidr n'est pas un CIDR IPv4 valide : %q",
			resource.SubnetCIDR,
		)
	}
	if !vcnNetwork.Contains(subnetNetwork.IP) {
		return fmt.Errorf(
			"Le CIDR du subnet doit appartenir au CIDR du VCN.",
		)
	}
	vcnPrefix, _ := vcnNetwork.Mask.Size()
	subnetPrefix, _ := subnetNetwork.Mask.Size()
	if subnetPrefix <= vcnPrefix {
		return fmt.Errorf(
			"resource.subnet_cidr doit etre plus specifique que resource.vcn_cidr",
		)
	}

	return nil
}

func validateModulePath(
	modulePath string,
	provider string,
	module string,
) error {
	_, err := commonroot.ResolveModulePath(modulePath, provider, module)
	return err
}

func validateIAMRequest(request *models.Request) error {
	resource := request.IAMResource
	if resource == nil {
		return fmt.Errorf("ressource iam manquante")
	}

	if request.Action == "delete" {
		if strings.TrimSpace(resource.ResourceName) == "" {
			return fmt.Errorf(
				"champ obligatoire manquant : resource.resource_name",
			)
		}
		if !terraformIdentifier.MatchString(resource.ResourceName) {
			return fmt.Errorf(
				"resource.resource_name n'est pas un identifiant Terraform valide : %q",
				resource.ResourceName,
			)
		}
		return nil
	}
	resource.ProjectID = strings.TrimSpace(resource.ProjectID)

	required := map[string]string{
		"resource.resource_name": resource.ResourceName,
		"resource.account_id":    resource.AccountID,
		"resource.display_name":  resource.DisplayName,
		"resource.description":   resource.Description,
		"resource.project_id":    resource.ProjectID,
		"resource.role":          resource.Role,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("champ obligatoire manquant : %s", field)
		}
	}
	if resource.ProjectID != request.ProjectID {
		return fmt.Errorf(
			"resource.project_id doit correspondre au contexte GCP project_id",
		)
	}

	if !terraformIdentifier.MatchString(resource.ResourceName) {
		return fmt.Errorf(
			"resource.resource_name n'est pas un identifiant Terraform valide : %q",
			resource.ResourceName,
		)
	}

	resource.Role = strings.TrimSpace(resource.Role)
	if !strings.HasPrefix(resource.Role, "roles/") {
		return fmt.Errorf("Le rôle IAM doit commencer par roles/")
	}
	if resource.Role == "roles/owner" || resource.Role == "roles/editor" {
		return fmt.Errorf(
			"Rôle IAM trop permissif interdit par la politique de sécurité : %s",
			resource.Role,
		)
	}

	return nil
}

func validateComputeRequest(request *models.Request) error {
	resource := request.ComputeResource
	if resource == nil {
		return fmt.Errorf("ressource compute manquante")
	}

	if request.Action == "delete" {
		if strings.TrimSpace(resource.ResourceName) == "" {
			return fmt.Errorf(
				"champ obligatoire manquant : resource.resource_name",
			)
		}
		if !terraformIdentifier.MatchString(resource.ResourceName) {
			return fmt.Errorf(
				"resource.resource_name n'est pas un identifiant Terraform valide : %q",
				resource.ResourceName,
			)
		}
		return nil
	}

	required := map[string]string{
		"resource.resource_name": resource.ResourceName,
		"resource.name":          resource.Name,
		"resource.machine_type":  resource.MachineType,
		"resource.zone":          resource.Zone,
		"resource.image":         resource.Image,
		"resource.network":       resource.Network,
	}

	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("champ obligatoire manquant : %s", field)
		}
	}

	if !terraformIdentifier.MatchString(resource.ResourceName) {
		return fmt.Errorf(
			"resource.resource_name n'est pas un identifiant Terraform valide : %q",
			resource.ResourceName,
		)
	}

	return nil
}

func validateStorageRequest(request *models.Request) error {
	resource := request.StorageResource
	if resource == nil {
		return fmt.Errorf("ressource storage manquante")
	}

	if request.Action == "delete" {
		if strings.TrimSpace(resource.ResourceName) == "" {
			return fmt.Errorf(
				"champ obligatoire manquant : resource.resource_name",
			)
		}
		if !terraformIdentifier.MatchString(resource.ResourceName) {
			return fmt.Errorf(
				"resource.resource_name n'est pas un identifiant Terraform valide : %q",
				resource.ResourceName,
			)
		}
		return nil
	}

	required := map[string]string{
		"resource.resource_name": resource.ResourceName,
		"resource.name":          resource.Name,
		"resource.location":      resource.Location,
		"resource.storage_class": resource.StorageClass,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("champ obligatoire manquant : %s", field)
		}
	}

	if resource.UniformBucketLevelAccess == nil {
		return fmt.Errorf(
			"champ obligatoire manquant : resource.uniform_bucket_level_access",
		)
	}

	if !terraformIdentifier.MatchString(resource.ResourceName) {
		return fmt.Errorf(
			"resource.resource_name n'est pas un identifiant Terraform valide : %q",
			resource.ResourceName,
		)
	}

	resource.StorageClass = strings.ToUpper(
		strings.TrimSpace(resource.StorageClass),
	)
	if _, valid := validStorageClasses[resource.StorageClass]; !valid {
		return fmt.Errorf(
			"resource.storage_class n'est pas valide : %q (valeurs acceptees : STANDARD, NEARLINE, COLDLINE, ARCHIVE)",
			resource.StorageClass,
		)
	}

	return nil
}

func validateNetworkRequest(request *models.Request) error {
	resource := request.NetworkResource
	if resource == nil {
		return fmt.Errorf("resource network manquante")
	}

	if request.Action == "delete" {
		required := map[string]string{
			"resource.resource_name":        resource.ResourceName,
			"resource.subnet_resource_name": resource.SubnetResourceName,
		}
		for field, value := range required {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("champ obligatoire manquant : %s", field)
			}
			if !terraformIdentifier.MatchString(value) {
				return fmt.Errorf(
					"%s n'est pas un identifiant Terraform valide : %q",
					field,
					value,
				)
			}
		}
		if resource.ResourceName == resource.SubnetResourceName {
			return fmt.Errorf(
				"resource.resource_name et resource.subnet_resource_name doivent etre differents",
			)
		}
		return nil
	}

	required := map[string]string{
		"resource.resource_name":        resource.ResourceName,
		"resource.name":                 resource.Name,
		"resource.subnet_resource_name": resource.SubnetResourceName,
		"resource.subnet_name":          resource.SubnetName,
		"resource.cidr":                 resource.CIDR,
		"resource.region":               resource.Region,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("champ obligatoire manquant : %s", field)
		}
	}

	identifiers := map[string]string{
		"resource.resource_name":        resource.ResourceName,
		"resource.subnet_resource_name": resource.SubnetResourceName,
	}
	for field, value := range identifiers {
		if !terraformIdentifier.MatchString(value) {
			return fmt.Errorf(
				"%s n'est pas un identifiant Terraform valide : %q",
				field,
				value,
			)
		}
	}

	if resource.ResourceName == resource.SubnetResourceName {
		return fmt.Errorf(
			"resource.resource_name et resource.subnet_resource_name doivent etre differents",
		)
	}

	ip, network, err := net.ParseCIDR(resource.CIDR)
	if err != nil || ip.To4() == nil || !ip.Equal(network.IP) {
		return fmt.Errorf(
			"resource.cidr n'est pas un CIDR IPv4 valide : %q",
			resource.CIDR,
		)
	}

	return nil
}
