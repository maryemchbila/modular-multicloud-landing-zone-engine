package clientcontext

import (
	"fmt"
	"regexp"
)

var clientIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

var validEnvironments = map[string]struct{}{
	"dev":     {},
	"staging": {},
	"prod":    {},
}

func Validate(clientID, environment string) error {
	if !clientIDPattern.MatchString(clientID) {
		return fmt.Errorf("client_id invalide : %q", clientID)
	}
	if _, valid := validEnvironments[environment]; !valid {
		return fmt.Errorf(
			"environment invalide %q : seules dev, staging et prod sont supportees",
			environment,
		)
	}
	return nil
}
