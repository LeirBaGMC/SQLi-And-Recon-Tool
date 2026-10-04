package policy

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
)

const (
	TargetModeSandbox       = "sandbox"
	TargetModeAuthorizedURL = "authorized_url"
)

type AuthorizedTarget struct {
	Mode          string
	Name          string
	URL           string
	Host          string
	Parameter     string
	OriginalValue string
}

type TargetRequest struct {
	Mode                   string
	Target                 string
	URL                    string
	AuthorizationConfirmed bool
}

var sandboxTargets = map[string]AuthorizedTarget{
	"vulnerable-app": {
		Mode:          TargetModeSandbox,
		Name:          "Aplicacion vulnerable",
		URL:           "http://vulnerable-app:8081/api/vulnerable/products?id=1",
		Host:          "vulnerable-app",
		Parameter:     "id",
		OriginalValue: "1",
	},
	"secure-app": {
		Mode:          TargetModeSandbox,
		Name:          "Aplicacion reparada",
		URL:           "http://secure-app:8081/api/secure/products/1",
		Host:          "secure-app",
		Parameter:     "id",
		OriginalValue: "1",
	},
}

func ValidateTarget(
	request TargetRequest,
) (AuthorizedTarget, error) {
	switch request.Mode {
	case TargetModeSandbox:
		return validateSandboxTarget(
			request.Target,
		)

	case TargetModeAuthorizedURL:
		return validateExternalTarget(
			request,
		)

	default:
		return AuthorizedTarget{}, fmt.Errorf(
			"el modo de objetivo no es valido",
		)
	}
}

func validateSandboxTarget(
	targetName string,
) (AuthorizedTarget, error) {
	targetName = strings.TrimSpace(
		targetName,
	)

	target, allowed := sandboxTargets[targetName]

	if !allowed {
		return AuthorizedTarget{}, fmt.Errorf(
			"el objetivo del sandbox no esta autorizado",
		)
	}

	return target, nil
}

func validateExternalTarget(
	request TargetRequest,
) (AuthorizedTarget, error) {
	if !request.AuthorizationConfirmed {
		return AuthorizedTarget{}, fmt.Errorf(
			"debes confirmar que tienes autorizacion para analizar el objetivo",
		)
	}

	rawURL := strings.TrimSpace(
		request.URL,
	)

	if rawURL == "" {
		return AuthorizedTarget{}, fmt.Errorf(
			"la URL del objetivo es obligatoria",
		)
	}

	if len(rawURL) > 2048 {
		return AuthorizedTarget{}, fmt.Errorf(
			"la URL supera el limite permitido",
		)
	}

	parsedURL, err := url.ParseRequestURI(
		rawURL,
	)
	if err != nil {
		return AuthorizedTarget{}, fmt.Errorf(
			"la URL proporcionada no es valida",
		)
	}

	if parsedURL.Scheme != "http" &&
		parsedURL.Scheme != "https" {
		return AuthorizedTarget{}, fmt.Errorf(
			"solo se permiten URLs con protocolo HTTP o HTTPS",
		)
	}

	if parsedURL.Hostname() == "" {
		return AuthorizedTarget{}, fmt.Errorf(
			"la URL no contiene un dominio valido",
		)
	}

	if parsedURL.User != nil {
		return AuthorizedTarget{}, fmt.Errorf(
			"no se permiten credenciales dentro de la URL",
		)
	}

	if parsedURL.Fragment != "" {
		return AuthorizedTarget{}, fmt.Errorf(
			"la URL no debe contener fragmentos",
		)
	}

	host := normalizeHost(
		parsedURL.Hostname(),
	)

	if net.ParseIP(host) != nil {
		return AuthorizedTarget{}, fmt.Errorf(
			"no se permiten direcciones IP como objetivo externo",
		)
	}

	if !isAllowedExternalHost(host) {
		return AuthorizedTarget{}, fmt.Errorf(
			"el dominio solicitado no esta admitido para este workshop",
		)
	}

	parameterName, originalValue :=
		detectOptionalParameter(parsedURL)

	return AuthorizedTarget{
		Mode:          TargetModeAuthorizedURL,
		Name:          "URL externa autorizada",
		URL:           parsedURL.String(),
		Host:          host,
		Parameter:     parameterName,
		OriginalValue: originalValue,
	}, nil
}

func detectOptionalParameter(
	parsedURL *url.URL,
) (string, string) {
	queryValues := parsedURL.Query()

	if len(queryValues) == 0 {
		return "", ""
	}

	parameterNames := make(
		[]string,
		0,
		len(queryValues),
	)

	for parameterName := range queryValues {
		parameterNames = append(
			parameterNames,
			parameterName,
		)
	}

	sort.Strings(parameterNames)

	for _, parameterName := range parameterNames {
		normalizedName := strings.TrimSpace(
			parameterName,
		)

		if normalizedName == "" {
			continue
		}

		if len(normalizedName) > 100 {
			continue
		}

		values := queryValues[parameterName]

		if len(values) == 0 {
			continue
		}

		originalValue := strings.TrimSpace(
			values[0],
		)

		if originalValue == "" {
			continue
		}

		if len(originalValue) > 500 {
			continue
		}

		return normalizedName, originalValue
	}

	return "", ""
}

func isAllowedExternalHost(
	host string,
) bool {
	allowedHosts :=
		loadAllowedExternalHosts()

	_, allowed := allowedHosts[host]

	return allowed
}

func loadAllowedExternalHosts() map[string]bool {
	result := make(map[string]bool)

	configuredHosts := os.Getenv(
		"ALLOWED_EXTERNAL_HOSTS",
	)

	hostEntries := strings.Split(
		configuredHosts,
		",",
	)

	for _, configuredHost := range hostEntries {
		normalizedHost := normalizeHost(
			configuredHost,
		)

		if normalizedHost == "" {
			continue
		}

		if strings.Contains(
			normalizedHost,
			"://",
		) {
			continue
		}

		if strings.Contains(
			normalizedHost,
			"/",
		) {
			continue
		}

		if net.ParseIP(normalizedHost) != nil {
			continue
		}

		result[normalizedHost] = true
	}

	return result
}

func normalizeHost(
	host string,
) string {
	normalizedHost := strings.ToLower(
		strings.TrimSpace(host),
	)

	return strings.TrimSuffix(
		normalizedHost,
		".",
	)
}
