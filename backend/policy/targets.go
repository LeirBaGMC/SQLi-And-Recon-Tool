package policy

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

const (
	TargetModeSandbox       = "sandbox"
	TargetModeAuthorizedURL = "authorized_url"
)

type AuthorizedTarget struct {
	Mode      string
	Name      string
	URL       string
	Host      string
	Parameter string
}

type TargetRequest struct {
	Mode                   string
	Target                 string
	URL                    string
	Parameter              string
	AuthorizationConfirmed bool
}

var sandboxTargets = map[string]AuthorizedTarget{
	"vulnerable-app": {
		Mode:      TargetModeSandbox,
		Name:      "Aplicacion vulnerable",
		URL:       "http://vulnerable-app:8081/api/vulnerable/products?id=1",
		Host:      "vulnerable-app",
		Parameter: "id",
	},
	"secure-app": {
		Mode:      TargetModeSandbox,
		Name:      "Aplicacion reparada",
		URL:       "http://secure-app:8081/api/secure/products/1",
		Host:      "secure-app",
		Parameter: "id",
	},
}

func ValidateTarget(request TargetRequest) (AuthorizedTarget, error) {
	switch request.Mode {
	case TargetModeSandbox:
		return validateSandboxTarget(request.Target)

	case TargetModeAuthorizedURL:
		return validateExternalTarget(request)

	default:
		return AuthorizedTarget{}, fmt.Errorf(
			"el modo de objetivo no es valido",
		)
	}
}

func validateSandboxTarget(
	targetName string,
) (AuthorizedTarget, error) {
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

	rawURL := strings.TrimSpace(request.URL)
	parameterName := strings.TrimSpace(request.Parameter)

	if rawURL == "" {
		return AuthorizedTarget{}, fmt.Errorf(
			"la URL del objetivo es obligatoria",
		)
	}

	if parameterName == "" {
		return AuthorizedTarget{}, fmt.Errorf(
			"el parametro que se analizara es obligatorio",
		)
	}

	parsedURL, err := url.ParseRequestURI(rawURL)
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

	host := strings.ToLower(
		strings.TrimSuffix(
			parsedURL.Hostname(),
			".",
		),
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

	queryValues := parsedURL.Query()

	if !queryValues.Has(parameterName) {
		return AuthorizedTarget{}, fmt.Errorf(
			"la URL no contiene el parametro indicado",
		)
	}

	parameterValue := strings.TrimSpace(
		queryValues.Get(parameterName),
	)

	if parameterValue == "" {
		return AuthorizedTarget{}, fmt.Errorf(
			"el parametro indicado no puede estar vacio",
		)
	}

	if len(parameterName) > 100 {
		return AuthorizedTarget{}, fmt.Errorf(
			"el nombre del parametro supera el limite permitido",
		)
	}

	if len(rawURL) > 2048 {
		return AuthorizedTarget{}, fmt.Errorf(
			"la URL supera el limite permitido",
		)
	}

	return AuthorizedTarget{
		Mode:      TargetModeAuthorizedURL,
		Name:      "URL externa autorizada",
		URL:       parsedURL.String(),
		Host:      host,
		Parameter: parameterName,
	}, nil
}

func isAllowedExternalHost(host string) bool {
	allowedHosts := loadAllowedExternalHosts()

	_, allowed := allowedHosts[host]

	return allowed
}

func loadAllowedExternalHosts() map[string]bool {
	result := make(map[string]bool)

	configuredHosts := os.Getenv(
		"ALLOWED_EXTERNAL_HOSTS",
	)

	for _, configuredHost := range strings.Split(
		configuredHosts,
		",",
	) {
		normalizedHost := strings.ToLower(
			strings.TrimSpace(configuredHost),
		)

		normalizedHost = strings.TrimSuffix(
			normalizedHost,
			".",
		)

		if normalizedHost == "" {
			continue
		}

		if strings.Contains(normalizedHost, "://") {
			continue
		}

		if strings.Contains(normalizedHost, "/") {
			continue
		}

		result[normalizedHost] = true
	}

	return result
}
