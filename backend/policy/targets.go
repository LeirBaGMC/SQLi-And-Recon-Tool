package policy

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

const (
	TargetModeSandbox       = "sandbox" // Alias de compatibilidad para solicitudes anteriores.
	TargetModeDVWA          = "dvwa"
	TargetModeAuthorizedURL = "authorized_url"
)

type AuthorizedTarget struct {
	BasicAuth     *url.Userinfo `json:"-"`
	DVWALevel     string
	Mode          string
	Name          string
	URL           string
	Host          string
	Parameter     string
	OriginalValue string
}

type TargetRequest struct {
	DVWALevel              string
	Mode                   string
	Target                 string
	URL                    string
	AuthorizationConfirmed bool
}

var sandboxTargets = map[string]AuthorizedTarget{
	"dvwa": {
		Mode:          TargetModeDVWA,
		Name:          "DVWA · SQL Injection (Low)",
		URL:           "http://dvwa/vulnerabilities/sqli/?id=1&Submit=Submit",
		Host:          "dvwa",
		Parameter:     "id",
		OriginalValue: "1",
	},
}

func ValidateTarget(
	request TargetRequest,
) (AuthorizedTarget, error) {
	switch request.Mode {
	case TargetModeSandbox, TargetModeDVWA:
		target, err := validateSandboxTarget(request.Target)
		if err != nil {
			return AuthorizedTarget{}, err
		}
		level := strings.ToLower(strings.TrimSpace(request.DVWALevel))
		if level == "" {
			level = "low"
		}
		if level != "low" && level != "medium" {
			return AuthorizedTarget{}, fmt.Errorf("el laboratorio admite los niveles Low y Medium")
		}
		target.DVWALevel = level
		if level == "medium" {
			target.Name = "DVWA · SQL Injection (Medium)"
			target.URL = "http://dvwa/vulnerabilities/sqli/"
		}
		return target, nil

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

	if parsedURL.Fragment != "" {
		return AuthorizedTarget{}, fmt.Errorf(
			"la URL no debe contener fragmentos",
		)
	}

	host := normalizeHost(
		parsedURL.Hostname(),
	)

	parameterName, originalValue :=
		detectOptionalParameter(parsedURL)
	credentials := parsedURL.User
	parsedURL.User = nil

	return AuthorizedTarget{
		BasicAuth:     credentials,
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
