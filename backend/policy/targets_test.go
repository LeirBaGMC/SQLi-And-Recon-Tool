package policy

import (
	"os"
	"testing"
)

func TestValidateAuthorizedExternalTarget(t *testing.T) {
	err := os.Setenv(
		"ALLOWED_EXTERNAL_HOSTS",
		"testaspnet.vulnweb.com",
	)
	if err != nil {
		t.Fatalf(
			"no se pudo configurar el dominio de prueba: %v",
			err,
		)
	}

	request := TargetRequest{
		Mode:                   TargetModeAuthorizedURL,
		URL:                    "http://testaspnet.vulnweb.com/ReadNews.aspx?id=2",
		Parameter:              "id",
		AuthorizationConfirmed: true,
	}

	target, err := ValidateTarget(request)
	if err != nil {
		t.Fatalf(
			"se esperaba un objetivo autorizado: %v",
			err,
		)
	}

	if target.Host != "testaspnet.vulnweb.com" {
		t.Fatalf(
			"se obtuvo un dominio inesperado: %s",
			target.Host,
		)
	}

	if target.Parameter != "id" {
		t.Fatalf(
			"se obtuvo un parametro inesperado: %s",
			target.Parameter,
		)
	}
}

func TestRejectsUnauthorizedHost(t *testing.T) {
	err := os.Setenv(
		"ALLOWED_EXTERNAL_HOSTS",
		"testaspnet.vulnweb.com",
	)
	if err != nil {
		t.Fatalf(
			"no se pudo configurar el dominio de prueba: %v",
			err,
		)
	}

	request := TargetRequest{
		Mode:                   TargetModeAuthorizedURL,
		URL:                    "https://example.com/products?id=2",
		Parameter:              "id",
		AuthorizationConfirmed: true,
	}

	_, err = ValidateTarget(request)

	if err == nil {
		t.Fatal(
			"se esperaba rechazar el dominio no autorizado",
		)
	}
}

func TestRejectsMissingAuthorization(t *testing.T) {
	err := os.Setenv(
		"ALLOWED_EXTERNAL_HOSTS",
		"testaspnet.vulnweb.com",
	)
	if err != nil {
		t.Fatalf(
			"no se pudo configurar el dominio de prueba: %v",
			err,
		)
	}

	request := TargetRequest{
		Mode:                   TargetModeAuthorizedURL,
		URL:                    "http://testaspnet.vulnweb.com/ReadNews.aspx?id=2",
		Parameter:              "id",
		AuthorizationConfirmed: false,
	}

	_, err = ValidateTarget(request)

	if err == nil {
		t.Fatal(
			"se esperaba solicitar confirmacion de autorizacion",
		)
	}
}

func TestRejectsMissingParameter(t *testing.T) {
	err := os.Setenv(
		"ALLOWED_EXTERNAL_HOSTS",
		"testaspnet.vulnweb.com",
	)
	if err != nil {
		t.Fatalf(
			"no se pudo configurar el dominio de prueba: %v",
			err,
		)
	}

	request := TargetRequest{
		Mode:                   TargetModeAuthorizedURL,
		URL:                    "http://testaspnet.vulnweb.com/ReadNews.aspx",
		Parameter:              "id",
		AuthorizationConfirmed: true,
	}

	_, err = ValidateTarget(request)

	if err == nil {
		t.Fatal(
			"se esperaba rechazar una URL sin el parametro",
		)
	}
}
