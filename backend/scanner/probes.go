package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/LeirBaGMC/sql-scanner/database"
	"github.com/LeirBaGMC/sql-scanner/models"
)

const (
	responseLimit  = 1048576
	requestTimeout = 10 * time.Second
)

type requestResult struct {
	StatusCode int
	DurationMS uint64
	Body       string
	FinalURL   string
}

func performRequest(client *http.Client, targetURL string) (requestResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return requestResult{}, err
	}

	req.Header.Set("User-Agent", "SQLi-Workshop-Scanner/2.0")

	startedAt := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return requestResult{}, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, responseLimit+1))
	if err != nil {
		return requestResult{}, err
	}
	if len(bodyBytes) > responseLimit {
		return requestResult{}, fmt.Errorf("la respuesta supera el limite de 1 MiB; no se compara contenido truncado")
	}

	return requestResult{
		StatusCode: resp.StatusCode,
		DurationMS: uint64(time.Since(startedAt).Milliseconds()),
		Body:       string(bodyBytes),
		FinalURL:   resp.Request.URL.String(),
	}, nil
}

func replaceQueryValue(rawURL, parameterName, newValue string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("no se pudo interpretar la URL: %w", err)
	}
	values := parsed.Query()
	if !values.Has(parameterName) {
		return "", fmt.Errorf("la URL no contiene el parametro seleccionado")
	}
	values.Set(parameterName, newValue)
	parsed.RawQuery = values.Encode()
	return parsed.String(), nil
}

func emitPayloadEvent(repo *database.Repository, scanID, eventType string, event models.PayloadExecutionEvent) {
	message, err := json.Marshal(event)
	if err != nil {
		return
	}
	repo.CreateEventWithoutInterrupting(scanID, eventType, string(message))
}
