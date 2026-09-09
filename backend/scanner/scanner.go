package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LeirBaGMC/sql-scanner/database"
)

const responseLimit = 1048576

type requestResult struct {
	StatusCode int
	DurationMS uint64
	Body       string
}

type vulnerableResponse struct {
	SecurityMode  string `json:"security_mode"`
	ReceivedInput string `json:"received_input"`
	ExecutedQuery string `json:"executed_query"`
	Risk          string `json:"risk"`
}

func RunScan(scanID string, targetURL string) {
	log.Printf(
		"Iniciando escaneo %s para el objetivo %s",
		scanID,
		targetURL,
	)

	if err := updateScanStatus(
		scanID,
		"RUNNING",
		"",
		true,
		false,
	); err != nil {
		log.Printf(
			"No se pudo iniciar el escaneo %s: %v",
			scanID,
			err,
		)
		return
	}

	if err := createScanEvent(
		scanID,
		"SCAN_STARTED",
		"El motor de escaneo inicio el analisis",
	); err != nil {
		log.Printf(
			"No se pudo registrar el evento inicial: %v",
			err,
		)
	}

	client := http.Client{
		Timeout: time.Duration(10_000_000_000),
	}

	baseline, err := performRequest(
		client,
		targetURL,
	)

	if err != nil {
		failScan(
			scanID,
			fmt.Sprintf(
				"No se pudo consultar el objetivo: %v",
				err,
			),
		)
		return
	}

	if err := createScanEvent(
		scanID,
		"BASELINE_COMPLETED",
		fmt.Sprintf(
			"Respuesta base recibida en %d ms con estado HTTP %d",
			baseline.DurationMS,
			baseline.StatusCode,
		),
	); err != nil {
		log.Printf(
			"No se pudo registrar la respuesta base: %v",
			err,
		)
	}

	parsedTarget, err := url.Parse(targetURL)
	if err != nil {
		failScan(
			scanID,
			"El objetivo autorizado contiene una URL invalida",
		)
		return
	}

	parameterName := "id"
	queryValues := parsedTarget.Query()

	if queryValues.Has(parameterName) {
		queryValues.Set(
			parameterName,
			"1 OR 1=1",
		)

		parsedTarget.RawQuery = queryValues.Encode()
	}

	testedURL := parsedTarget.String()

	probe, err := performRequest(
		client,
		testedURL,
	)

	if err != nil {
		failScan(
			scanID,
			fmt.Sprintf(
				"No se pudo completar la prueba controlada: %v",
				err,
			),
		)
		return
	}

	baselineProducts := strings.Count(
		baseline.Body,
		`"id":`,
	)

	probeProducts := strings.Count(
		probe.Body,
		`"id":`,
	)

	var responseMetadata vulnerableResponse

	metadataAvailable := json.Unmarshal(
		[]byte(probe.Body),
		&responseMetadata,
	) == nil

	isUnsafeMode := metadataAvailable &&
		responseMetadata.SecurityMode == "unsafe_concatenation"

	resultExpanded := probeProducts > baselineProducts

	if isUnsafeMode || resultExpanded {
		evidence := fmt.Sprintf(
			"Modo=%s; entrada=%s; resultados_base=%d; resultados_prueba=%d; consulta=%s",
			responseMetadata.SecurityMode,
			responseMetadata.ReceivedInput,
			baselineProducts,
			probeProducts,
			responseMetadata.ExecutedQuery,
		)

		err = createFinding(
			scanID,
			"SQL_INJECTION",
			"HIGH",
			"HIGH",
			testedURL,
			parameterName,
			evidence,
			baseline.DurationMS,
			probe.DurationMS,
			probe.StatusCode,
		)

		if err != nil {
			failScan(
				scanID,
				fmt.Sprintf(
					"No se pudo guardar el hallazgo: %v",
					err,
				),
			)
			return
		}

		if err := createScanEvent(
			scanID,
			"FINDING_CREATED",
			"Se detecto concatenacion insegura de entrada en una consulta SQL",
		); err != nil {
			log.Printf(
				"No se pudo registrar el hallazgo como evento: %v",
				err,
			)
		}
	} else {
		if err := createScanEvent(
			scanID,
			"NO_FINDING",
			"La prueba controlada no modifico la estructura ni el resultado esperado",
		); err != nil {
			log.Printf(
				"No se pudo registrar el resultado sin hallazgos: %v",
				err,
			)
		}
	}

	if err := updateScanStatus(
		scanID,
		"COMPLETED",
		"",
		false,
		true,
	); err != nil {
		log.Printf(
			"No se pudo completar el escaneo %s: %v",
			scanID,
			err,
		)
		return
	}

	if err := createScanEvent(
		scanID,
		"SCAN_COMPLETED",
		"El motor finalizo el escaneo correctamente",
	); err != nil {
		log.Printf(
			"No se pudo registrar el evento final: %v",
			err,
		)
	}

	log.Printf(
		"Escaneo %s completado",
		scanID,
	)
}

func performRequest(
	client http.Client,
	targetURL string,
) (requestResult, error) {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(10_000_000_000),
	)
	defer cancel()

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		targetURL,
		nil,
	)

	if err != nil {
		return requestResult{}, err
	}

	request.Header.Set(
		"User-Agent",
		"SQLi-Workshop-Scanner",
	)

	startedAt := time.Now()

	response, err := client.Do(request)
	if err != nil {
		return requestResult{}, err
	}
	defer response.Body.Close()

	duration := time.Since(startedAt)

	bodyBytes, err := io.ReadAll(
		io.LimitReader(
			response.Body,
			responseLimit,
		),
	)

	if err != nil {
		return requestResult{}, err
	}

	return requestResult{
		StatusCode: response.StatusCode,
		DurationMS: uint64(duration.Milliseconds()),
		Body:       string(bodyBytes),
	}, nil
}

func createFinding(
	scanID string,
	category string,
	severity string,
	confidence string,
	testedURL string,
	parameterName string,
	evidence string,
	baselineMS uint64,
	observedMS uint64,
	httpStatus int,
) error {
	const query = `
		INSERT INTO findings (
			scan_id,
			category,
			severity,
			confidence,
			tested_url,
			parameter_name,
			evidence,
			baseline_ms,
			observed_ms,
			http_status
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := database.DB.Exec(
		query,
		scanID,
		category,
		severity,
		confidence,
		testedURL,
		parameterName,
		evidence,
		baselineMS,
		observedMS,
		httpStatus,
	)

	return err
}

func createScanEvent(
	scanID string,
	eventType string,
	message string,
) error {
	const query = `
		INSERT INTO scan_events (
			scan_id,
			event_type,
			message
		)
		VALUES (?, ?, ?)
	`

	_, err := database.DB.Exec(
		query,
		scanID,
		eventType,
		message,
	)

	return err
}

func updateScanStatus(
	scanID string,
	status string,
	errorMessage string,
	setStartedAt bool,
	setCompletedAt bool,
) error {
	var query string

	switch {
	case setStartedAt:
		query = `
			UPDATE scans
			SET
				status = ?,
				error_message = NULL,
				started_at = CURRENT_TIMESTAMP
			WHERE id = ?
		`

		_, err := database.DB.Exec(
			query,
			status,
			scanID,
		)

		return err

	case setCompletedAt:
		query = `
			UPDATE scans
			SET
				status = ?,
				error_message = NULL,
				completed_at = CURRENT_TIMESTAMP
			WHERE id = ?
		`

		_, err := database.DB.Exec(
			query,
			status,
			scanID,
		)

		return err

	default:
		query = `
			UPDATE scans
			SET
				status = ?,
				error_message = ?
			WHERE id = ?
		`

		_, err := database.DB.Exec(
			query,
			status,
			errorMessage,
			scanID,
		)

		return err
	}
}

func failScan(
	scanID string,
	message string,
) {
	log.Printf(
		"El escaneo %s fallo: %s",
		scanID,
		message,
	)

	const query = `
		UPDATE scans
		SET
			status = ?,
			error_message = ?,
			completed_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`

	if _, err := database.DB.Exec(
		query,
		"FAILED",
		message,
		scanID,
	); err != nil {
		log.Printf(
			"No se pudo marcar el escaneo como fallido: %v",
			err,
		)
	}

	if err := createScanEvent(
		scanID,
		"SCAN_FAILED",
		message,
	); err != nil {
		log.Printf(
			"No se pudo registrar el evento de fallo: %v",
			err,
		)
	}
}
