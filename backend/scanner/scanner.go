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

const (
	responseLimit      = 1048576
	requestTimeout     = 10 * time.Second
	sandboxMode        = "sandbox"
	authorizedURLMode  = "authorized_url"
	externalProbeValue = "2 AND 1=2"
)

type requestResult struct {
	StatusCode int
	DurationMS uint64
	Body       string
	FinalURL   string
}

type vulnerableResponse struct {
	SecurityMode  string `json:"security_mode"`
	ReceivedInput string `json:"received_input"`
	ExecutedQuery string `json:"executed_query"`
	Risk          string `json:"risk"`
}

func RunScan(
	scanID string,
	targetURL string,
	parameterName string,
	targetMode string,
) {
	log.Printf(
		"Iniciando escaneo %s para %s en modo %s",
		scanID,
		targetURL,
		targetMode,
	)

	err := updateScanStatus(
		scanID,
		"RUNNING",
		"",
		true,
		false,
	)
	if err != nil {
		log.Printf(
			"No se pudo actualizar el estado inicial: %v",
			err,
		)
		return
	}

	createEventWithoutInterrupting(
		scanID,
		"SCAN_STARTED",
		"El motor inicio el analisis controlado",
	)

	client := http.Client{
		Timeout: requestTimeout,
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

	createEventWithoutInterrupting(
		scanID,
		"BASELINE_COMPLETED",
		fmt.Sprintf(
			"Respuesta base recibida en %d ms con estado HTTP %d",
			baseline.DurationMS,
			baseline.StatusCode,
		),
	)

	switch targetMode {
	case authorizedURLMode:
		err = scanAuthorizedURL(
			client,
			scanID,
			targetURL,
			parameterName,
			baseline,
		)

	default:
		err = scanSandbox(
			client,
			scanID,
			targetURL,
			parameterName,
			baseline,
		)
	}

	if err != nil {
		failScan(scanID, err.Error())
		return
	}

	err = updateScanStatus(
		scanID,
		"COMPLETED",
		"",
		false,
		true,
	)
	if err != nil {
		log.Printf(
			"No se pudo completar el escaneo %s: %v",
			scanID,
			err,
		)
		return
	}

	createEventWithoutInterrupting(
		scanID,
		"SCAN_COMPLETED",
		"El motor finalizo el escaneo correctamente",
	)

	log.Printf(
		"Escaneo %s completado",
		scanID,
	)
}

func scanSandbox(
	client http.Client,
	scanID string,
	targetURL string,
	parameterName string,
	baseline requestResult,
) error {
	testedURL, err := replaceQueryValue(
		targetURL,
		parameterName,
		"1 OR 1=1",
	)
	if err != nil {
		return err
	}

	probe, err := performRequest(
		client,
		testedURL,
	)
	if err != nil {
		return fmt.Errorf(
			"no se pudo completar la prueba del sandbox: %w",
			err,
		)
	}

	baselineProducts := strings.Count(
		baseline.Body,
		`"id":`,
	)

	probeProducts := strings.Count(
		probe.Body,
		`"id":`,
	)

	var metadata vulnerableResponse

	metadataAvailable := json.Unmarshal(
		[]byte(probe.Body),
		&metadata,
	) == nil

	unsafeMode := metadataAvailable &&
		metadata.SecurityMode == "unsafe_concatenation"

	resultExpanded := probeProducts > baselineProducts

	if !unsafeMode && !resultExpanded {
		createEventWithoutInterrupting(
			scanID,
			"NO_FINDING",
			"La prueba del sandbox no modifico el resultado esperado",
		)

		return nil
	}

	evidence := fmt.Sprintf(
		"Modo=%s; entrada=%s; resultados_base=%d; resultados_prueba=%d; consulta=%s",
		metadata.SecurityMode,
		metadata.ReceivedInput,
		baselineProducts,
		probeProducts,
		metadata.ExecutedQuery,
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
		return fmt.Errorf(
			"no se pudo guardar el hallazgo: %w",
			err,
		)
	}

	createEventWithoutInterrupting(
		scanID,
		"FINDING_CREATED",
		"Se detecto concatenacion insegura en el sandbox",
	)

	return nil
}

func scanAuthorizedURL(
	client http.Client,
	scanID string,
	targetURL string,
	parameterName string,
	baseline requestResult,
) error {
	falseConditionURL, err := replaceQueryValue(
		targetURL,
		parameterName,
		externalProbeValue,
	)
	if err != nil {
		return err
	}

	probe, err := performRequest(
		client,
		falseConditionURL,
	)
	if err != nil {
		return fmt.Errorf(
			"no se pudo completar la prueba externa: %w",
			err,
		)
	}

	if !sameHostname(targetURL, probe.FinalURL) {
		return fmt.Errorf(
			"el objetivo redirigio hacia un dominio diferente",
		)
	}

	errorSignature := detectSQLSignature(probe.Body)

	baselineLength := len(baseline.Body)
	probeLength := len(probe.Body)

	lengthDifference := absoluteDifference(
		baselineLength,
		probeLength,
	)

	differencePercentage := calculatePercentage(
		lengthDifference,
		baselineLength,
	)

	statusChanged := baseline.StatusCode != probe.StatusCode
	contentChanged := differencePercentage >= 20

	evidence := fmt.Sprintf(
		"Respuesta normal: HTTP %d, %d bytes, %d ms. Respuesta de prueba: HTTP %d, %d bytes, %d ms. Diferencia de contenido: %d por ciento. Firma SQL: %s",
		baseline.StatusCode,
		baselineLength,
		baseline.DurationMS,
		probe.StatusCode,
		probeLength,
		probe.DurationMS,
		differencePercentage,
		errorSignature,
	)

	if errorSignature != "" {
		err = createFinding(
			scanID,
			"POSSIBLE_SQL_INJECTION_ERROR",
			"HIGH",
			"HIGH",
			falseConditionURL,
			parameterName,
			evidence,
			baseline.DurationMS,
			probe.DurationMS,
			probe.StatusCode,
		)
		if err != nil {
			return fmt.Errorf(
				"no se pudo guardar el hallazgo externo: %w",
				err,
			)
		}

		createEventWithoutInterrupting(
			scanID,
			"FINDING_CREATED",
			"La respuesta externa contiene una firma de error SQL",
		)

		return nil
	}

	if statusChanged || contentChanged {
		err = createFinding(
			scanID,
			"POSSIBLE_SQL_INJECTION_DIFFERENTIAL",
			"MEDIUM",
			"MEDIUM",
			falseConditionURL,
			parameterName,
			evidence,
			baseline.DurationMS,
			probe.DurationMS,
			probe.StatusCode,
		)
		if err != nil {
			return fmt.Errorf(
				"no se pudo guardar el hallazgo diferencial: %w",
				err,
			)
		}

		createEventWithoutInterrupting(
			scanID,
			"FINDING_CREATED",
			"La entrada produjo una diferencia significativa en la respuesta",
		)

		return nil
	}

	observation := fmt.Sprintf(
		"Resultado inconcluso. Respuesta normal: HTTP %d, %d bytes, %d ms. Respuesta de prueba: HTTP %d, %d bytes, %d ms. Diferencia de contenido: %d por ciento. No se encontraron firmas de error SQL.",
		baseline.StatusCode,
		baselineLength,
		baseline.DurationMS,
		probe.StatusCode,
		probeLength,
		probe.DurationMS,
		differencePercentage,
	)

	createEventWithoutInterrupting(
		scanID,
		"SCAN_INCONCLUSIVE",
		observation,
	)

	return nil
}

func performRequest(
	client http.Client,
	targetURL string,
) (requestResult, error) {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		requestTimeout,
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
		DurationMS: uint64(
			time.Since(startedAt).Milliseconds(),
		),
		Body:     string(bodyBytes),
		FinalURL: response.Request.URL.String(),
	}, nil
}

func replaceQueryValue(
	rawURL string,
	parameterName string,
	newValue string,
) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf(
			"no se pudo interpretar la URL: %w",
			err,
		)
	}

	queryValues := parsedURL.Query()

	if !queryValues.Has(parameterName) {
		return "", fmt.Errorf(
			"la URL no contiene el parametro seleccionado",
		)
	}

	queryValues.Set(
		parameterName,
		newValue,
	)

	parsedURL.RawQuery = queryValues.Encode()

	return parsedURL.String(), nil
}

func sameHostname(
	originalURL string,
	finalURL string,
) bool {
	original, err := url.Parse(originalURL)
	if err != nil {
		return false
	}

	final, err := url.Parse(finalURL)
	if err != nil {
		return false
	}

	return strings.EqualFold(
		original.Hostname(),
		final.Hostname(),
	)
}

func detectSQLSignature(body string) string {
	normalizedBody := strings.ToLower(body)

	signatures := []string{
		"sql syntax",
		"syntax error",
		"unclosed quotation mark",
		"mysql",
		"mysqli",
		"odbc sql",
		"sql server",
		"ora-",
		"postgresql",
		"sqlite error",
		"database error",
	}

	for _, signature := range signatures {
		if strings.Contains(
			normalizedBody,
			signature,
		) {
			return signature
		}
	}

	return ""
}

func absoluteDifference(
	firstValue int,
	secondValue int,
) int {
	if firstValue >= secondValue {
		return firstValue - secondValue
	}

	return secondValue - firstValue
}

func calculatePercentage(
	difference int,
	baseline int,
) int {
	if baseline <= 0 {
		return 0
	}

	return difference * 100 / baseline
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

func createEventWithoutInterrupting(
	scanID string,
	eventType string,
	message string,
) {
	err := createScanEvent(
		scanID,
		eventType,
		message,
	)
	if err != nil {
		log.Printf(
			"No se pudo registrar el evento %s: %v",
			eventType,
			err,
		)
	}
}

func updateScanStatus(
	scanID string,
	status string,
	errorMessage string,
	setStartedAt bool,
	setCompletedAt bool,
) error {
	switch {
	case setStartedAt:
		const query = `
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
		const query = `
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
		const query = `
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

	_, err := database.DB.Exec(
		query,
		"FAILED",
		message,
		scanID,
	)
	if err != nil {
		log.Printf(
			"No se pudo marcar el escaneo como fallido: %v",
			err,
		)
	}

	createEventWithoutInterrupting(
		scanID,
		"SCAN_FAILED",
		message,
	)
}
