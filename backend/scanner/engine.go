package scanner

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/LeirBaGMC/sql-scanner/database"
	"github.com/LeirBaGMC/sql-scanner/models"
	"github.com/LeirBaGMC/sql-scanner/remediation"
)

const (
	authorizedURLMode        = "authorized_url"
	authorizedCandidateLimit = 8
)

// RunScan es el punto de entrada principal para ejecutar un análisis mediante el Worker Pool.
func RunScan(scanID, targetURL, parameterName, targetMode string, maxWorkers int, repo *database.Repository) {
	log.Printf("[Scanner] Iniciando escaneo %s en modo %s con concurrencia max=%d", scanID, targetMode, maxWorkers)

	if err := repo.UpdateScanStatus(scanID, "RUNNING", "", true, false); err != nil {
		log.Printf("[Scanner] Error al actualizar estado a RUNNING: %v", err)
		return
	}
	repo.CreateEventWithoutInterrupting(scanID, "SCAN_STARTED", "Worker Pool iniciado para el análisis controlado (Purple Team)")

	if maxWorkers <= 0 {
		maxWorkers = 5
	}

	client := &http.Client{Timeout: requestTimeout}
	var err error

	if targetMode == authorizedURLMode {
		err = runAuthorizedURLDiscovery(scanID, targetURL, repo)
	} else {
		err = runSandboxWorkerPool(scanID, targetURL, parameterName, maxWorkers, client, repo)
	}

	if err != nil {
		log.Printf("[Scanner] El escaneo %s falló: %v", scanID, err)
		_ = repo.UpdateScanStatus(scanID, "FAILED", err.Error(), false, true)
		repo.CreateEventWithoutInterrupting(scanID, "SCAN_FAILED", err.Error())
		return
	}

	// Blue Team: Generar reporte de remediación defensivo
	findings, _ := repo.GetFindingsByScanID(scanID)
	report := remediation.GenerateReport(scanID, findings, targetMode)
	_ = report // Disponible para futuras extensiones o exportación PDF

	if err = repo.UpdateScanStatus(scanID, "COMPLETED", "", false, true); err != nil {
		log.Printf("[Scanner] Error al marcar escaneo como completado: %v", err)
		return
	}
	repo.CreateEventWithoutInterrupting(scanID, "SCAN_COMPLETED", "Análisis completado exitosamente y reporte de remediación generado")
}

// runSandboxWorkerPool orquesta las pruebas concurrentes contra el sandbox interno.
func runSandboxWorkerPool(scanID, targetURL, parameterName string, maxWorkers int, client *http.Client, repo *database.Repository) error {
	if isSecureSandboxURL(targetURL) {
		return scanSecureSandbox(client, scanID, targetURL, parameterName, repo)
	}

	baseline, err := performRequest(client, targetURL)
	if err != nil {
		return fmt.Errorf("no se pudo consultar el endpoint base del sandbox: %w", err)
	}

	repo.CreateEventWithoutInterrupting(scanID, "BASELINE_COMPLETED", fmt.Sprintf(
		"Respuesta base recibida en %d ms con estado HTTP %d", baseline.DurationMS, baseline.StatusCode,
	))

	// Definir tareas de prueba que procesará el Worker Pool
	tasks := []models.ScanTask{
		{
			ID:          fmt.Sprintf("%s-task-boolean", scanID),
			ScanID:      scanID,
			TraceID:     fmt.Sprintf("trace-%s-bool", scanID),
			TargetURL:   targetURL,
			Parameter:   parameterName,
			Payload:     "1 OR 1=1",
			ProbeType:   "Boolean",
			Risk:        "HIGH",
			Description: "Condicion booleana controlada",
		},
		{
			ID:          fmt.Sprintf("%s-task-extraction", scanID),
			ScanID:      scanID,
			TraceID:     fmt.Sprintf("trace-%s-extract", scanID),
			TargetURL:   targetURL,
			Parameter:   parameterName,
			Payload:     "0 UNION ALL SELECT id,username,display_name,0,is_active FROM workshop_users WHERE 1=1",
			ProbeType:   "Extraction",
			Risk:        "CRITICAL",
			Description: "Exposicion controlada de datos ficticios",
		},
		{
			ID:          fmt.Sprintf("%s-task-time", scanID),
			ScanID:      scanID,
			TraceID:     fmt.Sprintf("trace-%s-time", scanID),
			TargetURL:   targetURL,
			Parameter:   parameterName,
			Payload:     "1 AND SLEEP(2)",
			ProbeType:   "TimeBased",
			Risk:        "HIGH",
			Description: "Inyeccion ciega basada en tiempo (Time-Based Blind)",
		},
	}

	jobs := make(chan models.ScanTask, len(tasks))
	var wg sync.WaitGroup
	var workerErrors []error
	var errMu sync.Mutex

	workerCount := maxWorkers
	if workerCount > len(tasks) {
		workerCount = len(tasks)
	}

	for w := 1; w <= workerCount; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for task := range jobs {
				var probeErr error
				switch task.ProbeType {
				case "Boolean":
					probeErr = executeBooleanProbe(client, task, baseline, repo)
				case "Extraction":
					probeErr = executeExtractionProbe(client, task, baseline, repo)
				case "TimeBased":
					probeErr = executeTimeBasedProbe(client, task, baseline, repo)
				}
				if probeErr != nil {
					errMu.Lock()
					workerErrors = append(workerErrors, probeErr)
					errMu.Unlock()
				}
			}
		}(w)
	}

	for _, task := range tasks {
		jobs <- task
	}
	close(jobs)

	wg.Wait()

	if len(workerErrors) > 0 {
		return workerErrors[0]
	}

	return nil
}

// runAuthorizedURLDiscovery ejecuta el rastreo pasivo sobre objetivos externos autorizados.
func runAuthorizedURLDiscovery(scanID, targetURL string, repo *database.Repository) error {
	repo.CreateEventWithoutInterrupting(scanID, "DISCOVERY_STARTED", "El motor inició el descubrimiento pasivo de enlaces y parámetros")

	candidates, summary, err := DiscoverCandidates(targetURL)
	if err != nil {
		return fmt.Errorf("no se pudo completar el descubrimiento: %w", err)
	}

	repo.CreateEventWithoutInterrupting(scanID, "DISCOVERY_COMPLETED", fmt.Sprintf(
		"Descubrimiento completado. Páginas visitadas: %d. Enlaces encontrados: %d. Parámetros encontrados: %d.",
		summary.PagesVisited, summary.LinksDiscovered, summary.CandidatesDiscovered,
	))

	if len(candidates) == 0 {
		repo.CreateEventWithoutInterrupting(scanID, "SCAN_INCONCLUSIVE", "No se encontraron parámetros GET analizables en el objetivo.")
		return nil
	}

	limit := len(candidates)
	if limit > authorizedCandidateLimit {
		limit = authorizedCandidateLimit
	}

	for i := 0; i < limit; i++ {
		candidate := candidates[i]
		repo.CreateEventWithoutInterrupting(scanID, "PARAMETER_DISCOVERED", fmt.Sprintf(
			"Parámetro %s con valor original %s detectado en %s",
			candidate.ParameterName, candidate.OriginalValue, candidate.URL,
		))
	}

	generateAuthorizedDemonstrations(scanID, candidates[:limit], repo)
	repo.CreateEventWithoutInterrupting(scanID, "SCAN_INCONCLUSIVE", "Se generaron demostraciones educativas sin enviar payloads destructivos al objetivo externo.")
	return nil
}

func generateAuthorizedDemonstrations(scanID string, candidates []DiscoveryCandidate, repo *database.Repository) {
	if len(candidates) == 0 {
		return
	}
	candidate := candidates[0]
	parameter := candidate.ParameterName

	if isRedirectParameter(parameter) {
		emitPayloadEvent(repo, scanID, "PAYLOAD_DEMONSTRATION", models.PayloadExecutionEvent{
			Name:               "Manipulacion de redireccion",
			Parameter:          parameter,
			Payload:            "https://dominio-externo.example/",
			Risk:               "MEDIUM",
			Result:             "SIMULATED",
			ExecutionType:      "SIMULATED",
			HypotheticalResult: "La aplicacion podria redirigir hacia un destino controlado por un tercero.",
			Reason:             "El parametro parece controlar una ruta de retorno.",
			Remediation:        "Permitir solamente rutas internas conocidas y usar una ruta segura predeterminada.",
		})
		return
	}

	demos := []models.PayloadExecutionEvent{
		{
			Name:               "Condicion booleana verdadera",
			Parameter:          parameter,
			Payload:            "valor OR 1=1",
			Risk:               "HIGH",
			Result:             "SIMULATED",
			ExecutionType:      "SIMULATED",
			HypotheticalResult: "La respuesta podria devolver mas registros que la solicitud original.",
			Reason:             "Una condicion siempre verdadera podria modificar un filtro concatenado.",
			Remediation:        "Utilizar consultas preparadas y validar el parametro.",
		},
		{
			Name:               "Exposicion de datos",
			Parameter:          parameter,
			Payload:            "UNION SELECT [columnas compatibles] FROM [tabla permitida]",
			Risk:               "CRITICAL",
			Result:             "SIMULATED",
			ExecutionType:      "SIMULATED",
			HypotheticalResult: "Una consulta vulnerable podria mezclar registros de otra tabla en la respuesta.",
			Reason:             "Una union compatible puede exponer datos si la entrada modifica la estructura SQL.",
			Remediation:        "Usar consultas preparadas y privilegios minimos.",
		},
	}

	for _, demo := range demos {
		emitPayloadEvent(repo, scanID, "PAYLOAD_DEMONSTRATION", demo)
	}
}

func isRedirectParameter(parameterName string) bool {
	name := strings.ToLower(strings.TrimSpace(parameterName))
	return map[string]bool{
		"returl": true, "returnurl": true, "return_url": true,
		"redirect": true, "redirecturl": true, "redirect_url": true,
		"next": true, "continue": true, "destination": true,
	}[name]
}
