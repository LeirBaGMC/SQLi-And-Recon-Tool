package scanner

import (
	"fmt"
	"log"

	"github.com/LeirBaGMC/sql-scanner/database"
	"github.com/LeirBaGMC/sql-scanner/policy"
)

const (
	authorizedURLMode        = "authorized_url"
	authorizedCandidateLimit = 8
)

// RunScan ejecuta sondas HTTP y conserva su evidencia antes del estado final.
func RunScan(scanID string, target policy.AuthorizedTarget, repo *database.Repository) {
	targetURL, targetMode, dvwaLevel := target.URL, target.Mode, target.DVWALevel
	log.Printf("[Scanner] Iniciando escaneo %s en modo %s", scanID, targetMode)

	if err := repo.UpdateScanStatus(scanID, "RUNNING", "", true, false); err != nil {
		log.Printf("[Scanner] Error al actualizar estado a RUNNING: %v", err)
		return
	}
	repo.CreateEventWithoutInterrupting(scanID, "SCAN_STARTED", "Motor HTTP iniciado para el análisis controlado")

	var err error

	if targetMode == authorizedURLMode {
		err = runAuthorizedURLDiscovery(scanID, target, repo)
	} else if targetMode == "dvwa" {
		err = runDVWAScan(scanID, targetURL, dvwaLevel, target.Workers, repo)
	} else {
		err = fmt.Errorf("modo de escaneo no compatible")
	}

	if err != nil {
		log.Printf("[Scanner] El escaneo %s falló: %v", scanID, err)
		_ = repo.UpdateScanStatus(scanID, "FAILED", err.Error(), false, true)
		repo.CreateEventWithoutInterrupting(scanID, "SCAN_FAILED", err.Error())
		return
	}

	if err = repo.UpdateScanStatus(scanID, "COMPLETED", "", false, true); err != nil {
		log.Printf("[Scanner] Error al marcar escaneo como completado: %v", err)
		return
	}
	repo.CreateEventWithoutInterrupting(scanID, "SCAN_COMPLETED", "Análisis completado; resultados guardados")
}

// URLs with parameters are tested directly; discovery is reserved for entry pages.
func runAuthorizedURLDiscovery(scanID string, target policy.AuthorizedTarget, repo *database.Repository) error {
	targetURL := target.URL
	candidates := extractCandidates(targetURL)
	if len(candidates) == 0 {
		repo.CreateEventWithoutInterrupting(scanID, "DISCOVERY_STARTED", "Buscar parametros GET en hasta cinco paginas del mismo origen")
		client, err := authorizedClient(targetURL, target.BasicAuth)
		if err != nil {
			return err
		}
		discovered, summary, err := discoverCandidates(client, targetURL, repositoryHTTPObserver(scanID, repo))
		if err != nil {
			return err
		}
		candidates = discovered
		repo.CreateEventWithoutInterrupting(scanID, "DISCOVERY_COMPLETED", fmt.Sprintf("Descubrimiento: %d paginas · %d enlaces · %d parametros", summary.PagesVisited, summary.LinksDiscovered, summary.CandidatesDiscovered))
	} else {
		repo.CreateEventWithoutInterrupting(scanID, "TARGET_SELECTED", "Analisis directo de los parametros de la URL introducida; sin rastrear otras paginas")
	}

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
			"Parametro %s · Valor base %s",
			candidate.ParameterName, candidate.OriginalValue,
		))
	}

	total, offset := 0, 0
	for _, candidate := range candidates[:limit] {
		total += authorizedProbeCount(candidate)
	}
	for i, candidate := range candidates[:limit] {
		if err := executeAuthorizedProbes(scanID, candidate, target.BasicAuth, fmt.Sprintf("candidate-%d", i+1), offset, total, repo); err != nil {
			return err
		}
		offset += authorizedProbeCount(candidate)
	}
	return nil
}
