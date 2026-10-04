package database

import (
	"database/sql"
	"encoding/json"
	"log"
	"time"

	"github.com/LeirBaGMC/sql-scanner/models"
)

// Repository gestiona las operaciones de persistencia del escáner en MySQL.
type Repository struct {
	db *sql.DB
}

// NewRepository crea una nueva instancia de Repository usando el pool de conexiones actual.
func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

// GetDefaultRepository retorna un repositorio respaldado por la conexión global DB.
func GetDefaultRepository() *Repository {
	return &Repository{db: DB}
}

// CreateScan inicializa un nuevo registro de escaneo en la base de datos.
func (r *Repository) CreateScan(scan *models.ScanStatusResponse) error {
	const query = `
		INSERT INTO scans (id, target_url, target_name, parameter_name, status, created_at)
		VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	`
	_, err := r.db.Exec(query, scan.ID, scan.TargetURL, scan.TargetName, scan.Parameter, scan.Status)
	return err
}

// GetScan recupera el estado de un escaneo por su ID.
func (r *Repository) GetScan(scanID string) (*models.ScanStatusResponse, error) {
	const query = `
		SELECT
			id,
			target_name,
			target_url,
			COALESCE(parameter_name, ''),
			status,
			COALESCE(error_message, ''),
			created_at,
			started_at,
			completed_at
		FROM scans
		WHERE id = ?
	`
	row := r.db.QueryRow(query, scanID)

	var scan models.ScanStatusResponse
	var createdAt time.Time
	var startedAt sql.NullTime
	var completedAt sql.NullTime

	err := row.Scan(
		&scan.ID,
		&scan.TargetName,
		&scan.TargetURL,
		&scan.Parameter,
		&scan.Status,
		&scan.ErrorMessage,
		&createdAt,
		&startedAt,
		&completedAt,
	)
	if err != nil {
		return nil, err
	}

	scan.ScanID = scan.ID
	scan.CreatedAt = createdAt.Format(time.RFC3339)
	if startedAt.Valid {
		scan.StartedAt = startedAt.Time.Format(time.RFC3339)
	}
	if completedAt.Valid {
		scan.CompletedAt = completedAt.Time.Format(time.RFC3339)
	}

	return &scan, nil
}

// UpdateScanStatus actualiza el estado, mensaje de error y timestamps del escaneo.
func (r *Repository) UpdateScanStatus(scanID, status, errorMessage string, setStartedAt, setCompletedAt bool) error {
	switch {
	case setStartedAt:
		_, err := r.db.Exec(`UPDATE scans SET status = ?, error_message = NULL, started_at = CURRENT_TIMESTAMP WHERE id = ?`, status, scanID)
		return err
	case setCompletedAt:
		_, err := r.db.Exec(`UPDATE scans SET status = ?, error_message = NULL, completed_at = CURRENT_TIMESTAMP WHERE id = ?`, status, scanID)
		return err
	default:
		_, err := r.db.Exec(`UPDATE scans SET status = ?, error_message = ? WHERE id = ?`, status, errorMessage, scanID)
		return err
	}
}

// CreateFinding almacena un hallazgo confirmado de vulnerabilidad.
func (r *Repository) CreateFinding(finding models.Finding) error {
	const query = `
		INSERT INTO findings (
			scan_id, category, severity, confidence, tested_url,
			parameter_name, evidence, baseline_ms, observed_ms, http_status, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	`
	_, err := r.db.Exec(
		query,
		finding.ScanID,
		finding.Category,
		finding.Severity,
		finding.Confidence,
		finding.TestedURL,
		finding.ParameterName,
		finding.Evidence,
		finding.BaselineMS,
		finding.ObservedMS,
		finding.HTTPStatus,
	)
	return err
}

// GetFindingsByScanID retorna todos los hallazgos asociados a un escaneo.
func (r *Repository) GetFindingsByScanID(scanID string) ([]models.Finding, error) {
	const query = `
		SELECT
			id,
			scan_id,
			category,
			severity,
			confidence,
			tested_url,
			COALESCE(parameter_name, ''),
			COALESCE(evidence, ''),
			COALESCE(baseline_ms, 0),
			COALESCE(observed_ms, 0),
			COALESCE(http_status, 0),
			created_at
		FROM findings
		WHERE scan_id = ?
		ORDER BY id ASC
	`
	rows, err := r.db.Query(query, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	findings := make([]models.Finding, 0)
	for rows.Next() {
		var f models.Finding
		var createdAt time.Time

		err := rows.Scan(
			&f.ID,
			&f.ScanID,
			&f.Category,
			&f.Severity,
			&f.Confidence,
			&f.TestedURL,
			&f.ParameterName,
			&f.Evidence,
			&f.BaselineMS,
			&f.ObservedMS,
			&f.HTTPStatus,
			&createdAt,
		)
		if err != nil {
			return nil, err
		}
		f.CreatedAt = createdAt.Format(time.RFC3339)

		// Deserializar evidencia de confirmación dual si existe en formato JSON
		if f.Evidence != "" {
			var dual models.DualConfirmation
			if json.Unmarshal([]byte(f.Evidence), &dual) == nil && dual.HTTP.Confirmed {
				f.DualConfirmation = &dual
			}
		}

		findings = append(findings, f)
	}

	return findings, rows.Err()
}

// CreateScanEvent registra un evento en la bitácora del escaneo.
func (r *Repository) CreateScanEvent(scanID, eventType, message string) error {
	const query = `INSERT INTO scan_events (scan_id, event_type, message, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)`
	_, err := r.db.Exec(query, scanID, eventType, message)
	return err
}

// CreateEventWithoutInterrupting registra un evento sin interrumpir la ejecución si ocurre un error.
func (r *Repository) CreateEventWithoutInterrupting(scanID, eventType, message string) {
	if err := r.CreateScanEvent(scanID, eventType, message); err != nil {
		log.Printf("[Repo] No se pudo registrar el evento %s: %v", eventType, err)
	}
}

// GetScanEventsByScanID retorna los eventos en orden cronológico.
func (r *Repository) GetScanEventsByScanID(scanID string) ([]models.ScanEventResponse, error) {
	const query = `
		SELECT id, scan_id, event_type, message, created_at
		FROM scan_events
		WHERE scan_id = ?
		ORDER BY id ASC
	`
	rows, err := r.db.Query(query, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]models.ScanEventResponse, 0)
	for rows.Next() {
		var ev models.ScanEventResponse
		var createdAt time.Time
		if err := rows.Scan(&ev.ID, &ev.ScanID, &ev.EventType, &ev.Message, &createdAt); err != nil {
			return nil, err
		}
		ev.CreatedAt = createdAt.Format(time.RFC3339)
		events = append(events, ev)
	}

	return events, rows.Err()
}
