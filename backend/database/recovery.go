package database

import (
	"context"
	"fmt"
)

const ScanInterruptedMessage = "El escaneo fue interrumpido por un reinicio del backend. Inicia una nueva prueba."

// Run before accepting requests in this single-backend deployment. Do not replay
// requests automatically: credentials and execution contexts are not persisted.
// The final state and its failure event must commit together.
func (r *Repository) FailInterruptedScans(ctx context.Context) (int, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, "SELECT id FROM scans WHERE status IN ('QUEUED', 'RUNNING') FOR UPDATE")
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	readErr := rows.Err()
	closeErr := rows.Close()
	if readErr != nil {
		return 0, readErr
	}
	if closeErr != nil {
		return 0, closeErr
	}
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, "UPDATE scans SET status = 'FAILED', error_message = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?", ScanInterruptedMessage, id); err != nil {
			return 0, fmt.Errorf("no se pudo cerrar el escaneo interrumpido: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO scan_events (scan_id, event_type, message, created_at) VALUES (?, 'SCAN_FAILED', ?, CURRENT_TIMESTAMP)", id, ScanInterruptedMessage); err != nil {
			return 0, fmt.Errorf("no se pudo conservar la interrupción del escaneo: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(ids), nil
}
