package api

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/LeirBaGMC/sql-scanner/database"
	"github.com/LeirBaGMC/sql-scanner/scanner"
	"github.com/gin-gonic/gin"
)

type StartScanRequest struct {
	Target string `json:"target" binding:"required"`
}

type ScanTarget struct {
	Name      string
	URL       string
	Parameter string
}

type ScanStatusResponse struct {
	ID           string `json:"id"`
	TargetName   string `json:"target_name"`
	TargetURL    string `json:"target_url"`
	Parameter    string `json:"parameter,omitempty"`
	Status       string `json:"status"`
	ErrorMessage string `json:"error_message,omitempty"`
	CreatedAt    string `json:"created_at"`
	StartedAt    string `json:"started_at,omitempty"`
	CompletedAt  string `json:"completed_at,omitempty"`
}

type FindingResponse struct {
	ID            uint64 `json:"id"`
	Category      string `json:"category"`
	Severity      string `json:"severity"`
	Confidence    string `json:"confidence"`
	TestedURL     string `json:"tested_url"`
	ParameterName string `json:"parameter_name,omitempty"`
	Evidence      string `json:"evidence,omitempty"`
	BaselineMS    uint64 `json:"baseline_ms,omitempty"`
	ObservedMS    uint64 `json:"observed_ms,omitempty"`
	HTTPStatus    uint16 `json:"http_status,omitempty"`
	CreatedAt     string `json:"created_at"`
}

var allowedTargets = map[string]ScanTarget{
	"vulnerable-app": {
		Name:      "Aplicacion vulnerable",
		URL:       "http://vulnerable-app:8081/api/vulnerable/products?id=1",
		Parameter: "id",
	},
	"secure-app": {
		Name:      "Aplicacion segura",
		URL:       "http://secure-app:8081/api/secure/products/1",
		Parameter: "id",
	},
}

func StartScanHandler(c *gin.Context) {
	var request StartScanRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "El campo target es obligatorio",
		})
		return
	}

	target, allowed := allowedTargets[request.Target]
	if !allowed {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "El objetivo solicitado no esta autorizado",
			"allowed_targets": []string{
				"vulnerable-app",
				"secure-app",
			},
		})
		return
	}

	scanID, err := generateScanID()
	if err != nil {
		log.Printf(
			"No se pudo generar el identificador del escaneo: %v",
			err,
		)

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "No se pudo crear el escaneo",
		})
		return
	}

	ctx, cancel := context.WithTimeout(
		c.Request.Context(),
		3*time.Second,
	)
	defer cancel()

	const query = `
		INSERT INTO scans (
			id,
			target_url,
			target_name,
			parameter_name,
			status
		)
		VALUES (?, ?, ?, ?, ?)
	`

	_, err = database.DB.ExecContext(
		ctx,
		query,
		scanID,
		target.URL,
		target.Name,
		target.Parameter,
		"QUEUED",
	)
	if err != nil {
		log.Printf(
			"No se pudo registrar el escaneo: %v",
			err,
		)

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "No se pudo registrar el escaneo",
		})
		return
	}

	go scanner.RunScan(scanID, target.URL)

	c.JSON(http.StatusAccepted, gin.H{
		"scan_id":        scanID,
		"target":         request.Target,
		"target_name":    target.Name,
		"target_url":     target.URL,
		"parameter_name": target.Parameter,
		"status":         "QUEUED",
	})
}

func GetScanStatusHandler(c *gin.Context) {
	scanID := c.Param("id")

	ctx, cancel := context.WithTimeout(
		c.Request.Context(),
		3*time.Second,
	)
	defer cancel()

	const query = `
		SELECT
			id,
			target_name,
			target_url,
			parameter_name,
			status,
			error_message,
			DATE_FORMAT(
				created_at,
				'%Y-%m-%dT%H:%i:%sZ'
			),
			DATE_FORMAT(
				started_at,
				'%Y-%m-%dT%H:%i:%sZ'
			),
			DATE_FORMAT(
				completed_at,
				'%Y-%m-%dT%H:%i:%sZ'
			)
		FROM scans
		WHERE id = ?
	`

	var response ScanStatusResponse
	var parameter sql.NullString
	var errorMessage sql.NullString
	var startedAt sql.NullString
	var completedAt sql.NullString

	err := database.DB.QueryRowContext(
		ctx,
		query,
		scanID,
	).Scan(
		&response.ID,
		&response.TargetName,
		&response.TargetURL,
		&parameter,
		&response.Status,
		&errorMessage,
		&response.CreatedAt,
		&startedAt,
		&completedAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Escaneo no encontrado",
		})
		return
	}

	if err != nil {
		log.Printf(
			"No se pudo consultar el escaneo %s: %v",
			scanID,
			err,
		)

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "No se pudo consultar el estado del escaneo",
		})
		return
	}

	response.Parameter = nullStringValue(parameter)
	response.ErrorMessage = nullStringValue(errorMessage)
	response.StartedAt = nullStringValue(startedAt)
	response.CompletedAt = nullStringValue(completedAt)

	c.JSON(http.StatusOK, response)
}

func GetScanResultsHandler(c *gin.Context) {
	scanID := c.Param("id")

	ctx, cancel := context.WithTimeout(
		c.Request.Context(),
		5*time.Second,
	)
	defer cancel()

	exists, err := scanExists(ctx, scanID)
	if err != nil {
		log.Printf(
			"No se pudo comprobar el escaneo %s: %v",
			scanID,
			err,
		)

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "No se pudieron consultar los resultados",
		})
		return
	}

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Escaneo no encontrado",
		})
		return
	}

	const query = `
		SELECT
			id,
			category,
			severity,
			confidence,
			tested_url,
			parameter_name,
			evidence,
			baseline_ms,
			observed_ms,
			http_status,
			DATE_FORMAT(
				created_at,
				'%Y-%m-%dT%H:%i:%sZ'
			)
		FROM findings
		WHERE scan_id = ?
		ORDER BY id ASC
	`

	rows, err := database.DB.QueryContext(
		ctx,
		query,
		scanID,
	)
	if err != nil {
		log.Printf(
			"No se pudieron consultar los hallazgos del escaneo %s: %v",
			scanID,
			err,
		)

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "No se pudieron obtener los resultados",
		})
		return
	}
	defer rows.Close()

	results := make([]FindingResponse, 0)

	for rows.Next() {
		var result FindingResponse
		var parameterName sql.NullString
		var evidence sql.NullString
		var baselineMS sql.NullInt64
		var observedMS sql.NullInt64
		var httpStatus sql.NullInt64

		err := rows.Scan(
			&result.ID,
			&result.Category,
			&result.Severity,
			&result.Confidence,
			&result.TestedURL,
			&parameterName,
			&evidence,
			&baselineMS,
			&observedMS,
			&httpStatus,
			&result.CreatedAt,
		)
		if err != nil {
			log.Printf(
				"No se pudo procesar un hallazgo: %v",
				err,
			)

			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "No se pudieron procesar los resultados",
			})
			return
		}

		result.ParameterName = nullStringValue(parameterName)
		result.Evidence = nullStringValue(evidence)
		result.BaselineMS = nullUint64Value(baselineMS)
		result.ObservedMS = nullUint64Value(observedMS)
		result.HTTPStatus = nullUint16Value(httpStatus)

		results = append(results, result)
	}

	if err := rows.Err(); err != nil {
		log.Printf(
			"La lectura de hallazgos fue interrumpida: %v",
			err,
		)

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "La lectura de resultados fue interrumpida",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_id":  scanID,
		"findings": results,
		"total":    len(results),
	})
}

func scanExists(
	ctx context.Context,
	scanID string,
) (bool, error) {
	const query = `
		SELECT EXISTS (
			SELECT 1
			FROM scans
			WHERE id = ?
		)
	`

	var exists bool

	err := database.DB.QueryRowContext(
		ctx,
		query,
		scanID,
	).Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}

func generateScanID() (string, error) {
	randomBytes := make([]byte, 16)

	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(randomBytes), nil
}

func nullStringValue(value sql.NullString) string {
	if !value.Valid {
		return ""
	}

	return value.String
}

func nullUint64Value(value sql.NullInt64) uint64 {
	if !value.Valid {
		return 0
	}

	if value.Int64 < 0 {
		return 0
	}

	return uint64(value.Int64)
}

func nullUint16Value(value sql.NullInt64) uint16 {
	if !value.Valid {
		return 0
	}

	if value.Int64 < 0 {
		return 0
	}

	if value.Int64 > 65535 {
		return 0
	}

	return uint16(value.Int64)
}
func HealthHandler(c *gin.Context) {
	ctx, cancel := context.WithTimeout(
		c.Request.Context(),
		2*time.Second,
	)
	defer cancel()

	if err := database.Ping(ctx); err != nil {
		log.Printf(
			"Fallo en el healthcheck de scanner-db: %v",
			err,
		)

		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":   "degraded",
			"service":  "scanner-backend",
			"database": "disconnected",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":   "ok",
		"service":  "scanner-backend",
		"database": "connected",
	})
}
