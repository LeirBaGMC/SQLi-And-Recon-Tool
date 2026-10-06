package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/LeirBaGMC/sql-scanner/database"
	"github.com/LeirBaGMC/sql-scanner/models"
	"github.com/LeirBaGMC/sql-scanner/policy"
	"github.com/LeirBaGMC/sql-scanner/remediation"
	"github.com/LeirBaGMC/sql-scanner/scanner"
	"github.com/gin-gonic/gin"
)

// Handler agrupa los controladores HTTP y la inyección de dependencias.
type Handler struct {
	repo *database.Repository
}

// NewHandler crea una nueva instancia de Handler con el repositorio especificado.
func NewHandler(repo *database.Repository) *Handler {
	return &Handler{repo: repo}
}

// StartScanHandler procesa la solicitud para iniciar un nuevo escaneo controlado.
func (h *Handler) StartScanHandler(c *gin.Context) {
	var request models.ScanRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "El cuerpo de la solicitud no es valido",
		})
		return
	}

	if request.Mode == "" {
		request.Mode = policy.TargetModeDVWA
	}

	target, err := policy.ValidateTarget(policy.TargetRequest{
		Mode:                   request.Mode,
		Target:                 request.Target,
		URL:                    request.URL,
		AuthorizationConfirmed: request.AuthorizationConfirmed,
		DVWALevel:              request.DVWALevel,
		DVWAVariant:            request.DVWAVariant,
		Workers:                request.Workers,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	scanID, err := generateScanID()
	if err != nil {
		log.Printf("[Handlers] No se pudo generar ID de escaneo: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "No se pudo crear el escaneo",
		})
		return
	}

	scanRecord := &models.ScanStatusResponse{
		ID:         scanID,
		ScanID:     scanID,
		TargetName: target.Name,
		TargetURL:  target.URL,
		Parameter:  target.Parameter,
		Status:     "QUEUED",
	}

	if err = h.repo.CreateScan(scanRecord); err != nil {
		log.Printf("[Handlers] No se pudo persistir el escaneo: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "No se pudo registrar el escaneo",
		})
		return
	}

	h.repo.CreateEventWithoutInterrupting(scanID, "SCAN_QUEUED", "El escaneo fue encolado para su ejecucion")

	// La respuesta HTTP no espera al escaneo.
	go scanner.RunScan(scanID, target, h.repo)

	c.JSON(http.StatusAccepted, gin.H{
		"id":             scanID,
		"scan_id":        scanID,
		"target_name":    target.Name,
		"target_url":     target.URL,
		"host":           target.Host,
		"parameter_name": target.Parameter,
		"original_value": target.OriginalValue,
		"status":         "QUEUED",
		"dvwa_level":     target.DVWALevel,
		"dvwa_variant":   target.DVWAVariant,
		"workers":        target.Workers,
	})
}

// GetScanStatusHandler retorna el estado; el reporte se consulta en /results.
func (h *Handler) GetScanStatusHandler(c *gin.Context) {
	scanID := strings.TrimSpace(c.Param("id"))
	if scanID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "El identificador del escaneo es obligatorio"})
		return
	}

	scan, err := h.repo.GetScan(scanID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "El escaneo no existe"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo consultar el escaneo"})
		return
	}

	c.JSON(http.StatusOK, scan)
}

// GetScanResultsHandler retorna los hallazgos y el informe defensivo Blue Team.
func (h *Handler) GetScanResultsHandler(c *gin.Context) {
	scanID := strings.TrimSpace(c.Param("id"))
	if scanID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "El identificador del escaneo es obligatorio"})
		return
	}

	scan, err := h.repo.GetScan(scanID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "El escaneo no existe"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo consultar el escaneo"})
		return
	}

	findings, err := h.repo.GetFindingsByScanID(scanID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudieron obtener los resultados"})
		return
	}

	events, err := h.repo.GetScanEventsByScanID(scanID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo consultar la evidencia de correccion"})
		return
	}
	report := remediation.GenerateScanReport(scan, findings, events)

	c.JSON(http.StatusOK, gin.H{
		"scan_id":            scanID,
		"findings":           findings,
		"total":              len(findings),
		"remediation_report": report,
	})
}

// GetScanEventsHandler retorna los eventos registrados durante el ciclo de vida del escaneo.
func (h *Handler) GetScanEventsHandler(c *gin.Context) {
	scanID := strings.TrimSpace(c.Param("id"))
	if scanID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "El identificador del escaneo es obligatorio"})
		return
	}

	events, err := h.repo.GetScanEventsByScanID(scanID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudieron obtener los eventos"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_id": scanID,
		"events":  events,
		"total":   len(events),
	})
}

// HealthHandler verifica la disponibilidad del servicio y la conexión a la base de datos.
func (h *Handler) HealthHandler(c *gin.Context) {
	if err := database.Ping(c.Request.Context()); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":   "unhealthy",
			"database": "disconnected",
			"error":    err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":   "ok",
		"service":  "sqli-workshop-backend",
		"database": "connected",
	})
}

func generateScanID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("error al generar bytes aleatorios: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}
