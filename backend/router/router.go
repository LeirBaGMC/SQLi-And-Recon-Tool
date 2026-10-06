package router

import (
	"net/http"
	"os"
	"strings"

	"github.com/LeirBaGMC/sql-scanner/database"
	"github.com/LeirBaGMC/sql-scanner/handlers"
	"github.com/gin-gonic/gin"
)

// SetupRouter configura el motor de Gin, middleware CORS y las rutas REST.
func SetupRouter(repo *database.Repository) *gin.Engine {
	r := gin.Default()

	// Only the local dashboard may use this API from a browser. A foreign
	// Origin must be rejected before starting a scan, not just hidden by CORS.
	origins := os.Getenv("SCANNER_ALLOWED_ORIGINS")
	if origins == "" {
		origins = "http://localhost:3000,http://127.0.0.1:3000"
	}
	allowedOrigins := map[string]bool{}
	for _, origin := range strings.Split(origins, ",") {
		allowedOrigins[strings.TrimSpace(origin)] = true
	}
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Add("Vary", "Origin")
		if origin := c.GetHeader("Origin"); origin != "" {
			if !allowedOrigins[origin] {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Origen del navegador no permitido"})
				return
			}
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET")
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	})

	h := handlers.NewHandler(repo)

	// Verificación de salud
	r.GET("/health", h.HealthHandler)

	// Grupo de endpoints de escaneo
	apiGroup := r.Group("/api")
	{
		apiGroup.POST("/scans", h.StartScanHandler)
		apiGroup.GET("/scans/:id", h.GetScanStatusHandler)
		apiGroup.GET("/scans/:id/results", h.GetScanResultsHandler)
		apiGroup.GET("/scans/:id/events", h.GetScanEventsHandler)
	}

	return r
}
