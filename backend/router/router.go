package router

import (
	"net/http"

	"github.com/LeirBaGMC/sql-scanner/database"
	"github.com/LeirBaGMC/sql-scanner/handlers"
	"github.com/gin-gonic/gin"
)

// SetupRouter configura el motor de Gin, middleware CORS y las rutas REST.
func SetupRouter(repo *database.Repository) *gin.Engine {
	r := gin.Default()

	// Middleware de CORS para permitir solicitudes del dashboard frontend
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-Scan-Task-ID, X-Purple-Trace")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

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
