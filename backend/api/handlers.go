package api

import (
	"github.com/LeirBaGMC/sql-scanner/database"
	"github.com/LeirBaGMC/sql-scanner/handlers"
	"github.com/gin-gonic/gin"
)

// Wrapper de compatibilidad hacia la nueva arquitectura desacoplada en package handlers.

func StartScanHandler(c *gin.Context) {
	handlers.NewHandler(database.GetDefaultRepository()).StartScanHandler(c)
}

func GetScanStatusHandler(c *gin.Context) {
	handlers.NewHandler(database.GetDefaultRepository()).GetScanStatusHandler(c)
}

func GetScanResultsHandler(c *gin.Context) {
	handlers.NewHandler(database.GetDefaultRepository()).GetScanResultsHandler(c)
}

func GetScanEventsHandler(c *gin.Context) {
	handlers.NewHandler(database.GetDefaultRepository()).GetScanEventsHandler(c)
}

func HealthHandler(c *gin.Context) {
	handlers.NewHandler(database.GetDefaultRepository()).HealthHandler(c)
}
