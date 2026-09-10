package main

import (
	"log"

	"github.com/LeirBaGMC/sql-scanner/api"
	"github.com/LeirBaGMC/sql-scanner/database"
	"github.com/gin-gonic/gin"
)

func main() {
	if err := database.Connect(); err != nil {
		log.Fatalf(
			"No se pudo iniciar el backend: %v",
			err,
		)
	}

	defer func() {
		if err := database.Close(); err != nil {
			log.Printf(
				"No se pudo cerrar scanner-db correctamente: %v",
				err,
			)
		}
	}()

	router := gin.Default()
	router.GET("/health", api.HealthHandler)
	apiGroup := router.Group("/api")
	{
		apiGroup.POST(
			"/scans",
			api.StartScanHandler,
		)

		apiGroup.GET(
			"/scans/:id",
			api.GetScanStatusHandler,
		)

		apiGroup.GET(
			"/scans/:id/results",
			api.GetScanResultsHandler,
		)

		apiGroup.GET(
			"/scans/:id/events",
			api.GetScanEventsHandler,
		)
	}

	log.Println(
		"Iniciando el backend del escaner en el puerto 8080",
	)

	if err := router.Run(":8080"); err != nil {
		log.Fatalf(
			"No se pudo iniciar el servidor HTTP: %v",
			err,
		)
	}
}
