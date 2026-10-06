package main

import (
	"context"
	"log"
	"time"

	"github.com/LeirBaGMC/sql-scanner/database"
	"github.com/LeirBaGMC/sql-scanner/router"
)

func main() {
	if err := database.Connect(); err != nil {
		log.Fatalf("No se pudo iniciar el backend: %v", err)
	}

	defer func() {
		if err := database.Close(); err != nil {
			log.Printf("No se pudo cerrar scanner-db correctamente: %v", err)
		}
	}()

	repo := database.NewRepository(database.DB)
	recoveryContext, cancelRecovery := context.WithTimeout(context.Background(), 30*time.Second)
	interrupted, err := repo.FailInterruptedScans(recoveryContext)
	cancelRecovery()
	if err != nil {
		log.Fatalf("No se pudieron recuperar los escaneos interrumpidos: %v", err)
	}
	if interrupted > 0 {
		log.Printf("%d escaneos anteriores marcados como interrumpidos", interrupted)
	}
	r := router.SetupRouter(repo)

	log.Println("Servidor del escáner iniciado en :8080 (Purple Team TICEC 2026)")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("No se pudo iniciar el servidor HTTP: %v", err)
	}
}
