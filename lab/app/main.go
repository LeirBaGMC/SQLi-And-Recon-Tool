package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	labdatabase "github.com/LeirBaGMC/SQLi-And-Recon-Tool/lab/app/internal/database"
)

type Application struct {
	database *sql.DB
	mode     string
}

type HealthResponse struct {
	Status   string `json:"status"`
	Service  string `json:"service"`
	Mode     string `json:"mode"`
	Database string `json:"database"`
	Time     string `json:"time"`
}

func main() {
	port := getEnvironment("APP_PORT", "8081")
	mode := getEnvironment("APP_MODE", "base")

	db, err := labdatabase.Open()
	if err != nil {
		log.Fatalf("No se pudo iniciar la aplicacion: %v", err)
	}
	defer db.Close()

	app := &Application{
		database: db,
		mode:     mode,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", app.homeHandler)
	mux.HandleFunc("GET /health", app.healthHandler)

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           requestLogger(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	log.Printf("Conexion con lab-db establecida correctamente")
	log.Printf(
		"Iniciando workshop-lab-app en el puerto %s, modo %s",
		port,
		mode,
	)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("No se pudo iniciar el servidor: %v", err)
	}
}

func (app *Application) homeHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{
		"message": "SQLi Workshop Lab",
		"status":  "running",
		"mode":    app.mode,
	}

	writeJSON(w, http.StatusOK, response)
}

func (app *Application) healthHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	response := HealthResponse{
		Status:   "ok",
		Service:  "workshop-lab-app",
		Mode:     app.mode,
		Database: "connected",
		Time:     time.Now().UTC().Format(time.RFC3339),
	}

	if err := labdatabase.Ping(ctx, app.database); err != nil {
		log.Printf("Fallo en healthcheck de MySQL: %v", err)

		response.Status = "degraded"
		response.Database = "disconnected"

		writeJSON(w, http.StatusServiceUnavailable, response)
		return
	}

	writeJSON(w, http.StatusOK, response)
}

func getEnvironment(name string, fallback string) string {
	value := os.Getenv(name)

	if value == "" {
		return fallback
	}

	return value
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("No se pudo escribir la respuesta JSON: %v", err)
	}
}

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startedAt := time.Now()

		next.ServeHTTP(w, r)

		log.Printf(
			"%s %s %s",
			r.Method,
			r.URL.Path,
			time.Since(startedAt),
		)
	})
}
