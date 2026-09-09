package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

type HealthResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
	Mode    string `json:"mode"`
	Time    string `json:"time"`
}

func main() {
	port := getEnvironment("APP_PORT", "8081")
	mode := getEnvironment("APP_MODE", "base")

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		response := HealthResponse{
			Status:  "ok",
			Service: "workshop-lab-app",
			Mode:    mode,
			Time:    time.Now().UTC().Format(time.RFC3339),
		}

		writeJSON(w, http.StatusOK, response)
	})

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		response := map[string]string{
			"message": "SQLi Workshop Lab",
			"status":  "running",
			"mode":    mode,
		}

		writeJSON(w, http.StatusOK, response)
	})

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           requestLogger(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	log.Printf(
		"Iniciando workshop-lab-app en el puerto %s, modo %s",
		port,
		mode,
	)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("No se pudo iniciar el servidor: %v", err)
	}
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
