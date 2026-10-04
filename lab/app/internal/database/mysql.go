package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

const (
	maxConnectionAttempts = 10
	connectionRetryDelay  = 3 * time.Second
	pingTimeout           = 3 * time.Second
)

// Open crea y valida la conexion con la base de datos del laboratorio.
func Open() (*sql.DB, error) {
	host := getEnvironment("DB_HOST", "lab-db")
	port := getEnvironment("DB_PORT", "3306")
	name := getEnvironment("DB_NAME", "workshop_db")
	user := getEnvironment("DB_USER", "workshop_user")
	password := os.Getenv("DB_PASSWORD")

	if password == "" {
		return nil, fmt.Errorf("la variable DB_PASSWORD es obligatoria")
	}

	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci",
		user,
		password,
		host,
		port,
		name,
	)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("no se pudo configurar MySQL: %w", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(2 * time.Minute)

	for attempt := 1; attempt <= maxConnectionAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
		err = db.PingContext(ctx)
		cancel()

		if err == nil {
			return db, nil
		}

		if attempt < maxConnectionAttempts {
			time.Sleep(connectionRetryDelay)
		}
	}

	db.Close()

	return nil, fmt.Errorf(
		"no se pudo conectar con MySQL despues de %d intentos: %w",
		maxConnectionAttempts,
		err,
	)
}

// Ping comprueba que la base de datos sigue disponible.
func Ping(ctx context.Context, db *sql.DB) error {
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("MySQL no responde: %w", err)
	}

	return nil
}

func getEnvironment(name string, fallback string) string {
	value := os.Getenv(name)

	if value == "" {
		return fallback
	}

	return value
}
