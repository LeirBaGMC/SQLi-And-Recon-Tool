package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

const (
	connectionAttempts = 10
	retryDelay         = 3 * time.Second
	pingTimeout        = 3 * time.Second
)

var DB *sql.DB

func Connect() error {
	host := getEnvironment("SCANNER_DB_HOST", "scanner-db")
	port := getEnvironment("SCANNER_DB_PORT", "3306")
	name := getEnvironment("SCANNER_DB_NAME", "scanner_db")
	user := getEnvironment("SCANNER_DB_USER", "scanner_user")
	password := os.Getenv("SCANNER_DB_PASSWORD")

	if password == "" {
		return fmt.Errorf(
			"la variable SCANNER_DB_PASSWORD es obligatoria",
		)
	}

	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4",
		user,
		password,
		host,
		port,
		name,
	)

	databaseConnection, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf(
			"no se pudo configurar la conexion con scanner-db: %w",
			err,
		)
	}

	databaseConnection.SetMaxOpenConns(10)
	databaseConnection.SetMaxIdleConns(5)
	databaseConnection.SetConnMaxLifetime(5 * time.Minute)
	databaseConnection.SetConnMaxIdleTime(2 * time.Minute)

	for attempt := 1; attempt <= connectionAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(
			context.Background(),
			pingTimeout,
		)

		err = databaseConnection.PingContext(ctx)
		cancel()

		if err == nil {
			DB = databaseConnection

			log.Printf(
				"Conexion con scanner-db establecida en el intento %d",
				attempt,
			)

			return nil
		}

		log.Printf(
			"scanner-db no disponible, intento %d de %d: %v",
			attempt,
			connectionAttempts,
			err,
		)

		if attempt < connectionAttempts {
			time.Sleep(retryDelay)
		}
	}

	databaseConnection.Close()

	return fmt.Errorf(
		"no se pudo conectar con scanner-db despues de %d intentos: %w",
		connectionAttempts,
		err,
	)
}

func Ping(ctx context.Context) error {
	if DB == nil {
		return fmt.Errorf(
			"la conexion con scanner-db no fue inicializada",
		)
	}

	if err := DB.PingContext(ctx); err != nil {
		return fmt.Errorf(
			"scanner-db no responde: %w",
			err,
		)
	}

	return nil
}

func Close() error {
	if DB == nil {
		return nil
	}

	return DB.Close()
}

func getEnvironment(name string, fallback string) string {
	value := os.Getenv(name)

	if value == "" {
		return fallback
	}

	return value
}
