package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"
)

type ProductsHandler struct {
	database *sql.DB
}

type Product struct {
	ID          uint64  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Price       float64 `json:"price"`
	IsActive    bool    `json:"is_active"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type ProductResponse struct {
	Product       Product           `json:"product"`
	QueryTemplate string            `json:"query_template"`
	Parameters    map[string]uint64 `json:"parameters"`
	SecurityMode  string            `json:"security_mode"`
}

func NewProductsHandler(database *sql.DB) *ProductsHandler {
	return &ProductsHandler{
		database: database,
	}
}

func (handler *ProductsHandler) List(
	w http.ResponseWriter,
	r *http.Request,
) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	const query = `
		SELECT
			id,
			name,
			description,
			price,
			is_active
		FROM products
		WHERE is_active = TRUE
		ORDER BY id ASC
	`

	rows, err := handler.database.QueryContext(ctx, query)
	if err != nil {
		log.Printf("No se pudieron consultar los productos: %v", err)

		writeJSON(w, http.StatusInternalServerError, ErrorResponse{
			Error: "No se pudieron obtener los productos",
		})

		return
	}
	defer rows.Close()

	products := make([]Product, 0)

	for rows.Next() {
		var product Product

		err := rows.Scan(
			&product.ID,
			&product.Name,
			&product.Description,
			&product.Price,
			&product.IsActive,
		)
		if err != nil {
			log.Printf("No se pudo procesar un producto: %v", err)

			writeJSON(w, http.StatusInternalServerError, ErrorResponse{
				Error: "No se pudieron procesar los productos",
			})

			return
		}

		products = append(products, product)
	}

	if err := rows.Err(); err != nil {
		log.Printf("Error durante la lectura de productos: %v", err)

		writeJSON(w, http.StatusInternalServerError, ErrorResponse{
			Error: "La consulta de productos fue interrumpida",
		})

		return
	}

	writeJSON(w, http.StatusOK, products)
}

func (handler *ProductsHandler) GetSecureByID(
	w http.ResponseWriter,
	r *http.Request,
) {
	idText := r.PathValue("id")

	productID, err := strconv.ParseUint(idText, 10, 64)
	if err != nil || productID == 0 {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: "El identificador debe ser un entero positivo",
		})

		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	const query = `
		SELECT
			id,
			name,
			description,
			price,
			is_active
		FROM products
		WHERE id = ?
		AND is_active = TRUE
	`

	var product Product

	err = handler.database.QueryRowContext(
		ctx,
		query,
		productID,
	).Scan(
		&product.ID,
		&product.Name,
		&product.Description,
		&product.Price,
		&product.IsActive,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			writeJSON(w, http.StatusNotFound, ErrorResponse{
				Error: "Producto no encontrado",
			})

			return
		}

		log.Printf(
			"No se pudo consultar el producto %d: %v",
			productID,
			err,
		)

		writeJSON(w, http.StatusInternalServerError, ErrorResponse{
			Error: "No se pudo obtener el producto",
		})

		return
	}

	response := ProductResponse{
		Product: product,
		QueryTemplate: `
SELECT id, name, description, price, is_active
FROM products
WHERE id = ?
AND is_active = TRUE
		`,
		Parameters: map[string]uint64{
			"id": productID,
		},
		SecurityMode: "prepared_statement",
	}

	writeJSON(w, http.StatusOK, response)
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("No se pudo escribir la respuesta JSON: %v", err)
	}
}
