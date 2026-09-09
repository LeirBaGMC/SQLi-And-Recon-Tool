package handlers

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"strings"
	"time"
)

type VulnerableProductsHandler struct {
	database *sql.DB
	mode     string
}

type VulnerableProductResponse struct {
	Products       []Product `json:"products"`
	ReceivedInput  string    `json:"received_input"`
	QueryTemplate  string    `json:"query_template"`
	ExecutedQuery  string    `json:"executed_query"`
	SecurityMode   string    `json:"security_mode"`
	Risk           string    `json:"risk"`
	Recommendation string    `json:"recommendation"`
	Warning        string    `json:"warning"`
}

func NewVulnerableProductsHandler(
	database *sql.DB,
	mode string,
) *VulnerableProductsHandler {
	return &VulnerableProductsHandler{
		database: database,
		mode:     mode,
	}
}

func (handler *VulnerableProductsHandler) GetByID(
	w http.ResponseWriter,
	r *http.Request,
) {
	if handler.mode != "vulnerable" {
		writeJSON(w, http.StatusNotFound, ErrorResponse{
			Error: "Endpoint no disponible",
		})
		return
	}

	productID := strings.TrimSpace(r.URL.Query().Get("id"))

	if productID == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: "El parametro id es obligatorio",
		})
		return
	}

	if len(productID) > 100 {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: "El parametro id supera el limite permitido",
		})
		return
	}

	ctx, cancel := context.WithTimeout(
		r.Context(),
		3*time.Second,
	)
	defer cancel()

	query := `
		SELECT
			id,
			name,
			description,
			price,
			is_active
		FROM products
		WHERE id = ` + productID + `
		AND is_active = TRUE
	`

	log.Printf(
		"LAB EDUCATIVO: ejecutando consulta concatenada: %s",
		query,
	)

	rows, err := handler.database.QueryContext(ctx, query)
	if err != nil {
		log.Printf(
			"Error SQL controlado en endpoint vulnerable: %v",
			err,
		)

		writeJSON(
			w,
			http.StatusInternalServerError,
			map[string]string{
				"error":          "La consulta SQL no pudo ejecutarse",
				"database_error": err.Error(),
				"executed_query": query,
				"security_mode":  "unsafe_concatenation",
			},
		)
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
			log.Printf(
				"No se pudo procesar el resultado vulnerable: %v",
				err,
			)

			writeJSON(
				w,
				http.StatusInternalServerError,
				ErrorResponse{
					Error: "No se pudo procesar el resultado",
				},
			)
			return
		}

		products = append(products, product)
	}

	if err := rows.Err(); err != nil {
		log.Printf(
			"Error al recorrer los resultados vulnerables: %v",
			err,
		)

		writeJSON(
			w,
			http.StatusInternalServerError,
			ErrorResponse{
				Error: "La lectura del resultado fue interrumpida",
			},
		)
		return
	}

	response := VulnerableProductResponse{
		Products:      products,
		ReceivedInput: productID,
		QueryTemplate: `
SELECT id, name, description, price, is_active
FROM products
WHERE id = [ENTRADA_DEL_USUARIO]
AND is_active = TRUE
	`,
		ExecutedQuery:  query,
		SecurityMode:   "unsafe_concatenation",
		Risk:           "La entrada del usuario forma parte del texto de la consulta SQL",
		Recommendation: "Utilizar una consulta preparada con un marcador de parametro",
		Warning:        "Endpoint deliberadamente vulnerable para uso educativo",
	}
	writeJSON(w, http.StatusOK, response)
}
