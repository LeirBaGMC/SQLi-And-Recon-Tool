package router

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestForeignOriginCannotStartScan(t *testing.T) {
	t.Setenv("SCANNER_ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")
	router := SetupRouter(nil)
	for _, origin := range []string{"https://untrusted.example", "null", "http://localhost:3000.attacker.example"} {
		request := httptest.NewRequest(http.MethodPost, "/api/scans", strings.NewReader(`{"mode":"dvwa","target":"dvwa"}`))
		request.Header.Set("Origin", origin)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden || response.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("foreign browser reached API: %s %d", origin, response.Code)
		}
	}
}

func TestAllowedDashboardPreflightAndNonBrowserRequests(t *testing.T) {
	t.Setenv("SCANNER_ALLOWED_ORIGINS", "http://localhost:3100,http://127.0.0.1:3100")
	router := SetupRouter(nil)
	request := httptest.NewRequest(http.MethodOptions, "/api/scans", nil)
	request.Header.Set("Origin", "http://127.0.0.1:3100")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || response.Header().Get("Access-Control-Allow-Origin") != "http://127.0.0.1:3100" {
		t.Fatal("dashboard preflight failed")
	}
	request = httptest.NewRequest(http.MethodGet, "/missing", nil)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatal("non-browser client blocked")
	}
}
