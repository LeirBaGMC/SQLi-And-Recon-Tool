package remediation

import (
	"testing"

	"github.com/LeirBaGMC/sql-scanner/models"
)

func TestGenerateReportWithFindings(t *testing.T) {
	findings := []models.Finding{
		{
			ID:            1,
			ScanID:        "test-scan-1",
			Category:      "SQL_INJECTION_BOOLEAN",
			Severity:      "HIGH",
			Confidence:    "HIGH",
			TestedURL:     "http://vulnerable-app:8081/api/vulnerable/products?id=1%20OR%201=1",
			ParameterName: "id",
		},
	}

	report := GenerateReport("test-scan-1", findings, "sandbox")
	if report == nil {
		t.Fatal("se esperaba un reporte generado, se obtuvo nil")
	}

	if report.RiskLevel != "CRITICAL" {
		t.Fatalf("se esperaba nivel de riesgo CRITICAL, se obtuvo: %s", report.RiskLevel)
	}

	if len(report.Recommendations) == 0 {
		t.Fatal("se esperaban recomendaciones defensivas en el informe")
	}

	if len(report.CodeExamples) == 0 {
		t.Fatal("se esperaban ejemplos de codigo seguro en el informe")
	}

	if report.KernelDefensePolicy == "" {
		t.Fatal("se esperaba una politica de defensa en Kernel (eBPF/Tetragon)")
	}
}

func TestGenerateReportSecure(t *testing.T) {
	report := GenerateReport("test-scan-secure", nil, "secure-app")
	if report == nil {
		t.Fatal("se esperaba un reporte generado, se obtuvo nil")
	}

	if report.RiskLevel != "SECURE" {
		t.Fatalf("se esperaba nivel de riesgo SECURE, se obtuvo: %s", report.RiskLevel)
	}

	if len(report.Recommendations) == 0 {
		t.Fatal("se esperaban recomendaciones defensivas")
	}
}
