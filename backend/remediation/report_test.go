package remediation

import (
	"strings"
	"testing"

	"github.com/LeirBaGMC/sql-scanner/models"
)

func TestExternalReportDoesNotClaimKernelEvidenceOrProtection(t *testing.T) {
	for _, mode := range []string{"authorized_url", "URL externa autorizada", "dvwa", "DVWA · SQL Injection (Low)", "DVWA · SQL Injection (Medium)"} {
		noFindings := GenerateReport("external", nil, mode)
		if noFindings.RiskLevel == "SECURE" {
			t.Fatal("external report claimed protection")
		}
		withFindings := GenerateReport("external", []models.Finding{{Severity: "HIGH", Confidence: "HTTP_ONLY"}}, mode)
		if strings.Contains(withFindings.Summary, "validación dual") {
			t.Fatal("external report claimed kernel evidence")
		}
	}
}

func TestDVWAMediumRemediationUsesPOSTAndNumericContext(t *testing.T) {
	report := GenerateReport("medium", []models.Finding{{Severity: "HIGH", Confidence: "HTTP_ONLY"}}, "DVWA · SQL Injection (Medium)")
	if len(report.CodeExamples) != 1 {
		t.Fatal("expected one DVWA-specific example")
	}
	example := report.CodeExamples[0]
	if !strings.Contains(example.VulnerableCode, "$_POST['id']") || !strings.Contains(example.VulnerableCode, "user_id = $id") || !strings.Contains(example.SecureCode, "INPUT_POST") || strings.Contains(example.SecureCode, "INPUT_GET") {
		t.Fatalf("Medium remediation has the wrong input context: %+v", example)
	}
}

func TestGenerateReportWithFindings(t *testing.T) {
	findings := []models.Finding{
		{
			ID:            1,
			ScanID:        "test-scan-1",
			Category:      "SQL_INJECTION_BOOLEAN",
			Severity:      "HIGH",
			Confidence:    "HIGH",
			TestedURL:     "http://localhost/products?id=1%20AND%201=2",
			ParameterName: "id",
		},
	}

	report := GenerateReport("test-scan-1", findings, "sandbox")
	if report == nil {
		t.Fatal("se esperaba un reporte generado, se obtuvo nil")
	}

	if report.RiskLevel != "HIGH" {
		t.Fatalf("se esperaba nivel de riesgo HIGH, se obtuvo: %s", report.RiskLevel)
	}

	if len(report.Recommendations) == 0 {
		t.Fatal("se esperaban recomendaciones defensivas en el informe")
	}

	if len(report.CodeExamples) == 0 {
		t.Fatal("se esperaban ejemplos de codigo seguro en el informe")
	}

	if strings.Contains(report.Summary, "validación dual") {
		t.Fatal("un nombre histórico no debe activar evidencia de kernel inexistente")
	}
}

func TestLegacyTargetWithoutFindingsRemainsUndetermined(t *testing.T) {
	report := GenerateReport("test-scan-secure", nil, "secure-app")
	if report == nil {
		t.Fatal("se esperaba un reporte generado, se obtuvo nil")
	}

	if report.RiskLevel != "UNDETERMINED" {
		t.Fatalf("se esperaba nivel de riesgo UNDETERMINED, se obtuvo: %s", report.RiskLevel)
	}

	if len(report.Recommendations) == 0 {
		t.Fatal("se esperaban recomendaciones defensivas")
	}
}
