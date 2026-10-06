package remediation

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/LeirBaGMC/sql-scanner/models"
)

// GenerateScanReport derives a regression verdict from persisted request evidence.
// A target label or zero findings alone cannot certify a correction.
func GenerateScanReport(scan *models.ScanStatusResponse, findings []models.Finding, events []models.ScanEventResponse) *models.RemediationReport {
	report := GenerateReport(scan.ScanID, findings, scan.TargetName)
	if !strings.HasPrefix(scan.TargetName, "DVWA · SQL Injection (") {
		return report
	}
	level := "low"
	if strings.Contains(scan.TargetName, "(Medium)") {
		level = "medium"
	}
	if strings.Contains(scan.TargetName, "(High)") {
		level = "high"
	}
	team := &models.BlueTeamReport{
		Level: level, Variant: "vulnerable", Verification: "PATCH_AVAILABLE",
		VerificationNote: "La variante corregida está disponible. Ejecuta una reprueba con el mismo nivel para medir su comportamiento HTTP.",
		PatchPath:        "infrastructure/dvwa/fixed/index.php", SensorStatus: "NOT_CONNECTED",
	}
	report.BlueTeam = team
	report.CodeExamples = []models.CodeComparison{dvwaCodeExample(level)}
	report.Recommendations = []string{
		"Usar la variante local corregida: validar id y vincularlo a una sentencia preparada mysqli; codificar la salida HTML.",
		"Repetir las seis peticiones en el mismo nivel. Una consulta legítima debe devolver el registro y las cinco entradas SQL deben rechazarse con respuesta explícita.",
		"Revisar por separado los permisos de base de datos. El usuario compartido de DVWA requiere funciones de otros módulos y setup; la reprueba no demuestra mínimo privilegio.",
		"Añadir observabilidad eBPF en el host Linux y correlación de eventos antes de considerar políticas de respuesta.",
	}
	if !strings.Contains(scan.TargetName, " · Corregido") {
		return report
	}
	team.Variant, team.Verification = "prepared", "INCONCLUSIVE"
	team.VerificationNote = "La reprueba no cumple todos los criterios. Revisa estado, respuestas HTTP y validación explícita; cero hallazgos no certifica la corrección."
	if len(findings) > 0 {
		team.Verification = "REGRESSION_DETECTED"
		team.VerificationNote = "Se detectó SQL Injection en la variante corregida. Mantén el hallazgo abierto y revisa el módulo desplegado."
	}
	requests := map[string]models.LabActivityEvent{}
	probes := map[string]string{}
	invalid := false
	for _, event := range events {
		switch event.EventType {
		case "SCAN_INCONCLUSIVE", "SCAN_FAILED":
			invalid = true
		case "LAB_ACTIVITY":
			var activity models.LabActivityEvent
			if json.Unmarshal([]byte(event.Message), &activity) != nil {
				invalid = true
				continue
			}
			if activity.Stage != "probe" || activity.State == "running" {
				continue
			}
			if _, exists := requests[activity.StepID]; exists {
				invalid = true
			}
			requests[activity.StepID] = activity
		case "PAYLOAD_EXECUTED":
			var probe models.PayloadExecutionEvent
			if json.Unmarshal([]byte(event.Message), &probe) != nil {
				invalid = true
				continue
			}
			if _, exists := probes[probe.Name]; exists {
				invalid = true
			}
			if probe.ExecutionType != "REAL" || probe.DVWALevel != level {
				invalid = true
			}
			probes[probe.Name] = probe.Result
		}
	}
	team.MeasuredRequests = len(requests)
	trueValue, falseValue := "1' AND '1'='1", "1' AND '1'='2"
	if level == "medium" {
		trueValue, falseValue = "1 AND 1=1", "1 AND 1=2"
	}
	values := []string{"1", "1'", trueValue, falseValue, trueValue, falseValue}
	for n := 1; n <= 6; n++ {
		request, exists := requests[fmt.Sprintf("probe-%d", n)]
		method := "GET"
		if level == "medium" {
			method = "POST"
		}
		if !exists || request.State != "completed" || request.StatusCode == nil || *request.StatusCode != 200 || request.Level != level || request.Method != method || request.Records == nil || request.Payload != values[n-1] {
			invalid = true
			continue
		}
		if n == 1 {
			team.BaselineRecords = *request.Records
			if *request.Records != 1 || request.ValidationResult != "accepted" || request.Payload != "1" {
				invalid = true
			}
		} else if request.ValidationResult == "rejected" && *request.Records == 0 {
			team.RejectedInputs++
		} else {
			invalid = true
		}
	}
	if len(findings) == 0 && !invalid && scan.Status == "COMPLETED" && len(requests) == 6 && len(probes) == 2 && probes["DVWA · Error SQL"] == "NOT_DETECTED" && probes["DVWA · Comparacion booleana"] == "NOT_DETECTED" && team.RejectedInputs == 5 {
		team.Verification = "HTTP_RETEST_PASSED"
		team.VerificationNote = "Reprueba HTTP aprobada: id=1 devuelve un registro y las cinco entradas SQL fueron rechazadas explícitamente sin registros. Alcance: estas sondas y este nivel; sin evidencia de kernel ni certificación global."
	}
	return report
}

func dvwaCodeExample(level string) models.CodeComparison {
	input := "$_GET['id'] ?? null"
	vulnerable := "$id = $_GET['id'];\n$sql = \"SELECT first_name, last_name FROM users WHERE user_id = '$id'\";"
	if level == "medium" {
		input = "$_POST['id'] ?? null"
		vulnerable = "$id = mysqli_real_escape_string($connection, $_POST['id']);\n$sql = \"SELECT first_name, last_name FROM users WHERE user_id = $id\";"
	}
	if level == "high" {
		input = "$_SESSION['workshop_fixed_id'] ?? null"
		vulnerable = "$id = $_SESSION['id'];\n$sql = \"SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1\";"
	}
	return models.CodeComparison{
		Language: "PHP (mysqli)", Title: "Corrección aplicada en la variante local DVWA",
		VulnerableCode: vulnerable + "\n$result = mysqli_query($connection, $sql);",
		SecureCode: "$input = " + input + `;
$id = is_string($input) ? filter_var($input, FILTER_VALIDATE_INT) : false;
if ($id === false || $id < 1) {
    // Rechazar antes de ejecutar SQL.
} else {
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    $stmt = mysqli_prepare($GLOBALS['___mysqli_ston'],
        'SELECT first_name, last_name FROM users WHERE user_id = ? LIMIT 1');
    mysqli_stmt_bind_param($stmt, 'i', $id);
    mysqli_stmt_execute($stmt);
    // Codificar los valores con htmlspecialchars antes de renderizar.
    mysqli_stmt_close($stmt);
}`,
		Explanation: "Extracto del módulo infrastructure/dvwa/fixed/index.php. Low usa GET, Medium POST y High una sesión propia del control corregido. La validación ocurre al consultar y la sentencia vincula id como entero. Los errores se registran sin detalles SQL en la respuesta.",
	}
}
