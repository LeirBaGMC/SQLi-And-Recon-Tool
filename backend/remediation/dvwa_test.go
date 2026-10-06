package remediation

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/LeirBaGMC/sql-scanner/models"
)

func regressionEvidence(level string) []models.ScanEventResponse {
	var events []models.ScanEventResponse
	add := func(kind string, value any) {
		body, _ := json.Marshal(value)
		events = append(events, models.ScanEventResponse{EventType: kind, Message: string(body)})
	}
	method := "GET"
	if level == "medium" {
		method = "POST"
	}
	trueValue, falseValue := "1' AND '1'='1", "1' AND '1'='2"
	if level == "medium" {
		trueValue, falseValue = "1 AND 1=1", "1 AND 1=2"
	}
	values := []string{"1", "1'", trueValue, falseValue, trueValue, falseValue}
	for n := 1; n <= 6; n++ {
		status, rows, validation := 200, 0, "rejected"
		if n == 1 {
			rows, validation = 1, "accepted"
		}
		add("LAB_ACTIVITY", models.LabActivityEvent{StepID: fmt.Sprintf("probe-%d", n), Stage: "probe", State: "completed", Level: level, Method: method, Payload: values[n-1], StatusCode: &status, Records: &rows, ValidationResult: validation})
	}
	for _, name := range []string{"DVWA · Error SQL", "DVWA · Comparacion booleana"} {
		add("PAYLOAD_EXECUTED", models.PayloadExecutionEvent{Name: name, Result: "NOT_DETECTED", ExecutionType: "REAL", DVWALevel: level})
	}
	return events
}

func TestCorrectedReportRequiresMeasuredEvidence(t *testing.T) {
	for _, level := range []string{"Low", "Medium", "High"} {
		t.Run(level, func(t *testing.T) {
			scan := &models.ScanStatusResponse{ScanID: "test", Status: "COMPLETED", TargetName: "DVWA · SQL Injection (" + level + ") · Corregido"}
			lower := map[string]string{"Low": "low", "Medium": "medium", "High": "high"}[level]
			for _, tc := range []struct {
				name   string
				events []models.ScanEventResponse
				status string
				want   string
			}{
				{"valid", regressionEvidence(lower), "COMPLETED", "HTTP_RETEST_PASSED"},
				{"empty", nil, "COMPLETED", "INCONCLUSIVE"},
				{"missing", regressionEvidence(lower)[1:], "COMPLETED", "INCONCLUSIVE"},
				{"failed", regressionEvidence(lower), "FAILED", "INCONCLUSIVE"},
				{"running", regressionEvidence(lower), "RUNNING", "INCONCLUSIVE"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					scan.Status = tc.status
					report := GenerateScanReport(scan, nil, tc.events)
					if report.BlueTeam.Verification != tc.want || report.BlueTeam.SensorStatus != "NOT_CONNECTED" {
						t.Fatalf("wrong verdict: %+v", report.BlueTeam)
					}
				})
			}
		})
	}
}

func TestCorrectedReportRejectsBlockedOrUnmarkedOrDuplicateEvidence(t *testing.T) {
	scan := &models.ScanStatusResponse{ScanID: "test", Status: "COMPLETED", TargetName: "DVWA · SQL Injection (Medium) · Corregido"}
	for _, change := range []func(*models.LabActivityEvent){
		func(a *models.LabActivityEvent) { code := 403; a.StatusCode = &code },
		func(a *models.LabActivityEvent) { a.ValidationResult = "" },
		func(a *models.LabActivityEvent) { a.State = "failed" },
		func(a *models.LabActivityEvent) { a.Method = "GET" },
		func(a *models.LabActivityEvent) { a.Payload = "1" },
	} {
		events := regressionEvidence("medium")
		var request models.LabActivityEvent
		_ = json.Unmarshal([]byte(events[1].Message), &request)
		change(&request)
		body, _ := json.Marshal(request)
		events[1].Message = string(body)
		if GenerateScanReport(scan, nil, events).BlueTeam.Verification == "HTTP_RETEST_PASSED" {
			t.Fatal("invalid evidence certified correction")
		}
	}
	events := regressionEvidence("medium")
	events = append(events, events[1])
	if GenerateScanReport(scan, nil, events).BlueTeam.Verification == "HTTP_RETEST_PASSED" {
		t.Fatal("duplicate evidence accepted")
	}
	if GenerateScanReport(scan, []models.Finding{{Severity: "HIGH"}}, regressionEvidence("medium")).BlueTeam.Verification != "REGRESSION_DETECTED" {
		t.Fatal("regression ignored")
	}
}

func TestExternalAndLegacyLabelsDoNotActivateBlueTeamVerification(t *testing.T) {
	for _, name := range []string{"URL externa autorizada", "secure-app", "dvwa"} {
		scan := &models.ScanStatusResponse{TargetName: name, Status: "COMPLETED"}
		if GenerateScanReport(scan, nil, regressionEvidence("medium")).BlueTeam != nil {
			t.Fatal("non-DVWA target has a correction verdict")
		}
	}
}
