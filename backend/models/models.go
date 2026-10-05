package models

import "time"

// ScanRequest representa la solicitud de inicio de un escaneo enviada desde el frontend.
type ScanRequest struct {
	Mode                   string `json:"mode"`
	Target                 string `json:"target"`
	URL                    string `json:"url"`
	AuthorizationConfirmed bool   `json:"authorization_confirmed"`
	DVWALevel              string `json:"dvwa_level,omitempty"`
}

// ScanStatusResponse representa el estado de un escaneo para la API REST.
type ScanStatusResponse struct {
	ID           string `json:"id"`
	ScanID       string `json:"scan_id"`
	TargetName   string `json:"target_name"`
	TargetURL    string `json:"target_url"`
	Parameter    string `json:"parameter,omitempty"`
	Status       string `json:"status"` // QUEUED, RUNNING, COMPLETED, FAILED
	ErrorMessage string `json:"error_message,omitempty"`
	CreatedAt    string `json:"created_at"`
	StartedAt    string `json:"started_at,omitempty"`
	CompletedAt  string `json:"completed_at,omitempty"`
}

// Finding representa un hallazgo de vulnerabilidad confirmado.
type Finding struct {
	ID            uint64 `json:"id"`
	ScanID        string `json:"scan_id"`
	Category      string `json:"category"` // SQL_INJECTION_BOOLEAN, SQL_INJECTION_DATA_EXPOSURE, etc.
	Severity      string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Confidence    string `json:"confidence"`
	TestedURL     string `json:"tested_url"`
	ParameterName string `json:"parameter_name,omitempty"`
	Payload       string `json:"payload,omitempty"`
	Evidence      string `json:"evidence,omitempty"`
	BaselineMS    uint64 `json:"baseline_ms,omitempty"`
	ObservedMS    uint64 `json:"observed_ms,omitempty"`
	HTTPStatus    uint16 `json:"http_status,omitempty"`
	CreatedAt     string `json:"created_at"`
}

// ScanEventResponse representa un evento registrado durante el ciclo de vida del escaneo.
type ScanEventResponse struct {
	ID        uint64 `json:"id"`
	ScanID    string `json:"scan_id"`
	EventType string `json:"event_type"`
	Message   string `json:"message"`
	CreatedAt string `json:"created_at"`
}

// PayloadExecutionEvent es el evento emitido a scan_events para renderizado en tiempo real en la UI.
type PayloadExecutionEvent struct {
	OriginalValue      *string      `json:"original_value,omitempty"`
	EncodedQuery       string       `json:"encoded_query,omitempty"`
	FinalURL           string       `json:"final_url,omitempty"`
	Checks             []ProbeCheck `json:"checks,omitempty"`
	CoverageNote       string       `json:"coverage_note,omitempty"`
	Method             string       `json:"method,omitempty"`
	RequestBody        string       `json:"request_body,omitempty"`
	DVWALevel          string       `json:"dvwa_level,omitempty"`
	BaselineDurationMS *uint64      `json:"baseline_duration_ms,omitempty"`
	ObservedDurationMS *uint64      `json:"observed_duration_ms,omitempty"`
	Name               string       `json:"name"`
	Parameter          string       `json:"parameter"`
	Payload            string       `json:"payload"`
	TestedURL          string       `json:"tested_url,omitempty"`
	StatusCode         int          `json:"status_code,omitempty"`
	BaselineSize       int          `json:"baseline_size"`
	ObservedSize       int          `json:"observed_size"`
	BaselineRecords    *int         `json:"baseline_records,omitempty"`
	TrueRecords        *int         `json:"true_records,omitempty"`
	ObservedRecords    *int         `json:"observed_records,omitempty"`
	Risk               string       `json:"risk"`
	Result             string       `json:"result"` // DETECTED, NOT_DETECTED, INCONCLUSIVE
	Reason             string       `json:"reason"`
	Remediation        string       `json:"remediation"`
	ExecutionType      string       `json:"execution_type"` // REAL; las demostraciones antiguas solo se leen en el frontend
}

// LabActivityEvent contains only public request metadata; never auth bodies,
// cookies, credentials, CSRF tokens or returned user records.
type LabActivityEvent struct {
	OriginalValue *string      `json:"original_value,omitempty"`
	EncodedQuery  string       `json:"encoded_query,omitempty"`
	FinalURL      string       `json:"final_url,omitempty"`
	Checks        []ProbeCheck `json:"checks,omitempty"`
	StepID        string       `json:"step_id"`
	Stage         string       `json:"stage"`
	State         string       `json:"state"`
	Summary       string       `json:"summary"`
	Level         string       `json:"level"`
	Method        string       `json:"method,omitempty"`
	URL           string       `json:"url,omitempty"`
	Payload       string       `json:"payload,omitempty"`
	Parameter     string       `json:"parameter,omitempty"`
	RequestNumber int          `json:"request_number,omitempty"`
	RequestTotal  int          `json:"request_total,omitempty"`
	StatusCode    *int         `json:"status_code,omitempty"`
	DurationMS    *uint64      `json:"duration_ms,omitempty"`
	ResponseBytes *int         `json:"response_bytes,omitempty"`
	Records       *int         `json:"records,omitempty"`
	Detail        string       `json:"detail,omitempty"`
}

// ProbeCheck stores measured comparisons, without storing response bodies.
type ProbeCheck struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// CodeComparison proporciona un ejemplo de código vulnerable vs código seguro.
type CodeComparison struct {
	Language       string `json:"language"`
	Title          string `json:"title"`
	VulnerableCode string `json:"vulnerable_code"`
	SecureCode     string `json:"secure_code"`
	Explanation    string `json:"explanation"`
}

// RemediationReport representa el informe técnico defensivo generado al finalizar el análisis.
type RemediationReport struct {
	ScanID          string           `json:"scan_id"`
	Summary         string           `json:"summary"`
	CWE             string           `json:"cwe"`
	RiskLevel       string           `json:"risk_level"`
	Recommendations []string         `json:"recommendations"`
	CodeExamples    []CodeComparison `json:"code_examples"`
	GeneratedAt     time.Time        `json:"generated_at"`
}
