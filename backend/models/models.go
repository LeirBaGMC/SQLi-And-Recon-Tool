package models

import "time"

// ScanRequest representa la solicitud de inicio de un escaneo enviada desde el frontend.
type ScanRequest struct {
	Mode                   string `json:"mode"`
	Target                 string `json:"target"`
	URL                    string `json:"url"`
	AuthorizationConfirmed bool   `json:"authorization_confirmed"`
	MaxWorkers             int    `json:"max_workers,omitempty"`
}

// ScanStatusResponse representa el estado de un escaneo para la API REST.
type ScanStatusResponse struct {
	ID                string             `json:"id"`
	ScanID            string             `json:"scan_id"`
	TargetName        string             `json:"target_name"`
	TargetURL         string             `json:"target_url"`
	Parameter         string             `json:"parameter,omitempty"`
	OriginalValue     string             `json:"original_value,omitempty"`
	Status            string             `json:"status"` // QUEUED, RUNNING, COMPLETED, FAILED
	ErrorMessage      string             `json:"error_message,omitempty"`
	RemediationReport *RemediationReport `json:"remediation_report,omitempty"`
	CreatedAt         string             `json:"created_at"`
	StartedAt         string             `json:"started_at,omitempty"`
	CompletedAt       string             `json:"completed_at,omitempty"`
}

// ScanTask representa una tarea individual enviada al Worker Pool concurrente.
type ScanTask struct {
	ID          string `json:"id"`
	ScanID      string `json:"scan_id"`
	TraceID     string `json:"trace_id"`
	TargetURL   string `json:"target_url"`
	Parameter   string `json:"parameter"`
	Payload     string `json:"payload"`
	ProbeType   string `json:"probe_type"` // Error, Boolean, Time, Extraction
	Risk        string `json:"risk"`       // LOW, MEDIUM, HIGH, CRITICAL
	Description string `json:"description"`
}

// HTTPConfirmation detalla la evidencia obtenida desde la respuesta HTTP (Red Team).
type HTTPConfirmation struct {
	Confirmed       bool   `json:"confirmed"`
	StatusCode      int    `json:"status_code"`
	LatencyMS       uint64 `json:"latency_ms"`
	EvidenceSummary string `json:"evidence_summary"`
	ErrorSignature  string `json:"error_signature,omitempty"`
}

// KernelConfirmation detalla la telemetría observada en el Kernel / socket de base de datos (Blue Team).
type KernelConfirmation struct {
	Confirmed        bool   `json:"confirmed"`
	TraceID          string `json:"trace_id"`
	TargetSocket     string `json:"target_socket"`     // e.g. "lab-db:3306"
	InterceptedQuery string `json:"intercepted_query"` // Consulta SQL que llegó al motor de BD
	Sensor           string `json:"sensor"`            // e.g. "Tetragon / eBPF (sys_enter_write)"
}

// DualConfirmation consolida la validación en capa HTTP y capa de Kernel.
type DualConfirmation struct {
	HTTP   HTTPConfirmation   `json:"http"`
	Kernel KernelConfirmation `json:"kernel"`
}

// Finding representa un hallazgo de vulnerabilidad confirmado.
type Finding struct {
	ID               uint64            `json:"id"`
	ScanID           string            `json:"scan_id"`
	Category         string            `json:"category"` // SQL_INJECTION_BOOLEAN, SQL_INJECTION_DATA_EXPOSURE, etc.
	Severity         string            `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Confidence       string            `json:"confidence"`
	TestedURL        string            `json:"tested_url"`
	ParameterName    string            `json:"parameter_name,omitempty"`
	Payload          string            `json:"payload,omitempty"`
	Evidence         string            `json:"evidence,omitempty"`
	BaselineMS       uint64            `json:"baseline_ms,omitempty"`
	ObservedMS       uint64            `json:"observed_ms,omitempty"`
	HTTPStatus       uint16            `json:"http_status,omitempty"`
	DualConfirmation *DualConfirmation `json:"dual_confirmation,omitempty"`
	CreatedAt        string            `json:"created_at"`
}

// ScanEventResponse representa un evento registrado durante el ciclo de vida del escaneo.
type ScanEventResponse struct {
	ID        uint64 `json:"id"`
	ScanID    string `json:"scan_id"`
	EventType string `json:"event_type"`
	Message   string `json:"message"`
	CreatedAt string `json:"created_at"`
}

// LabProduct representa un producto ficticio en el catálogo del laboratorio vulnerable.
type LabProduct struct {
	ID          uint64  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Price       float64 `json:"price"`
	IsActive    bool    `json:"is_active"`
}

// VulnerableResponse es el contrato de respuesta del endpoint del laboratorio vulnerable.
type VulnerableResponse struct {
	Products       []LabProduct `json:"products"`
	SecurityMode   string       `json:"security_mode"`
	ReceivedInput  string       `json:"received_input"`
	ExecutedQuery  string       `json:"executed_query"`
	Risk           string       `json:"risk"`
	Recommendation string       `json:"recommendation"`
}

// PayloadExecutionEvent es el evento emitido a scan_events para renderizado en tiempo real en la UI.
type PayloadExecutionEvent struct {
	Name               string       `json:"name"`
	Parameter          string       `json:"parameter"`
	Payload            string       `json:"payload"`
	TestedURL          string       `json:"tested_url,omitempty"`
	StatusCode         int          `json:"status_code,omitempty"`
	BaselineSize       int          `json:"baseline_size,omitempty"`
	ObservedSize       int          `json:"observed_size,omitempty"`
	Risk               string       `json:"risk"`
	Result             string       `json:"result"` // DETECTED, NOT_DETECTED, SIMULATED
	Reason             string       `json:"reason"`
	Remediation        string       `json:"remediation"`
	ExecutionType      string       `json:"execution_type"` // REAL, SIMULATED
	HypotheticalResult string       `json:"hypothetical_result,omitempty"`
	RecordsExposed     int          `json:"records_exposed,omitempty"`
	ExposedSample      []LabProduct `json:"exposed_sample,omitempty"`
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
	ScanID              string           `json:"scan_id"`
	Summary             string           `json:"summary"`
	CWE                 string           `json:"cwe"`
	RiskLevel           string           `json:"risk_level"`
	Recommendations     []string         `json:"recommendations"`
	CodeExamples        []CodeComparison `json:"code_examples"`
	KernelDefensePolicy string           `json:"kernel_defense_policy,omitempty"`
	GeneratedAt         time.Time        `json:"generated_at"`
}

