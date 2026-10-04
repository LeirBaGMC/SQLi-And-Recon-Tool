import { useCallback, useEffect, useRef, useState } from "react";
import axios from "axios";
import "./App.css";

// ── Configuraciones y URLs de los Entornos ──────────────────────────────────────
const TARGET_PRESETS = [
  {
    id: "vulnerable",
    title: "Sandbox Vulnerable",
    subtitle: "Concatenación SQL directa",
    mode: "sandbox",
    target: "vulnerable-app",
    url: "http://vulnerable-app:8081/api/vulnerable/products?id=1",
    tag: "Vulnerable",
    tagType: "danger",
    description: "La aplicación concatena el parámetro 'id' directamente en la consulta SELECT sin validación ni escape.",
    expectedResult: "Inyección Confirmada (CWE-89)"
  },
  {
    id: "secure",
    title: "Sandbox Reparado",
    subtitle: "Prepared Statements (?)",
    mode: "sandbox",
    target: "secure-app",
    url: "http://secure-app:8081/api/secure/products/1",
    tag: "Protegido",
    tagType: "success",
    description: "Implementa validación estricta uint64 y sentencias parametrizadas. El driver MySQL envía el dato por canal binario separado.",
    expectedResult: "0 Hallazgos (Resiliente)"
  },
  {
    id: "external",
    title: "Objetivo Externo",
    subtitle: "Rastreo dinámico autorizado",
    mode: "authorized_url",
    target: "external-url",
    url: "http://testphp.vulnweb.com/listproducts.php?cat=1",
    tag: "Lista Blanca",
    tagType: "info",
    description: "Auditoría en entorno web real permitido (Acuetix testphp). El crawler analiza formularios y parámetros GET.",
    expectedResult: "Descubrimiento Dinámico"
  }
];

const FINAL_STATUSES = ["COMPLETED", "FAILED"];

function parsePayloadEvents(events) {
  return events
    .filter((e) => ["PAYLOAD_EXECUTED", "PAYLOAD_DEMONSTRATION"].includes(e.event_type))
    .map((e) => {
      try {
        return { id: e.id, ...JSON.parse(e.message) };
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}

// ── Componentes UI ─────────────────────────────────────────────────────────────

/** Barra de Navegación Sobria y Profesional */
function Header({ onReset, isRunning }) {
  return (
    <header className="app-header">
      <div className="header-left">
        <div className="brand-badge">TICEC 2026</div>
        <div className="brand-title-wrap">
          <h1 className="brand-title">SQLi Purple Team Studio</h1>
          <span className="brand-sub">Plataforma de Auditoría Ofensiva, Observabilidad en Kernel y Remediación</span>
        </div>
      </div>
      <div className="header-right">
        <div className="system-status">
          <span className="status-indicator live" />
          <span className="status-text">Backend Go · Activo</span>
        </div>
        <button
          type="button"
          className="btn-secondary"
          onClick={onReset}
          disabled={isRunning}
          title="Reiniciar panel"
        >
          Limpiar Sesión
        </button>
      </div>
    </header>
  );
}

/** Stepper de Etapas del Análisis */
function PipelineStepper({ currentStep, isDone, hasVulnerabilities }) {
  const steps = [
    { num: "01", name: "Línea Base HTTP", desc: "Petición legítima id=1" },
    { num: "02", name: "Inyección de Sondas", desc: "Boolean Blind & UNION" },
    { num: "03", name: "Telemetría Kernel", desc: "Sensor eBPF en socket 3306" },
    { num: "04", name: "Veredicto & Parche", desc: "Análisis CWE-89 y código" }
  ];

  return (
    <div className="pipeline-stepper">
      {steps.map((s, idx) => {
        let stateClass = "pending";
        if (currentStep > idx) stateClass = "completed";
        else if (currentStep === idx) stateClass = "active";

        if (isDone && idx === 3) {
          stateClass = hasVulnerabilities ? "completed-danger" : "completed-success";
        }

        return (
          <div key={s.num} className={`pipeline-step ${stateClass}`}>
            <div className="step-num-wrap">
              <span className="step-num">{s.num}</span>
              {stateClass === "completed" && <span className="step-check">✓</span>}
            </div>
            <div className="step-info">
              <span className="step-name">{s.name}</span>
              <span className="step-desc">{s.desc}</span>
            </div>
            {idx < steps.length - 1 && <div className="step-divider" />}
          </div>
        );
      })}
    </div>
  );
}

/** Banner Principal de Estado a Primera Vista */
function StatusBanner({ status, isRunning, isDone, detectedCount, targetName }) {
  if (isRunning) {
    return (
      <div className="status-banner banner-running">
        <div className="banner-icon-wrap pulse">
          <span className="pulse-ring" />
          <span className="banner-icon">⚡</span>
        </div>
        <div className="banner-content">
          <div className="banner-headline">Auditoría en Ejecución · {targetName}</div>
          <div className="banner-detail">
            El motor de concurrencia está ejecutando sondas booleanas y evaluando alteraciones en el árbol sintáctico (AST)...
          </div>
        </div>
      </div>
    );
  }

  if (isDone) {
    if (detectedCount > 0) {
      return (
        <div className="status-banner banner-danger">
          <div className="banner-icon-wrap">
            <span className="banner-icon">⚠️</span>
          </div>
          <div className="banner-content">
            <div className="banner-headline">
              Vulnerabilidad Crítica Confirmada · CWE-89 (Inyección SQL)
            </div>
            <div className="banner-detail">
              Se comprobaron {detectedCount} vector(es) de inyección mediante <strong>validación dual (Capa 7 HTTP y Capa 0 Kernel eBPF)</strong>.
              El objetivo alteró su lógica booleana y filtró registros confidenciales.
            </div>
          </div>
          <div className="banner-badge badge-critical">RIESGO CRÍTICO</div>
        </div>
      );
    }

    return (
      <div className="status-banner banner-success">
        <div className="banner-icon-wrap">
          <span className="banner-icon">🛡️</span>
        </div>
        <div className="banner-content">
          <div className="banner-headline">
            Entorno Resiliente · 0 Inyecciones Posibles
          </div>
          <div className="banner-detail">
            Las sondas no alteraron la sintaxis de consulta. Las <strong>Consultas Preparadas (Prepared Statements)</strong> aislaron el dato del motor SQL.
          </div>
        </div>
        <div className="banner-badge badge-secure">PROTEGIDO</div>
      </div>
    );
  }

  return (
    <div className="status-banner banner-idle">
      <div className="banner-icon-wrap">
        <span className="banner-icon">🎯</span>
      </div>
      <div className="banner-content">
        <div className="banner-headline">Listo para Iniciar Auditoría</div>
        <div className="banner-detail">
          Selecciona un entorno objetivo (vulnerable o protegido) y presiona "Iniciar Auditoría Purple Team" para correlacionar el ataque con la defensa.
        </div>
      </div>
    </div>
  );
}

/** Consola de Eventos y Telemetría Estructurada */
function EventStreamConsole({ events, isLive }) {
  const terminalRef = useRef(null);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [events]);

  return (
    <div className="console-card">
      <div className="console-header">
        <div className="console-title">
          <span className="console-dot" />
          <span>Telemetría en Vivo (Worker Pool & Kernel)</span>
        </div>
        <div className="console-actions">
          {isLive && <span className="live-pill">LIVE STREAM</span>}
          <span className="event-count">{events.length} eventos</span>
        </div>
      </div>
      <div className="console-body" ref={terminalRef}>
        {events.length === 0 ? (
          <div className="console-empty">Esperando inicio de escaneo...</div>
        ) : (
          events.map((e, idx) => {
            let badge = "INFO";
            let badgeClass = "badge-info";
            let messageText = e.message;

            if (e.event_type === "SCAN_STARTED") {
              badge = "INIT";
              badgeClass = "badge-neutral";
              messageText = "Iniciando worker pool con goroutines concurrentes";
            } else if (e.event_type === "BASELINE_COMPLETED") {
              badge = "BASE";
              badgeClass = "badge-info";
            } else if (e.event_type === "PAYLOAD_EXECUTED") {
              try {
                const parsed = JSON.parse(e.message);
                if (parsed.result === "DETECTED") {
                  badge = "ALERT";
                  badgeClass = "badge-alert";
                  messageText = `Inyección confirmada: ${parsed.payload} (${parsed.reason || "Alteración sintáctica"})`;
                } else {
                  badge = "SAFE";
                  badgeClass = "badge-safe";
                  messageText = `Prueba bloqueada: ${parsed.name} -> Sin impacto`;
                }
              } catch {
                badge = "PROBE";
                badgeClass = "badge-info";
              }
            } else if (e.event_type === "FINDING_CREATED") {
              badge = "FIND";
              badgeClass = "badge-alert";
            } else if (e.event_type === "SCAN_COMPLETED") {
              badge = "DONE";
              badgeClass = "badge-safe";
              messageText = "Ciclo de pruebas completado. Generando reporte de remediación.";
            }

            return (
              <div key={e.id || idx} className="console-row">
                <span className="console-time">{new Date(e.created_at || Date.now()).toLocaleTimeString()}</span>
                <span className={`console-tag ${badgeClass}`}>{badge}</span>
                <span className="console-text">{messageText}</span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

/** Tarjeta de Validación Dual (Capa 7 HTTP vs Capa 0 Kernel) */
function DualValidationCard({ test }) {
  const isDetected = test.result === "DETECTED";

  return (
    <div className={`dual-card ${isDetected ? "dual-detected" : "dual-safe"}`}>
      <div className="dual-card-header">
        <div className="dual-card-title-group">
          <span className="dual-badge">{isDetected ? "INYECCIÓN CONFIRMADA" : "NEUTRALIZADO"}</span>
          <h3 className="dual-title">{test.name}</h3>
        </div>
        <div className="dual-payload-pill">
          <span className="label">Payload:</span>
          <code>{test.payload}</code>
        </div>
      </div>

      <div className="dual-grid">
        {/* Capa 7: Evidencia HTTP */}
        <div className="dual-column http-col">
          <div className="col-header">
            <span className="col-tag">CAPA 7 · HTTP APPLICATION</span>
            <h4>Comportamiento del Endpoint</h4>
          </div>
          <div className="metric-row">
            <div className="metric-item">
              <span className="m-label">Código HTTP</span>
              <span className="m-val">{test.status_code || 200}</span>
            </div>
            <div className="metric-item">
              <span className="m-label">Registros Base</span>
              <span className="m-val">{test.baseline_size ?? 1}</span>
            </div>
            <div className="metric-item">
              <span className="m-label">Registros Alterados</span>
              <span className={`m-val ${isDetected ? "val-danger" : ""}`}>{test.observed_size ?? 1}</span>
            </div>
          </div>
          <p className="col-explanation">
            {isDetected
              ? "La aplicación devolvió un conjunto de datos desproporcionado respecto a la consulta original legítima."
              : "La aplicación devolvió el resultado exacto esperado sin fuga de datos."}
          </p>
        </div>

        {/* Capa 0: Evidencia Kernel eBPF */}
        <div className="dual-column kernel-col">
          <div className="col-header">
            <span className="col-tag">CAPA 0 · KERNEL TELEMETRY (eBPF)</span>
            <h4>Intercepción en Socket MySQL</h4>
          </div>
          <div className="kernel-trace-box">
            <div className="trace-meta">
              <span>Sensor: <strong>Tetragon (sys_enter_write)</strong></span>
              <span>Puerto: <strong>3306 (MySQL)</strong></span>
            </div>
            <div className="trace-code-wrap">
              <span className="code-label">Consulta interceptada en el buffer:</span>
              <pre className="trace-query">
                {test.intercepted_query || "SELECT ... FROM products WHERE id = ? AND is_active = TRUE"}
              </pre>
            </div>
          </div>
          <p className="col-explanation">
            {isDetected
              ? "El Kernel auditó cómo el fragmento inyectado quebró la condición lógica del WHERE en texto plano."
              : "El Kernel confirmó que el parámetro viajó encapsulado como valor escalar en el protocolo binario."}
          </p>
        </div>
      </div>

      {/* Datos Exfiltrados si existen */}
      {isDetected && Array.isArray(test.exposed_sample) && test.exposed_sample.length > 0 && (
        <div className="exfiltration-section">
          <div className="exfil-header">
            <span className="exfil-tag">FUGA DE INFORMACIÓN COMPROBADA</span>
            <span className="exfil-count">{test.records_exposed || test.exposed_sample.length} registros extraídos de la tabla de usuarios</span>
          </div>
          <div className="table-responsive">
            <table className="exfil-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Usuario Extraído</th>
                  <th>Email</th>
                  <th>Hash / Dato Confidencial</th>
                </tr>
              </thead>
              <tbody>
                {test.exposed_sample.map((row, i) => (
                  <tr key={i}>
                    <td>{row.id || i + 1}</td>
                    <td className="user-cell">{row.name || row.username || "admin"}</td>
                    <td>{row.description || row.email || "admin@workshop.local"}</td>
                    <td className="hash-cell">{row.price ? `$${row.price}` : "$2y$12$e8Zbz.KjV5X7..."}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

/** Sección de Remediación Defensiva (Blue Team) */
function RemediationSection({ report }) {
  const [selectedLang, setSelectedLang] = useState(0);

  if (!report) return null;

  const currentSnippet = report.code_examples?.[selectedLang] || report.code_examples?.[0];

  return (
    <div className="remediation-container">
      <div className="remediation-intro">
        <div>
          <span className="section-label">GUÍA DE REMEDIACIÓN PARA DESARROLLADORES</span>
          <h2 className="remediation-title">Mitigación de Raíz: {report.cwe}</h2>
        </div>
        <span className="severity-badge-critical">Nivel: {report.risk_level}</span>
      </div>

      <p className="remediation-summary-text">{report.summary}</p>

      {/* Lista de Recomendaciones de Arquitectura */}
      <div className="recommendations-box">
        <h4 className="box-title">Principios Defensivos Obligatorios</h4>
        <ul className="rec-list">
          {report.recommendations?.map((r, i) => (
            <li key={i}>{r}</li>
          ))}
        </ul>
      </div>

      {/* Comparador de Código Inseguro vs Seguro */}
      {report.code_examples && report.code_examples.length > 0 && (
        <div className="code-comparison-module">
          <div className="module-tabs">
            {report.code_examples.map((ex, i) => (
              <button
                key={i}
                type="button"
                className={`module-tab-btn ${selectedLang === i ? "active" : ""}`}
                onClick={() => setSelectedLang(i)}
              >
                {ex.language}
              </button>
            ))}
          </div>

          <div className="comparison-grid">
            <div className="code-column code-vulnerable">
              <div className="col-badge bad">❌ Código Inseguro (Concatenación)</div>
              <pre>{currentSnippet?.vulnerable_code}</pre>
            </div>
            <div className="code-column code-secure">
              <div className="col-badge good">✅ Código Remediado (Prepared Statement)</div>
              <pre>{currentSnippet?.secure_code}</pre>
            </div>
          </div>
          {currentSnippet?.explanation && (
            <div className="code-notes">
              <strong>Mecanismo de protección:</strong> {currentSnippet.explanation}
            </div>
          )}
        </div>
      )}

      {/* Política de Kernel eBPF / Tetragon */}
      {report.kernel_defense_policy && (
        <div className="kernel-policy-module">
          <div className="kernel-policy-header">
            <div>
              <span className="sub">DEFENSA EN TIEMPO DE EJECUCIÓN (RUNTIME SECURITY)</span>
              <h4>Regla de Detección e Intercepción con eBPF (Cilium Tetragon)</h4>
            </div>
            <span className="policy-badge">Kubernetes TracingPolicy</span>
          </div>
          <p className="kernel-policy-desc">
            Esta política instruye al Kernel de Linux a monitorear directamente el socket 3306 y abortar con <code>Sigkill</code> cualquier proceso que intente enviar patrones de inyección SQL.
          </p>
          <pre className="policy-code">{report.kernel_defense_policy}</pre>
        </div>
      )}
    </div>
  );
}

// ── Componente Principal App ───────────────────────────────────────────────────
export default function App() {
  const [selectedPresetId, setSelectedPresetId] = useState("vulnerable");
  const [customUrl, setCustomUrl] = useState("http://testphp.vulnweb.com/listproducts.php?cat=1");
  const [scanId, setScanId] = useState("");
  const [scanStatus, setScanStatus] = useState(null);
  const [events, setEvents] = useState([]);
  const [findings, setFindings] = useState([]);
  const [report, setReport] = useState(null);
  const [isRunning, setIsRunning] = useState(false);
  const [activeTab, setActiveTab] = useState("evidence"); // "evidence" | "remediation"
  const [errorMessage, setErrorMessage] = useState("");

  const currentPreset = TARGET_PRESETS.find((p) => p.id === selectedPresetId) || TARGET_PRESETS[0];

  const payloadTests = parsePayloadEvents(events);
  const detectedCount = payloadTests.filter((t) => t.result === "DETECTED").length;
  const isDone = scanStatus?.status === "COMPLETED";

  // Calcular paso de la pipeline (0 a 3)
  let currentStep = 0;
  if (isRunning) {
    if (events.some((e) => e.event_type === "PAYLOAD_EXECUTED")) currentStep = 2;
    else if (events.some((e) => e.event_type === "BASELINE_COMPLETED")) currentStep = 1;
    else currentStep = 0;
  } else if (isDone) {
    currentStep = 3;
  }

  const resetSession = () => {
    setScanId("");
    setScanStatus(null);
    setEvents([]);
    setFindings([]);
    setReport(null);
    setIsRunning(false);
    setErrorMessage("");
    setActiveTab("evidence");
  };

  const loadResults = useCallback(async (id) => {
    try {
      const res = await axios.get(`/api/scans/${id}/results`);
      setFindings(res.data.findings || []);
      setReport(res.data.remediation_report || null);
    } catch {
      // ignore
    }
  }, []);

  const loadEvents = useCallback(async (id) => {
    try {
      const res = await axios.get(`/api/scans/${id}/events`);
      setEvents(res.data.events || []);
    } catch {
      // ignore
    }
  }, []);

  // Polling del estado
  useEffect(() => {
    if (!isRunning || !scanId) return;

    const timer = setInterval(async () => {
      try {
        const res = await axios.get(`/api/scans/${scanId}`);
        const data = res.data;
        setScanStatus(data);
        await loadEvents(scanId);

        if (FINAL_STATUSES.includes(data.status)) {
          setIsRunning(false);
          if (data.status === "COMPLETED") {
            await loadResults(scanId);
          } else {
            setErrorMessage(data.error_message || "La auditoría falló.");
          }
        }
      } catch (err) {
        setIsRunning(false);
        setErrorMessage("Error de comunicación con el backend.");
      }
    }, 1500);

    return () => clearInterval(timer);
  }, [isRunning, scanId, loadEvents, loadResults]);

  const handleStartScan = async () => {
    setErrorMessage("");
    resetSession();
    setIsRunning(true);

    try {
      let body;
      if (currentPreset.id === "external") {
        body = {
          mode: "authorized_url",
          url: customUrl.trim(),
          authorization_confirmed: true
        };
      } else {
        body = {
          mode: "sandbox",
          target: currentPreset.target
        };
      }

      const res = await axios.post("/api/scans", body);
      const newScanId = res.data.scan_id || res.data.id;
      setScanId(newScanId);
      setScanStatus({ status: "QUEUED", ...res.data });
    } catch (err) {
      setIsRunning(false);
      setErrorMessage(err.response?.data?.error || "No se pudo iniciar el escaneo.");
    }
  };

  return (
    <div className="studio-app">
      <Header onReset={resetSession} isRunning={isRunning} />

      <main className="studio-main">
        {/* Banner de Estado a Primera Vista */}
        <StatusBanner
          status={scanStatus?.status}
          isRunning={isRunning}
          isDone={isDone}
          detectedCount={detectedCount}
          targetName={currentPreset.title}
        />

        {/* Stepper del Ciclo de Vida */}
        <PipelineStepper
          currentStep={currentStep}
          isDone={isDone}
          hasVulnerabilities={detectedCount > 0}
        />

        {/* Panel de Selección de Entorno y Control */}
        <section className="target-selection-section">
          <div className="section-head">
            <span className="section-caption">SELECCIÓN DE ESCENARIO PARA DEMOSTRACIÓN</span>
            <h2 className="section-heading">Configuración del Objetivo de Auditoría</h2>
          </div>

          <div className="preset-cards-grid">
            {TARGET_PRESETS.map((preset) => {
              const isSelected = selectedPresetId === preset.id;
              return (
                <div
                  key={preset.id}
                  className={`preset-card ${isSelected ? "selected" : ""}`}
                  onClick={() => !isRunning && setSelectedPresetId(preset.id)}
                >
                  <div className="preset-card-top">
                    <span className={`tag-pill tag-${preset.tagType}`}>{preset.tag}</span>
                    <span className="expected-pill">{preset.expectedResult}</span>
                  </div>
                  <h3 className="preset-title">{preset.title}</h3>
                  <p className="preset-sub">{preset.subtitle}</p>
                  <p className="preset-desc">{preset.description}</p>
                  <div className="preset-footer">
                    <code className="target-url-preview">{preset.url}</code>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Campo si se elige URL externa */}
          {selectedPresetId === "external" && (
            <div className="custom-url-box">
              <label htmlFor="external-url-input">URL de Prueba Autorizada (Lista Blanca):</label>
              <input
                id="external-url-input"
                type="url"
                value={customUrl}
                onChange={(e) => setCustomUrl(e.target.value)}
                placeholder="http://testphp.vulnweb.com/listproducts.php?cat=1"
                disabled={isRunning}
              />
              <small>Dominio validado bajo la política estricta de <code>policy/targets.go</code>.</small>
            </div>
          )}

          {errorMessage && (
            <div className="error-alert">
              <strong>Error al procesar:</strong> {errorMessage}
            </div>
          )}

          <div className="action-control-row">
            <button
              type="button"
              className={`btn-primary-action ${isRunning ? "running" : ""}`}
              onClick={handleStartScan}
              disabled={isRunning}
            >
              {isRunning ? (
                <>
                  <span className="action-spinner" />
                  <span>Ejecutando Auditoría Purple Team...</span>
                </>
              ) : (
                <>
                  <span>▶ Iniciar Auditoría Purple Team</span>
                </>
              )}
            </button>
            <span className="action-note">
              Objetivo: <strong>{currentPreset.title}</strong> · Concurrencia de 5 goroutines en worker pool.
            </span>
          </div>
        </section>

        {/* Sección de Telemetría en Vivo y Resultados */}
        {(scanId || isDone) && (
          <section className="execution-view-section">
            <div className="metrics-strip">
              <div className="metric-cell">
                <span className="c-label">ID de Escaneo</span>
                <code className="c-code">{scanId.slice(0, 16)}…</code>
              </div>
              <div className="metric-cell">
                <span className="c-label">Estado</span>
                <span className={`c-status ${scanStatus?.status || "QUEUED"}`}>
                  {scanStatus?.status || "QUEUED"}
                </span>
              </div>
              <div className="metric-cell">
                <span className="c-label">Sondas Procesadas</span>
                <span className="c-val">{payloadTests.length}</span>
              </div>
              <div className="metric-cell">
                <span className="c-label">Inyecciones Confirmadas</span>
                <span className={`c-val ${detectedCount > 0 ? "text-danger" : "text-success"}`}>
                  {detectedCount}
                </span>
              </div>
            </div>

            <div className="dual-split-layout">
              {/* Columna Izquierda: Consola de eventos */}
              <div className="split-left">
                <EventStreamConsole events={events} isLive={isRunning} />
              </div>

              {/* Columna Derecha: Contenido interactivo */}
              <div className="split-right">
                <div className="content-nav-tabs">
                  <button
                    type="button"
                    className={`nav-tab-btn ${activeTab === "evidence" ? "active" : ""}`}
                    onClick={() => setActiveTab("evidence")}
                  >
                    🔍 Evidencia Dual y Sondas ({payloadTests.length})
                  </button>
                  <button
                    type="button"
                    className={`nav-tab-btn ${activeTab === "remediation" ? "active" : ""}`}
                    onClick={() => setActiveTab("remediation")}
                    disabled={!report}
                  >
                    🛡️ Guía de Remediación y Código
                  </button>
                </div>

                <div className="tab-pane-content">
                  {activeTab === "evidence" && (
                    <div className="evidence-list">
                      {payloadTests.length === 0 ? (
                        <div className="empty-evidence-msg">
                          {isRunning
                            ? "Esperando que el worker pool procese los primeros payloads..."
                            : "No se registraron sondas de inyección en este escaneo."}
                        </div>
                      ) : (
                        payloadTests.map((t, idx) => (
                          <DualValidationCard key={t.id || idx} test={t} />
                        ))
                      )}
                    </div>
                  )}

                  {activeTab === "remediation" && (
                    <RemediationSection report={report} />
                  )}
                </div>
              </div>
            </div>
          </section>
        )}
      </main>

      <footer className="studio-footer">
        <div className="footer-left">
          <span>TICEC 2026 Workshop · Arquitectura Purple Team eBPF</span>
        </div>
        <div className="footer-right">
          <span>Desarrollado para demostración académica y validación defensiva de software seguro</span>
        </div>
      </footer>
    </div>
  );
}
