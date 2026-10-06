import { useState } from "react";
import { TARGET_PRESETS } from "./scans/targets.js";
import useScan from "./hooks/useScan.js";
import { ModeIcon, ScanConnectionNotice, ScanError, StatusBanner } from "./components/ScanStatus.jsx";
import EventStreamConsole from "./components/EventStreamConsole.jsx";
import FindingCard from "./components/FindingCard.jsx";
import RemediationSection from "./components/RemediationSection.jsx";
import "./App.css";

export default function App() {
  const [selectedPresetId, setSelectedPresetId] = useState(null);
  const [customUrl, setCustomUrl] = useState("");
  const [dvwaLevel, setDVWALevel] = useState("medium");
  const [workers, setWorkers] = useState(1);
  const [dvwaVariant, setDVWAVariant] = useState("vulnerable");
  const currentPreset = TARGET_PRESETS.find(
    (preset) => preset.id === selectedPresetId,
  );
  const {
    scanId,
    scanStatus,
    events,
    report,
    isRunning,
    errorMessage,
    connectionError,
    reconnect,
    elapsedMS,
    metrics,
    baselineScan,
    payloadTests,
    detectedCount,
    isDone,
    isInconclusive,
    currentActivity,
    completedRequests,
    totalRequests,
    resetSession,
    handleStartScan,
    verifyCorrection,
  } = useScan({ currentPreset, customUrl, dvwaLevel, dvwaVariant, workers });

  return (
    <div className="studio-app">
      <header className="app-header">
        <a className="brand" href="#main-content">
          <span className="brand-mark" aria-hidden="true">
            S<span />
          </span>
          <span className="brand-name">SQLi Studio</span>
          <span className="brand-caption">TICEC 2026</span>
        </a>
        {scanId && (
          <button
            type="button"
            className="reset-button"
            disabled={isRunning}
            onClick={resetSession}
          >
            Nueva prueba
          </button>
        )}
      </header>
      <main
        className={`studio-main ${!currentPreset ? "entry-view" : ""}`}
        id="main-content"
      >
        <nav className="mode-switch" aria-label="Tipo de escaneo">
          {TARGET_PRESETS.map((preset) => (
            <button
              key={preset.id}
              type="button"
              className={`mode-button ${selectedPresetId === preset.id ? "selected" : ""}`}
              aria-pressed={selectedPresetId === preset.id}
              disabled={isRunning}
              onClick={() => {
                if (preset.id !== selectedPresetId) {
                  resetSession();
                  setSelectedPresetId(preset.id);
                }
              }}
            >
              <span className="mode-icon">
                <ModeIcon mode={preset.id} />
              </span>
              <span className="mode-label">{preset.title}<small>{preset.id === "dvwa" ? "Practica con DVWA y comprueba la corrección." : "Analiza una aplicación para la que tienes permiso."}</small></span>
              <span className="mode-arrow" aria-hidden="true">
                ↗
              </span>
            </button>
          ))}
        </nav>
        {currentPreset && (
          <>
            <div className="workspace-heading">
              <div>
                <p className="eyebrow">{selectedPresetId === "dvwa" ? "Laboratorio · Blue team" : "Análisis HTTP"}</p>
                <h1>{selectedPresetId === "dvwa" ? "Detectar, corregir y verificar" : "Analizar una URL autorizada"}</h1>
                <p>{selectedPresetId === "dvwa"
                  ? "Compara DVWA vulnerable con la corrección y revisa la evidencia de cada prueba."
                  : "Revisa los parámetros de una aplicación para la que tienes autorización."}</p>
              </div>
              <span className="scope-badge">Evidencia HTTP</span>
            </div>
            <form className="scan-toolbar" onSubmit={handleStartScan}>
              {selectedPresetId === "external" ? (
                <div className="url-field">
                  <label htmlFor="target-url">URL</label>
                  <input
                    id="target-url"
                    type="url"
                    required
                    placeholder="https://tu-sitio.com/ruta?id=1"
                    value={customUrl}
                    onChange={(event) => {
                      setCustomUrl(event.target.value);
                      resetSession();
                    }}
                    disabled={isRunning}
                    aria-describedby="url-help"
                  />
                  <small id="url-help">
                    Con parámetros se analiza esta URL; sin ellos se buscan
                    enlaces.
                  </small>
                </div>
              ) : (
                <div className="lab-target">
                  <span className="target-label">
                    <span className="target-icon">
                      <ModeIcon mode="dvwa" />
                    </span>
                    <span className="lab-name">
                      DVWA <span>SQL Injection</span>
                    </span>
                  </span>
                  <label className="level-control" htmlFor="dvwa-level">
                    Nivel
                    <select
                      id="dvwa-level"
                      value={dvwaLevel}
                      disabled={isRunning}
                      onChange={(event) => {
                        setDVWALevel(event.target.value);
                        resetSession();
                      }}
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                    </select>
                  </label>
                  <label className="level-control" htmlFor="dvwa-variant">
                    Variante
                    <select id="dvwa-variant" value={dvwaVariant} disabled={isRunning}
                      onChange={(event) => { setDVWAVariant(event.target.value); resetSession(); }}>
                      <option value="vulnerable">Vulnerable</option>
                      <option value="prepared">Corregida · SQL preparado</option>
                    </select>
                  </label>
                  <details className="advanced-config">
                    <summary>Opciones · {workers} worker{workers > 1 ? "s" : ""}</summary>
                    <label className="level-control" htmlFor="dvwa-workers">
                      Workers
                      <select id="dvwa-workers" value={workers} disabled={isRunning}
                        onChange={(event) => { setWorkers(Number(event.target.value)); resetSession(); }}>
                        <option value={1}>1</option>
                        <option value={2}>2</option>
                        <option value={4}>4</option>
                      </select>
                    </label>
                    <p>Sesiones independientes. Más workers no siempre reducen el tiempo total.</p>
                  </details>
                </div>
              )}
              <button
                className="start-button"
                type="submit"
                disabled={isRunning}
              >
                {isRunning ? (
                  <>
                    <span className="button-spinner" aria-hidden="true" />
                    {connectionError ? "Reconectando…" : "Escaneando…"}
                  </>
                ) : (
                  <>
                    {scanStatus?.status === "FAILED"
                      ? "Reintentar"
                      : selectedPresetId === "dvwa" && dvwaVariant === "prepared"
                        ? "Verificar corrección" : "Iniciar escaneo"}
                    <span aria-hidden="true">→</span>
                  </>
                )}
              </button>
            </form>
            {connectionError && <ScanConnectionNotice message={connectionError} onReconnect={reconnect} />}
            {errorMessage && (
              <ScanError
                message={errorMessage}
                showLab={
                  selectedPresetId === "external" &&
                  scanStatus?.status === "FAILED"
                }
                onOpenLab={() => {
                  resetSession();
                  setSelectedPresetId("dvwa");
                }}
              />
            )}
            <div className="scan-summary">
              <div className="activity-summary">
                <div role="status" aria-live="polite">
                  <StatusBanner
                    status={scanStatus?.status}
                    isRunning={isRunning}
                    isDone={isDone}
                    detectedCount={detectedCount}
                    isInconclusive={isInconclusive}
                    activity={currentActivity?.summary}
                    isReconnecting={Boolean(connectionError)}
                  />
                </div>
                {totalRequests && (
                  <span className="request-progress">
                    {completedRequests}/{totalRequests} respuestas de prueba
                  </span>
                )}
              </div>
              {elapsedMS != null && (
                <span
                  className="elapsed"
                  title="Desde el inicio hasta recibir los resultados; incluye la espera de actualización del panel."
                >
                  Tiempo del panel{" "}
                  <strong>{(elapsedMS / 1000).toFixed(1)} s</strong>
                </span>
              )}
            </div>
            {baselineScan && !report && (
              <p className="baseline-preserved" role="status">
                Escaneo anterior conservado: {baselineScan.detected} hallazgos · nivel {baselineScan.level}.
                {scanStatus?.status === "FAILED" || errorMessage
                  ? " La reprueba no se completó; la corrección sigue sin verificar."
                  : connectionError ? " Esperando conexión para consultar la reprueba." : " Verificando la variante corregida…"}
              </p>
            )}
            <RemediationSection report={report} baselineScan={baselineScan} scanId={scanId}
              isRunning={isRunning} onVerify={() => {
                setDVWAVariant("prepared");
                verifyCorrection();
              }} />
            <section className="panel results-panel" aria-labelledby="findings-title">
                <div className="panel-heading">
                  <h2 id="findings-title">Resultados de las pruebas</h2>
                  <span className="quiet">
                    {(scanStatus?.status === "FAILED" || (isDone && isInconclusive)) && detectedCount === 0
                      ? "Sin veredicto"
                      : payloadTests.length ? `${detectedCount} hallazgos` : "Pendiente"}
                  </span>
                </div>
                <div className={`findings-body ${payloadTests.length ? "findings-grid" : ""}`}>
                  {payloadTests.length ? (
                    payloadTests.map((test, index) => (
                      <FindingCard test={test} key={test.id ?? index} />
                    ))
                  ) : (
                    <p className="empty-state">
                      {isRunning
                        ? "Esperando resultados…"
                        : scanStatus?.status === "FAILED"
                          ? "No se completaron pruebas SQL. Sin veredicto sobre la vulnerabilidad."
                          : "Inicia el escaneo para ver los resultados y el siguiente paso de corrección."}
                    </p>
                  )}
                </div>
            </section>
            <details className="technical-panel" key={scanId || "idle"}>
              <summary>Registro HTTP y rendimiento <span>{events.length ? `${events.length} eventos registrados` : "Sin actividad"}</span></summary>
              {metrics && (
                <dl className="performance-metrics">
                  <div><dt>Total del backend</dt><dd>{metrics.total_ms.toFixed(1)} ms</dd></div>
                  <div><dt>Sesiones</dt><dd>{metrics.session_ms.toFixed(1)} ms</dd></div>
                  <div><dt>Sondas</dt><dd>{metrics.probe_ms.toFixed(1)} ms</dd></div>
                  <div><dt>Peticiones HTTP</dt><dd>{metrics.http_requests}</dd></div>
                  <div><dt>No concluyentes</dt><dd>{metrics.inconclusive}</dd></div>
                  <div><dt>Fallos de transporte</dt><dd>{metrics.failed_requests}</dd></div>
                </dl>
              )}
              <EventStreamConsole events={events} isLive={isRunning} />
            </details>
          </>
        )}
      </main>
    </div>
  );
}
