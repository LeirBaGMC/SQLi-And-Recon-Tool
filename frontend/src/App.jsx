import { useState } from "react";
import { TARGET_PRESETS } from "./scans/targets.js";
import useScan from "./hooks/useScan.js";
import { ModeIcon, ScanError, StatusBanner } from "./components/ScanStatus.jsx";
import EventStreamConsole from "./components/EventStreamConsole.jsx";
import FindingCard from "./components/FindingCard.jsx";
import RemediationSection from "./components/RemediationSection.jsx";
import "./App.css";

export default function App() {
  const [selectedPresetId, setSelectedPresetId] = useState(null);
  const [customUrl, setCustomUrl] = useState("");
  const [dvwaLevel, setDVWALevel] = useState("medium");
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
    elapsedMS,
    payloadTests,
    detectedCount,
    isDone,
    isInconclusive,
    currentActivity,
    completedRequests,
    totalRequests,
    resetSession,
    handleStartScan,
  } = useScan({ currentPreset, customUrl, dvwaLevel });

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
            Limpiar
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
              <span className="mode-label">{preset.title}</span>
              <span className="mode-arrow" aria-hidden="true">
                ↗
              </span>
            </button>
          ))}
        </nav>
        {currentPreset && (
          <>
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
                    <span className="target-name">
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
                    </select>
                  </label>
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
                    Escaneando…
                  </>
                ) : (
                  <>
                    {scanStatus?.status === "FAILED"
                      ? "Reintentar"
                      : "Iniciar escaneo"}
                    <span aria-hidden="true">→</span>
                  </>
                )}
              </button>
            </form>
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
                  Tiempo total{" "}
                  <strong>{(elapsedMS / 1000).toFixed(1)} s</strong>
                </span>
              )}
            </div>
            <div className="execution-grid">
              <EventStreamConsole
                events={events}
                isLive={isRunning}
                key={scanId || "idle"}
              />
              <section className="panel" aria-labelledby="findings-title">
                <div className="panel-heading">
                  <h2 id="findings-title">Vulnerabilidades</h2>
                  <span className="quiet">
                    {scanStatus?.status === "FAILED" && detectedCount === 0
                      ? "Sin veredicto"
                      : `${detectedCount} detectadas`}
                  </span>
                </div>
                <div className="findings-body">
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
                          : "Sin resultados todavía."}
                    </p>
                  )}
                  <RemediationSection report={report} />
                </div>
              </section>
            </div>
          </>
        )}
      </main>
    </div>
  );
}
