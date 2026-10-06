export function ScanError({ message, showLab, onOpenLab }) {
  return (
    <div className="error-alert" role="alert">
      <p>{message}</p>
      {showLab && (
        <button type="button" className="recovery-button" onClick={onOpenLab}>
          Abrir laboratorio DVWA <span aria-hidden="true">↗</span>
        </button>
      )}
    </div>
  );
}

export function ScanConnectionNotice({ message, onReconnect }) {
  return (
    <div className="connection-notice" role="status">
      <div><strong>Conexión interrumpida</strong><p>{message}</p></div>
      <button type="button" className="defense-button" onClick={onReconnect}>Volver a consultar</button>
    </div>
  );
}

export function ModeIcon({ mode }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {mode === "dvwa" ? (
        <>
          <path d="M9 3h6M10 3v6l-5.6 9.3A1.8 1.8 0 0 0 6 21h12a1.8 1.8 0 0 0 1.6-2.7L14 9V3" />
          <path d="M8 14h8" />
        </>
      ) : (
        <>
          <circle cx="12" cy="12" r="9" />
          <path d="M3 12h18M12 3c4 4.5 4 13.5 0 18-4-4.5-4-13.5 0-18Z" />
        </>
      )}
    </svg>
  );
}

export function StatusBanner({
  status,
  isRunning,
  isDone,
  detectedCount,
  isInconclusive,
  activity,
  isReconnecting,
}) {
  const text =
    status === "FAILED"
      ? "Escaneo interrumpido"
      : isReconnecting
        ? "Esperando conexión con el backend"
        : isRunning
        ? activity || "Escaneando…"
        : !isDone
          ? "Listo para escanear"
          : detectedCount > 0
            ? `${detectedCount} hallazgos SQLi`
            : isInconclusive
              ? "Resultado no concluyente"
              : "SIN HALLAZGOS · En las pruebas ejecutadas";
  return (
    <span
      className={`scan-status ${isRunning ? "running" : isDone && detectedCount > 0 ? "detected" : ""}`}
    >
      {text}
    </span>
  );
}
