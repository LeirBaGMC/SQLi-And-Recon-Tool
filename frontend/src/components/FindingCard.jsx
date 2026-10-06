import ProbeDetail from "./ProbeDetail.jsx";

// Legacy demonstration events must never appear as real detections.
export default function FindingCard({ test }) {
  if (test.isSimulated)
    return (
      <article className="finding">
        <span className="finding-state">DEMOSTRACIÓN · NO EJECUTADA</span>
        <h3>{test.name || "Demostración"}</h3>
        <code className="payload">{test.payload}</code>
        <details>
          <summary>Ver ejemplo</summary>
          <p>{test.hypothetical_result || "Sin descripción disponible."}</p>
        </details>
      </article>
    );
  const isDetected = test.result === "DETECTED";
  return (
    <article className={`finding ${isDetected ? "finding-detected" : ""}`}>
      <div className="finding-heading">
        <h3>{test.name || "Prueba HTTP"}</h3>
        <span className="finding-state">
          {isDetected
            ? "INYECCIÓN DETECTADA"
            : test.result === "NOT_DETECTED"
              ? "SIN DETECCIÓN"
              : "SIN VEREDICTO"}
        </span>
      </div>
      {test.result !== "DETECTED" && test.reason && (
        <p className="finding-reason">{test.reason}</p>
      )}
      <details>
        <summary>Ver evidencia</summary>
        <code className="payload">{test.payload || "Sin payload reportado"}</code>
        {(isDetected || !test.reason) && (
          <p>{test.reason || "Sin explicación reportada."}</p>
        )}
        <ProbeDetail data={test} url={test.tested_url} />
        <dl className="evidence-metrics">
          <div>
            <dt>Código HTTP</dt>
            <dd>{test.status_code ?? "Sin datos"}</dd>
          </div>
          <div>
            <dt>Bytes base</dt>
            <dd>{test.baseline_size ?? "Sin datos"}</dd>
          </div>
          <div>
            <dt>Bytes observados</dt>
            <dd>{test.observed_size ?? "Sin datos"}</dd>
          </div>
          {test.method && (
            <div>
              <dt>Método</dt>
              <dd>{test.method}</dd>
            </div>
          )}
          {test.observed_duration_ms != null && (
            <div>
              <dt>Tiempo de respuesta</dt>
              <dd>{test.observed_duration_ms} ms</dd>
            </div>
          )}
          {test.dvwa_level && (
            <div>
              <dt>Nivel DVWA</dt>
              <dd>{test.dvwa_level}</dd>
            </div>
          )}
          {test.baseline_records != null && (
            <>
              <div>
                <dt>Registros base</dt>
                <dd>{test.baseline_records}</dd>
              </div>
              {test.true_records != null && <div>
                <dt>Condición verdadera</dt>
                <dd>{test.true_records ?? "Sin datos"}</dd>
              </div>}
              <div>
                <dt>{test.true_records != null ? "Condición falsa" : "Registros observados"}</dt>
                <dd>{test.observed_records ?? "Sin datos"}</dd>
              </div>
            </>
          )}
        </dl>
        <code className="request-url">
          {test.tested_url || "Sin URL reportada"}
        </code>
        {test.request_body && (
          <code className="request-url">POST{test.input_url ? ` ${test.input_url}` : ""}: {test.request_body}</code>
        )}
      </details>
    </article>
  );
}
