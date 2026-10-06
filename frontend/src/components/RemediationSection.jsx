import { useRef } from "react";

const verificationLabels = {
  PATCH_AVAILABLE: "Corrección disponible",
  HTTP_RETEST_PASSED: "Reprueba HTTP aprobada",
  REGRESSION_DETECTED: "Hallazgo abierto",
  INCONCLUSIVE: "Corrección sin verificar",
};

function CodeExamples({ examples }) {
  return examples?.map((example, index) => (
    <details className="code-example" key={index}>
      <summary>{example.language} · Ver corrección de código</summary>
      <div className="code-comparison">
        <div><h3>Código vulnerable</h3><pre>{example.vulnerable_code}</pre></div>
        <div><h3>Consulta preparada</h3><pre>{example.secure_code}</pre></div>
      </div>
      <p className="quiet">{example.explanation}</p>
    </details>
  ));
}

export default function RemediationSection({ report, baselineScan, scanId, isRunning, onVerify }) {
  const ebpfRef = useRef(null);
  if (!report) return null;
  const team = report.blue_team;
  if (!team) return (
    <details className="remediation generic-remediation">
      <summary>Remediación</summary>
      <p>{report.summary}</p>
      <ul>{report.recommendations?.map((item, index) => <li key={index}>{item}</li>)}</ul>
      <CodeExamples examples={report.code_examples} />
    </details>
  );

  const passed = team.verification === "HTTP_RETEST_PASSED";
  const regression = team.verification === "REGRESSION_DETECTED";
  const prepared = team.variant === "prepared";
  const statusDescription = passed
    ? "La consulta legítima funciona y las cinco entradas SQL fueron rechazadas en esta reprueba."
    : regression
      ? "Se detectó SQL Injection en la variante corregida. El hallazgo sigue abierto."
      : prepared
        ? "Falta evidencia suficiente para aprobar la corrección. Revisa las respuestas y vuelve a verificar."
        : "El código preparado está disponible. El siguiente paso es comprobarlo con las mismas pruebas.";

  function openEBPFPlan() {
    if (!ebpfRef.current) return;
    ebpfRef.current.open = true;
    ebpfRef.current.querySelector("summary")?.focus();
  }

  function downloadEvidence() {
    const url = URL.createObjectURL(new Blob([JSON.stringify({
      scan_id: scanId, baseline_scan: baselineScan || null, remediation_report: report,
    }, null, 2)], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `dvwa-blue-team-${scanId}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  return (
    <section className="panel blue-team" id="correction" aria-labelledby="blue-team-title">
      <div className="panel-heading">
        <h2 id="blue-team-title">Corrección del laboratorio</h2>
        <span className="quiet">CWE-89 · {team.level}</span>
      </div>
      <div className="blue-team-body">
        <ol className="defense-phases" aria-label="Fases de defensa">
          <li className="phase-complete"><span>01</span><div>Corregir SQL<small>Código disponible</small></div></li>
          <li className={passed ? "phase-complete" : "phase-current"} aria-current={!passed ? "step" : undefined}>
            <span>02</span><div>Verificar por HTTP<small>{passed ? "Reprueba aprobada" : prepared ? "Revisión pendiente" : "Siguiente paso"}</small></div>
          </li>
          <li className={passed ? "phase-current" : ""} aria-current={passed ? "step" : undefined}>
            <span>03</span><div>Observar con eBPF<small>Sensor no conectado</small></div>
          </li>
        </ol>
        <div className={`verification-result ${passed ? "passed" : regression ? "regression" : ""}`}>
          <div role="status">
            <strong>{verificationLabels[team.verification] || "Corrección sin verificar"}</strong>
            <p>{statusDescription}</p>
          </div>
          <div className="next-action">
            {passed ? (
              <button type="button" className="defense-button primary" onClick={openEBPFPlan}>Ver plan eBPF <span aria-hidden="true">→</span></button>
            ) : (
              <button type="button" className="defense-button primary" disabled={isRunning} onClick={onVerify}>
                {prepared ? "Repetir verificación" : "Probar variante corregida"} <span aria-hidden="true">→</span>
              </button>
            )}
            <small>{passed ? "Preparación del sensor · sin bloqueo activo" : `Mismo nivel ${team.level} · nuevo escaneo`}</small>
          </div>
        </div>
        {prepared && (
          <dl className="verification-metrics">
            <div><dt>Respuestas medidas</dt><dd>{team.measured_requests}/6</dd></div>
            <div><dt>Registros con id=1</dt><dd>{team.baseline_records}</dd></div>
            <div><dt>Entradas SQL rechazadas</dt><dd>{team.rejected_inputs}/5</dd></div>
          </dl>
        )}
        {baselineScan && (
          <div className="comparison-wrap">
            <table className="retest-comparison">
              <caption>Antes y después · nivel {team.level}</caption>
              <thead><tr><th scope="col">Evidencia</th><th scope="col">Vulnerable</th><th scope="col">Corregida</th></tr></thead>
              <tbody>
                <tr><th scope="row">Hallazgos HTTP</th><td>{baselineScan.detected} detectados</td><td>{regression ? "Detectados · revisar" : passed ? "Sin detección en estas sondas" : "Sin veredicto"}</td></tr>
                <tr><th scope="row">Resultado</th><td>Escaneo completado</td><td>{verificationLabels[team.verification] || "Sin verificar"}</td></tr>
              </tbody>
            </table>
          </div>
        )}
        <details className="correction-details">
          <summary>Qué cambia y cómo se verifica</summary>
          <p>El módulo corregido valida <code>id</code> como entero positivo, usa una consulta preparada mysqli y codifica la salida HTML.</p>
          <p className="source-path">Archivo del laboratorio: <code>{team.patch_path}</code>. La variante vulnerable sigue disponible para comparar.</p>
          <p>{team.verification_note}</p>
          <p>Permisos de la cuenta compartida de DVWA: revisión pendiente.</p>
          <dl className="scan-references">
            {baselineScan && <div><dt>Escaneo vulnerable</dt><dd><code>{baselineScan.scan_id}</code></dd></div>}
            <div><dt>Escaneo actual</dt><dd><code>{scanId}</code></dd></div>
          </dl>
          <CodeExamples examples={report.code_examples} />
        </details>
        <details className="ebpf-action" ref={ebpfRef}>
          <summary>Preparar observabilidad eBPF <span className="sensor-label">Sensor no conectado</span></summary>
          <p>El siguiente paso es observar procesos y conexiones en el host Linux del laboratorio. No hay eventos de kernel ni políticas de bloqueo activas en esta aplicación.</p>
          <ol>
            <li>Preparar un host Linux con un sensor como Tetragon y verificar su compatibilidad con el kernel. Docker Desktop requiere observar el kernel Linux que ejecuta los contenedores.</li>
            <li>Empezar en modo monitor: identificar los contenedores de DVWA y MariaDB; registrar identidad de proceso, conexiones de red, instante y nombre de política.</li>
            <li>Repetir ambas variantes y correlacionar por ventana temporal, contenedor y conexión. Para asociar una petición exacta, añadir trazas de aplicación con un ID compartido.</li>
            <li>Validar alertas y falsos positivos antes de activar respuesta. Un evento de red no revela por sí solo la estructura SQL ni confirma una inyección.</li>
          </ol>
          <p className="evidence-limit">Criterio de cierre: sensor operativo, eventos reales correlacionados y cobertura documentada. La observabilidad eBPF complementa la consulta preparada.</p>
          <a href="https://tetragon.io/docs/getting-started/" target="_blank" rel="noreferrer">Abrir guía oficial de Tetragon ↗</a>
        </details>
        <div className="defense-footer">
          <p className="quiet">Evidencia actual: HTTP. Una reprueba aprobada cubre este módulo, nivel y conjunto de sondas.</p>
          <button type="button" className="defense-button" onClick={downloadEvidence}>Descargar reporte JSON</button>
        </div>
      </div>
    </section>
  );
}
