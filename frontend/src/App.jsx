import { useCallback, useEffect, useMemo, useState } from "react";
import axios from "axios";
import "./App.css";

const STEPS = [
  {
    number: 1,
    title: "Escanear",
    description: "Selecciona un objetivo autorizado.",
  },
  {
    number: 2,
    title: "Comprender",
    description: "Observa cómo cambia la consulta SQL.",
  },
  {
    number: 3,
    title: "Reparar",
    description: "Aplica y verifica la solución.",
  },
];

const TARGETS = [
  {
    id: "vulnerable-app",
    title: "Laboratorio vulnerable",
    subtitle: "Recomendado para comenzar",
    description:
      "Aplicación del sandbox que incorpora directamente la entrada del usuario dentro de una consulta SQL.",
    expected:
      "El escáner debería demostrar que la entrada puede modificar la lógica de la consulta.",
    actionLabel: "Iniciar demostración vulnerable",
    disabled: false,
  },
  {
    id: "secure-app",
    title: "Laboratorio reparado",
    subtitle: "Consulta preparada",
    description:
      "Versión reparada que mantiene la entrada separada de la estructura de la consulta SQL.",
    expected: "La misma prueba no debería reproducir el hallazgo.",
    actionLabel: "Analizar versión reparada",
    disabled: false,
  },
  {
    id: "authorized-url",
    title: "URL autorizada",
    subtitle: "Objetivo externo",
    description:
      "Permite analizar una aplicación propia o un entorno de pruebas autorizado por el instructor.",
    expected:
      "El dominio deberá formar parte de la lista permitida del workshop.",
    actionLabel: "Configurar URL autorizada",
    disabled: false,
  },
];

const FINAL_STATUSES = ["COMPLETED", "FAILED"];

function App() {
  const [currentStep, setCurrentStep] = useState(1);
  const [selectedTarget, setSelectedTarget] = useState("vulnerable-app");
  const [authorizedURL, setAuthorizedURL] = useState(
    "http://testaspnet.vulnweb.com/ReadNews.aspx?id=2",
  );

  const [authorizedParameter, setAuthorizedParameter] = useState("id");

  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);

  const [scanEvents, setScanEvents] = useState([]);

  const [scanId, setScanId] = useState("");
  const [scanStatus, setScanStatus] = useState(null);
  const [findings, setFindings] = useState([]);
  const [totalFindings, setTotalFindings] = useState(0);

  const [isStarting, setIsStarting] = useState(false);
  const [isPolling, setIsPolling] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);

  const [verificationStatus, setVerificationStatus] = useState("idle");
  const [verificationMessage, setVerificationMessage] = useState("");

  const targetInformation = useMemo(
    () => TARGETS.find((target) => target.id === selectedTarget),
    [selectedTarget],
  );

  const primaryFinding = findings[0] || null;
  const inconclusiveEvent = scanEvents.find(
    (event) => event.event_type === "SCAN_INCONCLUSIVE",
  );

  const loadResults = useCallback(async (currentScanId) => {
    const response = await axios.get(`/api/scans/${currentScanId}/results`);

    const receivedFindings = response.data.findings || [];
    const receivedTotal = response.data.total || 0;

    setFindings(receivedFindings);
    setTotalFindings(receivedTotal);

    return {
      findings: receivedFindings,
      total: receivedTotal,
    };
  }, []);
  const loadEvents = useCallback(async (currentScanId) => {
    try {
      const response = await axios.get(`/api/scans/${currentScanId}/events`);

      const receivedEvents = response.data.events || [];

      setScanEvents(receivedEvents);

      return receivedEvents;
    } catch (error) {
      console.error("No se pudieron obtener los eventos:", error);

      return [];
    }
  }, []);

  const loadStatus = useCallback(
    async (currentScanId) => {
      try {
        const response = await axios.get(`/api/scans/${currentScanId}`);

        const currentStatus = response.data;
        setScanStatus(currentStatus);

        if (!FINAL_STATUSES.includes(currentStatus.status)) {
          return;
        }

        setIsPolling(false);

        if (currentStatus.status === "FAILED") {
          setErrorMessage(
            currentStatus.error_message || "El escaneo no pudo completarse.",
          );
          return;
        }

        await loadResults(currentScanId);
        await loadEvents(currentScanId);
        setCurrentStep(2);
      } catch (error) {
        console.error("No se pudo consultar el escaneo:", error);

        setIsPolling(false);
        setErrorMessage("No se pudo consultar el estado del escaneo.");
      }
    },
    [loadResults, loadEvents],
  );

  useEffect(() => {
    if (!isPolling || !scanId) {
      return undefined;
    }

    loadStatus(scanId);

    const intervalId = window.setInterval(() => {
      loadStatus(scanId);
    }, 2000);

    return () => {
      window.clearInterval(intervalId);
    };
  }, [isPolling, scanId, loadStatus]);

  const resetScan = () => {
    setScanId("");
    setScanStatus(null);
    setFindings([]);
    setTotalFindings(0);
    setScanEvents([]);
    setErrorMessage("");
    setShowTechnicalDetails(false);
    setVerificationStatus("idle");
    setVerificationMessage("");
  };

  const startScan = async () => {
    if (selectedTarget === "authorized-url" && !authorizationConfirmed) {
      setErrorMessage(
        "Debes confirmar que tienes autorización para analizar este objetivo.",
      );
      return;
    }

    if (
      selectedTarget === "authorized-url" &&
      (!authorizedURL.trim() || !authorizedParameter.trim())
    ) {
      setErrorMessage("La URL y el parámetro son obligatorios.");
      return;
    }

    resetScan();

    setIsStarting(true);
    setCurrentStep(1);

    try {
      const requestBody =
        selectedTarget === "authorized-url"
          ? {
              mode: "authorized_url",
              url: authorizedURL.trim(),
              parameter: authorizedParameter.trim(),
              authorization_confirmed: authorizationConfirmed,
            }
          : {
              mode: "sandbox",
              target: selectedTarget,
            };

      const response = await axios.post("/api/scans", requestBody);

      setScanId(response.data.scan_id);

      setScanStatus({
        id: response.data.scan_id,
        target_name: response.data.target_name,
        target_url: response.data.target_url,
        parameter: response.data.parameter_name,
        status: response.data.status,
      });

      setIsPolling(true);
    } catch (error) {
      console.error("No se pudo iniciar el escaneo:", error);

      setErrorMessage(
        error.response?.data?.error || "No se pudo iniciar el escaneo.",
      );
    } finally {
      setIsStarting(false);
    }
  };

  const waitForCompletedScan = async (currentScanId) => {
    const maximumAttempts = 15;

    for (let attempt = 1; attempt <= maximumAttempts; attempt += 1) {
      const statusResponse = await axios.get(`/api/scans/${currentScanId}`);

      if (statusResponse.data.status === "FAILED") {
        throw new Error(
          statusResponse.data.error_message ||
            "La verificación no pudo completarse.",
        );
      }

      if (statusResponse.data.status === "COMPLETED") {
        return loadResults(currentScanId);
      }

      await new Promise((resolve) => {
        window.setTimeout(resolve, 1000);
      });
    }

    throw new Error("La verificación superó el tiempo de espera.");
  };

  const verifyRepair = async () => {
    setVerificationStatus("running");
    setVerificationMessage(
      "Ejecutando la misma prueba contra la versión reparada...",
    );
    setErrorMessage("");

    try {
      const response = await axios.post("/api/scans", {
        target: "secure-app",
      });

      const results = await waitForCompletedScan(response.data.scan_id);

      if (results.total === 0) {
        setVerificationStatus("success");
        setVerificationMessage(
          "La misma prueba no reprodujo el hallazgo en la versión reparada.",
        );
        return;
      }

      setVerificationStatus("failed");
      setVerificationMessage(
        "La prueba todavía produjo hallazgos. La reparación debe revisarse.",
      );
    } catch (error) {
      console.error("No se pudo verificar la reparación:", error);

      setVerificationStatus("failed");
      setVerificationMessage(
        error.message || "No se pudo completar la verificación.",
      );
    }
  };

  const getStatusLabel = (status) => {
    const labels = {
      QUEUED: "Preparando escaneo",
      RUNNING: "Analizando objetivo",
      COMPLETED: "Análisis completado",
      FAILED: "El análisis falló",
    };

    return labels[status] || "Sin iniciar";
  };

  const goToStep = (stepNumber) => {
    if (stepNumber === 1) {
      setCurrentStep(1);
      return;
    }

    if (!scanStatus || scanStatus.status !== "COMPLETED") {
      return;
    }

    setCurrentStep(stepNumber);
  };

  return (
    <div className="workshop-app">
      <header className="workshop-header">
        <div>
          <p className="workshop-label">Taller práctico de seguridad</p>

          <h1>Inyección SQL: detectar, entender y reparar</h1>

          <p>
            Completa las tres etapas para observar cómo una entrada insegura
            modifica una consulta SQL y cómo evitarlo mediante consultas
            preparadas.
          </p>
        </div>

        <div className="header-progress">Paso {currentStep} de 3</div>
      </header>

      <nav className="step-navigation">
        {STEPS.map((step) => {
          const isActive = currentStep === step.number;
          const isCompleted = currentStep > step.number;
          const isAvailable =
            step.number === 1 || scanStatus?.status === "COMPLETED";

          return (
            <button
              type="button"
              key={step.number}
              className={[
                "step-button",
                isActive ? "active" : "",
                isCompleted ? "completed" : "",
              ].join(" ")}
              disabled={!isAvailable}
              onClick={() => goToStep(step.number)}
            >
              <span>{step.number}</span>

              <div>
                <strong>{step.title}</strong>
                <small>{step.description}</small>
              </div>
            </button>
          );
        })}
      </nav>

      <main className="workshop-content">
        {currentStep === 1 && (
          <section className="workshop-stage">
            <div className="stage-main">
              <div className="stage-heading">
                <p>Etapa 1</p>
                <h2>¿Qué deseas analizar?</h2>

                <span>
                  Selecciona un objetivo incluido en el laboratorio o una URL
                  autorizada por el instructor.
                </span>
              </div>

              <div className="target-options">
                {TARGETS.map((target) => (
                  <button
                    type="button"
                    key={target.id}
                    disabled={target.disabled || isStarting || isPolling}
                    className={[
                      "target-card",
                      selectedTarget === target.id ? "selected" : "",
                      target.disabled ? "disabled" : "",
                    ].join(" ")}
                    onClick={() => setSelectedTarget(target.id)}
                  >
                    <div className="target-card-header">
                      <span className="selection-indicator" />

                      <div>
                        <strong>{target.title}</strong>
                        <small>{target.subtitle}</small>
                      </div>
                    </div>

                    <p>{target.description}</p>

                    {target.disabled && (
                      <span className="coming-soon">
                        Pendiente de configurar dominios autorizados
                      </span>
                    )}
                  </button>
                ))}
              </div>
              {selectedTarget === "authorized-url" && (
                <div className="authorized-url-form">
                  <div className="authorized-field">
                    <label htmlFor="authorized-url">URL admitida</label>

                    <input
                      id="authorized-url"
                      type="url"
                      value={authorizedURL}
                      onChange={(event) => setAuthorizedURL(event.target.value)}
                      placeholder="http://testaspnet.vulnweb.com/ReadNews.aspx?id=2"
                      disabled={isStarting || isPolling}
                    />

                    <small>
                      El dominio debe estar incluido en la política del
                      workshop.
                    </small>
                  </div>

                  <div className="authorized-field">
                    <label htmlFor="authorized-parameter">
                      Parámetro que se analizará
                    </label>

                    <input
                      id="authorized-parameter"
                      type="text"
                      value={authorizedParameter}
                      onChange={(event) =>
                        setAuthorizedParameter(event.target.value)
                      }
                      placeholder="id"
                      disabled={isStarting || isPolling}
                    />
                  </div>

                  <label className="authorization-confirmation">
                    <input
                      type="checkbox"
                      checked={authorizationConfirmed}
                      onChange={(event) =>
                        setAuthorizationConfirmed(event.target.checked)
                      }
                      disabled={isStarting || isPolling}
                    />

                    <span>
                      Confirmo que este objetivo es un laboratorio autorizado
                      para pruebas de seguridad.
                    </span>
                  </label>
                </div>
              )}

              {targetInformation && (
                <div className="expected-result">
                  <strong>Resultado esperado</strong>
                  <p>{targetInformation.expected}</p>
                </div>
              )}

              {errorMessage && (
                <div className="workshop-error">
                  <strong>No se pudo continuar</strong>
                  <p>{errorMessage}</p>
                </div>
              )}

              <button
                type="button"
                className="main-action"
                disabled={
                  isStarting || isPolling || targetInformation?.disabled
                }
                onClick={startScan}
              >
                {isStarting || isPolling
                  ? getStatusLabel(scanStatus?.status)
                  : targetInformation?.actionLabel}
              </button>

              {scanStatus && (
                <div className="scan-progress-card">
                  <div className="progress-spinner" />

                  <div>
                    <strong>{getStatusLabel(scanStatus.status)}</strong>

                    <p>Objetivo: {scanStatus.target_name}</p>

                    <small>Identificador: {scanStatus.id}</small>
                  </div>
                </div>
              )}
            </div>

            <aside className="stage-help">
              <h3>Antes de comenzar</h3>

              <ol>
                <li>Selecciona primero el laboratorio vulnerable.</li>
                <li>El motor enviará una entrada controlada.</li>
                <li>Después podrás observar cómo cambió la consulta.</li>
                <li>
                  Finalmente ejecutarás la misma prueba contra la versión
                  reparada.
                </li>
              </ol>

              <div className="authorization-notice">
                <strong>Uso autorizado</strong>

                <p>
                  Utiliza únicamente los objetivos del sandbox o aplicaciones
                  para las que tengas permiso explícito.
                </p>
              </div>
            </aside>
          </section>
        )}

        {currentStep === 2 && (
          <section className="workshop-stage">
            <div className="stage-main">
              <div className="stage-heading">
                <p>Etapa 2</p>

                <h2>
                  {totalFindings > 0
                    ? "Se encontró una posible inyección SQL"
                    : "La prueba no reprodujo la vulnerabilidad"}
                </h2>

                <span>
                  Analicemos el resultado en un lenguaje más sencillo.
                </span>
              </div>

              {totalFindings > 0 && primaryFinding ? (
                <>
                  <div className="finding-explanation">
                    <h3>¿Qué ocurrió?</h3>

                    <p>
                      El escáner comenzó solicitando un solo producto. Después
                      agregó una condición adicional que siempre es verdadera.
                    </p>

                    <p>
                      La aplicación devolvió más resultados porque la entrada
                      fue incorporada directamente dentro del texto SQL.
                    </p>
                  </div>

                  <div className="transformation-flow">
                    <div className="transformation-card">
                      <span>Entrada normal</span>
                      <code>1</code>
                    </div>

                    <div className="flow-arrow">→</div>

                    <div className="transformation-card warning">
                      <span>Entrada de prueba</span>
                      <code>1 OR 1=1</code>
                    </div>
                  </div>

                  <div className="query-comparison">
                    <article>
                      <span>Consulta esperada</span>
                      <pre>WHERE id = 1</pre>
                    </article>

                    <article className="danger-query">
                      <span>Consulta modificada</span>
                      <pre>WHERE id = 1 OR 1=1</pre>
                    </article>
                  </div>

                  <div className="simple-explanation">
                    <strong>¿Por qué es peligroso?</strong>

                    <p>
                      La condición <code>OR 1=1</code> siempre es verdadera. En
                      una aplicación real podría permitir acceder a datos que la
                      consulta original no debía devolver.
                    </p>
                  </div>

                  <button
                    type="button"
                    className="technical-toggle"
                    onClick={() =>
                      setShowTechnicalDetails(!showTechnicalDetails)
                    }
                  >
                    {showTechnicalDetails
                      ? "Ocultar detalles técnicos"
                      : "Ver detalles técnicos"}
                  </button>

                  {showTechnicalDetails && (
                    <div className="technical-details">
                      <dl>
                        <div>
                          <dt>Severidad</dt>
                          <dd>{primaryFinding.severity}</dd>
                        </div>

                        <div>
                          <dt>Confianza</dt>
                          <dd>{primaryFinding.confidence}</dd>
                        </div>

                        <div>
                          <dt>Parámetro</dt>
                          <dd>{primaryFinding.parameter_name}</dd>
                        </div>

                        <div>
                          <dt>Estado HTTP</dt>
                          <dd>{primaryFinding.http_status}</dd>
                        </div>

                        <div>
                          <dt>Tiempo normal</dt>
                          <dd>{primaryFinding.baseline_ms} ms</dd>
                        </div>

                        <div>
                          <dt>Tiempo observado</dt>
                          <dd>{primaryFinding.observed_ms} ms</dd>
                        </div>
                      </dl>

                      <h4>Evidencia registrada</h4>
                      <pre>{primaryFinding.evidence}</pre>

                      <h4>URL analizada</h4>
                      <code>{primaryFinding.tested_url}</code>
                    </div>
                  )}
                </>
              ) : (
                <div className="no-finding-message">
                  {inconclusiveEvent ? (
                    <>
                      <strong>Resultado inconcluso</strong>

                      <p>
                        La prueba limitada no encontró evidencia suficiente para
                        confirmar una inyección SQL. Este resultado no certifica
                        que el objetivo sea seguro.
                      </p>

                      <p>{inconclusiveEvent.message}</p>
                    </>
                  ) : (
                    <>
                      <strong>La prueba no reprodujo el hallazgo</strong>

                      <p>
                        La entrada analizada no modificó el resultado esperado
                        durante esta prueba controlada.
                      </p>
                    </>
                  )}
                </div>
              )}

              <div className="stage-actions">
                <button
                  type="button"
                  className="secondary-action"
                  onClick={() => setCurrentStep(1)}
                >
                  Volver a escanear
                </button>

                <button
                  type="button"
                  className="main-action"
                  onClick={() => setCurrentStep(3)}
                >
                  Continuar con la reparación
                </button>
              </div>
            </div>

            <aside className="stage-help">
              <h3>Concepto clave</h3>

              <p>
                Una inyección SQL ocurre cuando la entrada del usuario puede
                modificar la estructura o la lógica de una consulta.
              </p>

              <p>
                El problema no es solamente el texto ingresado. El problema
                principal es cómo la aplicación lo incorpora en SQL.
              </p>
            </aside>
          </section>
        )}

        {currentStep === 3 && (
          <section className="workshop-stage">
            <div className="stage-main">
              <div className="stage-heading">
                <p>Etapa 3</p>
                <h2>Corregir y verificar</h2>

                <span>
                  Sustituye la concatenación por una consulta preparada y
                  ejecuta nuevamente la prueba.
                </span>
              </div>

              <div className="remediation-comparison">
                <article className="unsafe-code">
                  <span>Antes: concatenación insegura</span>

                  <pre>{'query := "SELECT ... WHERE id = " + id'}</pre>

                  <p>La entrada se convierte en parte del código SQL.</p>
                </article>

                <article className="safe-code">
                  <span>Después: consulta preparada</span>

                  <pre>
                    {`const query = "
    SELECT ...
    WHERE id = ?
"

row := database.QueryRowContext(
    ctx,
    query,
    id,
)`}
                  </pre>

                  <p>La estructura SQL y el valor se envían por separado.</p>
                </article>
              </div>

              <div className="remediation-checklist">
                <h3>Lista de comprobación</h3>

                <ul>
                  <li>Utilizar consultas preparadas.</li>
                  <li>Validar el tipo y formato de la entrada.</li>
                  <li>Evitar mostrar errores internos de MySQL.</li>
                  <li>Utilizar privilegios mínimos en la base.</li>
                  <li>Repetir la prueba después de corregir.</li>
                </ul>
              </div>

              <button
                type="button"
                className="main-action"
                disabled={verificationStatus === "running"}
                onClick={verifyRepair}
              >
                {verificationStatus === "running"
                  ? "Verificando reparación..."
                  : "Ejecutar la misma prueba contra la versión reparada"}
              </button>

              {verificationStatus !== "idle" && (
                <div
                  className={["verification-result", verificationStatus].join(
                    " ",
                  )}
                >
                  <strong>
                    {verificationStatus === "success"
                      ? "Reparación verificada"
                      : verificationStatus === "running"
                        ? "Verificación en progreso"
                        : "La reparación requiere revisión"}
                  </strong>

                  <p>{verificationMessage}</p>

                  {verificationStatus === "success" && (
                    <ul>
                      <li>La entrada ya no modifica la consulta.</li>
                      <li>La prueba no produjo hallazgos.</li>
                      <li>La consulta preparada mitigó el riesgo.</li>
                    </ul>
                  )}
                </div>
              )}

              <div className="stage-actions">
                <button
                  type="button"
                  className="secondary-action"
                  onClick={() => setCurrentStep(2)}
                >
                  Volver a la explicación
                </button>

                <button
                  type="button"
                  className="secondary-action"
                  onClick={() => {
                    resetScan();
                    setSelectedTarget("vulnerable-app");
                    setCurrentStep(1);
                  }}
                >
                  Reiniciar workshop
                </button>
              </div>
            </div>

            <aside className="stage-help">
              <h3>Defensa en profundidad</h3>

              <p>La consulta preparada es la corrección principal.</p>

              <p>
                La validación de entrada, los privilegios mínimos y un WAF son
                capas adicionales, pero no sustituyen la reparación del código.
              </p>
            </aside>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;
