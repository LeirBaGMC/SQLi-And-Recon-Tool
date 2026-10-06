import { useEffect, useRef, useState } from "react";
import { buildLogEntries } from "../scans/events.js";
import ProbeDetail from "./ProbeDetail.jsx";

export function LogRow({ entry }) {
  const { activity, probe } = entry;
  const isDemonstration =
    probe &&
    (entry.event_type === "PAYLOAD_DEMONSTRATION" ||
      probe.execution_type === "SIMULATED" ||
      probe.result === "SIMULATED");
  const alert =
    activity?.state === "failed" ||
    activity?.state === "http_error" ||
    (!isDemonstration && probe?.result === "DETECTED") ||
    entry.event_type === "SCAN_FAILED";
  const time = (
    <time>
      {entry.created_at ? new Date(entry.created_at).toLocaleTimeString() : "—"}
    </time>
  );
  if (!activity && !probe)
    return (
      <div className={`console-row ${alert ? "alert-row" : ""}`}>
        {time}
        <span>{entry.label}</span>
      </div>
    );
  const simulated = isDemonstration;
  const pending = activity?.state === "running";
  const status =
    activity?.status_code ?? (!simulated ? probe?.status_code : null);
  const duration =
    activity?.duration_ms ?? (!simulated ? probe?.observed_duration_ms : null);
  const method = activity?.method || (!simulated ? probe?.method : null);
  const url = activity?.url || (!simulated ? probe?.tested_url : null);
  const payload = activity?.payload || probe?.payload;
  const detail = activity?.detail || probe?.reason;
  const rows = activity?.records;
  const hasDetail =
    url || payload || detail || activity?.response_bytes != null;
  const content = (
    <>
      {time}
      <span className="log-content">
        <span className="log-label">{entry.label}</span>
        <span className="log-meta">
          {activity?.worker_id && <span>Worker {activity.worker_id}</span>}
          {method && <span>{method}</span>}
          {status != null && <span>HTTP {status}</span>}
          {duration != null && <span>{duration} ms</span>}
          {rows != null && <span>{rows} registro(s)</span>}
          {entry.event_type === "HTTP_ACTIVITY" &&
            activity?.response_bytes != null && (
              <span>{activity.response_bytes} bytes</span>
            )}
          {pending && <span>En curso</span>}
          {activity?.state === "failed" && <span>Sin respuesta válida</span>}
        </span>
      </span>
    </>
  );
  if (!hasDetail)
    return (
      <div className={`console-row ${alert ? "alert-row" : ""}`}>{content}</div>
    );
  return (
    <details className={`log-entry ${alert ? "alert-row" : ""}`}>
      <summary>{content}</summary>
      <div className="log-detail">
        {url && (
          <>
            <span>Petición enviada</span>
            <code>
              {method ? `${method} ` : ""}
              {url}
            </code>
          </>
        )}
        {payload && (activity || probe).original_value == null && (
          <p>
            <span>
              Entrada {activity?.parameter || probe?.parameter || "id"}
            </span>
            <code>{payload}</code>
          </p>
        )}
        <ProbeDetail data={activity || probe} url={url} />
        {probe?.request_body && !simulated && (
          <p>
            <span>Cuerpo POST</span>
            {probe.input_url && <code>{probe.input_url}</code>}
            <code>{probe.request_body}</code>
          </p>
        )}
        {activity?.response_bytes != null && (
          <p>
            Respuesta: {activity.response_bytes} bytes
            {activity.level && ` · Nivel ${activity.level}`}
          </p>
        )}
        {detail && <p>{detail}</p>}
      </div>
    </details>
  );
}

export default function EventStreamConsole({ events, isLive }) {
  const terminalRef = useRef(null);
  const [followLogs, setFollowLogs] = useState(true);
  const lastEventId = events.at(-1)?.id;
  const entries = buildLogEntries(events);
  useEffect(() => {
    if (followLogs && terminalRef.current)
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
  }, [lastEventId, followLogs]);
  return (
    <section className="panel" aria-labelledby="logs-title">
      <div className="panel-heading">
        <h2 id="logs-title">Logs</h2>
        <div className="log-controls">
          <button
            type="button"
            className={`follow-button ${followLogs ? "following" : ""}`}
            title={
              followLogs
                ? "Pausar el desplazamiento automático"
                : "Seguir los eventos nuevos"
            }
            onClick={() => setFollowLogs((value) => !value)}
          >
            {followLogs ? "Pausar" : "Reanudar"}
          </button>
          <span className="quiet">
            {isLive ? "En vivo" : `${entries.length} eventos`}
          </span>
        </div>
      </div>
      <div
        className="console-body"
        ref={terminalRef}
        tabIndex={0}
        aria-label="Logs del escaneo"
        onScroll={() => {
          const console = terminalRef.current;
          if (
            console &&
            console.scrollHeight - console.scrollTop - console.clientHeight > 48
          )
            setFollowLogs(false);
        }}
      >
        {entries.length === 0 ? (
          <p className="empty-state">Los eventos aparecerán aquí.</p>
        ) : (
          entries.map((entry, index) => (
            <LogRow
              entry={entry}
              key={entry.activity?.step_id || entry.id || index}
            />
          ))
        )}
      </div>
    </section>
  );
}
