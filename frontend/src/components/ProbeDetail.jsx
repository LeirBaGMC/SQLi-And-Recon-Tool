export default function ProbeDetail({ data, url }) {
  return (
    <div className="probe-detail">
      {data.original_value != null && (
        <div className="mutation">
          <span>Original · {data.parameter}</span>
          <code>
            {data.original_value === "" ? "(vacío)" : data.original_value}
          </code>
          <span>Payload(s)</span>
          <code>{data.payload || "Sin payload"}</code>
        </div>
      )}
      {data.encoded_query && (
        <p className="encoded-query">
          <span>Query enviada · codificación URL</span>
          <code>{data.encoded_query}</code>
        </p>
      )}
      {data.final_url && data.final_url !== url && (
        <p className="encoded-query">
          <span>URL final tras redirección</span>
          <code>{data.final_url}</code>
        </p>
      )}
      {data.checks?.length > 0 && (
        <>
          <dl className="diagnostic-checks">
            {data.checks.map((check, index) => (
              <div key={index}>
                <dt>{check.label}</dt>
                <dd>{check.value}</dd>
              </div>
            ))}
          </dl>
          <p className="evidence-limit">
            Estas comprobaciones observan HTTP; no muestran la consulta SQL
            ejecutada en el servidor.
          </p>
        </>
      )}
      {data.coverage_note && (
        <p className="coverage-note">{data.coverage_note}</p>
      )}
    </div>
  );
}
