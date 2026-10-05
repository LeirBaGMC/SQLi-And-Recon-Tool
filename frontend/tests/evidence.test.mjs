import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import assert from "node:assert/strict";
import { test } from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { buildSync } from "esbuild";

const bundle = buildSync({
  stdin: {
    contents: `export { parsePayloadEvents, buildLogEntries } from '../src/scans/events.js';
      export { validateExternalUrl } from '../src/scans/targets.js';
      export { default as FindingCard } from '../src/components/FindingCard.jsx';
      export { LogRow } from '../src/components/EventStreamConsole.jsx';
      export { StatusBanner, ScanError } from '../src/components/ScanStatus.jsx';`,
    resolveDir: fileURLToPath(new URL(".", import.meta.url)),
  },
  bundle: true,
  platform: "node",
  format: "cjs",
  jsx: "automatic",
  external: ["react"],
  write: false,
});
const context = {
  module: { exports: {} },
  require: createRequire(import.meta.url),
  URL,
};
vm.createContext(context);
vm.runInContext(bundle.outputFiles[0].text, context);
const {
  parsePayloadEvents,
  FindingCard,
  StatusBanner,
  buildLogEntries,
  LogRow,
  ScanError,
  validateExternalUrl,
} = context.module.exports;
const render = (Component, props) =>
  renderToStaticMarkup(React.createElement(Component, props));

test("URL validation accepts domains, IPs, local hosts, credentials and custom ports", () => {
  assert.equal(
    validateExternalUrl(
      " http://TESTPHP.vulnweb.com:80/listproducts.php?cat=1 ",
    ),
    "http://testphp.vulnweb.com/listproducts.php?cat=1",
  );
  assert.equal(
    validateExternalUrl("http://user:pass@testphp.vulnweb.com:8000/?cat=1"),
    "http://user:pass@testphp.vulnweb.com:8000/?cat=1",
  );
  assert.equal(
    validateExternalUrl("https://user:pass@testphp.vulnweb.com:8443/?cat=1"),
    "https://user:pass@testphp.vulnweb.com:8443/?cat=1",
  );
  for (const value of [
    "https://example.com/?cat=1",
    "http://localhost:8000/?id=1",
    "http://127.0.0.1:8000/?id=1",
    "http://[::1]:8000/?id=1",
    "http://host.docker.internal:8000/?id=1",
  ])
    assert.equal(validateExternalUrl(value), value);
  for (const value of [
    "",
    "/ruta?id=1",
    "http://testphp.vulnweb.com/#cat=1",
    "javascript:alert(1)",
    "ftp://example.com/file",
  ])
    assert.throws(() => validateExternalUrl(value));
});

test("external request logs show the selected parameter and byte evidence without DVWA records", () => {
  const events = ["running", "failed"].map((state, index) => ({
    id: index + 1,
    event_type: "HTTP_ACTIVITY",
    message: JSON.stringify({
      step_id: "candidate-1-probe-1",
      summary: "Conectar al objetivo",
      state,
      method: "GET",
      parameter: "cat",
      payload: "1",
      duration_ms: state === "failed" ? 10000 : undefined,
      detail: state === "failed" ? "timeout" : undefined,
    }),
  }));
  const entries = buildLogEntries(events);
  assert.equal(entries.length, 1);
  const html = render(LogRow, { entry: entries[0] });
  assert.match(html, /Entrada cat/);
  assert.match(html, /10000 ms/);
  assert.match(html, /Sin respuesta válida/);
  assert.doesNotMatch(html, /HTTP 200|registro\(s\)|Entrada id/);
  const success = render(LogRow, {
    entry: {
      event_type: "HTTP_ACTIVITY",
      label: "Linea base",
      activity: { response_bytes: 843, status_code: 200, state: "completed" },
    },
  });
  assert.match(success, /843 bytes/);
});

test("external failure offers a laboratory recovery action and never claims no findings", () => {
  assert.match(
    render(ScanError, { message: "El objetivo no respondió", showLab: true }),
    /Abrir laboratorio DVWA/,
  );
  assert.doesNotMatch(
    render(ScanError, { message: "URL no válida", showLab: false }),
    /Abrir laboratorio/,
  );
  assert.match(
    render(StatusBanner, { status: "FAILED", isDone: false, detectedCount: 0 }),
    /Escaneo interrumpido/,
  );
  assert.doesNotMatch(
    render(StatusBanner, { status: "FAILED", isDone: false, detectedCount: 0 }),
    /SIN HALLAZGOS/,
  );
});

test("expanded evidence explains mutation, encoding, measured comparisons and skipped probes", () => {
  const data = {
    result: "NOT_DETECTED",
    method: "GET",
    parameter: "flag",
    original_value: "failed",
    payload: "failed'",
    encoded_query: "flag=failed%27",
    tested_url: "http://localhost/?flag=failed%27",
    reason:
      "La respuesta cambió, pero no incluyó una firma nueva de error SQL.",
    checks: [
      { label: "Contenido idéntico a la base", value: "No" },
      { label: "Diferencia de tamaño", value: "+0 bytes" },
    ],
    coverage_note: "Comparación booleana omitida: el valor original es texto.",
  };
  for (const html of [
    render(FindingCard, { test: data }),
    render(LogRow, {
      entry: {
        event_type: "PAYLOAD_EXECUTED",
        label: "Error SQL controlado: sin detección",
        probe: data,
      },
    }),
  ]) {
    assert.match(html, /Original · flag/);
    assert.match(html, /flag=failed%27/);
    assert.match(html, /Contenido idéntico a la base<\/dt><dd>No/);
    assert.match(html, /\+0 bytes/);
    assert.match(html, /Comparación booleana omitida/);
    assert.match(html, /no muestran la consulta SQL/);
    assert.doesNotMatch(html, /<details[^>]* open/);
  }
  const legacy = render(FindingCard, {
    test: { result: "NOT_DETECTED", baseline_size: 2203, observed_size: 2203 },
  });
  assert.doesNotMatch(legacy, /Contenido idéntico|Original ·|Firma SQL nueva/);
});

test("demonstrations remain hypothetical even with a detected result", () => {
  const [event] = parsePayloadEvents([
    {
      id: 1,
      event_type: "PAYLOAD_DEMONSTRATION",
      message: JSON.stringify({ result: "DETECTED", payload: "example" }),
    },
  ]);
  assert.equal(event.isSimulated, true);
  const html = render(FindingCard, { test: event });
  assert.match(html, /DEMOSTRACIÓN · NO EJECUTADA/);
  assert.doesNotMatch(html, /INYECCIÓN DETECTADA|NEUTRALIZADO|Código HTTP/);
});

test("activity logs update one request row and retain actual zero metrics", () => {
  const events = ["running", "completed"].map((state, index) => ({
    id: index + 1,
    event_type: "LAB_ACTIVITY",
    message: JSON.stringify({
      step_id: "probe-4",
      stage: "probe",
      summary: "Condición falsa",
      state,
      method: "POST",
      url: "http://dvwa/vulnerabilities/sqli/",
      ...(state === "completed"
        ? { status_code: 200, duration_ms: 0, records: 0, response_bytes: 0 }
        : {}),
    }),
  }));
  const entries = buildLogEntries(events);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].activity.state, "completed");
  const html = render(LogRow, { entry: entries[0] });
  assert.match(html, /HTTP 200/);
  assert.match(html, /0 ms/);
  assert.match(html, /0 registro/);
  assert.match(html, /Respuesta: 0 bytes/);
  assert.doesNotMatch(html, /<details[^>]* open/);
});

test("failed and simulated logs never fabricate successful HTTP responses", () => {
  const [failed] = buildLogEntries([
    {
      event_type: "LAB_ACTIVITY",
      message: JSON.stringify({
        step_id: "login",
        summary: "Autenticar",
        state: "failed",
        detail: "timeout",
      }),
    },
  ]);
  const html = render(LogRow, { entry: failed });
  assert.match(html, /Sin respuesta/);
  assert.doesNotMatch(html, /HTTP 200|registro\(s\)/);
  const [demo] = buildLogEntries([
    {
      event_type: "PAYLOAD_DEMONSTRATION",
      message: JSON.stringify({
        name: "Ejemplo",
        result: "DETECTED",
        status_code: 200,
      }),
    },
  ]);
  assert.match(render(LogRow, { entry: demo }), /demostración no ejecutada/);
  assert.doesNotMatch(render(LogRow, { entry: demo }), /HTTP 200/);
});

test("Medium evidence displays POST request body and measured timing", () => {
  const html = render(FindingCard, {
    test: {
      result: "DETECTED",
      method: "POST",
      dvwa_level: "medium",
      observed_duration_ms: 0,
      request_body: "Submit=Submit&id=1+AND+1%3D2",
      tested_url: "http://dvwa/vulnerabilities/sqli/",
    },
  });
  assert.match(html, /Nivel DVWA/);
  assert.match(html, /medium/);
  assert.match(html, /POST: Submit=Submit/);
  assert.match(html, /0 ms/);
});

test("missing evidence does not fabricate HTTP, SQL or exposed data", () => {
  const html = render(FindingCard, { test: { result: "NOT_DETECTED" } });
  assert.match(html, /Sin datos/);
  assert.match(html, /Sin URL reportada/);
  assert.doesNotMatch(html, /KERNEL TELEMETRY|Consulta interceptada/);
  assert.doesNotMatch(html, /SELECT|>200<|admin@|Kernel confirmó/);
});

test("DVWA counts preserve zero and distinguish true and false conditions", () => {
  const html = render(FindingCard, {
    test: {
      result: "DETECTED",
      status_code: 200,
      baseline_size: 0,
      observed_size: 0,
      baseline_records: 1,
      true_records: 1,
      observed_records: 0,
      tested_url: "http://dvwa/vulnerabilities/sqli/",
    },
  });
  assert.match(html, />200</);
  assert.match(html, /Condición falsa/);
  assert.match(html, />0</);
  assert.match(html, /http:\/\/dvwa\/vulnerabilities\/sqli\//);
  assert.doesNotMatch(html, /Hash|admin|tabla de usuarios/);
});

test("completed demonstrations produce an inconclusive banner", () => {
  const html = render(StatusBanner, {
    isDone: true,
    isInconclusive: true,
    detectedCount: 0,
  });
  assert.match(html, /Resultado no concluyente/);
  assert.doesNotMatch(html, /PROTEGIDO|SIN HALLAZGOS/);
});

test("no detections does not claim protection or dual validation", () => {
  const html = render(StatusBanner, { isDone: true, detectedCount: 0 });
  assert.match(html, /SIN HALLAZGOS/);
  assert.doesNotMatch(html, /PROTEGIDO/);
  assert.doesNotMatch(
    render(StatusBanner, { isDone: true, detectedCount: 1 }),
    /validación dual|registros confidenciales/,
  );
});
