import { FINAL_STATUSES } from "./targets.js";

// One request chain at a time. A transport error changes connection state only;
// the server remains the authority for the scan status and its evidence.
export function watchScan({
  scanId, client, signal, onStatus, onEvents, onReport, onComplete,
  onConnectionError, schedule = setTimeout, cancelScheduled = clearTimeout,
}) {
  let stopped = false;
  let timer;
  let failures = 0;
  const options = { signal, timeout: 15000 };
  const inactive = () => stopped || signal.aborted;

  async function poll() {
    if (inactive()) return;
    try {
      const status = (await client.get(`/api/scans/${scanId}`, options)).data;
      if (inactive()) return;
      onStatus(status);
      const events = (await client.get(`/api/scans/${scanId}/events`, options)).data;
      if (inactive()) return;
      onEvents(events.events || []);
      if (status.status === "COMPLETED") {
        const results = (await client.get(`/api/scans/${scanId}/results`, options)).data;
        if (inactive()) return;
        onReport(results.remediation_report || null);
      }
      failures = 0;
      onConnectionError("");
      if (FINAL_STATUSES.includes(status.status)) {
        stopped = true;
        onComplete(status);
      } else timer = schedule(poll, 350);
    } catch {
      if (inactive()) return;
      failures += 1;
      onConnectionError("No se pudo consultar el backend. Conservamos esta prueba y volveremos a consultar el mismo escaneo automáticamente.");
      const delay = Math.min(1000 * 2 ** Math.min(failures - 1, 4), 10000);
      timer = schedule(poll, delay);
    }
  }

  void poll();
  return () => {
    stopped = true;
    cancelScheduled(timer);
  };
}
