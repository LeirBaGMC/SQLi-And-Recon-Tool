export function parsePayloadEvents(events) {
  return events
    .filter((event) =>
      ["PAYLOAD_EXECUTED", "PAYLOAD_DEMONSTRATION"].includes(event.event_type),
    )
    .flatMap((event) => {
      try {
        const test = JSON.parse(event.message);
        return [
          {
            ...test,
            id: event.id,
            isSimulated:
              event.event_type === "PAYLOAD_DEMONSTRATION" ||
              test.execution_type === "SIMULATED" ||
              test.result === "SIMULATED",
          },
        ];
      } catch {
        return [];
      }
    });
}

function eventMessage(event) {
  if (
    ["PAYLOAD_EXECUTED", "PAYLOAD_DEMONSTRATION"].includes(event.event_type)
  ) {
    try {
      const probe = JSON.parse(event.message);
      const result =
        event.event_type === "PAYLOAD_DEMONSTRATION" ||
        probe.execution_type === "SIMULATED"
          ? "demostración no ejecutada"
          : probe.result === "DETECTED"
            ? "detectada"
            : probe.result === "NOT_DETECTED"
              ? "sin detección"
              : "no concluyente";
      const records =
        probe.baseline_records != null
          ? ` · Registros ${probe.baseline_records} / ${probe.true_records ?? "—"} / ${probe.observed_records ?? "—"}`
          : "";
      return `${probe.name}: ${result}${records}`;
    } catch {
      return event.message;
    }
  }
  return (
    {
      SCAN_QUEUED: "Escaneo en cola",
      SCAN_STARTED: "Motor HTTP iniciado",
      SCAN_COMPLETED: "Escaneo completado · Resultados guardados",
    }[event.event_type] || event.message
  );
}

// Replace a request start with its response using the same step_id.
export function buildLogEntries(events) {
  const entries = [];
  const steps = new Map();
  const hasActivity = events.some((event) =>
    ["LAB_ACTIVITY", "HTTP_ACTIVITY"].includes(event.event_type),
  );
  for (const event of events) {
    if (["LAB_ACTIVITY", "HTTP_ACTIVITY"].includes(event.event_type)) {
      try {
        const activity = JSON.parse(event.message);
        if (!activity.step_id || !activity.summary) throw new Error();
        const entry = { ...event, activity, label: activity.summary };
        if (steps.has(activity.step_id))
          entries[steps.get(activity.step_id)] = entry;
        else {
          steps.set(activity.step_id, entries.length);
          entries.push(entry);
        }
      } catch {
        entries.push({ ...event, label: "Evento HTTP sin datos válidos" });
      }
    } else {
      if (
        hasActivity &&
        ["FINDING_CREATED", "BASELINE_COMPLETED"].includes(event.event_type)
      )
        continue;
      let probe = null;
      if (
        ["PAYLOAD_EXECUTED", "PAYLOAD_DEMONSTRATION"].includes(event.event_type)
      ) {
        try {
          probe = JSON.parse(event.message);
        } catch {
          /* Retain the original event. */
        }
      }
      entries.push({ ...event, probe, label: eventMessage(event) });
    }
  }
  return entries;
}
