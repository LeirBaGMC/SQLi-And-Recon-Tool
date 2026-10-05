import { useEffect, useRef, useState } from "react";
import axios from "axios";
import { FINAL_STATUSES, validateExternalUrl } from "../scans/targets.js";
import { buildLogEntries, parsePayloadEvents } from "../scans/events.js";

// Own the scan lifecycle, polling and elapsed time; presentation stays in App.
export default function useScan({ currentPreset, customUrl, dvwaLevel }) {
  const [scanId, setScanId] = useState("");
  const [scanStatus, setScanStatus] = useState(null);
  const [events, setEvents] = useState([]);
  const [report, setReport] = useState(null);
  const [isRunning, setIsRunning] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [elapsedMS, setElapsedMS] = useState(null);
  const startedRef = useRef(0);
  const submissionRef = useRef(false);
  const payloadTests = parsePayloadEvents(events);
  const realTests = payloadTests.filter((test) => !test.isSimulated);
  const detectedCount = realTests.filter(
    (test) => test.result === "DETECTED",
  ).length;
  const isDone = scanStatus?.status === "COMPLETED";
  const isInconclusive =
    events.some((event) => event.event_type === "SCAN_INCONCLUSIVE") ||
    realTests.length === 0 ||
    realTests.some(
      (test) => !["DETECTED", "NOT_DETECTED"].includes(test.result),
    );
  const logEntries = buildLogEntries(events);
  const currentActivity = [...logEntries]
    .reverse()
    .find((entry) => entry.activity)?.activity;
  const completedRequests = logEntries.filter(
    (entry) =>
      entry.activity?.stage === "probe" &&
      ["completed", "http_error"].includes(entry.activity.state),
  ).length;
  const totalRequests =
    currentActivity?.request_total ||
    logEntries.find((entry) => entry.activity?.request_total)?.activity
      .request_total;

  function resetSession() {
    setScanId("");
    setScanStatus(null);
    setEvents([]);
    setReport(null);
    setErrorMessage("");
    setElapsedMS(null);
  }

  useEffect(() => {
    if (!isRunning) return;
    const timer = setInterval(
      () => setElapsedMS(performance.now() - startedRef.current),
      100,
    );
    return () => clearInterval(timer);
  }, [isRunning]);

  useEffect(() => {
    if (!isRunning || !scanId) return;
    const controller = new AbortController();
    const options = { signal: controller.signal, timeout: 15000 };
    let timer;
    async function poll() {
      try {
        const statusResponse = await axios.get(`/api/scans/${scanId}`, options);
        const eventsResponse = await axios.get(
          `/api/scans/${scanId}/events`,
          options,
        );
        if (controller.signal.aborted) return;
        setScanStatus(statusResponse.data);
        setEvents(eventsResponse.data.events || []);
        if (FINAL_STATUSES.includes(statusResponse.data.status)) {
          if (statusResponse.data.status === "COMPLETED") {
            const results = await axios.get(
              `/api/scans/${scanId}/results`,
              options,
            );
            if (controller.signal.aborted) return;
            setReport(results.data.remediation_report || null);
          } else
            setErrorMessage(
              statusResponse.data.error_message || "El escaneo falló.",
            );
          setElapsedMS(performance.now() - startedRef.current);
          setIsRunning(false);
        } else timer = setTimeout(poll, 350);
      } catch (error) {
        if (axios.isCancel(error) || controller.signal.aborted) return;
        setElapsedMS(performance.now() - startedRef.current);
        setScanStatus((previous) => ({ ...previous, status: "FAILED" }));
        setErrorMessage(
          "No se pudo actualizar el escaneo. Revisa la conexión con el backend.",
        );
        setIsRunning(false);
      }
    }
    poll();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [isRunning, scanId]);

  async function handleStartScan(event) {
    event.preventDefault();
    if (submissionRef.current || isRunning || !currentPreset) return;
    if (currentPreset.id === "external") {
      try {
        validateExternalUrl(customUrl);
      } catch (error) {
        setErrorMessage(error.message);
        return;
      }
    }
    submissionRef.current = true;
    resetSession();
    startedRef.current = performance.now();
    setElapsedMS(0);
    setIsRunning(true);
    try {
      const body =
        currentPreset.id === "external"
          ? {
              mode: "authorized_url",
              url: validateExternalUrl(customUrl),
              authorization_confirmed: true,
            }
          : {
              mode: currentPreset.mode,
              target: currentPreset.target,
              dvwa_level: dvwaLevel,
            };
      const response = await axios.post("/api/scans", body, { timeout: 15000 });
      const id = response.data.scan_id || response.data.id;
      if (!id) throw new Error("Missing scan ID");
      setScanId(id);
      setScanStatus({ status: "QUEUED", ...response.data });
    } catch (error) {
      setElapsedMS(performance.now() - startedRef.current);
      setIsRunning(false);
      setErrorMessage(
        error.response?.data?.error || "No se pudo iniciar el escaneo.",
      );
    } finally {
      submissionRef.current = false;
    }
  }

  return {
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
  };
}
