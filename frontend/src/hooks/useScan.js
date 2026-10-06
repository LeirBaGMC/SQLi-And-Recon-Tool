import { useEffect, useRef, useState } from "react";
import axios from "axios";
import { validateExternalUrl } from "../scans/targets.js";
import { watchScan } from "../scans/polling.js";
import { buildLogEntries, parsePayloadEvents, parseDVWAMetrics } from "../scans/events.js";

// Own the scan lifecycle, polling and elapsed time; presentation stays in App.
export default function useScan({ currentPreset, customUrl, dvwaLevel, dvwaVariant, workers }) {
  const [scanId, setScanId] = useState("");
  const [scanStatus, setScanStatus] = useState(null);
  const [events, setEvents] = useState([]);
  const [report, setReport] = useState(null);
  const [isRunning, setIsRunning] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [connectionError, setConnectionError] = useState("");
  const [pollRevision, setPollRevision] = useState(0);
  const [elapsedMS, setElapsedMS] = useState(null);
  const [baselineScan, setBaselineScan] = useState(null);
  const startedRef = useRef(0);
  const submissionRef = useRef(false);
  const payloadTests = parsePayloadEvents(events);
  const metrics = parseDVWAMetrics(events);
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

  function clearCurrentScan() {
    setScanId("");
    setScanStatus(null);
    setEvents([]);
    setReport(null);
    setErrorMessage("");
    setConnectionError("");
    setElapsedMS(null);
  }

  function resetSession() {
    clearCurrentScan();
    setBaselineScan(null);
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
    const stop = watchScan({
      scanId, client: axios, signal: controller.signal,
      onStatus: setScanStatus, onEvents: setEvents, onReport: setReport,
      onConnectionError: setConnectionError,
      onComplete(status) {
        if (status.status === "FAILED") {
          setErrorMessage(status.error_message || "El escaneo falló.");
        }
        setElapsedMS(performance.now() - startedRef.current);
        setIsRunning(false);
      },
    });
    return () => {
      controller.abort();
      stop();
    };
  }, [isRunning, scanId, pollRevision]);

  function reconnect() {
    if (scanId && isRunning) setPollRevision((previous) => previous + 1);
  }

  async function startScan(variant = dvwaVariant) {
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
    if (currentPreset.id === "dvwa" && variant === "prepared" && isDone &&
        report?.blue_team?.variant === "vulnerable") {
      setBaselineScan({ scan_id: scanId, level: dvwaLevel, workers, detected: detectedCount });
    } else if (variant !== "prepared") setBaselineScan(null);
    clearCurrentScan();
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
              target: "dvwa",
              dvwa_level: dvwaLevel,
              dvwa_variant: variant,
              workers,
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

  function handleStartScan(event) {
    event.preventDefault();
    return startScan();
  }

  function verifyCorrection() {
    return startScan("prepared");
  }

  return {
    scanId,
    scanStatus,
    events,
    report,
    isRunning,
    errorMessage,
    connectionError,
    reconnect,
    elapsedMS,
    metrics,
    baselineScan,
    payloadTests,
    detectedCount,
    isDone,
    isInconclusive,
    currentActivity,
    completedRequests,
    totalRequests,
    resetSession,
    handleStartScan,
    verifyCorrection,
  };
}
