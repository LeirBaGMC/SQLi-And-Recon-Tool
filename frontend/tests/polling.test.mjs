import assert from "node:assert/strict";
import { test } from "node:test";
import { watchScan } from "../src/scans/polling.js";

const settle = () => new Promise((resolve) => setImmediate(resolve));
function observe(script) {
  const state = { statuses: [], events: [{ id: "preserved" }], report: null, completions: [], errors: [] };
  const calls = [];
  const scheduled = [];
  const controller = new AbortController();
  const stop = watchScan({
    scanId: "original-id", signal: controller.signal,
    client: { async get(url, options) {
      calls.push(url);
      assert.equal(options.signal, controller.signal);
      const next = script.shift();
      assert.ok(next, `Unexpected request: ${url}`);
      if (next.error) throw next.error;
      return { data: next.data };
    } },
    onStatus: (status) => state.statuses.push(status),
    onEvents: (events) => { state.events = events; },
    onReport: (report) => { state.report = report; },
    onComplete: (status) => state.completions.push(status),
    onConnectionError: (message) => state.errors.push(message),
    schedule(callback, delay) { const timer = { callback, delay }; scheduled.push(timer); return timer; },
    cancelScheduled(timer) { const index = scheduled.indexOf(timer); if (index >= 0) scheduled.splice(index, 1); },
  });
  return { state, calls, scheduled, controller, stop };
}
const networkError = () => ({ error: new Error("Backend disconnected") });
const running = () => ({ data: { scan_id: "original-id", status: "RUNNING" } });
const completed = () => ({ data: { scan_id: "original-id", status: "COMPLETED" } });
const events = () => ({ data: { events: [{ id: 7, event_type: "PAYLOAD_EXECUTED" }] } });
const report = () => ({ data: { remediation_report: { scan_id: "original-id", summary: "Measured evidence" } } });

test("connection loss retains server status and evidence, then resumes the same scan without creating another", async () => {
  const watcher = observe([running(), events(), networkError(), completed(), events(), report()]);
  await settle();
  const nextPoll = watcher.scheduled.shift();
  assert.equal(nextPoll.delay, 350);
  await nextPoll.callback();
  assert.equal(watcher.state.statuses.at(-1).status, "RUNNING");
  assert.equal(watcher.state.events[0].id, 7);
  assert.equal(watcher.state.completions.length, 0);
  const retry = watcher.scheduled.shift();
  assert.equal(retry.delay, 1000);
  await retry.callback();
  assert.equal(watcher.state.statuses.at(-1).status, "COMPLETED");
  assert.equal(watcher.state.report.scan_id, "original-id");
  assert.equal(watcher.state.completions.length, 1);
  assert.equal(watcher.state.errors.at(-1), "");
  assert.ok(watcher.calls.every((url) => url.startsWith("/api/scans/original-id")));
  assert.ok(watcher.state.statuses.every((status) => status.status !== "FAILED"));
  watcher.stop();
});

test("a failed results fetch retries without changing a completed backend scan to FAILED", async () => {
  const watcher = observe([completed(), events(), networkError(), completed(), events(), report()]);
  await settle();
  assert.equal(watcher.state.statuses.at(-1).status, "COMPLETED");
  assert.equal(watcher.state.events[0].id, 7);
  assert.equal(watcher.state.completions.length, 0);
  await watcher.scheduled.shift().callback();
  assert.equal(watcher.state.completions.length, 1);
  assert.ok(watcher.state.report);
  watcher.stop();
});

test("only a FAILED response from the backend finishes the scan as failed", async () => {
  const watcher = observe([{ data: { status: "FAILED", error_message: "Interrupted by restart" } }, events()]);
  await settle();
  assert.equal(watcher.state.completions[0].error_message, "Interrupted by restart");
  assert.equal(watcher.scheduled.length, 0);
  assert.equal(watcher.state.errors.at(-1), "");
  watcher.stop();
});

test("repeated connection errors back off to ten seconds without inventing a scan status", async () => {
  const watcher = observe(Array.from({ length: 7 }, networkError));
  await settle();
  for (const delay of [1000, 2000, 4000, 8000, 10000, 10000]) {
    const timer = watcher.scheduled.shift();
    assert.equal(timer.delay, delay);
    await timer.callback();
  }
  assert.equal(watcher.state.statuses.length, 0);
  assert.equal(watcher.state.completions.length, 0);
  watcher.stop();
  assert.equal(watcher.scheduled.length, 0);
});

test("aborting an old request suppresses late responses and retries", async () => {
  const controller = new AbortController();
  let release;
  const callbacks = [];
  const stop = watchScan({
    scanId: "old-id", signal: controller.signal,
    client: { get: () => new Promise((resolve) => { release = resolve; }) },
    onStatus: () => callbacks.push("status"), onEvents: () => callbacks.push("events"),
    onReport: () => callbacks.push("report"), onComplete: () => callbacks.push("complete"),
    onConnectionError: () => callbacks.push("error"), schedule: () => callbacks.push("retry"),
  });
  controller.abort();
  stop();
  release({ data: { status: "COMPLETED" } });
  await settle();
  assert.deepEqual(callbacks, []);
});
