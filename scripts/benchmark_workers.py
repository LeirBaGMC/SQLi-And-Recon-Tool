"""Compare a fixed DVWA workload with 1, 2 and 4 isolated workers."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import statistics
import time
from urllib.request import Request, build_opener, ProxyHandler

ROOT = Path(__file__).resolve().parents[1]
API = "http://127.0.0.1:3000/api/scans"
OPENER = build_opener(ProxyHandler({}))


def api(url, body=None):
    data = None if body is None else json.dumps(body).encode()
    with OPENER.open(Request(url, data=data, headers={"Content-Type": "application/json"}), timeout=15) as response:
        return json.load(response)


def run(level, workers):
    started = time.perf_counter()
    scan_id = api(API, {"mode": "dvwa", "target": "dvwa", "dvwa_level": level, "workers": workers})["scan_id"]
    deadline = started + 90
    while time.perf_counter() < deadline:
        state = api(f"{API}/{scan_id}")
        if state["status"] in ("COMPLETED", "FAILED"):
            break
        time.sleep(0.025)
    else:
        raise RuntimeError(f"Scan timeout: {scan_id}")
    end_to_end_ms = (time.perf_counter() - started) * 1000
    events = api(f"{API}/{scan_id}/events")["events"]
    probes = [json.loads(event["message"]) for event in events if event["event_type"] == "PAYLOAD_EXECUTED"]
    activities = [json.loads(event["message"]) for event in events if event["event_type"] == "LAB_ACTIVITY"]
    metrics_events = [json.loads(event["message"]) for event in events if event["event_type"] == "DVWA_METRICS"]
    metrics = metrics_events[-1] if metrics_events else {}
    results = api(f"{API}/{scan_id}/results")
    boolean = next((probe for probe in probes if "booleana" in probe["name"]), {})
    # Compare semantic evidence, excluding worker assignment and timing.
    evidence = [{key: probe.get(key) for key in ("name", "result", "payload", "status_code", "baseline_records", "true_records", "observed_records", "method", "dvwa_level", "execution_type")} for probe in probes]
    evidence_digest = hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest()
    expected_http = 4 * workers + (12 if level == "high" else 6)
    completed = [activity for activity in activities if activity.get("stage") == "probe" and activity["state"] in ("completed", "http_error")]
    error_result = probes[0].get("result") if probes else None
    error_valid = error_result in ("NOT_DETECTED", "DETECTED") if level == "high" else error_result == "DETECTED"
    valid = (state["status"] == "COMPLETED" and len(probes) == 2
             and error_valid and boolean.get("result") == "DETECTED"
             and boolean.get("baseline_records") == 1 and boolean.get("true_records") == 1
             and boolean.get("observed_records") == 0 and len(boolean.get("checks", [])) == 5
             and all(probe.get("execution_type") == "REAL" for probe in probes)
             and len(completed) == 6 and len({activity["step_id"] for activity in completed}) == 6
             and metrics.get("workers") == workers and metrics.get("http_requests") == expected_http
             and metrics.get("completed_probes") == 6 and metrics.get("failed_requests") == 0
             and metrics.get("inconclusive") == 0 and results["total"] == sum(probe.get("result") == "DETECTED" for probe in probes))
    return {"scan_id": scan_id, "level": level, "workers": workers, "status": state["status"],
            "end_to_end_ms": round(end_to_end_ms, 3), "metrics": metrics, "valid_evidence": valid,
            "findings": results["total"], "evidence_digest": evidence_digest, "probes": evidence}


def percentile(values, fraction):
    ordered = sorted(values)
    index = (len(ordered) - 1) * fraction
    low = int(index)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (index - low)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, choices=range(3, 31), default=5)
    args = parser.parse_args()
    records, warmups = [], []
    combinations = [(level, workers) for level in ("low", "medium", "high") for workers in (1, 2, 4)]
    # One warmup per configuration, retained for audit but excluded from statistics.
    for level, workers in combinations:
        warmups.append(run(level, workers))
    for repetition in range(args.runs):
        # Rotate and alternate order; never overlap independent scan runs.
        order = combinations[repetition % len(combinations):] + combinations[:repetition % len(combinations)]
        if repetition % 2:
            order = list(reversed(order))
        for level, workers in order:
            record = {"run": repetition + 1, **run(level, workers)}
            records.append(record)
            print(f"{level:6} / {workers} workers / run {repetition + 1}: backend {record['metrics'].get('total_ms', 0):.1f} ms, probes {record['metrics'].get('probe_ms', 0):.1f} ms, valid={record['valid_evidence']}", flush=True)
    summary = []
    equivalent = True
    for level in ("low", "medium", "high"):
        level_records = [record for record in records if record["level"] == level]
        equivalent = equivalent and len({record["evidence_digest"] for record in level_records}) == 1
        baseline = statistics.median(record["metrics"]["total_ms"] for record in level_records if record["workers"] == 1)
        probe_baseline = statistics.median(record["metrics"]["probe_ms"] for record in level_records if record["workers"] == 1)
        for workers in (1, 2, 4):
            group = [record for record in level_records if record["workers"] == workers]
            clocks = [record["metrics"]["total_ms"] for record in group]
            probe_ms = statistics.median(record["metrics"]["probe_ms"] for record in group)
            total_ms = statistics.median(clocks)
            summary.append({"level": level, "workers": workers, "median_total_ms": round(total_ms, 3),
                            "p95_total_ms": round(percentile(clocks, .95), 3),
                            "median_session_ms": round(statistics.median(record["metrics"]["session_ms"] for record in group), 3),
                            "median_probe_ms": round(probe_ms, 3), "total_speedup": round(baseline / total_ms, 3),
                            "probe_speedup": round(probe_baseline / probe_ms, 3),
                            "http_requests": group[0]["metrics"]["http_requests"],
                            "valid_runs": sum(record["valid_evidence"] for record in group),
                            "inconclusive": sum(record["metrics"]["inconclusive"] for record in group),
                            "transport_failures": sum(record["metrics"]["failed_requests"] for record in group)})
    valid = equivalent and all(record["valid_evidence"] for record in records + warmups)
    report = {"created_at": datetime.now(timezone.utc).isoformat(), "runs_per_configuration": args.runs,
              "evidence_equivalent": equivalent, "valid": valid,
              "method": "Local Docker DVWA; six fixed logical probes: baseline, quote, true/false twice. Baseline first; five jobs on a bounded pool. Fresh isolated session per worker. High serializes each input POST + result GET. Warmup excluded; rotated alternating run order. Backend monotonic wall clocks include trace persistence; total also includes finding persistence. API polling is separately measured and excluded from backend clocks.",
              "request_accounting": "HTTP calls = 4 authentication calls per worker + 6 probes (Low/Medium) or 12 input/probe calls (High). Redirect hops are excluded. Concurrent jobs wait for trace persistence; authentication overhead is included in total. HTTP 500 with a known signature is measured evidence, not a transport failure.",
              "limitations": "Pilot on one local machine; small sample and six logical probes, no WAN load or time-based injection. A larger worker count may cost more than it saves. Negative-control and unstable-response checks run in Go tests; this live DVWA benchmark alone cannot estimate general recall or false-positive rate. sqlmap and eBPF are outside this worker experiment.",
              "summary": summary, "warmups": warmups, "runs": records}
    output = ROOT / "docs/benchmarks"
    output.mkdir(parents=True, exist_ok=True)
    (output / "workers-latest.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = ["# DVWA: High y concurrencia conservando evidencia", "", f"Fecha UTC: {report['created_at']}", "",
             f"{args.runs} ejecuciones medidas por configuración, una de calentamiento. Evidencia equivalente: {equivalent}. Validación completa: {valid}.", "",
             "| Nivel | Workers | Total mediana ms | p95 ms | Sesiones ms | Sondas ms | Speedup total | Speedup sondas | HTTP | Válidas |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |"]
    for row in summary:
        lines.append(f"| {row['level']} | {row['workers']} | {row['median_total_ms']:.1f} | {row['p95_total_ms']:.1f} | {row['median_session_ms']:.1f} | {row['median_probe_ms']:.1f} | {row['total_speedup']:.2f}× | {row['probe_speedup']:.2f}× | {row['http_requests']} | {row['valid_runs']}/{args.runs} |")
    lines += ["", "Speedup = mediana con 1 worker / mediana con N workers. Menor que 1 significa más lento. p95 usa interpolación lineal; con pocas muestras solo describe este piloto.", "", report["method"], "", report["request_accounting"], "", "La comparación booleana exige siempre base/true/false = 1/1/0. High intenta ocultar el error en su fuente, pero la respuesta de esta instalación determina si se detecta una firma; el benchmark conserva ambos veredictos y exige que sean iguales entre workers. El hash compara la evidencia semántica, excluyendo tiempos y asignación de worker.", "", report["limitations"], "", "Los identificadores de escaneo y las ejecuciones individuales se conservan en workers-latest.json. Los eventos HTTP completos permanecen en el historial del backend."]
    (output / "workers-latest.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Report saved: docs/benchmarks/workers-latest.md; evidence equivalent={equivalent}")
    if not valid:
        raise SystemExit("Benchmark failed evidence validation; do not claim a speed gain with preserved detection")


if __name__ == "__main__":
    main()
