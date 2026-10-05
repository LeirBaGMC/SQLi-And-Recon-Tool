"""Compare local DVWA detection runs; keep cookies and raw tool output in memory."""
import argparse
import http.cookiejar
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from urllib.parse import urlencode
from urllib.request import Request, build_opener, HTTPCookieProcessor, ProxyHandler

ROOT = Path(__file__).resolve().parents[1]
API = "http://127.0.0.1:3000"
DVWA = "http://127.0.0.1:8000"
TARGET = DVWA + "/vulnerabilities/sqli/?id=1&Submit=Submit"


def request(opener, url, data=None):
    with opener.open(Request(url, data=data), timeout=15) as response:
        return response.read().decode("utf-8", errors="replace"), response.geturl()


def token(page):
    # Official DVWA renders name before value for this hidden input.
    match = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)", page)
    if not match:
        raise RuntimeError("DVWA CSRF token missing")
    return match.group(1)


def login():
    jar = http.cookiejar.CookieJar()
    opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(jar))
    page, _ = request(opener, DVWA + "/login.php")
    page, final_url = request(opener, DVWA + "/login.php", urlencode({
        "username": os.getenv("DVWA_USERNAME", "admin"),
        "password": os.getenv("DVWA_PASSWORD", "password"),
        "Login": "Login", "user_token": token(page),
    }).encode())
    if final_url.endswith("login.php") or "logout.php" not in page:
        raise RuntimeError("DVWA login failed")
    page, _ = request(opener, DVWA + "/security.php")
    page, _ = request(opener, DVWA + "/security.php", urlencode({
        "security": "low", "seclev_submit": "Submit", "user_token": token(page),
    }).encode())
    if "<em>low</em>" not in page:
        raise RuntimeError("DVWA Low not confirmed")
    return "; ".join(f"{cookie.name}={cookie.value}" for cookie in jar)


def app_run():
    opener = build_opener(ProxyHandler({}))
    started = time.perf_counter()
    req = Request(API + "/api/scans", data=b'{"mode":"dvwa","target":"dvwa","dvwa_level":"low"}', headers={"Content-Type": "application/json"})
    with opener.open(req, timeout=15) as response:
        scan_id = json.load(response)["scan_id"]
    while time.perf_counter() - started < 90:
        page, _ = request(opener, API + f"/api/scans/{scan_id}")
        state = json.loads(page)
        if state["status"] in ("COMPLETED", "FAILED"):
            break
        time.sleep(0.05)
    else:
        raise RuntimeError("App timeout")
    elapsed = time.perf_counter() - started
    if state["status"] != "COMPLETED":
        raise RuntimeError("App scan failed")
    page, _ = request(opener, API + f"/api/scans/{scan_id}/events")
    probes = [json.loads(event["message"]) for event in json.loads(page)["events"] if event["event_type"] == "PAYLOAD_EXECUTED"]
    boolean = next((probe for probe in probes if "booleana" in probe.get("name", "").lower()), None)
    detected = bool(boolean and boolean.get("execution_type") == "REAL" and boolean.get("result") == "DETECTED")
    return {"tool": "SQLi Studio", "seconds": round(elapsed, 4), "boolean_detected": detected,
            "probes": len(probes), "scan_id": scan_id}


def sqlmap_run(sqlmap_path):
    started = time.perf_counter()
    cookies = login()
    # Unique output directory prevents reuse of previous injection knowledge.
    with tempfile.TemporaryDirectory(prefix="dvwa-sqlmap-") as output:
        args = [sys.executable, str(sqlmap_path), "-u", TARGET, "--cookie", cookies,
                "-p", "id", "--batch", "--technique=B", "--level=1", "--risk=1",
                "--threads=1", "--dbms=MySQL", "--timeout=10", "--retries=0",
                "--ignore-proxy", "--disable-coloring", "--flush-session",
                "--output-dir", output]
        result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=90, encoding="utf-8", errors="replace")
        elapsed = time.perf_counter() - started
        text = result.stdout + result.stderr
        # Require final injection evidence, not a heuristic or echoed test name.
        detected = result.returncode == 0 and "Type: boolean-based blind" in text and "Parameter: id (GET)" in text
        count = re.search(r"with a total of (\d+) HTTP", text)
        return {"tool": "sqlmap", "seconds": round(elapsed, 4), "boolean_detected": detected,
                "detection_http_requests": int(count.group(1)) if count else None,
                "exit_code": result.returncode}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sqlmap", type=Path, default=ROOT / "tools/sqlmap/sqlmap.py")
    parser.add_argument("--runs", type=int, choices=range(3, 11), default=3)
    args = parser.parse_args()
    if not args.sqlmap.is_file():
        parser.error("Clone https://github.com/sqlmapproject/sqlmap into tools/sqlmap first")
    version_output = subprocess.run([sys.executable, str(args.sqlmap), "--version", "--batch"], stdin=subprocess.DEVNULL, capture_output=True, text=True, check=True).stdout
    version = version_output.splitlines()[0].strip()
    revision = subprocess.run(["git", "-C", str(args.sqlmap.parent), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    records = []
    for run in range(1, args.runs + 1):
        # Alternate order to reduce a fixed warm-cache advantage.
        runners = [app_run, lambda: sqlmap_run(args.sqlmap)]
        if run % 2 == 0:
            runners.reverse()
        for runner in runners:
            record = {"run": run, **runner()}
            records.append(record)
            print(f"{record['tool']} #{run}: {record['seconds']:.3f} s | Boolean detected: {record['boolean_detected']}", flush=True)
    report = {"created_at": datetime.now(timezone.utc).isoformat(), "target": TARGET, "dvwa_security": "low",
              "sqlmap_version": version, "sqlmap_revision": revision,
              "method": "Sequential runs, alternating order, fresh sessions. End-to-end monotonic clock: login + detection; app polling interval 50 ms. sqlmap Python startup included. Result-report rendering excluded.",
              "scope": "App: SQL error signature + two repeated boolean pairs. sqlmap: boolean-only, id, MySQL, level 1, risk 1, one thread. Both confirm boolean injection; algorithms and payload counts differ. No enumeration requested.",
              "limitations": "Same DVWA instance; app HTTP runs through Docker DNS, sqlmap through host loopback. Pilot on one machine, not a general performance ranking.",
              "runs": records, "medians_seconds": {tool: round(statistics.median(record["seconds"] for record in records if record["tool"] == tool), 4) for tool in ("SQLi Studio", "sqlmap")}}
    output = ROOT / "docs/benchmarks"
    output.mkdir(parents=True, exist_ok=True)
    (output / "dvwa-latest.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    rows = ["# Medición local sobre DVWA Low", "", f"Fecha UTC: {report['created_at']}", "", "| Herramienta | Mediana (s) | Detección booleana |", "| --- | ---: | --- |"]
    for tool, median in report["medians_seconds"].items():
        count = sum(record["boolean_detected"] for record in records if record["tool"] == tool)
        rows.append(f"| {tool} | {median:.3f} | {count}/{args.runs} ejecuciones |")
    rows += ["", report["method"], "", report["scope"], "", report["limitations"], "", f"sqlmap {version}; commit `{revision}`.", "", "Los tiempos menores no implican mayor cobertura ni precisión. Consulte dvwa-latest.json para las ejecuciones individuales."]
    (output / "dvwa-latest.md").write_text("\n".join(rows) + "\n", encoding="utf-8")
    print("Report saved to docs/benchmarks/dvwa-latest.md", flush=True)
    if not all(record["boolean_detected"] for record in records):
        raise SystemExit("Benchmark incomplete: at least one run did not confirm boolean injection")


if __name__ == "__main__":
    main()
