# DVWA: High y concurrencia conservando evidencia

Fecha UTC: 2026-10-05T15:44:11.399502+00:00

5 ejecuciones medidas por configuración, una de calentamiento. Evidencia equivalente: True. Validación completa: True.

| Nivel | Workers | Total mediana ms | p95 ms | Sesiones ms | Sondas ms | Speedup total | Speedup sondas | HTTP | Válidas |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| low | 1 | 248.6 | 259.6 | 70.3 | 114.0 | 1.00× | 1.00× | 10 | 5/5 |
| low | 2 | 272.5 | 298.2 | 119.6 | 105.1 | 0.91× | 1.08× | 14 | 5/5 |
| low | 4 | 434.7 | 499.3 | 261.9 | 113.3 | 0.57× | 1.01× | 22 | 5/5 |
| medium | 1 | 257.8 | 312.1 | 74.2 | 123.0 | 1.00× | 1.00× | 10 | 5/5 |
| medium | 2 | 305.4 | 390.4 | 146.7 | 117.7 | 0.84× | 1.04× | 14 | 5/5 |
| medium | 4 | 419.9 | 464.8 | 259.0 | 107.4 | 0.61× | 1.15× | 22 | 5/5 |
| high | 1 | 331.2 | 375.5 | 69.3 | 210.2 | 1.00× | 1.00× | 16 | 5/5 |
| high | 2 | 399.2 | 406.8 | 128.1 | 207.3 | 0.83× | 1.01× | 20 | 5/5 |
| high | 4 | 500.5 | 539.1 | 244.4 | 197.4 | 0.66× | 1.06× | 28 | 5/5 |

Speedup = mediana con 1 worker / mediana con N workers. Menor que 1 significa más lento. p95 usa interpolación lineal; con pocas muestras solo describe este piloto.

Local Docker DVWA; six fixed logical probes: baseline, quote, true/false twice. Baseline first; five jobs on a bounded pool. Fresh isolated session per worker. High serializes each input POST + result GET. Warmup excluded; rotated alternating run order. Backend monotonic wall clocks include trace persistence; total also includes finding persistence. API polling is separately measured and excluded from backend clocks.

HTTP calls = 4 authentication calls per worker + 6 probes (Low/Medium) or 12 input/probe calls (High). Redirect hops are excluded. Concurrent jobs wait for trace persistence; authentication overhead is included in total. HTTP 500 with a known signature is measured evidence, not a transport failure.

La comparación booleana exige siempre base/true/false = 1/1/0. High intenta ocultar el error en su fuente, pero la respuesta de esta instalación determina si se detecta una firma; el benchmark conserva ambos veredictos y exige que sean iguales entre workers. El hash compara la evidencia semántica, excluyendo tiempos y asignación de worker.

Pilot on one local machine; small sample and six logical probes, no WAN load or time-based injection. A larger worker count may cost more than it saves. Negative-control and unstable-response checks run in Go tests; this live DVWA benchmark alone cannot estimate general recall or false-positive rate. sqlmap and eBPF are outside this worker experiment.

Los identificadores de escaneo y las ejecuciones individuales se conservan en workers-latest.json. Los eventos HTTP completos permanecen en el historial del backend.
