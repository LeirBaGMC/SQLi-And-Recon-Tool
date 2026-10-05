# Medición local sobre DVWA Low

Fecha UTC: 2026-10-04T22:13:39.176130+00:00

| Herramienta | Mediana (s) | Detección booleana |
| --- | ---: | --- |
| SQLi Studio | 0.178 | 3/3 ejecuciones |
| sqlmap | 5.525 | 3/3 ejecuciones |

Sequential runs, alternating order, fresh sessions. End-to-end monotonic clock: login + detection; app polling interval 50 ms. sqlmap Python startup included. Result-report rendering excluded.

App: SQL error signature + two repeated boolean pairs. sqlmap: boolean-only, id, MySQL, level 1, risk 1, one thread. Both confirm boolean injection; algorithms and payload counts differ. No enumeration requested.

Same DVWA instance; app HTTP runs through Docker DNS, sqlmap through host loopback. Pilot on one machine, not a general performance ranking.

sqlmap 1.10.9.32#dev; commit `1d9965d0033d7a0e9e8bfd9cb066a5e4cb55b590`.

Los tiempos menores no implican mayor cobertura ni precisión. Consulte dvwa-latest.json para las ejecuciones individuales.
