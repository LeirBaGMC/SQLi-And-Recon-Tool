# SQLi Studio y sqlmap

Comparación realizada el 5 de octubre de 2026 sobre el código activo del proyecto,
la documentación oficial de sqlmap y una prueba local repetida sobre DVWA Low.

SQLi Studio ofrece una interfaz educativa con pruebas acotadas y evidencia HTTP.
sqlmap ofrece un motor de auditoría con un alcance mucho mayor. La coincidencia
en este laboratorio permite validar un caso común; no establece equivalencia
entre las herramientas.

## Alcance y arquitectura

| Aspecto | SQLi Studio actual | sqlmap |
| --- | --- | --- |
| Implementación | Backend Go, frontend React, API REST e historial MySQL | Python, CLI y servidor API |
| Detección | Firma nueva de error SQL y condiciones booleanas repetidas | Seis familias SQL: booleanas, temporales, errores, UNION, consultas apiladas e inline |
| Entradas | Parámetros GET de URL; POST en el adaptador DVWA Medium | GET, POST, cookies y cabeceras; solicitudes y formularios configurables |
| Sesiones | Login y CSRF específicos de DVWA; Basic para URL | Opciones generales de autenticación, cookies y sesiones |
| Comparación HTTP | URL genérica: igualdad del cuerpo; DVWA: registros extraídos del HTML | Comparación configurable de respuestas y tratamiento de contenido dinámico |
| Persistencia | Historial de escaneos, eventos y hallazgos en MySQL | Archivos de sesión y resultados, con reanudación |
| Resultado para el usuario | Panel en español, peticiones medidas y ejemplos de remediación | Diagnóstico técnico y opciones de enumeración y explotación |

Fuentes de sqlmap: [repositorio oficial](https://github.com/sqlmapproject/sqlmap),
[funcionalidades](https://github.com/sqlmapproject/sqlmap/wiki/Features) y
[manual](https://github.com/sqlmapproject/sqlmap/wiki/Usage).
La comparación de respuestas también se revisó en la copia local de
`tools/sqlmap/lib/request/comparison.py`.

La sonda de comilla de SQLi Studio reconoce una firma SQL nueva en la respuesta.
No implementa la extracción mediante errores que puede realizar sqlmap.
Los tiempos registrados por nuestro motor son métricas HTTP; actualmente no
constituyen una técnica de detección por retraso SQL.

## Medición repetida en el laboratorio

Se ejecutó `scripts/benchmark_dvwa.py --runs 3` contra la misma instancia local
de DVWA Low. Copia medida de sqlmap: `1.10.9.32#dev`, commit
`1d9965d0033d7a0e9e8bfd9cb066a5e4cb55b590`. No se actualizó esa copia; la
documentación consultada describe el repositorio oficial actual.

| Herramienta | Mediana de tiempo | Confirmación booleana |
| --- | ---: | ---: |
| SQLi Studio | 0,295 s | 3/3 |
| sqlmap | 3,753 s | 3/3 |

Sesiones nuevas, ejecución secuencial y orden alternado. El tiempo incluye login
y detección; sqlmap incluye además el arranque de Python. Para sqlmap se fijaron
`--technique=B`, `--dbms=MySQL`, `--level=1`, `--risk=1` y `--threads=1`.
SQLi Studio ejecutó su sonda de error y dos pares booleanos repetidos.
No se solicitó enumeración de datos.

El benchmark consulta el estado de SQLi Studio cada 50 ms; este tiempo no es
el cronómetro del navegador. Las rutas HTTP tampoco son idénticas: backend
por DNS Docker y sqlmap por loopback del host.

Nuestro motor realiza seis peticiones de sonda en DVWA, además de las necesarias
para autenticar y configurar la sesión. sqlmap informó 163 peticiones de detección
en cada ejecución; ambos recuentos tienen alcances distintos.

Este ensayo contiene un único caso vulnerable y tres repeticiones por herramienta.
No mide falsos positivos, falsos negativos ni cobertura en otras aplicaciones.
La menor latencia de un recorrido especializado no demuestra mayor precisión.

Resultados completos: [reporte de tiempos](benchmarks/dvwa-latest.md) y
[ejecuciones individuales](benchmarks/dvwa-latest.json).

## Mejoras que esta comparación permite priorizar

1. Comparar respuestas dinámicas sin depender de igualdad completa del HTML.
   Actualmente pueden volver inconcluyente una prueba sobre una URL genérica.
2. Añadir solicitudes POST y gestión de cookies/CSRF para objetivos genéricos.
   Hoy ese flujo está implementado específicamente para DVWA.
3. Crear una matriz de evaluación con DVWA Low/Medium, casos parametrizados y
   respuestas inestables. Medir detección correcta, falsas alarmas y solicitudes,
   además del tiempo; la página de práctica eliminada no forma parte del ensayo.
4. Ampliar técnicas solo con pruebas que permitan verificar sus resultados.

Conclusión: SQLi Studio ya reproduce la detección booleana en este laboratorio
y facilita explicar su evidencia. sqlmap conserva una cobertura y flexibilidad
mucho mayores para auditorías generales.
