# Guía del expositor: SQLi Studio con DVWA

Workshop de 90 minutos para desarrolladores. Presentación principal: diapositivas 1–28. Anexos: 29–30.

## Preparación

- Abrir la presentación en vista del moderador. Las notas contienen tiempos, pasos y fuentes.
- Mantener la app en http://localhost:3000 y DVWA en http://localhost:8000.
- Abrir el editor en la raíz del proyecto. Preparar dvwa.go, authorized.go, report.go, hooks/useScan.js y scans/events.js.
- Preparar una terminal con los servicios activos. No proyectar .env, contraseñas, cookies o tokens.
- En un solo proyector, alternar con Alt+Tab. Volver a la siguiente diapositiva al terminar cada demo. En dos monitores, mantener las notas en la pantalla del expositor.
- Aumentar el tamaño del texto del editor antes de empezar. Mostrar una función por vez. Usar app y código lado a lado solo si ambos resultan legibles.
- Las demos utilizan el entorno local. No dependen de testphp.vulnweb.com ni de dominios de terceros.
- Las capturas de las diapositivas 9 y 17 son respaldo si falla una ejecución.

## Cambios de pantalla

| Diapositiva | Pantalla | Qué mostrar |
| --- | --- | --- |
| 8 | App | Laboratorio Medium, logs POST y comparación booleana |
| 11 | Editor | backend/scanner/dvwa.go:220, probeDVWA |
| 12 | Editor | loginDVWA:177 y dvwaRows:54 |
| 13 | App | Low, método GET y contexto entre comillas |
| 16 | App | Modo URL con login.php?flag=failed en DVWA local |
| 19 | Editor | authorized.go:129, responseChecks y newSignature |
| 22 | App y editor | Remediación y GenerateReport:12 |
| 23 | Terminal | Integración DVWA y pruebas automatizadas |
| 25 | Editor, opcional | scripts/benchmark_dvwa.py e informe guardado |
| 26 | Editor, breve | frontend/src/scans/events.js, buildLogEntries |

## Guion por diapositiva

### 1. SQL Injection con DVWA Evidencia, código y remediación

00–02 min. Presentación y objetivo: seguir una entrada desde HTTP hasta la evidencia y proponer una corrección en código. Anunciar que alternaremos diapositivas, navegador y editor. La implementación actual usa DVWA y evidencia HTTP. No afirmar que existe un sensor eBPF integrado.

Fuentes: README.md y código del proyecto. Formato y recursos de marca: presentación CEDIA/TICEC suministrada.

### 2. Workshop de 90 minutos

02–04 min. Mostrar el recorrido. Reservar los últimos diez minutos para la medición local y preguntas. Los anexos son de consulta, fuera de los 90 minutos. No dejar toda la demostración para el final. Si falta tiempo, recortar la segunda ejecución Low y conservar la lectura de evidencia y el ejercicio de remediación.

Fuentes: Proyecto SQLi Studio.

### 3. Qué hace SQLi Studio

04–06 min. Aclarar el alcance al inicio. Distinguir resultados reales de la app y futuras ampliaciones. El título de la presentación de referencia mencionaba eBPF, pero el backend actual no conecta un sensor. El scanner externo tampoco ejecuta UNION, extracción, escrituras ni retardos.

Fuentes: README.md; backend/scanner/engine.go; backend/scanner/authorized.go; backend/scanner/dvwa.go.

### 4. La entrada puede alterar una consulta

06–08 min. Explicar que una cadena concatenada permite que un dato aporte sintaxis. Usar el ejemplo para predecir que la condición falsa puede eliminar el resultado. Es código didáctico, no una lectura del SQL remoto. Preguntar qué ocurriría si la consulta usa un parámetro enlazado.

Fuentes: https://go.dev/doc/database/sql-injection
https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

### 5. DVWA Low y Medium

08–10 min. Ambos niveles siguen siendo vulnerables en este módulo. Medium utiliza un formulario POST y escape de entrada en el código de DVWA, pero conserva un contexto numérico concatenado. No presentar Medium como aplicación reparada. Las cadenas de Low están ajustadas al SQL entre comillas. La app ofrece solo Low y Medium.

Fuentes: https://github.com/digininja/DVWA/blob/master/vulnerabilities/sqli/source/low.php
https://github.com/digininja/DVWA/blob/master/vulnerabilities/sqli/source/medium.php
backend/scanner/dvwa.go:220

### 6. Servicios del proyecto

10–13 min. Seguir una ejecución: useScan envía POST /api/scans; el handler valida, crea el registro y lanza RunScan; el motor realiza solicitudes a DVWA; el repositorio guarda eventos y hallazgos; React consulta estado y eventos. Mostrar compose.yaml si la audiencia pregunta por redes. Scanner DB y DVWA DB cumplen funciones distintas. Las sondas de cada escaneo son secuenciales; el handler lanza una goroutine para responder sin esperar su finalización.

Fuentes: compose.yaml; backend/handlers/handlers.go; backend/scanner/engine.go; backend/database/repository.go; frontend/src/hooks/useScan.js.

### 7. Preparación para la demostración

13–15 min. Mostrar terminal ya preparada, no descargar dependencias frente a la audiencia. Tener .env configurado antes de iniciar. npm install solo si faltan dependencias. Alternativa íntegra en Docker: docker compose -f compose.yaml up -d --build, sin Vite simultáneo. No usar ambos frontends en el puerto 3000. No proyectar el contenido de .env. dvwa-init conserva los datos existentes.

Fuentes: README.md; compose.yaml; frontend/vite.config.js.

### 8. Laboratorio en DVWA Medium

15–21 min. CAMBIO A APP. Abrir http://localhost:3000, Laboratorio, Medium e Iniciar escaneo. Pausar el seguimiento antes de expandir un log. Buscar POST, id y las repeticiones. Resultado esperado en el DVWA preparado: dos pruebas reales, seis respuestas de prueba y hallazgos por error SQL y comparación booleana. Las solicitudes de sesión van aparte. Si el resultado cambia, explicar lo medido y acudir al anexo de diagnóstico. Volver a la diapositiva 9.

Fuentes: backend/scanner/dvwa.go; tests/integration/dvwa.ps1.

### 9. Una ejecución del laboratorio

21–23 min. La captura es evidencia de una ejecución local anterior, no una cifra garantizada para todas las ejecuciones. Señalar los dos hallazgos y las seis respuestas. La condición verdadera conservó un registro y la falsa devolvió cero. Leer estos números en la app en vivo con la evidencia abierta. Si el navegador no está disponible, utilizar esta captura como respaldo.

Fuentes: Captura del proyecto docs/dvwa-activity.jpg, 4 de octubre de 2026.

### 10. Seis peticiones, dos pruebas

23–25 min. Explicar la diferencia entre cantidad de pruebas y peticiones. Error SQL es una prueba; comparación booleana es otra, con cuatro solicitudes. La base completa el total de seis. Login y configuración de nivel no se cuentan dentro de esas seis peticiones.

Fuentes: backend/scanner/dvwa.go:220–321.

### 11. Selección del payload según el nivel

25–30 min. CAMBIO A EDITOR. Abrir backend/scanner/dvwa.go, función probeDVWA, desde la línea 220. Mostrar probeTarget: GET para Low, POST para Medium. Localizar trueValue/falseValue y la extracción de filas. El fragmento de diapositiva conserva la selección real; las dos asignaciones de filas se separan para facilitar la lectura. Buscar la comprobación de repetición y el caso trueRows igual a base con falseRows vacío. No explicar todo el archivo. Volver a diapositiva 12.

Fuentes: backend/scanner/dvwa.go:220; backend/scanner/dvwa.go:282–318.

### 12. Una prueba necesita una sesión válida

30–33 min. CAMBIO A EDITOR opcional. En backend/scanner/dvwa.go localizar loginDVWA:177 y dvwaRows:54. Mostrar cómo el motor exige logout.php tras login y el nivel confirmado. Explicar que el parser compara registros observados, no toda la página dinámica de DVWA. No proyectar contraseñas ni cookies. Frontend y scanner mantienen sesiones separadas.

Fuentes: backend/scanner/dvwa.go:54; backend/scanner/dvwa.go:177.

### 13. La misma prueba en DVWA Low

33–39 min. CAMBIO A APP. En Laboratorio seleccionar Low e iniciar. Abrir un log y la evidencia booleana. Mostrar GET y payload entre comillas. Volver al editor solo si hace falta conectar el valor con probeTarget. Pedir a los participantes que expliquen por qué el payload no tiene el mismo texto en ambos niveles. Volver a la diapositiva 14.

Fuentes: backend/scanner/dvwa.go; tests/integration/dvwa.ps1 -Level low.

### 14. Qué sostiene la detección booleana

39–45 min. Ejercicio breve: preguntar por qué HTTP 200 no resuelve el diagnóstico. La app evalúa contenido/registros y reproducibilidad. Si los registros cambian entre repeticiones, emite INCONCLUSIVE. La app no captura la consulta SQL del servidor ni registra los nombres de las personas devueltas por DVWA. No confundir bytes y registros.

Fuentes: backend/scanner/dvwa.go:302–318.

### 15. La URL define el plan de pruebas

45–48 min. Explicar tres peticiones para texto y siete para valores numéricos. La app acepta dominios, IP, puertos y Basic Auth. No afirmar que una lista blanca o un bloqueo general de redes privadas protege este modo. Para el workshop se utilizará exclusivamente la infraestructura local controlada. URLs externas requieren autorización del propietario. Esta autorización operativa es distinta del booleano que envía el frontend.

Fuentes: backend/scanner/authorized.go; backend/scanner/discovery.go; backend/scanner/engine.go; backend/policy/targets.go.

### 16. Diagnóstico de una URL sin detección

48–53 min. CAMBIO A APP. URL exacta: http://host.docker.internal:8000/login.php?flag=failed. Es la página de login local de DVWA, no su módulo SQLi. Permite demostrar el flujo externo y el diagnóstico sin depender de sitios externos. Se esperan tres solicitudes; no una vulnerabilidad. failed es el valor original. La comilla viaja codificada como %27. El login puede cambiar su token y mantener el mismo tamaño. Si host.docker.internal no existe fuera de Docker, usar un destino de entrenamiento accesible desde donde corre el backend. Volver a diapositiva 17.

Fuentes: docs/authorized-http-tests.md; captura docs/url-payload-diagnostics.jpg.

### 17. El log explica la prueba sin detección

53–56 min. En la app abrir Ver evidencia. Leer Original: failed, Payload: failed', Query: flag=failed%27. En la captura las respuestas conservan el tamaño, pero el contenido cambió. No aparece una firma SQL reconocida y la comparación booleana se omitió por tratarse de texto. Estas comprobaciones explican la decisión del motor; no permiten asegurar cómo el servidor utilizó flag. La captura corresponde al login local.

Fuentes: docs/url-payload-diagnostics.jpg; backend/scanner/authorized.go, responseChecks; frontend/src/components/ProbeDetail.jsx.

### 18. Resultado de prueba y estado del escaneo

56–59 min. Diferenciar resultado de una prueba y estado de ejecución del escaneo. FAILED vive en el escaneo; DETECTED, NOT_DETECTED e INCONCLUSIVE en resultados de pruebas. Un escaneo COMPLETED puede contener una prueba no concluyente. NOT_DETECTED no certifica que el sitio sea seguro. Las pruebas completadas antes de un fallo permanecen guardadas.

Fuentes: backend/models/models.go; backend/scanner/engine.go; backend/scanner/authorized.go; frontend/src/hooks/useScan.js; frontend/src/components/ScanStatus.jsx.

### 19. Interpretación de los logs

59–65 min. Dar dos minutos de discusión. Respuesta A: la prueba de error no detecta SQLi; igual tamaño no implica igual contenido. Para la booleana se necesita estabilidad y comparación verdadera/falsa reproducible. Respuesta B: escaneo FAILED y sin veredicto para la prueba interrumpida, conservando resultados previos. CAMBIO A EDITOR: mostrar responseChecks y la condición newSignature en backend/scanner/authorized.go:129–225. Mostrar que el log no inventa una causa interna del servidor.

Fuentes: backend/scanner/authorized.go; frontend/tests/evidence.test.mjs.

### 20. Consulta parametrizada en Go

65–68 min. Explicar que el marcador enlaza el valor por separado. El símbolo ? es propio del driver MySQL usado aquí; otros drivers utilizan marcadores distintos. id debe validarse antes y err manejarse antes de leer rows. Mostrar backend/remediation/report.go. Es un ejemplo defensivo: la app genera recomendaciones, no modifica por sí misma DVWA.

Fuentes: https://go.dev/doc/database/sql-injection
backend/remediation/report.go.

### 21. Consulta preparada en PHP

68–71 min. Ejemplo didáctico de remediación del patrón de Medium. Validación de tipo y consulta preparada son controles complementarios. La presentación no modifica el módulo de DVWA. La conexión PDO y el manejo de excepciones se omiten en este fragmento para centrar la explicación. Si se implementa después, configurar el driver y ejecutar pruebas sobre el endpoint reparado.

Fuentes: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
backend/remediation/report.go.

### 22. Evidencia y propuesta de corrección

71–76 min. CAMBIO A APP Y EDITOR. Si el proyector lo permite, poner app a la izquierda y editor a la derecha; si el texto queda pequeño, alternar ventanas. Abrir Remediación y backend/remediation/report.go:12. Mantener un solo fragmento visible. Pedir que identifiquen qué evita el cambio de sintaxis y dónde validar el identificador. Aclarar que generar un reporte no aplica el parche. No prometer una ejecución contra secure-app: el laboratorio anterior ya no existe.

Fuentes: backend/remediation/report.go; frontend/src/components/RemediationSection.jsx.

### 23. Pruebas que acompañan la demostración

76–80 min. CAMBIO A TERMINAL. Preferir resultados preparados. La imagen Docker del backend ejecuta go test ./... durante build si Go local no está disponible. El script PowerShell va en la raíz del repositorio y necesita servicios activos. Mostrar el test de cambios de cuerpo con igual longitud en authorized_test.go y los tests de evidencia en frontend/tests/evidence.test.mjs. Una prueba de un endpoint reparado debe enviar entrada legítima y conservar resultados, además de impedir que una condición cambie el conjunto devuelto. No afirmar que esa prueba de parche ya forma parte del laboratorio actual.

Fuentes: backend/Dockerfile; backend/scanner/authorized_test.go; backend/scanner/dvwa_test.go; frontend/tests/evidence.test.mjs; tests/integration/dvwa.ps1.

### 24. Piloto frente a sqlmap

80–83 min. Datos guardados del 4 de octubre de 2026 UTC. La mediana se calcula con tiempos monotónicos desde login hasta detección. SQLi Studio usa dos pruebas específicas; sqlmap trabaja con técnica B, nivel 1, riesgo 1, un hilo y MySQL. El arranque de Python se incluye en sqlmap; el reporte visual se excluye en ambos. Las rutas de red difieren, Docker interno y loopback del host. El cronómetro del frontend incluye espera de actualización y no es la métrica de este piloto. No extrapolar los valores a rendimiento general ni cobertura equivalente.

Fuentes: docs/benchmarks/dvwa-latest.json; docs/benchmarks/dvwa-latest.md; scripts/benchmark_dvwa.py.

### 25. Cómo repetir la comparación

83–85 min. CAMBIO A EDITOR opcional. Mostrar scripts/benchmark_dvwa.py, funciones app_run, sqlmap_run y main. La copia oficial de sqlmap debe estar instalada previamente en tools/sqlmap. No realizar una descarga ni un benchmark largo durante el workshop; usar el informe guardado y ofrecer la repetición después. Un tiempo menor no implica más cobertura ni más precisión.

Fuentes: scripts/benchmark_dvwa.py; docs/benchmarks/dvwa-latest.json.

### 26. Una petición ocupa una fila de log

85–87 min. CAMBIO BREVE A EDITOR si queda tiempo. Abrir frontend/src/scans/events.js, buildLogEntries. Mostrar cómo los eventos running y completed comparten step_id y actualizan una fila. LogRow y ProbeDetail mantienen datos técnicos dentro de detalles desplegables. Pausar afecta al desplazamiento automático, no al escaneo. Si el tiempo se agota, resumir este punto sin cambiar de pantalla.

Fuentes: frontend/src/scans/events.js; frontend/src/components/EventStreamConsole.jsx; frontend/src/components/ProbeDetail.jsx.

### 27. Qué nos llevamos al código diario

87–90 min. Abrir preguntas. Preguntas de apoyo: por qué Medium sigue siendo vulnerable, por qué 0 hallazgos no acredita seguridad y qué haría falta para comparar con sqlmap de forma más amplia. Recapitular el recorrido por app, logs y código sin añadir funcionalidades inexistentes.

Fuentes: https://go.dev/doc/database/sql-injection
https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
README.md.

### 28. Gracias

Fin del workshop de 90 minutos. Los siguientes dos slides son anexos de consulta. El QR y los recursos gráficos del cierre pertenecen a la plantilla CEDIA/TICEC suministrada. No representan un enlace al repositorio del proyecto.

Fuentes: Diseño original CEDIA/TICEC suministrado por el usuario.

### 29. Respaldo si una demostración falla

Anexo, fuera del tiempo de exposición. No borrar volúmenes para resolver una demo: hay datos históricos. Verificar frontend Vite, backend y DVWA. No cambiar objetivos a un dominio tercero improvisado. Las capturas incluidas son respaldo y deben identificarse como capturas, no como una ejecución en vivo.

Fuentes: README.md; compose.yaml; docs/authorized-http-tests.md.

### 30. Fuentes y puntos de entrada

Fuentes primarias consultadas el 4 de octubre de 2026. Las referencias del proyecto corresponden al código actual. El material docs/workshop anterior se conserva como histórico y no debe usarse para afirmar que hay sensores eBPF o un secure-app activos. Cada diapositiva incluye sus fuentes en estas notas.

Fuentes: https://github.com/digininja/DVWA/blob/master/vulnerabilities/sqli/source/low.php
https://github.com/digininja/DVWA/blob/master/vulnerabilities/sqli/source/medium.php
https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
https://go.dev/doc/database/sql-injection
README.md; docs/benchmarks/dvwa-latest.json.
