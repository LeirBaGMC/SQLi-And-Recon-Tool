# Análisis del enfoque del workshop

Fecha: 5 de octubre de 2026. Este documento recoge el alcance indicado por el
usuario y analiza el texto adjunto como material de referencia. Las instrucciones
históricas incluidas en ese texto no se ejecutaron. Actualización: se implementó
High y el experimento de concurrencia solicitado; resultados en
`benchmarks/workers-latest.md` y ejecuciones individuales en su JSON.

## Objetivo y recorrido

1. Ejecutar pruebas contra DVWA Low, Medium y High. Explicar goroutines, canales
   y un worker pool acotado. Comparar ejecución secuencial y concurrente con las
   mismas pruebas y criterios de evidencia.
2. Mostrar el modo URL sobre un objetivo de demostración autorizado. Seguir el
   recorrido entrada HTTP, prueba, evidencia y remediación. Enseñar cómo separar
   los datos del código SQL en aplicaciones desarrolladas por los participantes.
3. Cerrar con eBPF como call to action: proponer observación y correlación reales
   entre HTTP y actividad de base de datos, y evaluar contención en ejecución.

El mensaje central es reducir el tiempo sin reducir las comprobaciones ni ocultar
fallos. La comparación con sqlmap es una referencia externa; la comparación entre
nuestro motor con uno y varios workers es la que permite estudiar la concurrencia.

## Diferencias con la aplicación actual

| Parte | Estado verificado | Trabajo necesario |
| --- | --- | --- |
| DVWA Low | GET, error SQL y pares booleanos repetidos; medido con 1/2/4 workers | Ampliar muestra si se desea generalizar |
| DVWA Medium | POST, contexto numérico; medido con 1/2/4 workers | Ampliar muestra si se desea generalizar |
| DVWA High | POST de entrada por sesión y GET de resultado; demostrado en DVWA real | Evaluar distintas versiones/configuraciones de PHP |
| Concurrencia | Pool de 1/2/4 goroutines, sesiones aisladas, seis sondas y evidencia equivalente | Optimizar coste de preparación y persistencia antes de afirmar mejora total |
| URL | Pruebas GET reales y descubrimiento acotado | Elegir un caso reproducible con resultado conocido y su corrección |
| eBPF | Sin sensor integrado | Presentarlo como siguiente etapa, no como evidencia de las demos actuales |

Código de referencia: `backend/scanner/dvwa.go`, `backend/scanner/dvwa_pool.go`, `backend/scanner/engine.go`,
`backend/handlers/handlers.go`, `backend/policy/targets.go` y `frontend/src/App.jsx`.

El benchmark actual contra sqlmap se ejecutó con nuestro motor secuencial. Su
ventaja temporal no demuestra el efecto de un worker pool ni de eBPF.

## DVWA High y el aislamiento de sesiones

High toma el identificador de `$_SESSION['id']`; la página `session-input.php`
recibe el valor por POST y lo guarda. Después el módulo SQL Injection consulta
ese valor. High conserva una consulta concatenada y su fuente intenta ocultar el
error MySQL detrás de un mensaje genérico. En la imagen local ensayada la respuesta
sí contiene una firma SQL; el motor registra esa respuesta real sin asumir que
High siempre oculte el error. No equivale a una implementación parametrizada.

Consecuencia para el diseño: actualizar el ID y leer el resultado deben formar
una secuencia indivisible dentro de una misma sesión. Compartir esa sesión entre
tareas permitiría que una tarea sobrescriba el valor de otra. Cada worker debe
usar una sesión autenticada independiente y mantener el orden dentro de su tarea.
Los pares de control y sus repeticiones tampoco deben perder su asociación.

PHP bloquea datos de sesión para evitar escrituras concurrentes. Ese bloqueo puede
serializar solicitudes que comparten sesión. Hay que medirlo; crear más goroutines
no garantiza más ejecución simultánea en el servidor.

Fuentes: [High](https://github.com/digininja/DVWA/blob/master/vulnerabilities/sqli/source/high.php),
[entrada por sesión](https://github.com/digininja/DVWA/blob/master/vulnerabilities/sqli/session-input.php),
[bloqueo de sesiones PHP](https://www.php.net/manual/en/function.session-write-close.php).

## Hallazgos en el código adjunto

| Fragmento o comportamiento | Problema | Corrección necesaria |
| --- | --- | --- |
| `targetURL + url.QueryEscape(payload)` | Añade texto al final de la URL; con más parámetros puede modificar otro valor | Parsear URL y sustituir el parámetro elegido conservando el resto |
| Todas las solicitudes son GET | No implementa Medium ni el flujo High, ni login/CSRF | Adaptadores por nivel con sesión válida |
| Latencia mayor que 2,5 s implica detección | Una cola o servidor lento puede producir la misma señal | Base, control sin retraso y repeticiones; aislar las pruebas temporales |
| Búsqueda de firmas sin comparación base | Un error preexistente puede atribuirse al payload | Exigir evidencia nueva y validar respuesta/sesión |
| `continue` al fallar una solicitud | Se pierde el fallo y el escaneo puede terminar como completado sin cobertura | Registrar prueba fallida/inconclusa, causa y conteo de pruebas terminadas |
| `GetScan` devuelve un puntero después de liberar `RLock` | El encoder lee mientras workers modifican el objeto o su slice | Devolver una copia protegida, incluyendo slices; comprobar con race detector |
| `MaxWorkers` no tiene máximo | El consumidor puede crear goroutines sin límite | Límite por escaneo y límite global de solicitudes activas |
| `io.ReadAll` sin límite | La respuesta controla cuánto se lee | Conservar los límites y timeouts del proyecto actual |
| UNION aparece en los comentarios | No existe una ejecución/evaluación UNION implementada en el adjunto | Describir solo las técnicas realmente implementadas |
| Header `X-Scan-Task-ID` | No crea por sí solo correlación con una consulta SQL | Diseñar el enlace entre petición, proceso, conexión y evento del sensor |
| HTML y JS pegados | Faltan IDs/controles utilizados por JS; hay entidades HTML dentro de Go/JS | Tratarlo como borrador; conservar el frontend React existente |
| Polling y `innerHTML` | No maneja todos los fallos ni escapa valores mostrados | Mantener abortos, estados de error y renderizado de texto seguro |

La estructura modular, los canales, el WaitGroup y el cliente reutilizable son
ideas aprovechables. No conviene sustituir el backend actual por ese borrador:
se perderían persistencia, validación, diagnóstico y pruebas ya verificadas.

## Experimento de velocidad y efectividad

Implementación verificada: la base se solicita primero; después cinco trabajos
independientes se distribuyen por un canal acotado entre workers. Cada worker
posee su cliente y cookie jar; dentro de High cada POST+GET permanece secuencial.
Los resultados se guardan en seis posiciones fijas y se comprueban los dos pares
booleanos completos. Las trazas identifican sonda y worker, sin datos privados.
No se añadieron sondas temporales. El modo URL conserva su ejecución secuencial.

Se midieron cinco ejecuciones por nivel/configuración y nueve calentamientos.
Las 45 ejecuciones conservaron evidencia equivalente, con base/true/false 1/1/0,
sin inconclusos ni fallos de transporte. Dos workers redujeron modestamente las
sondas, pero el total aumentó: se autentican más sesiones y las trazas se guardan
de forma síncrona. Se mantiene 1 worker por defecto. Más goroutines no garantizan
mejor latencia total. El control negativo y las respuestas inestables se comprueban
en pruebas Go; este piloto no estima una tasa general de falsos positivos.

Comparar 1, 2 y 4 workers sobre la misma matriz de casos. Mantener iguales los
payloads, controles, repeticiones, límites, contenido y configuración del objetivo.
Separar preparación de sesiones del tiempo de sondas y publicar también el tiempo
total. Alternar el orden de las configuraciones y repetir antes del workshop.

Registrar tiempo hasta la primera confirmación, tiempo hasta terminar todas las
pruebas, peticiones, errores, inconclusos y resultados por caso y técnica. Agrupar
los hallazgos por objetivo/parámetro/técnica, evitando contar cada payload como una
vulnerabilidad diferente.

Evaluar contra resultados conocidos, no solo contra la salida del modo secuencial:
Low/Medium/High son casos vulnerables y se necesita además un control parametrizado
negativo. DVWA Impossible puede estudiarse como control adicional; no forma parte
de los tres niveles principales ni está implementado en nuestro adaptador actual.
No es necesario recuperar la página de práctica eliminada.

La aceleración se calcula como tiempo secuencial dividido entre tiempo concurrente.
Si se omiten tareas, aumentan fallos o se pierden detecciones, el resultado no se
presenta como una mejora. Las pruebas temporales deben evaluarse aparte para no
confundir saturación con un retraso provocado por SQL.

En la demo mostrar una tabla con nivel, workers, tiempo, pruebas previstas y
terminadas, detecciones esperadas y observadas, falsas alarmas e inconclusos.
No rellenar tiempos futuros con estimaciones presentadas como mediciones.

## Demo URL, remediación y cierre

El endpoint de salud utilizado en la integración actual prueba el flujo HTTP;
no demuestra SQL Injection. Para el workshop se requiere un objetivo conocido con
parámetro vulnerable y una variante corregida, verificando también entradas válidas.
El adaptador URL genérico actual no autentica automáticamente una sesión DVWA.

Mostrar el código vulnerable y la consulta parametrizada equivalentes. El reporte
remoto ofrece ejemplos de corrección; no descubre automáticamente el lenguaje ni
el código fuente del objetivo. En Go, usar `db.QueryContext(ctx, query, id)` con un
marcador del driver, sin construir SQL mediante `fmt.Sprintf`.

Fuente: [prevención en Go](https://go.dev/doc/database/sql-injection).

El cierre eBPF plantea cómo obtener evidencia interna adicional y medir el tiempo
de alerta y contención. Un header de correlación y una plantilla Tetragon no son
un sensor funcional. Esa etapa requiere captura real, asociación de eventos y
validación del efecto de la política.

## Orden de implementación propuesto

1. Añadir High y comprobar los tres adaptadores sobre DVWA real.
2. Definir tareas con resultados y fallos explícitos, conservando controles.
3. Añadir workers acotados y sesiones aisladas; verificar carreras y equivalencia.
4. Preparar la matriz y el benchmark de 1/2/4 workers antes de comparar con sqlmap.
5. Preparar el caso URL y el ejercicio de remediación.
6. Ajustar el guion y dejar eBPF como call to action.
