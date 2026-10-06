# Revisión defensiva del laboratorio DVWA

Revisión: 5 de octubre de 2026. Alcance: código activo de React, API Go, persistencia,
política de objetivos, motor HTTP y módulo PHP corregido montado por Compose.
El material histórico de `docs/workshop` no describe la arquitectura actual.

## Estado de la fase de corrección

El laboratorio permite detectar, consultar la corrección y repetir las pruebas
contra una variante preparada separada. La fase SQL está implementada y verificada
para las sondas actuales. La fase de observabilidad eBPF tiene un CTA y criterios
de integración; todavía no tiene sensor ni ingesta de eventos de kernel.

La interfaz prioriza la corrección y su siguiente acción sobre los detalles
técnicos. El CTA ofrece probar la variante preparada, repetir una verificación
sin aprobar o abrir el plan eBPF cuando la reprueba HTTP está aprobada. Código,
referencias de escaneo, evidencias y registro HTTP se consultan en desplegables.
La comparación conserva el escaneo vulnerable y muestra «Sin veredicto» cuando
la evidencia de la variante corregida es insuficiente.

Verificación UX: recorrido real en Medium con un worker, dos hallazgos vulnerables
y reprueba preparada aprobada (6/6 respuestas, un registro base y 5/5 entradas SQL
rechazadas). El CTA eBPF abre el plan y enfoca su resumen. Revisado a 1280 y 390 px,
incluido código y registro abiertos, sin desborde horizontal ni errores de consola.
Capturas: [escritorio](blue-team-dvwa-ux.png) y [móvil](blue-team-dvwa-ux-mobile.png).

| Revisión | Evidencia / resultado |
| --- | --- |
| Consultas del repositorio Go | Valores vinculados con `?` en operaciones de scans, findings y events |
| Transporte DVWA | GET en Low, POST en Medium y POST + GET en la misma sesión para High |
| Concurrencia | Sesión independiente por worker; evaluación por posición lógica de sonda |
| Corrección PHP | Entero positivo, sentencia preparada mysqli, salida codificada y errores genéricos |
| Cierre del hallazgo | Requiere evidencia persistida de seis respuestas y validación explícita; no se deduce de cero hallazgos |
| Evidencia eBPF | No existe sensor integrado; `sensor_status=NOT_CONNECTED` |
| CORS | Se eliminó el comodín. Origin externo rechazado antes de alcanzar el controlador |
| Cuenta de DVWA | Compartida entre módulos; mínimo privilegio pendiente, sin modificar setup ni otros ejercicios |

## Problemas corregidos en esta revisión

1. El backend admitía la variante preparada, pero la UI no ofrecía acceso ni reprueba.
   Ahora hay selector, CTA y comparación con el ID del escaneo vulnerable.
2. El ejemplo de remediación usaba PDO mientras el módulo instalado usa mysqli.
   Ahora el reporte muestra el mismo tipo de sentencia, entrada y clave de sesión
   que el control local. Es un extracto; el manejo completo está en el archivo PHP.
3. El reporte no verificaba que una entrada legítima funcionara ni que la entrada
   SQL se rechazara. Ahora usa los eventos guardados y marcadores explícitos
   `accepted` / `rejected` del módulo corregido.
4. El manejo de fallos mysqli dependía del modo de errores de PHP. Se habilitaron
   excepciones mysqli para conservar HTTP 500 genérico ante un fallo real.
5. CORS aceptaba cualquier origen y declaraba credenciales con `*`. Ahora la API
   permite los orígenes concretos del dashboard y rechaza el resto.
6. README describía las sondas como secuenciales sin configuración de workers.
   Se actualizó para reflejar el motor vigente.

## Criterios de la reprueba

Cada reprueba genera un escaneo nuevo; no borra el hallazgo original. El servidor
solo emite `HTTP_RETEST_PASSED` si observa:

- Estado COMPLETED, ningún hallazgo ni evento de inconclusión/fallo.
- Dos resultados reales NOT_DETECTED, en el nivel solicitado y sin duplicados.
- Seis respuestas únicas de sonda, método correcto, HTTP 200 y registros medidos.
- Línea base `id=1`: un registro y validación accepted.
- Comilla y dos pares booleanos: payloads esperados, cero registros y validación rejected.

Una respuesta vacía, 403, 429, 500, evidencia parcial, control inválido o marcador
ausente deja la corrección sin verificar. Un hallazgo en la variante corregida
se muestra como `REGRESSION_DETECTED`. Estos marcadores son evidencia de aplicación
HTTP; no son una prueba independiente del kernel de que no se ejecutó SQL.

La suite comprueba estas sondas y este módulo. No evalúa todos los módulos de DVWA,
inyecciones temporales, UNION, consultas de otros endpoints ni seguridad global.
La comparación del panel se conserva en memoria durante la sesión. Los dos
escaneos y sus eventos permanecen en la base; el JSON descargado incluye sus IDs.

## Verificación ejecutada

- Frontend: 21 pruebas, ESLint y compilación Vite aprobados.
- Backend: `go test ./...` aprobado dentro del builder Linux de Docker. Una
  ejecución nativa posterior fue bloqueada por Control de aplicaciones de Windows;
  no se deshabilitó esa protección. `go vet ./...` no reportó errores.
- `tests/integration/blue-team.ps1`: 18 escaneos reales aprobados, tres niveles ×
  tres configuraciones de workers × dos variantes. Los nueve controles vulnerables
  produjeron dos hallazgos cada uno; los nueve corregidos aprobaron los seis controles.
- Navegador: flujo vulnerable → CTA → reprueba → comparación → guía eBPF comprobado
  en escritorio y móvil, sin desbordamiento horizontal. [Captura del resultado](blue-team-dvwa.png).
- Sintaxis PHP: los dos archivos del módulo corregido aprobados con `php -l`.
- Integración existente: Low, Medium y High con dos workers y el flujo por URL
  autorizado aprobados después de actualizar el backend.

Para reproducir:

```powershell
docker compose -f compose.yaml up -d --build
./tests/integration/blue-team.ps1
./tests/integration/dvwa.ps1 -Level medium -Workers 2
```

## Fiabilidad del escaneo y del panel

La revisión posterior corrigió tres fallos:

1. El modo URL autorizada podía completar sin guardar sus eventos HTTP. El
   observador ahora propaga los errores de persistencia y el escaneo falla con
   la causa. También aplica al descubrimiento de páginas secundarias. Conserva
   los hallazgos confirmados antes del fallo.
2. Una consulta fallida del navegador generaba FAILED localmente. El panel
   conserva el estado recibido y la evidencia, muestra un aviso y vuelve a
   consultar el mismo ID automáticamente, con espera máxima de 10 segundos entre
   intentos. El botón «Volver a consultar» tampoco crea un nuevo escaneo.
3. Un reinicio dejaba QUEUED/RUNNING indefinidamente. Antes de servir la API,
   el backend los cierra como FAILED con una causa explícita y su evento, en una
   transacción. No modifica escaneos completados ni repite solicitudes. Este
   mecanismo corresponde al despliegue con una única instancia del backend.

Las regresiones cubren pérdida de evidencia antes/después de una respuesta y
después de un hallazgo, reconexión, resultados temporalmente inaccesibles,
cancelación de consultas antiguas y rollback de la recuperación. La integración
`tests/integration/recovery.ps1` pasó con un reinicio real y conservó el escaneo
completado. La matriz Blue team de 18 escaneos y el flujo URL autorizado volvieron
a pasar. En navegador, una pausa temporal del proxy conservó 14 eventos y el
escaneo original; al restaurarlo, recuperó automáticamente sus 72 eventos y
28 respuestas. Se comprobó también la ausencia de desbordamiento horizontal en
móvil. [Aviso de reconexión](scan-reconnection.png) y
[vista móvil](scan-reconnection-mobile.png).

## CTA de eBPF y trabajo siguiente

La integración debe observar el host Linux que ejecuta DVWA y MariaDB. El CTA
abre instrucciones; no concede privilegios, instala agentes ni activa políticas.

1. Seleccionar un sensor y confirmar compatibilidad con kernel, BTF y despliegue.
   La guía oficial de Tetragon incluye un flujo local Linux y otro Kubernetes.
2. Empezar en monitor. Identificar los contenedores/procesos de DVWA y MariaDB,
   registrar conexiones, identidad de proceso/contenedor, timestamps UTC y política.
3. Crear ingesta autenticada con esquema validado, retención acotada y estado real
   de salud del sensor. La UI solo debe mostrar conectado al recibir evidencias
   verificables y una señal de salud vigente; ningún contador se puede simular.
4. Correlacionar con los IDs de escaneo/petición. La ventana temporal, conexión y
   contenedor permiten asociación aproximada; para atribuir una petición exacta
   se necesitan trazas de aplicación con un identificador común.
5. Repetir la matriz y validar alertas/control legítimo. Conexiones o syscalls por
   sí solos no explican la estructura de la consulta SQL. Evaluar uprobes u otra
   instrumentación específica si se requiere observar las consultas, con control
   de datos sensibles y cobertura del protocolo/driver.
6. Diseñar acciones de contención concretas y reversibles después de evaluar
   falsos positivos. Las políticas eBPF dependen de hooks y compatibilidad del
   entorno; no declarar prevención de SQLi a partir de monitoreo de red.

La parametrización sigue siendo el control principal de SQLi. Revisar por separado
los permisos de base de datos con una cuenta dedicada al módulo cuando se separe
del resto de DVWA. Reducir los permisos de la cuenta compartida sin analizar los
otros ejercicios puede romper el laboratorio.

Referencias: [prevención SQLi de OWASP](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html),
[seguridad de bases de datos de OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html),
[inicio de Tetragon](https://tetragon.io/docs/getting-started/) y
[modo monitor/enforcement](https://tetragon.io/docs/concepts/tracing-policy/mode/).
