# SQL Injection Scanner · DVWA

Dashboard React y API Go para ejecutar pruebas SQL Injection contra DVWA local y un objetivo externo autorizado.

## Arranque

1. Configura `.env` a partir de `.env.example` si todavía no existe.
2. Ejecuta `docker compose -f compose.yaml up -d --build`.
3. Abre el dashboard en http://localhost:3000 y DVWA en http://localhost:8000.

El backend escucha en http://localhost:8080. El usuario de entrenamiento de DVWA
es `admin` y su contraseña inicial es `password`. El servicio `dvwa-init` utiliza
la página oficial de setup para inicializar una base nueva; en arranques siguientes
conserva los datos existentes.

Para desarrollo del frontend, levanta `docker compose -f compose.yaml up -d --build backend`
y ejecuta `npm install` y `npm run dev` desde `frontend`. Vite conecta con
`http://127.0.0.1:8080`; `BACKEND_PROXY_URL` permite usar otra dirección.
No ejecutes simultáneamente Vite y el frontend Docker en el mismo puerto 3000.

## Objetivos y pruebas

- **DVWA · SQL Injection (Low / Medium / High):** el panel propone Medium y permite
  seleccionar Low o High, con 1, 2 o 4 workers (por defecto 1). Login con cookies y
  token CSRF, nivel confirmado en una sesión independiente por worker, petición
  base, sonda de error SQL y pares booleanos repetidos. Low utiliza GET y condiciones
  entre comillas; Medium utiliza POST y condiciones numéricas. High guarda `id`
  por POST en `session-input.php` y consulta por GET dentro de la misma sesión.
  El motor compara registros HTML, ignorando la entrada reflejada y tokens dinámicos.
- **Análisis por URL:** admite dominios, IP y hosts locales mediante HTTP/HTTPS,
  con credenciales Basic y puertos personalizados. Analiza directamente los parámetros de la URL indicada.
  Si no contiene parámetros, busca enlaces en hasta cinco páginas del mismo origen.
  Muestra cada petición GET y distingue fallos de conexión de pruebas sin detección.
  El comportamiento está documentado en `docs/authorized-http-tests.md`.

Las peticiones y hallazgos son reales. La evidencia es HTTP; no hay un sensor eBPF
integrado. Una respuesta bloqueada, inestable o una sesión inválida no se interpreta
como protección. El panel distingue bytes recibidos de registros observados.

## Corrección del laboratorio · Blue team

Al completar un escaneo DVWA, el panel muestra el código vulnerable y el extracto
mysqli de la corrección local. **Probar variante corregida** inicia otro escaneo
con el mismo nivel y workers, conservando el ID y el conteo de hallazgos anterior
para la comparación. El selector **Variante** permite probar directamente ambos
módulos. El módulo `sqli-fixed` se monta desde `infrastructure/dvwa/fixed`; el
módulo vulnerable oficial sigue disponible como control de entrenamiento.

La corrección valida `id` como entero positivo, usa `mysqli_prepare` y
`mysqli_stmt_bind_param`, codifica la salida HTML y responde a errores SQL sin
exponer sus detalles. High utiliza su propia clave de sesión y valida al consultar.
El reporte solo muestra **Reprueba HTTP aprobada** cuando el escaneo completó,
no hay hallazgos ni sondas inconclusas, están las seis respuestas HTTP 200,
`id=1` devuelve un registro y las cinco entradas SQL presentan rechazo explícito
sin registros. Los escaneos anteriores que no conservan ese indicador permanecen
sin verificar. El reporte se puede descargar como JSON; las evidencias detalladas
siguen en `/api/scans/:id/events` y la comparación del panel dura esta sesión.

El CTA **Preparar observabilidad eBPF** abre los pasos y la guía oficial de
Tetragon. Su estado actual es **Sensor no conectado**: no instala sensores ni
activa bloqueo. Los permisos mínimos de base de datos y la correlación de eventos
de kernel siguen pendientes. Ver [revisión y criterios defensivos](docs/BLUE_TEAM_DVWA.md).

El laboratorio Go anterior y sus servicios `vulnerable-app`, `secure-app` y `lab-db`
fueron sustituidos por DVWA. Los datos históricos del escáner se conservan.

El laboratorio registra el inicio y la respuesta de cada petición con método,
estado HTTP, duración, bytes y número de registros. El panel agrupa ambos eventos
en una fila; las URL y entradas se despliegan al abrirla. Nunca registra contraseñas,
cookies, tokens CSRF ni nombres de usuarios devueltos por DVWA. El indicador de
avance cuenta las seis respuestas de prueba, separadas de la autenticación y los
seis POST adicionales de High. Cada petición conserva un ID y su worker; los
veredictos se evalúan por posición lógica, independientemente del orden de llegada.
Las sondas fallidas o las repeticiones inestables se marcan como inconclusas. Un
error al persistir evidencia hace fallar el escaneo. El
botón «Pausar» detiene el desplazamiento automático y «Reanudar» lo activa.

Si falla una consulta del panel, conserva el ID, el estado conocido y la evidencia;
reintenta automáticamente con esperas de 1 a 10 segundos. **Volver a consultar**
consulta ese mismo escaneo, sin crear otra ejecución. Una pérdida de conexión
no se convierte en un fallo SQL ni en un resultado sin hallazgos.
Al arrancar el backend, los escaneos anteriores QUEUED/RUNNING se cierran como
FAILED con la causa del reinicio y su evento, en una transacción. Conserva los
hallazgos anteriores y no repite solicitudes automáticamente. Este mecanismo
corresponde al despliegue actual con una sola instancia del backend.

## Arquitectura

| Servicio | Función | Acceso |
| --- | --- | --- |
| frontend | React servido por Nginx o Vite | localhost:3000 |
| backend | API REST y motor de pruebas | localhost:8080 |
| scanner-db | Historial, eventos y hallazgos | Red interna |
| dvwa | Aplicación PHP de entrenamiento | localhost:8000 |
| dvwa-db | MariaDB exclusiva de DVWA | Red interna |
| dvwa-init | Inicialización idempotente | Ejecución única |

DVWA utiliza la imagen oficial del proyecto y se publica únicamente en la interfaz
local. Sus bases de datos no publican puertos. `compose.yaml` es la configuración
principal; `docker-compose.yml` la incluye por compatibilidad.

## Verificación

- `npm test`, `npm run lint` y `npm run build` desde `frontend`.
- `go test ./...` desde `backend`; también se ejecuta al construir su imagen Docker.
- `./tests/integration/dvwa.ps1` desde PowerShell con frontend y backend activos:
  comprueba Medium con dos pruebas reales, seis respuestas medidas y al menos un
  hallazgo. Añade `-Level low` o `-Level high` y `-Workers 1`, `2` o `4`.
- `./tests/integration/blue-team.ps1` prueba ambas variantes en Low, Medium y
  High con 1, 2 y 4 workers: 18 escaneos reales y sus criterios de corrección.
- `./tests/integration/recovery.ps1` reinicia el backend con un escaneo de prueba
  pendiente y comprueba su cierre y la conservación de un escaneo completado.
  Requiere que no haya otros escaneos activos antes de comenzar.
- `tests/integration/infrastructure.sh` comprueba los servicios Docker.
- `./tests/integration/authorized-url.ps1` verifica el flujo externo real, incluyendo
  errores persistidos, logs HTTP y ausencia de rastreo previo para una URL con parámetros.
  Por defecto utiliza el endpoint local de salud del backend; `-TargetURL` permite
  elegir otra URL de prueba con parámetros. El endpoint de salud comprueba el flujo
  HTTP, sin demostrar una vulnerabilidad SQL.

## Comparación con sqlmap

La comparación entre workers se reproduce con `python scripts/benchmark_workers.py --runs 5`.
Ejecuta los tres niveles, conserva seis sondas lógicas por escaneo y verifica
equivalencia de evidencia, incluidos los dos pares booleanos y sus registros.
Publica tiempos de sesiones, sondas y total del backend, p95, peticiones y fallos
en `docs/benchmarks/workers-latest.md` y `.json`; el reloj del panel se muestra aparte.
En este piloto 2 workers redujeron el tiempo de sondas, pero aumentaron el total
por las sesiones y su registro. No se presenta ese aumento como una mejora.

El panel abre con dos accesos: Laboratorio y URL autorizada. Al completar DVWA,
la corrección y su siguiente acción aparecen antes de los resultados: probar la
variante corregida, repetir una verificación inconclusa o consultar el plan eBPF
tras aprobar la reprueba HTTP. El sensor se identifica como no conectado.
El código, los IDs, las evidencias de cada prueba y el registro HTTP se despliegan
al solicitarlos. Los workers están en Opciones. El tiempo del panel incluye las
actualizaciones hasta recibir los resultados en el navegador y no es la medida
utilizada en el benchmark.

Para repetir la medición local necesitas Python 3 y una copia oficial de sqlmap:

```powershell
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git tools/sqlmap
python scripts/benchmark_dvwa.py --runs 3
```

Con frontend, backend y DVWA activos, el script compara tres ejecuciones por
herramienta, alterna su orden y crea sesiones nuevas. Utiliza explícitamente Low,
exclusivamente DVWA
en localhost:8000, nivel Low y el parámetro id. sqlmap se limita a detección
booleana, nivel 1, riesgo 1 y un hilo, sin solicitar extracción de datos. Utiliza
DVWA_USERNAME y DVWA_PASSWORD del entorno si configuraste otras credenciales.

La mediana y las ejecuciones individuales quedan en `docs/benchmarks/dvwa-latest.md`
y `docs/benchmarks/dvwa-latest.json`. La medición incluye login y detección; sqlmap
incluye el arranque de Python y la app incluye hasta 50 ms de espera de consulta.
El motor de la app tiene dos pruebas concretas; sqlmap comprueba más variantes.
Las rutas de red también difieren (Docker interno frente a loopback del host).
Esta prueba local no demuestra superioridad general ni cobertura equivalente.

## Referencia

Para recorrer el código activo, utiliza [la guía completa de código](docs/CODIGO_GUIA.md).
Explica cada módulo, el flujo desde el botón hasta MySQL y el orden de estudio.
La [guía del expositor de 90 minutos](docs/workshop-90/entregables/Guia_expositor_90_min.md)
indica cuándo mostrar la app o el editor durante la presentación.

El estado de un escaneo se consulta en `GET /api/scans/:id`; el reporte se genera
en `GET /api/scans/:id/results`. DVWA admite 1, 2 o 4 workers con sesiones
independientes. No hay telemetría de kernel en el código activo.

La API rechaza peticiones de navegador con un Origin distinto al dashboard local.
`SCANNER_ALLOWED_ORIGINS` define los orígenes en el backend; Compose deriva sus
valores de `FRONTEND_PORT`. Los clientes de consola pueden seguir usando la API.

[DVWA oficial](https://github.com/digininja/DVWA). El material en `docs/workshop`
corresponde a la arquitectura anterior y se conserva como referencia histórica.
