# 📖 DOCUMENTO MAESTRO: EXPLICACIÓN EXHAUSTIVA DE ARQUITECTURA, CÓDIGO Y FLUJOS
## Proyecto: SQLi Purple Team Studio (TICEC 2026)
### Detección de Inyección SQL (CWE-89), Observabilidad en Kernel con eBPF y Remediación Defensiva

---

# 📑 ÍNDICE GENERAL

1. [VISIÓN GENERAL Y EL PARADIGMA PURPLE TEAM](#1-visión-general-y-el-paradigma-purple-team)
2. [INFRAESTRUCTURA Y VIRTUALIZACIÓN CON DOCKER](#2-infraestructura-y-virtualización-con-docker)
   * 2.1 Topología de Redes y Servicios (`compose.yaml`)
   * 2.2 Dockerfile del Backend (Hardening, CGO, DWARF)
   * 2.3 Dockerfile del Frontend y Servidores Web
3. [BACKEND EN GO: ANÁLISIS EXHAUSTIVO ARCHIVO POR ARCHIVO](#3-backend-en-go-análisis-exhaustivo-archivo-por-archivo)
   * 3.1 Orquestación y Punto de Entrada (`backend/main.go`)
   * 3.2 El Cable de Conexión y Pool (`backend/database/database.go`)
   * 3.3 El Patrón Repositorio y Consultas SQL (`backend/database/repository.go`)
   * 3.4 El Contrato de Datos y Dominio (`backend/models/models.go`)
   * 3.5 Enrutamiento HTTP, CORS y Middlewares (`backend/router/router.go`)
   * 3.6 Controladores y Asincronía (`backend/handlers/handlers.go`)
   * 3.7 Guardrails Éticos y Mitigación Anti-SSRF (`backend/policy/targets.go`)
   * 3.8 El Motor del Escáner y Concurrencia (`backend/scanner/engine.go`)
   * 3.9 Las Sondas de Auditoría: Boolean, UNION y Time-Based (`backend/scanner/probes.go`)
   * 3.10 Descubrimiento Dinámico y Crawler (`backend/scanner/discovery.go`)
   * 3.11 Motor de Remediación y eBPF Tetragon (`backend/remediation/report.go`)
4. [EL LABORATORIO DE ENTORNOS DE PRUEBA (`lab/app/`)](#4-el-laboratorio-de-entornos-de-prueba-labapp)
   * 4.1 Punto de Entrada de los Sandboxes (`lab/app/main.go`)
   * 4.2 El Endpoint Inseguro: Concatenación y AST (`vulnerable_products.go`)
   * 4.3 El Endpoint Seguro: Validación Tipada y Prepared Statements (`products.go`)
   * 4.4 Bases de Datos MySQL del Laboratorio (`lab-db` vs `scanner-db`)
5. [FRONTEND EN REACT: INTERFAZ Y CONSUMOS](#5-frontend-en-react-interfaz-y-consumos)
   * 5.1 Arquitectura del Componente Principal (`frontend/src/App.jsx`)
   * 5.2 Máquina de Estados, Polling y Ciclo de Vida
   * 5.3 Los Presets de Demostración (Vulnerable, Reparado, Externo)
   * 5.4 Componentes de Evidencia Dual y Remediación en Pantalla
   * 5.5 Sistema de Diseño, Estilos y Experiencia de Usuario (`App.css`)
6. [TRAZA COMPLETA DE PUNTA A PUNTA (END-TO-END TRACE)](#6-traza-completa-de-punta-a-punta-end-to-end-trace)
7. [CONCEPTOS DE SEGURIDAD AVANZADA (AST, WAF, WORKER POOLS, EBPF)](#7-conceptos-de-seguridad-avanzada-ast-waf-worker-pools-ebpf)

---

# 1. VISIÓN GENERAL Y EL PARADIGMA PURPLE TEAM

### El Problema de la Seguridad Tradicional
Durante décadas, la ciberseguridad corporativa y académica ha operado en dos silos aislados:
* **Red Team (Ofensivo):** Utiliza herramientas como *sqlmap*, *Burp Suite* o *Nmap* para encontrar vulnerabilidades y extraer información sensible. Entrega reportes que señalan fallas pero no aportan soluciones en código.
* **Blue Team (Defensivo):** Monitorea logs de texto en Capa 7 (WAFs, firewalls) y aplica parches a ciegas sin entender con precisión la mecánica de explotación.

### La Solución: El Paradigma Purple Team
Este proyecto implementa una plataforma interactiva donde el ataque y la defensa se fusionan en un ciclo cerrado:
1. **Auditoría Ofensiva Automatizada:** El escáner ejecuta pruebas de inyección SQL (CWE-89) mediante un motor concurrente en Go.
2. **Validación Dual (Dual Confirmation):** La vulnerabilidad no se da por confirmada únicamente porque la respuesta HTTP cambió; se correlaciona con la telemetría del Kernel de Linux mediante sensores **eBPF** en el puerto de base de datos (`3306`).
3. **Remediación Inmediata:** El sistema genera en tiempo real el parche de código seguro en **Go**, **PHP** y **Python**, junto con una política en YAML para **Cilium Tetragon** que neutraliza el ataque en tiempo de ejecución.

---

# 2. INFRAESTRUCTURA Y VIRTUALIZACIÓN CON DOCKER

Todo el ecosistema se ejecuta en contenedores Docker organizados a través del archivo [compose.yaml](file:///c:/Users/Pandora/Desktop/SQL/compose.yaml).

### 2.1 Topología de Redes y Servicios

```
                              [ RED PÚBLICA: public_net ]
                                           │
                          [ sqli-frontend: Nginx (:3000) ]
                                           │
                                    REST API / JSON
                                           ▼
                          [ sqli-backend: Go Engine (:8080) ]
                                           │
        ┌──────────────────────────────────┴──────────────────────────────────┐
        │ [ RED DEL ESCÁNER: scanner_net ]                                    │ [ RED DE LABORATORIO: lab_net ]
        ▼                                                                     ▼
[ sqli-scanner-db: MySQL 8 ]                                          [ sqli-lab-db: MySQL 8 ]
  • Persistencia de auditorías                                          • Datos de prueba
  • Registro de hallazgos                                               • Tabla vulnerable
  • Logs de telemetría                                                        ▲             ▲
                                                                              │             │
                                              [ sqli-vulnerable-app (:8081) ]─┘             └─[ sqli-secure-app (:8081) ]
```

* **Aislamiento de Redes:**
  * `public_net`: Conecta el navegador del usuario al frontend Nginx.
  * `scanner_net`: Red interna (marcada con `internal: true`). El backend en Go habla con su base de datos de auditoría `scanner-db` de forma aislada.
  * `lab_net`: Red de prueba (también `internal: true`). Los sandboxes (`vulnerable-app` y `secure-app`) se comunican con `lab-db` en el puerto 3306.

---

### 2.2 Dockerfile del Backend (`backend/Dockerfile`)
Analizamos línea por línea el archivo de construcción del contenedor principal:

```dockerfile
1: FROM golang:1.25-alpine AS builder
```
* **Multi-Stage Build:** Inicia la etapa de compilación (`builder`) sobre Alpine Linux. Todo el SDK de Go se descartará en la etapa final.

```dockerfile
3: WORKDIR /app
5: COPY go.mod go.sum ./
6: RUN go mod download
```
* **Caché de Capas:** Copia únicamente los manifiestos de dependencias antes de copiar el código fuente. Si el código cambia pero las librerías no, Docker reutiliza la caché y la compilación tarda 1 segundo.

```dockerfile
8: COPY . .
10: RUN CGO_ENABLED=0 GOOS=linux go build \
11:     -trimpath \
12:     -ldflags="-s -w" \
13:     -o /out/scanner-backend \
14:     .
```
* **`CGO_ENABLED=0`:** Deshabilita la interoperabilidad con librerías en C. Produce un **binario 100% estático** sin dependencias externas de `glibc` o `musl`, permitiendo que el binario se ejecute en cualquier distribución de Linux.
* **`GOOS=linux`:** Fuerza la compilación para la arquitectura Linux.
* **`-trimpath` (Seguridad):** Elimina las rutas del sistema de archivos local del desarrollador en el binario compilado para evitar fuga de información en trazas de error.
* **`-ldflags="-s -w"` (Optimización):**
  * `-s`: Elimina la tabla de símbolos de depuración.
  * `-w`: Elimina la información de depuración DWARF.
  * *Resultado:* Reduce el tamaño del ejecutable de ~25 MB a ~12 MB y dificulta la ingeniería inversa.

```dockerfile
16: FROM alpine:3.22
18: RUN addgroup -S scanner && adduser -S -G scanner scanner
21: WORKDIR /app
23: COPY --from=builder /out/scanner-backend /app/scanner-backend
25: USER scanner
27: EXPOSE 8080
29: ENTRYPOINT ["/app/scanner-backend"]
```
* **Hardening y Menor Privilegio:** Crea un usuario sin privilegios de root (`scanner`), copia únicamente el binario compilado y ejecuta la aplicación bajo ese usuario. Si un atacante explotara el backend, no tendrá permisos de root en el host.

---

# 3. BACKEND EN GO: ANÁLISIS EXHAUSTIVO ARCHIVO POR ARCHIVO

---

### 3.1 Orquestación y Punto de Entrada (`backend/main.go`)

```go
func main() {
	if err := database.Connect(); err != nil {
		log.Fatalf("No se pudo iniciar el backend: %v", err)
	}

	defer func() {
		if err := database.Close(); err != nil {
			log.Printf("No se pudo cerrar scanner-db correctamente: %v", err)
		}
	}()

	repo := database.GetDefaultRepository()
	r := router.SetupRouter(repo)

	log.Println("Servidor del escáner iniciado en :8080 (Purple Team TICEC 2026)")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("No se pudo iniciar el servidor HTTP: %v", err)
	}
}
```

* **Línea 11 (`database.Connect`):** Inicializa el pool de conexiones hacia MySQL. Si falla tras 10 intentos, `log.Fatalf` detiene la ejecución (principio *Fail-Fast*).
* **Líneas 15-19 (`defer database.Close`):** Garantiza que al terminar el programa se cierren todos los sockets TCP abiertos con MySQL, evitando file descriptors huérfanos.
* **Líneas 21-22 (Inyección de Dependencias):** Se crea el repositorio de base de datos y se inyecta en el enrutador HTTP (`SetupRouter(repo)`).
* **Línea 25 (`r.Run(":8080")`):** Inicia el servidor web escuchando en el puerto 8080.

---

### 3.2 El Cable de Conexión y Pool (`backend/database/database.go`)

Este archivo gestiona la conectividad física y la resiliencia de red con la base de datos de auditoría (`scanner-db`).

* **El DSN (Data Source Name):**
  ```go
  dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4", user, password, host, port, name)
  ```
  * `parseTime=true`: Obliga al driver de MySQL a mapear las columnas `DATETIME` a structs `time.Time` nativos de Go.
  * `charset=utf8mb4`: Soporta codificación UTF-8 de 4 bytes (necesario para payloads complejos y caracteres internacionales).

* **Dimensionamiento del Pool de Conexiones:**
  ```go
  databaseConnection.SetMaxOpenConns(10)
  databaseConnection.SetMaxIdleConns(5)
  databaseConnection.SetConnMaxLifetime(5 * time.Minute)
  databaseConnection.SetConnMaxIdleTime(2 * time.Minute)
  ```
  * `SetMaxOpenConns(10)`: Limita a 10 las conexiones simultáneas abiertas. Evita agotar la memoria de MySQL durante picos de escaneo.
  * `SetMaxIdleConns(5)`: Mantiene 5 conexiones en espera listas para ser reutilizadas sin tener que negociar el saludo TCP de nuevo.

* **Resiliencia con Bucle de Reintentos:**
  MySQL tarda entre 5 y 10 segundos en arrancar en frío en Docker. El backend ejecuta un bucle `for` de hasta 10 intentos con pausas de 3 segundos (`time.Sleep(3 * time.Second)`) ejecutando `databaseConnection.PingContext(ctx)` hasta que la base de datos esté lista.

---

### 3.3 El Patrón Repositorio y Consultas SQL (`backend/database/repository.go`)

Encapsula todas las operaciones de persistencia. **El 100% de las sentencias utilizan consultas preparadas con signos de interrogación `?`**.

#### Métodos principales:
1. **`CreateScan(scan)`:** Inserta un nuevo registro en la tabla `scans` con estado `QUEUED`.
2. **`GetScan(scanID)`:** Recupera el estado actual de una auditoría. Utiliza `COALESCE(error_message, '')` en SQL y `sql.NullTime` en Go para evitar caídas (*panics*) cuando columnas de fecha como `completed_at` son nulas (`NULL`). Convierte las fechas a formato ISO 8601 (`time.RFC3339`) para que React las pinte sin problemas de zona horaria.
3. **`UpdateScanStatus(scanID, status, ...)`:** Controla la máquina de estados (`QUEUED` $\to$ `RUNNING` $\to$ `COMPLETED` o `FAILED`), actualizando los sellos de tiempo `started_at` y `completed_at`.
4. **`CreateFinding(finding)`:** Guarda un vector de inyección confirmado en la tabla `findings`, registrando la URL probada, el parámetro, la severidad (`CRITICAL`), las latencias y el JSON de evidencia dual.
5. **`CreateEventWithoutInterrupting(...)`:** Registra eventos de telemetría en la tabla `scan_events` bajo un patrón *best-effort*: si ocurre un error al escribir el log en la BD, se registra en consola pero **no interrumpe el escaneo**.

---

### 3.4 El Contrato de Datos y Dominio (`backend/models/models.go`)

Define la estructura de los datos que fluyen entre Go, MySQL y React:

* **`ScanRequest`:** Los parámetros de entrada enviados por el usuario desde el frontend (`mode`, `target`, `url`, `authorization_confirmed`).
* **`ScanStatusResponse`:** El estado del escaneo que el frontend consulta mediante polling (`scan_id`, `status`, `created_at`, `started_at`, `completed_at`, `remediation_report`).
* **`ScanTask`:** Una unidad de trabajo atómica enviada a través de los canales del Worker Pool (`ProbeType`, `Payload`, `Parameter`, `TargetURL`, `TraceID`).
* **`DualConfirmation` y `DualEvidence`:** Modela la correlación entre Capa 7 (HTTP) y Capa 0 (Kernel eBPF):
  * `HTTPConfirmation`: `{ Confirmed: true, StatusCode: 200, LatencyMS: 15 }`
  * `KernelConfirmation`: `{ Confirmed: true, TargetSocket: "lab-db:3306", InterceptedQuery: "SELECT...", Sensor: "Tetragon / eBPF" }`
* **`Finding`:** Registro formal de una vulnerabilidad descubierta.
* **`RemediationReport`:** El reporte técnico entregado al Blue Team con la guía de mitigación y el manifiesto YAML de Tetragon.

---

### 3.5 Enrutamiento HTTP, CORS y Middlewares (`backend/router/router.go`)

* **Framework Gin:** Configurado con `gin.Default()`, que incluye middleware de registro de peticiones (*Logger*) y recuperación automática de caídas (*Recovery*).
* **Middleware de CORS (Cross-Origin Resource Sharing):**
  Como React corre en `http://localhost:3000` y Go en `http://localhost:8080`, el navegador bloquea la comunicación por defecto. El middleware agrega los encabezados `Access-Control-Allow-Origin: *` y responde inmediatamente a las peticiones pre-flight `OPTIONS` con código `HTTP 204 No Content`.
* **Rutas expuestas:**
  * `GET /health` $\to$ Verificación de salud (usado por Docker Compose).
  * `POST /api/scans` $\to$ Iniciar nuevo escaneo.
  * `GET /api/scans/:id` $\to$ Consultar estado del escaneo (polling).
  * `GET /api/scans/:id/results` $\to$ Obtener hallazgos y guía de remediación.
  * `GET /api/scans/:id/events` $\to$ Obtener la bitácora de eventos y telemetría.

---

### 3.6 Controladores y Asincronía (`backend/handlers/handlers.go`)

Analizamos el controlador más importante: **`StartScanHandler`**:

1. **Deserialización:** `c.ShouldBindJSON(&request)` valida la sintaxis del JSON entrante.
2. **Evaluación de Políticas:** Llama a `policy.ValidateTarget(...)`. Si el destino viola las reglas de seguridad o no cuenta con autorización, rechaza la petición con `HTTP 400 Bad Request`.
3. **ID Criptográficamente Seguro:** Genera un identificador de escaneo de 128 bits utilizando `crypto/rand` (imposible de predecir o falsificar por atacantes).
4. **Persistencia Inicial:** Guarda el escaneo en la base de datos con estado `QUEUED`.
5. **Ejecución Asíncrona con Goroutine:**
   ```go
   go scanner.RunScan(scanID, target.URL, target.Parameter, target.Mode, workers, h.repo)
   ```
   Al anteponer la palabra clave `go`, la función pesada de auditoría se delega a un hilo ultraligero independiente. El controlador no se queda esperando y responde al navegador en menos de 5 milisegundos con un código **`HTTP 202 Accepted`**.

---

### 3.7 Guardrails Éticos y Mitigación Anti-SSRF (`backend/policy/targets.go`)

Garantiza que la herramienta no pueda ser convertida en un arma ofensiva contra terceros:

1. **Lista Blanca Inmutable de Sandboxes:** En modo sandbox, solo se admiten los destinos internos pre-registrados (`vulnerable-app` y `secure-app`). Cualquier otra entrada es denegada.
2. **Requisitos Estrictos para URLs Externas:**
   * **Consentimiento Explícito:** La petición debe incluir obligatoriamente `authorization_confirmed: true`.
   * **Protocolo Válido:** Solo se permiten esquemas `http` y `https`.
   * **Sin Credenciales:** Deniega URLs que incluyan usuarios o claves (`http://user:pass@host`).
   * **Bloqueo Total de Direcciones IP Numéricas (Anti-SSRF):** Mediante `net.ParseIP(host) != nil`, el escáner rechaza cualquier IP directa. Esto evita ataques contra la red interna del congreso (`192.168.x.x`, `10.x.x.x`) y bloquea intentos de acceder al servicio de metadatos de Cloud de AWS/GCP (`169.254.169.254`).
   * **Lista Blanca de Dominios Autorizados:** Solo permite auditar dominios académicos públicos de prueba como `testphp.vulnweb.com`.

---

### 3.8 El Motor del Escáner y Concurrencia (`backend/scanner/engine.go`)

Orquesta el análisis técnico mediante el patrón **Worker Pool**:

```go
tasks := []models.ScanTask{
    { Payload: "1 OR 1=1", ProbeType: "Boolean", ... },
    { Payload: "0 UNION ALL SELECT ...", ProbeType: "Extraction", ... },
    { Payload: "1 AND SLEEP(2)", ProbeType: "TimeBased", ... },
}

jobs := make(chan models.ScanTask, len(tasks))
var wg sync.WaitGroup

for w := 1; w <= workerCount; w++ {
    wg.Add(1)
    go func(workerID int) {
        defer wg.Done()
        for task := range jobs {
            switch task.ProbeType {
            case "Boolean":
                executeBooleanProbe(...)
            case "Extraction":
                executeExtractionProbe(...)
            case "TimeBased":
                executeTimeBasedProbe(...)
            }
        }
    }(w)
}

for _, task := range tasks {
    jobs <- task
}
close(jobs)
wg.Wait()
```

* `jobs := make(chan models.ScanTask, len(tasks))`: Canal con búfer donde se encolan las tareas.
* `sync.WaitGroup`: Bloquea la función principal hasta que el último worker termine (`wg.Wait()`).
* **Concurrencia sin DoS:** Las 3 sondas se ejecutan simultáneamente en paralelo a través de los workers sin abrir cientos de conexiones descontroladas contra el servidor de pruebas.

---

### 3.9 Las Sondas de Auditoría: Boolean, UNION y Time-Based (`backend/scanner/probes.go`)

Aquí se implementa la lógica de detección de cada vector:

#### 1. Sonda Booleana (`executeBooleanProbe`)
* **Payload:** `1 OR 1=1`
* **Mecanismo:** Envía la petición y compara la respuesta frente a la línea base legítima (`baseline`). Si el número de productos devueltos en el JSON es mayor que en la línea base (`len(probeResp.Products) > len(baselineResp.Products)`), confirma que la condición lógica `OR 1=1` anuló la restricción del `WHERE`.

#### 2. Sonda de Extracción UNION (`executeExtractionProbe`)
* **Payload:** `0 UNION ALL SELECT id,username,display_name,0,is_active FROM workshop_users WHERE 1=1`
* **Mecanismo:** Deserializa los productos recibidos. Si encuentra en los nombres valores como `"student"` o `"instructor"` (que pertenecen a la tabla privada `workshop_users`), confirma la exfiltración masiva de datos no autorizados.

#### 3. Sonda Basada en Tiempo / Timelapse (`executeTimeBasedProbe`)
* **Payload:** `1 AND SLEEP(2)`
* **Mecanismo:** No analiza el texto ni el tamaño de la respuesta; mide la **latencia de socket en milisegundos**.
  * Latencia de línea base legítima: ~15 ms.
  * Latencia con inyección de retardo: **> 1,800 ms (cerca de 2,000 ms)**.
  * Al detectar el incremento temporal inducido, confirma la inyección a ciegas (*Time-Based Blind*).

#### Inyección de Encabezados Purple Team:
En cada petición enviada mediante `performRequestWithTrace`, el cliente inyecta cabeceras personalizadas:
* `X-Scan-Task-ID`: El identificador de la tarea atómica.
* `X-Purple-Trace`: El identificador de correlación para que el sensor eBPF en el Kernel pueda mapear la petición HTTP exacta con la llamada al sistema en el socket.

---

### 3.10 Descubrimiento Dinámico y Crawler (`backend/scanner/discovery.go`)

Cuando se audita una URL externa (`testphp.vulnweb.com`), el escáner no adivina parámetros a ciegas; utiliza un **Web Crawler**:
1. Descarga el HTML de la página objetivo.
2. Analiza el DOM buscando formularios (`<form action="..." method="...">`) y campos de entrada (`<input name="...">`).
3. Extrae enlaces con query strings (`href="listproducts.php?cat=1"`).
4. Genera dinámicamente tareas de prueba para cada parámetro descubierto (`cat`, `artist`, etc.).

---

### 3.11 Motor de Remediación y eBPF Tetragon (`backend/remediation/report.go`)

Transforma los hallazgos en soluciones accionables para el Blue Team:
* Genera recomendaciones de arquitectura de software (validación estricta de tipos, principio de mínimo privilegio en el usuario de MySQL).
* Genera comparativas de código antes vs después en **Go** (`strconv.ParseUint` + `?`), **PHP** (`filter_input` + `PDO::prepare`) y **Python** (`cursor.execute(query, (id,))`).
* Genera el manifiesto YAML de **Cilium Tetragon (`TracingPolicy`)** con kprobe en `sys_enter_write` y acción `Sigkill` para protección en runtime.

---

# 4. EL LABORATORIO DE ENTORNOS DE PRUEBA (`lab/app/`)

En el directorio `lab/app/` reside el código fuente de los objetivos de prueba. Ambos contenedores (`vulnerable-app` y `secure-app`) se compilan a partir del mismo binario en Go, pero su comportamiento se activa según la variable de entorno `APP_MODE`.

---

### 4.1 Punto de Entrada (`lab/app/main.go`)

* Inicia un servidor HTTP nativo en el puerto `8081`.
* Registra los endpoints:
  * `GET /health` $\to$ Verificación de salud y conexión con `lab-db`.
  * `GET /api/vulnerable/products` $\to$ Controlador vulnerable (solo activo en `APP_MODE=vulnerable`).
  * `GET /api/secure/products/{id}` $\to$ Controlador seguro (solo activo en `APP_MODE=secure`).

---

### 4.2 El Endpoint Inseguro (`lab/app/internal/handlers/vulnerable_products.go`)

#### La Falla Crítica:
```go
productID := strings.TrimSpace(r.URL.Query().Get("id"))

query := `
    SELECT id, name, description, price, is_active
    FROM products
    WHERE id = ` + productID + `
    AND is_active = TRUE
`
rows, err := handler.database.QueryContext(ctx, query)
```
* **Qué sale mal:** El parámetro `id` se extrae como una cadena de texto sin validar su contenido. Se concatena directamente con el operador `+`.
* Si `productID` es `1 OR 1=1`, el árbol sintáctico (AST) se altera, devolviendo toda la tabla.
* Si `productID` contiene `UNION SELECT`, exfiltra la tabla `workshop_users`.
* Si `productID` contiene `SLEEP(2)`, el hilo de base de datos se congela por 2 segundos.

---

### 4.3 El Endpoint Seguro (`lab/app/internal/handlers/products.go`)

#### La Fortaleza Defensiva:
```go
idText := r.PathValue("id")

// Barrera 1: Validación estricta de tipos en memoria (CPU)
productID, err := strconv.ParseUint(idText, 10, 64)
if err != nil || productID == 0 {
    writeJSON(w, http.StatusBadRequest, ErrorResponse{
        Error: "El identificador debe ser un entero positivo",
    })
    return
}

// Barrera 2: Consulta Parametrizada (MySQL)
const query = `
    SELECT id, name, description, price, is_active
    FROM products
    WHERE id = ?
    AND is_active = TRUE
`
err = handler.database.QueryRowContext(ctx, query, productID).Scan(...)
```

1. **Barrera 1 (Validación Tipada):** Si el atacante envía comillas, espacios o sentencias SQL, `strconv.ParseUint` falla instantáneamente en la CPU de Go. La aplicación responde `HTTP 400 Bad Request` en **0.2 milisegundos sin tocar la base de datos**.
2. **Barrera 2 (Prepared Statement):** El motor MySQL compila la plantilla con `?`. El parámetro `productID` viaja por el protocolo binario separado. Aunque pasara una cadena extraña, MySQL nunca la interpreta como código ejecutable.

---

### 4.4 Bases de Datos MySQL del Laboratorio

1. **`sqli-scanner-db` (Puerto 3306 interno):**
   * Almacena las tablas del escáner: `scans` (metadatos de auditorías), `findings` (vulnerabilidades descubiertas) y `scan_events` (bitácora de telemetría en vivo).
2. **`sqli-lab-db` (Puerto 3306 interno):**
   * Almacena las tablas del negocio ficticio: `products` (catálogo público) y `workshop_users` (usuarios ficticios con contraseñas hash, usada para demostrar ataques de exfiltración UNION).

---

# 5. FRONTEND EN REACT: INTERFAZ Y CONSUMOS

El frontend es una **Single Page Application (SPA)** moderna construida con **React 19** y **Vite**, empaquetada en un contenedor Nginx sirviendo en el puerto `3000`.

---

### 5.1 Arquitectura del Componente Principal (`frontend/src/App.jsx`)

El archivo [App.jsx](file:///c:/Users/Pandora/Desktop/SQL/frontend/src/App.jsx) concentra la lógica de visualización y el consumo de la API REST del backend:

* **Gestión de Estado React:**
  * `scanId`: Almacena el identificador único del escaneo en curso.
  * `scanStatus`: Objeto con el estado actual (`QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`).
  * `events`: Array con todos los eventos de telemetría emitidos por el Worker Pool.
  * `report`: Objeto con el informe técnico de remediación y políticas eBPF.
  * `isRunning`: Booleano que deshabilita botones durante un escaneo activo.

---

### 5.2 Máquina de Estados, Polling y Ciclo de Vida

Para mostrar el progreso en tiempo real sin recargar la página, el frontend implementa un efecto de sondeo periódico (**Polling**):

```javascript
useEffect(() => {
  if (!isRunning || !scanId) return;

  const timer = setInterval(async () => {
    try {
      const res = await axios.get(`/api/scans/${scanId}`);
      setScanStatus(res.data);
      await loadEvents(scanId);

      if (FINAL_STATUSES.includes(res.data.status)) {
        setIsRunning(false);
        if (res.data.status === "COMPLETED") {
          await loadResults(scanId);
        }
      }
    } catch (err) {
      setIsRunning(false);
    }
  }, 1500);

  return () => clearInterval(timer);
}, [isRunning, scanId]);
```
* Cada **1,500 milisegundos**, React consulta `/api/scans/:id` y `/api/scans/:id/events`.
* En cuanto el backend cambia el estado a `COMPLETED`, el temporizador se destruye con `clearInterval` y se descargan los resultados finales con `loadResults`.

---

### 5.3 Los Presets de Demostración (`TARGET_PRESETS`)

Permiten al expositor cambiar de escenario con un solo clic:
1. **Sandbox Vulnerable:** Apunta a `vulnerable-app:8081` (espera confirmación de vulnerabilidad CWE-89).
2. **Sandbox Reparado:** Apunta a `secure-app:8081` (espera 0 hallazgos y certificación de resiliencia).
3. **Objetivo Externo:** Activa el campo para ingresar `http://testphp.vulnweb.com/listproducts.php?cat=1` con crawler web.

---

### 5.4 Componentes UI Especializados

1. **`Header`:** Muestra la marca del congreso TICEC 2026, el indicador verde de conectividad del backend y el botón para limpiar sesión.
2. **`StatusBanner`:** Banner superior de alto impacto. Muestra en rojo vibrante **"VULNERABILIDAD CRÍTICA CONFIRMADA (CWE-89)"** cuando hay brecha, o en verde esmeralda **"SISTEMA RESILIENTE · 0 HALLAZGOS"** cuando se audita la versión segura.
3. **`PipelineStepper`:** Barra de progreso en 4 pasos visuales:
   * Paso 1: Línea Base HTTP (petición legítima).
   * Paso 2: Inyección de Sondas (Boolean, UNION y Time).
   * Paso 3: Telemetría de Kernel (eBPF en socket 3306).
   * Paso 4: Veredicto & Parche (generación de informe).
4. **`DualValidationCard`:** Tarjeta de evidencia dual. Muestra lado a lado lo que ocurrió en **Capa 7 (HTTP Status y Latencia)** contra lo que capturó el sensor de **Capa 0 (Socket TCP y Query interceptado en Kernel)**.
5. **`RemediationSection`:** Pestañas interactivas para alternar el código de parche en **Go**, **PHP** y **Python**, junto con un bloque de sintaxis que muestra el YAML de **Cilium Tetragon**.

---

# 6. TRAZA COMPLETA DE PUNTA A PUNTA (END-TO-END TRACE)

¿Qué ocurre exactamente cuando el usuario presiona **"Iniciar Auditoría"** en la pantalla?

```
[ PASO 1: NAVEGADOR WEB (React :3000) ]
  • El usuario selecciona "Sandbox Vulnerable".
  • React envía: POST http://localhost:8080/api/scans
    Body: { "mode": "sandbox", "target": "vulnerable-app" }

[ PASO 2: ROUTER & MIDDLEWARE (Go :8080) ]
  • router.go aprueba el paso mediante el middleware CORS.
  • handlers.go toma la petición en StartScanHandler.

[ PASO 3: POLÍTICAS & PERSISTENCIA ]
  • policy.ValidateTarget verifica que "vulnerable-app" está en la lista blanca.
  • generateScanID() crea un hash seguro de 128 bits: "a3f89c01de45...".
  • repository.CreateScan() guarda el registro en scanner-db con estado "QUEUED".
  • handlers.go responde al navegador: HTTP 202 Accepted { id: "a3f89c..." }.
  • React recibe el 202 y comienza su sondeo (polling) cada 1.5s.

[ PASO 4: MOTOR CONCURRENTE (Goroutine de Fondo) ]
  • Se lanza en segundo plano: go scanner.RunScan(...).
  • El escáner actualiza el estado a "RUNNING" en scanner-db.
  • Ejecuta la petición de línea base contra vulnerable-app:8081/api/vulnerable/products?id=1.
  • Línea base responde en 15 ms con 2 productos activos.

[ PASO 5: WORKER POOL & DISPARO PARALELO DE SONDAS ]
  • Se encolan 3 tareas en el canal 'jobs':
    - Tarea 1: Boolean ("1 OR 1=1")
    - Tarea 2: Extracción UNION ("0 UNION ALL SELECT...")
    - Tarea 3: Time-Based ("1 AND SLEEP(2)")
  • 3 workers (goroutines) toman las tareas simultáneamente.

[ PASO 6: EJECUCIÓN EN SANDBOX & TELEMETRÍA ]
  • Worker 1 dispara "1 OR 1=1":
    - vulnerable-app concatena el string y envía a lab-db:3306.
    - Sensor eBPF en Kernel intercepta la llamada sys_enter_write con la consulta alterada.
    - MySQL devuelve 5 productos (ampliación de registros detectada).
    - Se registra el hallazgo SQL_INJECTION_BOOLEAN en scanner-db.
  • Worker 2 dispara UNION:
    - MySQL devuelve registros ficticios de workshop_users.
    - Se confirma fuga de información crítica y se guarda el hallazgo.
  • Worker 3 dispara SLEEP(2):
    - La petición tarda 2,015 ms (> 1800 ms de umbral).
    - Se confirma inyección basada en tiempo y se guarda el hallazgo.

[ PASO 7: REMEDIACIÓN & FINALIZACIÓN ]
  • sync.WaitGroup finaliza la espera.
  • remediation.GenerateReport() recopila los hallazgos y genera parches en Go, PHP, Python y la regla Tetragon.
  • El escáner actualiza el estado a "COMPLETED" en scanner-db.

[ PASO 8: VISUALIZACIÓN EN REACT ]
  • En el siguiente ciclo de polling (1.5s), React detecta el estado "COMPLETED".
  • React descarga los resultados finales con /api/scans/:id/results.
  • La pantalla se actualiza: Banner Rojo de Alerta Crítica, Stepper al 100%, 3 tarjetas de evidencia dual y guía de parches lista para el ponente.
```

---

# 7. CONCEPTOS DE SEGURIDAD AVANZADA (AST, WAF, WORKER POOLS, EBPF)

### 7.1 AST (Abstract Syntax Tree)
* El árbol sintáctico es la estructura en memoria que el compilador genera para representar la semántica de una instrucción.
* **La falla de inyección SQL no es un error de ejecución; es un error de compilación**. Al concatenar datos, el analizador sintáctico interpreta los tokens del atacante (`OR`, `UNION`, `SLEEP`) como operadores del lenguaje en lugar de valores literales.
* La precedencia del operador `AND` sobre `OR` hace que la condición tautológica `1=1` neutralice por completo los filtros del `WHERE`.

### 7.2 WAFs y sus Limitaciones
* Operan en Capa 7 (HTTP) comparando firmas y expresiones regulares.
* Sufren de **Impedancia Semántica**: no conocen la estructura de la base de datos ni cómo el motor SQL procesará los bytes tras múltiples decodificaciones (nested URL encode `%2527`, comentarios `/**/`, secuencias UTF-8).
* Producen falsos positivos en búsquedas legítimas o falsos negativos ante atacantes avanzados.

### 7.3 Concurrencia con Worker Pools en Go
* Las Goroutines son hilos en espacio de usuario administrados por el runtime de Go (consumen apenas 2 KB de memoria frente a los 1-8 MB de un hilo del sistema operativo).
* El patrón **Worker Pool** utiliza canales con búfer (`jobs := make(chan ScanTask)`) para limitar el número de tareas simultáneas.
* Evita la saturación del servidor auditado, previene caídas por DoS accidental y sincroniza el final del escaneo con `sync.WaitGroup`.

### 7.4 eBPF y Cilium Tetragon
* **eBPF:** Máquina virtual en el Kernel de Linux que permite ejecutar programas seguros compilados en tiempo de ejecución (JIT) sin alterar el código del kernel ni cargar módulos inestables.
* **In-Kernel Verifier:** Garantiza matemáticamente que los programas eBPF no generen bucles infinitos, accesos ilegales a memoria ni caídas del sistema (*kernel panics*).
* **Kprobe en `sys_enter_write`:** Intercepta la llamada al sistema que la aplicación utiliza para transmitir datos por el socket hacia el puerto 3306 de MySQL. Es la verdad absoluta: para que MySQL entienda la orden, el texto debe viajar decodificado.
* **Cilium Tetragon:** Operador de seguridad en tiempo de ejecución que aplica políticas `TracingPolicy`. Si el búfer en el socket contiene un patrón malicioso (`1 OR 1=1`), Tetragon despacha una señal sincrónica **`Sigkill`** directamente desde el Kernel, interrumpiendo el proceso infractor en nanosegundos antes de que el ataque se complete.
