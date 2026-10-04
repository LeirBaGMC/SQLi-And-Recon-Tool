---
marp: true
theme: gaia
_class: lead
paginate: true
backgroundColor: #0A0E17
color: #F9FAFB
style: |
  section {
    font-family: 'Inter', sans-serif;
    padding: 40px 60px;
    background-color: #0A0E17;
    color: #F9FAFB;
  }
  h1 { color: #A5B4FC; font-size: 2.2rem; }
  h2 { color: #818CF8; font-size: 1.6rem; border-bottom: 2px solid #374151; padding-bottom: 8px; }
  h3 { color: #E0E7FF; font-size: 1.2rem; }
  code { font-family: 'JetBrains Mono', monospace; background: #1E293B; color: #38BDF8; padding: 2px 6px; border-radius: 4px; }
  pre { background: #111827; border: 1px solid #374151; padding: 14px; border-radius: 8px; font-size: 0.8rem; }
  strong { color: #F87171; }
  em { color: #34D399; font-style: normal; font-weight: bold; }
  .speaker-note { background: #162032; border-left: 4px solid #6366F1; padding: 10px; margin-top: 15px; font-size: 0.8rem; color: #94A3B8; }
---

# TICEC 2026 · WORKSHOP TÉCNICO
## Más allá del WAF: Detección de Inyección SQL (CWE-89), Observabilidad en Kernel con eBPF y Remediación Defensiva
### Enfoque Purple Team para Aplicaciones Cloud-Native

**Expositor(es):** Equipo de Investigación Purple Team
**Duración:** 120 minutos (Exposición + Live Demo al final)
**Audiencia:** Ingenieros de Software, Arquitectos Cloud, Investigadores en Ciberseguridad

---

## 🗺️ Agenda del Workshop (120 min)

1. **Fundamentos y la Persistencia de CWE-89** (20 min)
   * Anatomía del ataque, alteración del Árbol Sintáctico (AST) y limitaciones de WAFs.
2. **El Paradigma Purple Team & eBPF** (20 min)
   * Ruptura del enfoque reactivo: Observabilidad en Capa 0 (Kernel) vs Capa 7 (HTTP).
3. **Arquitectura e Ingeniería del Escáner en Go** (15 min)
   * Concurrencia sin DoS: Worker Pools, Goroutines, Canales y Guardrails éticos.
4. **Defensa en Profundidad y Remediación** (15 min)
   * Protocolo binario de MySQL, Prepared Statements y políticas de Tetragon.
5. **GRAN FINAL: Demostración en Vivo con la App** (35 min)
   * Sandbox Vulnerable vs Sandbox Reparado vs Entorno Externo.
6. **Conclusiones, DevSecOps y Q&A** (15 min)

---

## Slide 01: La Realidad de CWE-89 tras 25 años

### ¿Por qué seguimos hablando de SQL Injection en 2026?
* **OWASP Top 10:** Permanece consistentemente en la categoría *A03:2021 - Injection*.
* **La Causa Raíz:** Mezcla del **canal de control** (comandos SQL) con el **canal de datos** (entrada no confiable).
* **Impacto Típico:**
  * Evasión completa de autenticación (`admin' --`).
  * Extracción masiva de datos mediante `UNION`.
  * Ejecución remota de comandos en motores con extensiones habilitadas (`xp_cmdshell`, `sys_eval`).

> *"El problema nunca ha sido el lenguaje SQL; el problema es que el compilador del motor interpreta la entrada del usuario como instrucciones sintácticas."*

<div class="speaker-note">
<strong>Guion del Ponente (Qué decir):</strong> Iniciar dando la bienvenida a TICEC 2026. Preguntar a la sala cuántos han visto un SQLi en producción. Explicar que a pesar de los frameworks modernos (ORMs), las concatenaciones dinámicas para reportes o filtros ad-hoc siguen creando brechas multimillonarias.
</div>

---

## Slide 02: Anatomía de la Alteración del AST (Abstract Syntax Tree)

### Cómo el motor relacional procesa la consulta:

```
[ Consulta Original ]
SELECT * FROM products WHERE id = [INPUT] AND is_active = TRUE;

[ Entrada Maliciosa ]
INPUT: 1 OR 1=1

[ Consulta Resultante ]
SELECT * FROM products WHERE id = 1 OR 1=1 AND is_active = TRUE;
```

* **Operador de Mayor Precedencia:** `AND` tiene mayor precedencia que `OR`.
* **Evaluación Booleana:**
  `(id = 1) OR (1=1 AND is_active = TRUE)`
  Como `1=1` siempre es verdadero para cada fila, **la condición WHERE se evalúa a TRUE para toda la tabla**.

<div class="speaker-note">
<strong>Guion del Ponente:</strong> Explicar el concepto de Abstract Syntax Tree (AST). Mostrar que el analizador léxico de MySQL no sabe qué parte escribió el desarrollador y qué parte envió el atacante; para el motor todo es un solo bloque de código.
</div>

---

## Slide 03: Tipologías de SQLi y Vectores de Explotación

| Tipo de SQLi | Mecanismo | Huella de Detección |
|---|---|---|
| **In-Band (Clásica)** | La misma conexión devuelve el dato (e.g., `UNION SELECT`). | Diferencial de longitud y registros en respuesta HTTP. |
| **Error-Based** | Provoca conversiones forzadas (e.g., `XPATH syntax error`). | Strings de error en el cuerpo (`SQL syntax`, `ORA-01756`). |
| **Blind (Booleana)** | No hay error visible; se infiere por verdadero/falso. | La página cambia sutilmente de tamaño o estado. |
| **Blind (Time-Based)** | Inyección de retardos (`SLEEP(5)`, `pg_sleep`). | Latencia de socket inusualmente alta (> 5000 ms). |

*En este workshop nos enfocamos en **Boolean-Based Blind** y **In-Band UNION Extraction** por ser los vectores más representativos.*

<div class="speaker-note">
<strong>Guion del Ponente:</strong> Resaltar la dificultad de detectar ataques a ciegas (Blind SQLi). Un WAF normal a menudo no ve diferencias porque la respuesta sigue siendo un HTTP 200 con contenido HTML casi idéntico.
</div>

---

## Slide 04: La Falacia de la Seguridad en el Borde (WAF Tradicional)

### ¿Por qué los WAFs tradicionales fallan ante un atacante persistente?

* **Evasión por Codificación (Encoding bypasses):**
  * URL Encoding anidado (`%2527`).
  * Comentarios en línea (`SEL/*comment*/ECT`).
  * Variaciones de charset (UTF-8 overlong sequences).
* **Inspección de Capa 7 Aislada:**
  * El WAF no tiene visibilidad de cómo el compilador de base de datos interpretará la cadena final.
* **Costo de Mantenimiento:**
  * Listas de expresiones regulares kilométricas que generan falsos positivos y rompen aplicaciones legítimas.

<div class="speaker-note">
<strong>Guion del Ponente:</strong> Aclarar que no estamos diciendo que los WAFs sean inútiles, sino que son insuficientes por sí solos. Depender únicamente de un WAF es como poner un candado blindado en una puerta de cartón.
</div>

---

## Slide 05: El Enfoque Purple Team: Fusión de Ataque y Defensa

```
┌────────────────────────┐         ┌────────────────────────┐
│        RED TEAM        │         │       BLUE TEAM        │
│   (Fuerza Ofensiva)    │         │   (Fuerza Defensiva)   │
│  - Descubrimiento      │         │  - Validación Dual     │
│  - Sondas de Inyección │ ──────> │  - Sensor de Kernel    │
│  - Medición de Fuga    │         │  - Parcheo en Código   │
└────────────────────────┘         └────────────────────────┘
                    ▲                   │
                    └──── FEEDBACK ─────┘
                    (Mejora Continua)
```

* **Objetivo Purple Team:** No basta con saber que el sistema es vulnerable; se audita **cómo el sistema defiende, observa y reacciona** en tiempo real.

<div class="speaker-note">
<strong>Guion del Ponente:</strong> Presentar el concepto del workshop. Nuestro proyecto no es una herramienta de ataque (como sqlmap puro) ni un simple escáner estático (SAST). Es un laboratorio interactivo Purple Team.
</div>

---

## Slide 06: La Nueva Frontera: Observabilidad en Kernel con eBPF

### ¿Qué es eBPF (extended Berkeley Packet Filter)?
* Tecnología del Kernel de Linux que permite ejecutar programas seguros en el espacio del Kernel sin modificar el código fuente del sistema ni cargar módulos inestables (`kmods`).
* **Kprobes (Kernel Probes):** Permite enganchar funciones del sistema operativo:
  * `sys_enter_write`: Intercepta escrituras de buffers en descriptores de archivos y sockets.
  * `sys_enter_connect`: Monitorea aperturas de sesiones hacia bases de datos.

### ¿Por qué es revolucionario para bases de datos?
* **Cero Impacto en el Driver:** No requiere habilitar el lento *General Query Log* de MySQL.
* **Inviolable por el Atacante:** Aunque el atacante engañe al WAF en HTTP, **el texto final decodificado debe enviarse obligatoriamente por el socket al motor de base de datos**.

<div class="speaker-note">
<strong>Guion del Ponente:</strong> Explicar a los académicos que eBPF es uno de los campos de investigación más activos en Linux Foundation y Cloud Native Computing Foundation (CNCF). El Kernel no miente.
</div>

---

## Slide 07: Comparación Arquitectónica: HTTP vs eBPF

```
ATACANTE ──> [ HTTP Request: GET /products?id=1%20OR%201=1 ]
                   │
                   ▼ (Capa 7: El WAF ve texto posiblemente ofuscado)
             [ Servidor Web (Go / PHP / Python) ]
                   │
                   ▼  sys_enter_write (Socket fd hacia MySQL :3306)
             ══════════════════════════════════════════════════════
             KERNEL DE LINUX (Espacio de Observabilidad eBPF)
             Intercepta el buffer exacto:
             "SELECT id, name FROM products WHERE id = 1 OR 1=1"
             ══════════════════════════════════════════════════════
                   │
                   ▼
             [ Motor MySQL (Ejecución del Query) ]
```

<div class="speaker-note">
<strong>Guion del Ponente:</strong> Resaltar este diagrama. Esta es la esencia de nuestra "Validación Dual": comparamos la respuesta en Capa 7 (lo que vio el cliente) con la llamada en Capa 0 (lo que el Kernel escribió en el socket del puerto 3306).
</div>

---

## Slide 08: Sensores en Runtime con Cilium Tetragon

### De la Observabilidad a la Contención Activa
* **Cilium Tetragon:** Operador de seguridad en tiempo de ejecución para Linux/Kubernetes.
* **Capacidad de Bloqueo Inmediato:** Mediante un *TracingPolicy*, el Kernel no solo registra la violación; puede enviar una señal `Sigkill` al hilo o contenedor que emitió la consulta anómala.

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "block-sqli-runtime"
spec:
  kprobes:
    - call: "sys_enter_write"
      syscall: true
      selectors:
        - matchArgs:
            - index: 1
              operator: "Prefix"
              values: ["SELECT * FROM workshop_users", "1 OR 1=1"]
          matchActions:
            - action: Sigkill
```

<div class="speaker-note">
<strong>Guion del Ponente:</strong> Explicar el snippet YAML. Si una consulta contiene el patrón prohibido, Tetragon interrumpe el syscall antes de que el motor de base de datos termine de procesarlo.
</div>

---

## Slide 09: Arquitectura de Nuestro Escáner Purple Team

### Sistema Modular Basado en Microservicios Contenerizados:

```
[ Frontend React (SPA :3000) ]
        │  REST API
        ▼
[ Backend Go (:8080) ] ── (Worker Pool / Canales de Concurrencia)
   ├── Policy Engine      --> Valida lista blanca (Sandbox o Testphp)
   ├── Crawler Discovery  --> Mapea endpoints y formularios
   ├── Probes Engine      --> Ejecuta sondas booleanas y de extracción
   └── Dual Confirmation  --> Correlaciona HTTP + Kernel
        │
   ├── [ Scanner DB (MySQL) ]  --> Guarda scans, eventos y reportes
   └── [ Targets de Laboratorio ]
        ├── vulnerable-app (:8081) ──> lab-db (MySQL :3306)
        └── secure-app (:8081)     ──> lab-db (MySQL :3306)
```

<div class="speaker-note">
<strong>Guion del Ponente:</strong> Explicar la separación de responsabilidades. Todo el stack corre en Docker Compose en redes privadas aisladas (`scanner_net`, `lab_net`, `public_net`).
</div>

---

## Slide 10: Ingeniería Concurrente en Go (Worker Pool)

### ¿Por qué no lanzar 1000 goroutines simultáneas?
* **Riesgo:** Un escáner sin control de flujo se convierte en un ataque de **Denegación de Servicio (DoS)** involuntario contra el servidor auditado.
* **Nuestra Solución:** Patrón *Worker Pool* con canales con buffer y `sync.WaitGroup`:

```go
jobs := make(chan models.ScanTask, len(tasks))
var wg sync.WaitGroup

// Limitado a un número controlado de workers (e.g. 5)
for w := 1; w <= maxWorkers; w++ {
    wg.Add(1)
    go func() {
        defer wg.Done()
        for task := range jobs {
            executeTask(task, ...)
        }
    }()
}
```

<div class="speaker-note">
<strong>Guion del Ponente:</strong> Resaltar la eficiencia de Go para herramientas de seguridad. Mínimo consumo de RAM (apenas 20 MB para todo el backend) y control estricto de concurrencia.
</div>

---

## Slide 11: Seguridad por Diseño: El Módulo de Políticas

### Prevención de Uso Malicioso (Anti-SSRF & Guardrails)
* Los escáneres de seguridad no deben ser convertidos en armas de ataque contra terceros.
* **[policy/targets.go]:**
  * Solo permite destinos internos (`vulnerable-app`, `secure-app`).
  * Destinos externos requieren **autorización explícita** (`authorization_confirmed: true`) y pertenecer a dominios académicos/de prueba permitidos (`testphp.vulnweb.com`).
  * Previene ataques de *Server-Side Request Forgery (SSRF)* contra metadatos de Cloud (`169.254.169.254`) o redes privadas del congreso.

<div class="speaker-note">
<strong>Guion del Ponente:</strong> Fundamental para la ética académica de TICEC. Demostramos cómo construir herramientas de seguridad con salvaguardas que impiden abusos ilegales.
</div>

---

## Slide 12: Remediación en la Raíz: Consultas Parametrizadas

### ¿Por qué las Consultas Preparadas (Prepared Statements) son 100% efectivas?

* **Fase 1: Preparación (Prepare):**
  El cliente envía la plantilla SQL al motor:
  `SELECT id, name FROM products WHERE id = ? AND is_active = TRUE;`
  El motor **compila el AST** y determina que `?` solo puede ser un valor escalar.
* **Fase 2: Ejecución (Execute):**
  El parámetro `1 OR 1=1` se envía por el protocolo binario.
  El motor busca productos cuyo campo `id` sea exactamente la cadena literal `"1 OR 1=1"`.
  **Es imposible que el dato altere la estructura del árbol compilado.**

<div class="speaker-note">
<strong>Guion del Ponente:</strong> Hacer una pausa dramática aquí. Preguntar: "¿Por qué un prepared statement no se puede inyectar?" Explicar la separación física de la fase de compilación y la fase de paso de parámetros.
</div>

---

## Slide 13: Comparativa de Código: Inseguro vs Seguro en Go

### Enfoque Vulnerable:
```go
// ❌ Concatenación directa: Rompe el AST
query := "SELECT id, name, price FROM products WHERE id = " + productID
rows, err := db.QueryContext(ctx, query)
```

### Enfoque Remediado:
```go
// ✅ Validación de tipo estricta + Parámetro posicional
id, err := strconv.ParseUint(productID, 10, 64)
if err != nil {
    return ErrParametroInvalido
}
query := "SELECT id, name, price FROM products WHERE id = ? AND is_active = TRUE"
rows, err := db.QueryContext(ctx, query, id)
```

<div class="speaker-note">
<strong>Guion del Ponente:</strong> Destacar la doble defensa: 1) Validar el tipo antes de tocar la BD (`strconv.ParseUint`); 2) Usar siempre `?` para el enlace de parámetros.
</div>

---

## Slide 14: Comparativa de Código: PHP y Python

### PHP (PDO):
```php
// ❌ Concatenación:
$sql = "SELECT id, name FROM products WHERE id = " . $_GET['id'];

// ✅ PDO con Parámetro Nombrado:
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
$stmt = $pdo->prepare('SELECT id, name FROM products WHERE id = :id AND is_active = 1');
$stmt->execute(['id' => $id]);
```

### Python (DB-API):
```python
# ❌ f-strings vulnerables:
query = f"SELECT id, name FROM products WHERE id = {user_input}"

# ✅ Parámetros como tupla independiente:
query = "SELECT id, name FROM products WHERE id = %s AND is_active = %s"
cursor.execute(query, (int(user_input), True))
```

<div class="speaker-note">
<strong>Guion del Ponente:</strong> Mostrar que el concepto es universal. Da igual si programas en Go, PHP, Java o Python: la regla de oro es nunca interpolar variables en cadenas SQL.
</div>

---

## Slide 15: Introducción a la Demostración en Vivo

### Lo que veremos en la Aplicación Purple Team:

1. **Escenario A: La Brecha (Sandbox Vulnerable)**
   * Inyección de payload booleano (`1 OR 1=1`) y extracción UNION.
   * Telemetría en vivo del worker pool.
   * Alerta roja: Evidencia de Capa 7 + Intercepción de Kernel Capa 0 + Fuga de usuarios.
2. **Escenario B: La Resiliencia (Sandbox Reparado)**
   * Mismos payloads atacando la aplicación con *Prepared Statements*.
   * Alerta verde: 0 hallazgos, sistema resiliente, confirmación de falso positivo evitado.
3. **Escenario C: Auditoría Externa Controlada**
   * Descubrimiento dinámico de parámetros en entorno real (`testphp.vulnweb.com`).

---

## Slide 16: ¡PASE A LA DEMOSTRACIÓN EN VIVO!

```
══════════════════════════════════════════════════════════════════════
               DEMOSTRACIÓN INTERACTIVA EN TIEMPO REAL
               Dashboard Purple Team: http://localhost:3000
══════════════════════════════════════════════════════════════════════
```

*(En este momento, el expositor cambia a la pantalla del navegador y terminales).*

---

## Slide 17: Resumen Post-Demo: Lecciones del Laboratorio

1. **La telemetría de Kernel elimina la incertidumbre:**
   * No tuvimos que adivinar qué pasó; el sensor interceptó la query cruda en el socket 3306.
2. **Las consultas preparadas no reducen el rendimiento:**
   * De hecho, al reusar el plan de ejecución precompilado en el motor SQL, son más rápidas que las consultas dinámicas.
3. **Validación Dual = Cero Falsos Positivos:**
   * La correlación entre la respuesta HTTP y el trace de Kernel permite a los equipos de seguridad certificar sin dudas si una vulnerabilidad es explotable o no.

<div class="speaker-note">
<strong>Guion del Ponente:</strong> Regresar a las diapositivas tras la demo en vivo. Recapitular lo que todos acaban de presenciar en pantalla.
</div>

---

## Slide 18: Integración DevSecOps: Shift-Left Security

### Cómo incorporar este enfoque en el ciclo de vida:

```
[ Código en Git ]
       │
       ▼ (Pull Request)
[ Pipeline CI/CD (GitHub Actions / GitLab CI) ]
       ├── 1. SAST (Análisis estático de código buscando concatenaciones)
       ├── 2. Build de Contenedores Efímeros (Docker Compose)
       ├── 3. DAST Purple Team Scanner (Ejecuta sondas automáticas)
       └── 4. Quality Gate: Bloquea el merge si hay findings > CRITICAL
       │
       ▼ (Aprobado)
[ Despliegue en Kubernetes con Políticas eBPF (Tetragon) ]
```

<div class="speaker-note">
<strong>Guion del Ponente:</strong> Vincular el proyecto con la industria y la ingeniería de software actual. Mostrar cómo este escáner puede ejecutarse en modo headless dentro de un pipeline de integración continua.
</div>

---

## Slide 19: Conclusiones

* **1. CWE-89 es una falla de diseño, no de complejidad:** Se soluciona separando el código del dato mediante el protocolo de sentencias preparadas.
* **2. eBPF redefine la ciberseguridad defensiva:** La visibilidad en el espacio del Kernel permite detectar y mitigar ataques en tiempo de ejecución sin sobrecargar las aplicaciones.
* **3. El enfoque Purple Team acelera la remediación:** Cuando el desarrollador ve exactamente cómo se alteró su consulta y recibe el parche en su lenguaje, el tiempo de remediación (MTTR) cae a minutos.

---

## Slide 20: Preguntas y Discusión Abierta

### ¡Muchas Gracias!

* **Repositorio del Proyecto:** `github.com/LeirBaGMC/SQLi-And-Recon-Tool`
* **Tecnologías Utilizadas:** Go 1.22, React 19, Docker Compose, MySQL 8, eBPF/Tetragon architecture.
* **Contacto:** [Tus datos / Redes académicas / Email]

```
                       ESPACIO PARA PREGUNTAS (Q&A)
                  ¿Dudas, comentarios o retroalimentación?
```
