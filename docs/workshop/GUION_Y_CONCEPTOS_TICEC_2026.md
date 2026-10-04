# TICEC 2026 · GUÍA MAESTRA, COMPENDIO CONCEPTUAL Y GUION DEL PONENTE

**Título del Workshop:**  
*Más allá del WAF: Detección de Inyección SQL (CWE-89), Observabilidad en Kernel con eBPF y Remediación Defensiva (Enfoque Purple Team para Aplicaciones Cloud-Native)*

**Duración:** 120 Minutos  
**Congreso:** TICEC 2026 (Tecnologías de la Información y Comunicación en Ecuador)  
**Audiencia:** Investigadores en Computación, Ingenieros de Software, Arquitectos Cloud, Profesionales de Ciberseguridad.

---

# 📚 SECCIÓN I: COMPENDIO CONCEPTUAL PROFUNDO

Esta sección desglosa minuciosamente los cuatro pilares tecnológicos solicitados, explicados con precisión académica y analogías intuitivas para que domines cada concepto ante cualquier pregunta del jurado.

---

## 1. AST (Abstract Syntax Tree / Árbol Sintáctico Abstracto)

### ¿Qué es exactamente?
Un **AST** es una representación jerárquica en forma de árbol de la estructura gramatical de un programa o consulta SQL. Es el resultado del proceso de compilación tras pasar por dos fases:
1. **Análisis Léxico (Lexer / Tokenizer):** Convierte una cadena de caracteres brutos en una secuencia de fichas léxicas o *tokens* (ej. `SELECT`, `FROM`, identificadores, operadores lógicos).
2. **Análisis Sintáctico (Parser):** Aplica la gramática formal del lenguaje (BNF de SQL-92/2016) para verificar si la secuencia de tokens tiene sentido lógico y genera el árbol sintáctico.

```
                  Pipeline del Motor Relacional (MySQL / PostgreSQL):
Cadena SQL ──> [ Lexer ] ──> Tokens ──> [ Parser ] ──> [ AST ] ──> [ Optimizador ] ──> Plan de Ejecución
```

### ¿Cómo altera SQL Injection la topología del AST?
El motor de base de datos **no ejecuta texto plano; ejecuta el árbol generado por el parser**.

#### Caso A: Consulta Legítima
```sql
SELECT * FROM products WHERE id = 1 AND is_active = TRUE;
```
* **Topología del AST:**
  * Nodo Raíz: `SELECT`
  * Cláusula: `WHERE`
  * Operador Lógico Raíz: `AND`
    * Hijo Izquierdo: Condición de Igualdad `(id == 1)`
    * Hijo Derecho: Condición Booleana `(is_active == TRUE)`

Ambas condiciones deben cumplirse estrictamente para devolver una fila.

#### Caso B: Inyección Booleana (`INPUT = 1 OR 1=1`)
Cuando el programador concatena texto (`WHERE id = ` + input), el texto inyectado **pasa por el Lexer y el Parser como si fueran palabras clave del lenguaje**:
```sql
SELECT * FROM products WHERE id = 1 OR 1=1 AND is_active = TRUE;
```

* **El Conflicto de Precedencia de Operadores:**
  En el estándar ANSI SQL, el operador lógico `AND` tiene mayor precedencia que `OR` (similar a la multiplicación frente a la suma en aritmética: $A + B \times C$).
  
* **Mutación del Árbol:**
  El compilador agrupa la consulta así:
  $$\text{WHERE } (\text{id} = 1) \lor (1 = 1 \land \text{is\_active} = \text{TRUE})$$

  Como $1 = 1$ es una **tautología absoluta** (siempre es verdadera para cada tupla evaluada), la rama derecha siempre evalúa a `TRUE` para registros activos, y la cláusula `OR` hace que toda la condición general sea verdadera para cualquier fila donde $id=1$ o donde la fila esté activa.

> 💡 **La Lección para el Congreso:**  
> *"El ataque no hackea la base de datos; engaña al compilador haciéndole reescribir la forma del árbol antes de que el motor genere el plan de ejecución."*

---

## 2. WAFs (Web Application Firewalls) y sus Limitaciones

### ¿Qué es un WAF?
Un **WAF** es un dispositivo de seguridad perimetral que opera en la **Capa 7 del modelo OSI (Capa de Aplicación)**. Inspecciona las peticiones HTTP/HTTPS que viajan hacia los servidores web, buscando patrones de ataque predefinidos mediante firmas y expresiones regulares (Regex).

### ¿Por qué fallan sistemáticamente ante atacantes avanzados?
Un WAF tradicional sufre de lo que en ciencias de la computación llamamos **Impedancia Semántica (Semantic Mismatch)**:
> El WAF analiza **texto plano en tránsito**, pero la base de datos ejecuta **árboles compilados tras múltiples capas de decodificación**.

#### 1. Evasión por Múltiples Capas de Codificación (Nested Encodings)
Si una aplicación pasa por un proxy reverso (Nginx) y luego al backend (Go):
* Atacante envía: `%2527` (Doble URL Encoding de la comilla simple `'`).
* El WAF de borde ve `%2527`, no ve comillas obvias y **deja pasar la petición**.
* Nginx decodifica `%2527` a `%27`.
* El framework en Go decodifica `%27` al caracter ASCII `'`.
* La comilla llega limpia a MySQL y rompe la consulta.

#### 2. Evasión por Comentarios y Tokens Nulos
El estándar SQL permite comentarios en línea:
```sql
UNI/**/ON/*random_comment*/SEL/**/ECT 1,username,password FROM users
```
Un WAF con expresiones regulares simples que busque la secuencia `UNION SELECT` no encontrará coincidencia porque hay caracteres interpuestos, pero el lexer de MySQL simplemente descarta los comentarios como espacios en blanco.

#### 3. Ceguera de Contexto
El WAF no sabe si la base de datos detrás del servidor es MySQL 8, PostgreSQL 16, Oracle o SQLite. Cada motor tiene funciones propietarias (`SLEEP()`, `pg_sleep()`, `DBMS_LOCK.SLEEP()`, `WAITFOR DELAY`). Para cubrir todas las combinaciones posibles, el WAF necesitaría miles de reglas que terminarían causando **falsos positivos** (bloqueando usuarios legítimos que escriben palabras comunes como "union", "order" o "select" en un blog o buscador).

---

## 3. Concurrencia en Go: Worker Pool con Canales y Goroutines

### Goroutines vs Hilos del Sistema Operativo
* **Hilo del Sistema Operativo (OS Thread):** Administrado por el kernel de Linux. Cada hilo reserva entre **1 MB y 8 MB de memoria virtual** para su pila (stack). Cambiar de un hilo a otro (Context Switch) requiere cambiar de modo usuario a modo kernel en la CPU, lo cual es costoso (cientos de ciclos de reloj).
* **Goroutine:** Administrada en espacio de usuario por el **Go Runtime Scheduler** (el modelo $M:N$, donde $M$ goroutines son multiplexadas sobre $N$ hilos del kernel).
  * Una goroutine inicia con apenas **2 KB de memoria**.
  * El cambio de contexto ocurre en modo usuario en apenas una fracción de tiempo.
  * Se pueden levantar decenas de miles de goroutines simultáneamente en un portátil modesto.

### El Peligro del Escaneo Ingenuo
Si un programador novato hace esto en un escáner de seguridad:
```go
for _, task := range tasks {
    go executeProbe(task) // ❌ Peligro: Concurrencia descontrolada
}
```
Si la lista contiene 1,000 tareas, Go lanzará 1,000 conexiones HTTP en el mismo milisegundo. Esto saturará el pool de conexiones de red del servidor auditado, agotará los descriptores de archivo (*file descriptors*) y tumbará el servicio. **El escáner cometería un ataque de Denegación de Servicio (DoS) involuntario.**

### La Solución de Ingeniería: El Patrón Worker Pool
En nuestro proyecto (`backend/scanner/engine.go`), implementamos un **Worker Pool con canales amortiguados (buffered channels)** y sincronización:

```
[ Tareas en Cola ] ──> [ Canal: chan models.ScanTask (Buffer) ]
                               │
            ┌──────────────────┼──────────────────┐
            ▼                  ▼                  ▼
     [ Worker 1 (go) ]  [ Worker 2 (go) ]  [ Worker 3 (go) ]   <── Máximo controlado (e.g. 5 workers)
            │                  │                  │
            └──────────────────┼──────────────────┘
                               ▼
               [ Barrera: sync.WaitGroup ] ──> Termina el análisis
```

#### Elementos clave en el código:
1. `jobs := make(chan models.ScanTask, len(tasks))`: Un canal es una estructura de datos segura para concurrencia (*Thread-Safe Queue*) basada en paso de mensajes.
2. `for w := 1; w <= workerCount; w++`: Limitamos el número de workers activos a un número seguro (por ejemplo 5).
3. `wg.Add(1)` y `defer wg.Done()`: `sync.WaitGroup` actúa como un contador de referencias. `wg.Wait()` bloquea el hilo orquestador hasta que todos los workers hayan terminado de vaciar la cola.
4. `errMu sync.Mutex`: Si dos workers detectan un error simultáneamente, un cerrojo de exclusión mutua (`Mutex`) evita **condiciones de carrera (Race Conditions)** al escribir en la lista de errores.

---

## 4. eBPF y Cilium Tetragon (Explicación a Fondo de Capa 0)

Este es el concepto más innovador del proyecto y el que causará mayor impacto ante el comité técnico.

### ¿Qué es eBPF (extended Berkeley Packet Filter)?
Tradicionalmente, para observar o interceptar lo que hace el sistema operativo, los ingenieros tenían dos opciones malas:
1. **Modificar el código fuente del Kernel de Linux:** Imposible para empresas comerciales, requiere años de aprobación en la comunidad Linux.
2. **Escribir un Módulo de Kernel (`kmod` / LKM):** Peligroso. Si un módulo de kernel tiene un puntero nulo o un desbordamiento de memoria, provoca un **Kernel Panic** y congela toda la máquina física o servidor en producción.

**eBPF resuelve esto de forma revolucionaria:**
Es una **máquina virtual segura JIT (Just-In-Time) compilada que corre dentro del propio Kernel de Linux**.
* **El Verificador de Kernel (In-Kernel Verifier):** Antes de que un programa eBPF se ejecute, el kernel lo somete a una prueba estricta:
  * Comprueba que no tenga bucles infinitos.
  * Comprueba que nunca desreferencie memoria fuera de sus límites.
  * Comprueba que siempre termine su ejecución.
  Si el programa no pasa la prueba matemática, el Kernel **se niega a cargarlo**. Es 100% inmune a colapsar el sistema.

### Kprobes (Kernel Probes) y Syscalls
Cuando un servidor web (escrito en Go, PHP o Python) quiere hablar con MySQL, no puede enviar electricidad al cable de red por sí mismo; debe pedirle permiso al sistema operativo mediante una **Llamada al Sistema (System Call o Syscall)**.

* La función estándar de Linux para enviar datos por un socket TCP es **`sys_enter_write`** (o `sys_write`).
* Sus argumentos a bajo nivel en la arquitectura x86_64 son:
  * Registro `RDI` (Argumento 0): El File Descriptor (`fd`), un número entero que identifica el socket conectado al puerto 3306.
  * Registro `RSI` (Argumento 1): El puntero al búfer en memoria (`char_buf`) con el texto exacto que viajará por la red.

```
+─────────────────────────────────────────────────────────────+
| ESPACIO DE USUARIO (User Space)                             |
| Aplicación Web (Go/PHP) concatena:                          |
| "SELECT * FROM products WHERE id = " + "1 OR 1=1"           |
|                                                             |
| Llama a: write(socket_fd, "SELECT ... WHERE id = 1 OR 1=1") |
+──────────────────────────────┬──────────────────────────────+
                               │ Syscall Trap
+──────────────────────────────▼──────────────────────────────+
| ESPACIO DE KERNEL (Kernel Space)                            |
|                                                             |
| [ Hook Kprobe: sys_enter_write ] <── Sensor eBPF Intercepta |
|   ├── Lee argumento 0 (fd -> Socket lab-db:3306)           |
|   └── Lee argumento 1 (Buffer con la inyección desnudada)   |
|                                                             |
| ¿Coincide con política de ataque?                           |
|   ├── SÍ ──> ¡Dispara SIGKILL! (Proceso muerto en el acto)  |
|   └── NO ──> Permite que viaje por la tarjeta de red        |
+──────────────────────────────┬──────────────────────────────+
                               │ TCP Packet
+──────────────────────────────▼──────────────────────────────+
| Motor MySQL 8.0 (lab-db:3306)                               |
+─────────────────────────────────────────────────────────────+
```

### ¿Por qué el Kernel nunca miente?
En Capa 7 (HTTP), el atacante puede usar cifrado TLS, saltos de proxies reversos, encoding en base64 o trucos de cabeceras. Pero **para que la base de datos entienda la consulta, el servidor web tiene que traducirla a texto SQL claro antes de mandarla al socket de MySQL**.  
Por eso la intercepción en `sys_enter_write` es la fuente de verdad definitiva: intercepta la consulta en el último milímetro antes de entrar al cable de red.

### Cilium Tetragon: De la Observabilidad a la Contención Activa
**Cilium Tetragon** es una herramienta de código abierto desarrollada por Isovalent / CNCF (Cloud Native Computing Foundation). Utiliza eBPF para aplicar seguridad en tiempo de ejecución en clústeres de Kubernetes y servidores Linux.

Miremos la política que genera nuestro sistema:
```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "block-sqli-runtime"
spec:
  kprobes:
    - call: "sys_enter_write"
      syscall: true
      args:
        - index: 0
          type: "int"      # Descriptor de archivo del socket
        - index: 1
          type: "char_buf" # Texto que va hacia MySQL
      selectors:
        - matchArgs:
            - index: 1
              operator: "Prefix"
              values:
                - "SELECT * FROM workshop_users"
                - "1 OR 1=1"
          matchActions:
            - action: Sigkill
```

#### ¿Qué hace `action: Sigkill`?
En el momento exacto en que el sensor eBPF lee el búfer y detecta la firma prohibited (`1 OR 1=1`), Tetragon no se limita a escribir una alerta en un archivo de log: **envía una señal de terminación forzada e inmediata (`SIGKILL`) al hilo o contenedor infractor**.  
La conexión TCP se rompe de forma instantánea. La consulta maliciosa jamás llega a completarse en la base de datos.

---

# 🎙️ SECCIÓN II: GUION Y DIÁLOGO DEL PONENTE (SLIDE POR SLIDE)

Usa este guion en tu presentación. Está sincronizado exactamente con las **19 diapositivas visuales** de [slides.html](file:///c:/Users/Pandora/Desktop/SQL/docs/workshop/slides.html).

---

### 🟢 Slide 0: Portada
*(Muestra el título principal con la estética oscura y los metadatos de TICEC 2026).*

**Tu Diálogo:**
> *"Muy buenos días con todos los presentes, distinguidos miembros del comité técnico de TICEC 2026, colegas docentes, investigadores y estudiantes.  
> Es un verdadero placer estar con ustedes en este congreso.  
> Hoy presentamos el workshop técnico titulado: **Más allá del WAF: Detección de Inyección SQL, Observabilidad en Kernel con eBPF y Remediación Defensiva**.  
> Durante las próximas dos horas vamos a abordar una de las vulnerabilidades más antiguas y a la vez más persistentes de la ingeniería de software: CWE-89. Pero no lo haremos desde una perspectiva teórica tradicional. Demostraremos cómo romper el aislamiento entre el Red Team y el Blue Team implementando un enfoque Purple Team: observaremos el flujo de consultas directamente en el Kernel de Linux mediante eBPF, analizaremos un motor concurrente en Go con Worker Pools, y cerraremos con una demostración interactiva en vivo ejecutada sobre contenedores Docker."*

---

### 🟢 Slide 1: Ruta del Workshop (120 Minutos)
*(Muestra el stepper horizontal dividido en 4 fases de tiempo).*

**Tu Diálogo:**
> *"Para garantizar una experiencia dinámica y estructurada, el taller se desarrollará en cuatro bloques:  
> En los primeros 25 minutos exploraremos los fundamentos de gramática de compiladores: qué es el AST (Abstract Syntax Tree) y por qué los WAFs de Capa 7 fallan ante atacantes persistentes.  
> Los siguientes 25 minutos los dedicaremos a la ingeniería del escáner en Go: diseño concurrente sin riesgo de denegación de servicio mediante canales y goroutines.  
> En el tercer bloque de 20 minutos entraremos a la innovación en el sistema operativo: observabilidad con eBPF y contención con Cilium Tetragon.  
> Y dejaremos los últimos 50 minutos para lo más emocionante: la demostración práctica en vivo contra sandboxes reales y la sesión abierta de preguntas y debate."*

---

### 🟢 Slide 2: La Confusión de Canales (CWE-89)
*(Muestra el diagrama de flujo donde el canal de datos y el de control se fusionan).*

**Tu Diálogo:**
> *"Empecemos haciéndonos una pregunta obligada: ¿Por qué seguimos hablando de SQL Injection en pleno 2026?  
> La razón técnica no radica en que SQL sea un lenguaje defectuoso. La causa raíz es lo que en arquitectura de software llamamos **Confusión de Canales**.  
> Como pueden apreciar en el diagrama, una aplicación vulnerable toma dos flujos de información completamente distintos: por un lado, el **canal de control**, que son las palabras clave sintácticas escritas por el desarrollador (`SELECT`, `FROM`, `WHERE`); y por otro lado, el **canal de datos**, que es la entrada no confiable que proviene del usuario en el navegador.  
> Cuando el servidor web comete el error de concatenar ambos canales con un simple operador de suma, el analizador léxico del motor relacional es incapaz de distinguirlos. Para el motor, todo el texto plano es código ejecutable. El dato contamina el control."*

---

### 🟢 Slide 3: Anatomía de la Alteración del AST
*(Muestra el árbol sintáctico con la bifurcación del operador AND y OR en colores).*

**Tu Diálogo:**
> *"Profundicemos en qué le pasa al motor de base de datos internamente.  
> Toda base de datos relacional compila la consulta construyendo un **AST: Abstract Syntax Tree**.  
> Miren la consulta original: `WHERE id = [INPUT] AND is_active = TRUE`.  
> Si inyectamos la clásica cadena `1 OR 1=1`, la consulta final se convierte en lo que ven en pantalla.  
> ¿Por qué funciona este ataque? Por una regla fundamental de gramática formal: el operador lógico `AND` tiene mayor precedencia léxica que `OR`.  
> El analizador no evalúa de izquierda a derecha; agrupa `(1=1 AND is_active = TRUE)`.  
> Como `1=1` es una tautología absoluta que jamás puede ser falsa, la rama derecha evalúa a verdadero, y el operador `OR` provoca que toda la cláusula WHERE devuelva `TRUE` para toda la tabla. El motor descarta los índices y entrega todos los registros."*

---

### 🟢 Slide 4: La Falacia de la Seguridad en el Borde (WAF)
*(Muestra el diagrama del atacante evadiendo el WAF y llegando a MySQL).*

**Tu Diálogo:**
> *"Frente a este riesgo, la respuesta tradicional de muchas organizaciones es: 'Contratemos un WAF perimetral'.  
> Lamentablemente, confiar ciegamente en un WAF es una falacia de seguridad.  
> Un WAF inspecciona strings en Capa 7 utilizando reglas estáticas de expresiones regulares. Un atacante experimentado puede evadirlo utilizando técnicas de codificación: doble URL encoding (`%2527`), comentarios SQL interpuestos entre palabras clave como `UNI/**/ON SEL/**/ECT`, o variaciones de conjuntos de caracteres UTF-8.  
> El WAF no ve palabras sospechosas continuas y permite el paso; pero cuando el backend decodifica la cadena, la consulta llega desnuda al motor. En seguridad solemos usar esta analogía: depender únicamente de un WAF perimetral es como colocar un candado blindado de titanio sobre una puerta hecha de cartón."*

---

### 🟢 Slide 5: El Paradigma Purple Team
*(Muestra el diagrama de sinergia entre Red Team y Blue Team con el bucle de feedback).*

**Tu Diálogo:**
> *"Aquí es donde proponemos un cambio de paradigma: el enfoque **Purple Team**.  
> El Red Team ofensivo no debe limitarse a vulnerar y reportar; debe trabajar en sincronía con el Blue Team defensivo.  
> En nuestra plataforma, el Red Team ejecuta el crawler y las sondas de inyección controladas; el Blue Team monitorea los sockets en el Kernel y aplica confirmación dual; y en cuanto se confirma el vector, el sistema genera de inmediato el parche de código seguro y la política de infraestructura.  
> Nuestro objetivo no es romper cosas; es reducir drásticamente el MTTR (Mean Time to Remediation), el tiempo que un equipo tarda en blindar su código."*

---

### 🟢 Slide 6: Observabilidad con eBPF en Kernel
*(Muestra el diagrama de Capa 7 HTTP hacia Capa 0 Kernel con la kprobe en sys_enter_write).*

**Tu Diálogo:**
> *"Para lograr que el Blue Team tenga certeza absoluta sin dejarse engañar por trampas de Capa 7, recurrimos a la tecnología más revolucionaria en el ecosistema Linux actual: **eBPF**.  
> eBPF nos permite ejecutar código seguro verificado directamente dentro del Kernel de Linux sin necesidad de compilar módulos inestables.  
> Colocamos un sensor mediante una kprobe en la llamada al sistema `sys_enter_write`.  
> Miren el diagrama: el atacante puede alterar la petición HTTP o cifrarla; pero para que el servidor web obtenga datos de la base de datos, **está obligado por el protocolo TCP a transmitir la consulta SQL decodificada por el socket hacia el puerto 3306**.  
> Nuestro sensor de eBPF intercepta ese búfer exacto en el espacio del Kernel antes de que la tarjeta de red lo entregue a MySQL. El principio es contundente: **Capa 7 puede ser ofuscada; el Kernel jamás miente**."*

---

### 🟢 Slide 7: Runtime Security con Cilium Tetragon
*(Muestra la política YAML de TracingPolicy y la acción Sigkill).*

**Tu Diálogo:**
> *"Pero no nos quedamos solo en la observabilidad pasiva; avanzamos hacia la **contención activa en tiempo de ejecución**.  
> Utilizando **Cilium Tetragon**, definimos una política de rastreo (`TracingPolicy`) a nivel de clúster de Kubernetes.  
> Como ven en el manifiesto YAML en pantalla, le indicamos al Kernel: 'Monitorea todas las llamadas `sys_enter_write`. Si el búfer transmitido contiene el prefijo `1 OR 1=1` o un intento de exfiltrar la tabla `workshop_users`, ejecuta inmediatamente la acción `Sigkill`'.  
> El Kernel de Linux despacha una señal de terminación sincrónica al proceso antes de que la base de datos termine de procesar el ataque. Es defensa activa en el corazón del sistema operativo."*

---

### 🟢 Slide 8: Arquitectura de Microservicios del Proyecto
*(Muestra la topología de los 6 contenedores Docker y las 3 redes virtuales).*

**Tu Diálogo:**
> *"Pasemos a revisar la arquitectura de ingeniería que sostiene este laboratorio.  
> Todo el entorno corre sobre Docker Compose dividido en 6 contenedores y 3 redes privadas:  
> 1. `public_net`: Donde corre nuestra interfaz SPA en React en el puerto 3000.  
> 2. `scanner_net`: La red privada del motor del escáner en Go (puerto 8080) conectada a su propia base de datos `scanner-db` para persistir auditorías y eventos.  
> 3. `lab_net`: La red de prueba completamente aislada donde residen los dos objetivos (`vulnerable-app` y `secure-app`) conectados a `lab-db`.  
> Esta segregación de red garantiza que los escaneos ocurran en un ambiente controlado sin interferir con la infraestructura host."*

---

### 🟢 Slide 9: Concurrencia con Worker Pool en Go
*(Muestra el canal de tareas con buffer y las goroutines sincronizadas con WaitGroup).*

**Tu Diálogo:**
> *"Hablemos de cómo construimos el motor del escáner en Go.  
> En auditorías de seguridad, un error común es lanzar goroutines sin límite, lo cual provoca denegaciones de servicio accidentales.  
> Para evitarlo, implementamos el patrón **Worker Pool**.  
> Creamos un canal seguro con búfer (`jobs`) que almacena las tareas de prueba. Inicializamos un número estrictamente controlado de workers (por defecto 5 goroutines en paralelo).  
> Cada worker extrae una tarea de la cola, dispara la sonda y se sincroniza mediante un `sync.WaitGroup`. Logramos paralelismo masivo consumiendo apenas 20 MB de memoria RAM."*

---

### 🟢 Slide 10: Las 3 Sondas del Escáner
*(Muestra las tarjetas comparativas: Boolean, UNION y Time-Based).*

**Tu Diálogo:**
> *"Nuestro motor evalúa tres vectores fundamentales de explotación:  
> 1. **Boolean Blind:** Inyecta `1 OR 1=1` y analiza si la respuesta expandió el número de productos visibles en el DOM.  
> 2. **UNION Extraction:** Inyecta un operador `UNION ALL SELECT` para comprobar si es posible exfiltrar registros de usuarios ficticios de la tabla `workshop_users`.  
> 3. **Time-Based Blind (Timelapse):** Inyecta `1 AND SLEEP(2)`. Aquí no analizamos texto; medimos la latencia. Si la petición normal tarda 15 milisegundos y la inyectada supera los 1,800 milisegundos, confirmamos matemáticamente la inyección temporal."*

---

### 🟢 Slide 11: Guardrails Éticos y Anti-SSRF
*(Muestra el flujo de validación de políticas y bloqueos de IPs privadas).*

**Tu Diálogo:**
> *"Un compromiso innegociable en TICEC es la ética en la investigación. ¿Cómo evitamos que nuestro escáner sea utilizado para fines ilícitos?  
> En el archivo `policy/targets.go` implementamos un módulo estricto de salvaguardas:  
> En modo sandbox solo se admiten los destinos internos pre-registrados.  
> En modo externo, se exige confirmación explícita de autorización del propietario, se bloquean todas las direcciones IP numéricas directas para erradicar ataques de Server-Side Request Forgery (SSRF) contra metadatos de Cloud (`169.254.169.254`) o redes locales del congreso, y se limita el escaneo a entornos autorizados como `testphp.vulnweb.com`."*

---

### 🟢 Slide 12: El Mecanismo de los Prepared Statements
*(Muestra la división de dos fases: PREPARE del AST vs EXECUTE binario).*

**Tu Diálogo:**
> *"Llegamos al núcleo de la remediación: ¿Por qué las consultas preparadas erradican el problema al 100%?  
> Porque dividen la operación en dos fases físicas independientes:  
> En la Fase 1 (`PREPARE`), el cliente envía la plantilla: `SELECT ... WHERE id = ?`. El motor MySQL compila el AST y define que el signo `?` es exclusivamente un valor escalar literal.  
> En la Fase 2 (`EXECUTE`), el parámetro viaja mediante el protocolo binario. Aunque el atacante envíe `1 OR 1=1`, MySQL busca productos cuyo identificador sea literalmente esa cadena de texto. El analizador sintáctico no vuelve a ejecutarse; es imposible adulterar la lógica precompilada."*

---

### 🟢 Slide 13: Código Frente a Frente en los Sandboxes
*(Muestra el código inseguro de vulnerable_products.go vs el código seguro de products.go).*

**Tu Diálogo:**
> *"En pantalla tienen el código fuente exacto de nuestros dos objetivos:  
> A la izquierda, `vulnerable-app`: concatena variables directamente en la consulta SQL.  
> A la derecha, `secure-app`: aplica **Defensa en Profundidad**.  
> Primero, ejecuta validación de tipos estricta con `strconv.ParseUint` en memoria; si alguien envía una comilla o letras, Go aborta en 0.2 milisegundos sin tocar la base de datos.  
> Segundo, vincula el parámetro con el placeholder `?`. Doble barrera, resiliencia absoluta."*

---

### 🟢 Slide 14: Plan de la Demostración en Vivo
*(Muestra los 3 escenarios: A Brecha, B Resiliencia, C Web Real).*

**Tu Diálogo:**
> *"Es momento de poner a prueba la teoría frente a la evidencia experimental.  
> En los próximos minutos realizaremos tres pruebas en tiempo real:  
> Primero: Atacaremos `vulnerable-app` para presenciar la alerta roja, la exfiltración y la captura de eBPF.  
> Segundo: Atacaremos `secure-app` con las mismas sondas para demostrar la resiliencia del sistema.  
> Tercero: Ejecutaremos el crawler contra un objetivo web real autorizado."*

---

### 🟢 Slide 15: Pase a la Demostración Práctica
*(Botón interactivo de salto al Dashboard).*

**Tu Diálogo:**
> *(Cambiando a la pestaña del navegador en `http://localhost:3000`)*  
> *"Acompáñenme al dashboard interactivo para presenciar la telemetría en tiempo real."*

---

### 🟢 Slide 16: La Matriz de Confirmación Dual (Al volver de la demo)
*(Muestra la tabla comparativa de evidencias HTTP vs Kernel).*

**Tu Diálogo:**
> *"Como acabamos de observar en la demostración en vivo, la clave técnica de nuestra propuesta es la **Confirmación Dual**.  
> Muchos escáneres generan falsos positivos porque solo miran si el código HTTP cambió. Nosotros correlacionamos el diferencial de Capa 7 con la traza de syscall en Capa 0. Si ambos coinciden, el equipo de seguridad tiene la certeza matemática de que la vulnerabilidad es explotable."*

---

### 🟢 Slide 17: DevSecOps Shift-Left Pipeline
*(Muestra el pipeline de CI/CD en GitHub Actions hacia Kubernetes).*

**Tu Diálogo:**
> *"¿Cómo se traduce esto en valor para la industria? Integrándolo en el ciclo de vida continuo (DevSecOps).  
> Nuestro escáner puede ejecutarse en modo headless dentro de un pipeline de GitHub Actions en cada Pull Request. Si un desarrollador introduce una concatenación accidental, el Quality Gate bloquea la integración antes de llegar a producción. Y en producción, Kubernetes queda resguardado por las políticas de Tetragon."*

---

### 🟢 Slide 18: Conclusiones y Q&A
*(Muestra los 3 pilares finales y los datos de contacto/repositorio).*

**Tu Diálogo:**
> *"Para concluir este workshop:  
> 1. CWE-89 no se resuelve con parches temporales ni WAFs mágicos; se resuelve separando el código del dato mediante sentencias preparadas.  
> 2. eBPF redefine la observabilidad defensiva, dándonos visibilidad incorruptible en el Kernel de Linux.  
> 3. El enfoque Purple Team acelera la remediación al proporcionar al desarrollador el diagnóstico y la solución en un solo ciclo.  
> El repositorio con todo el código fuente está disponible públicamente en GitHub. Les agradecemos profundamente su presencia e interés, y abrimos el micrófono para la ronda de preguntas y debate técnico. ¡Muchas gracias!"*

---

# 🛡️ SECCIÓN III: BANCO DE PREGUNTAS DIFÍCILES DEL JURADO (Y CÓMO RESPONDERLAS)

Prepárate con estas respuestas técnicas ante preguntas complejas de la audiencia:

### Pregunta 1: "¿Por qué afirman que los Prepared Statements tienen 100% de efectividad si existen ataques de Second-Order SQLi?"
> **Tu Respuesta:**  
> *"Excelente pregunta. Las consultas preparadas garantizan 100% de inmunidad en la **fase de ejecución de la consulta inmediata** porque los datos no alteran el AST precompilado. En una inyección de segundo orden (Second-Order SQLi), el dato malicioso se guarda legítimamente en la base de datos y se ejecuta posteriormente en una segunda consulta diferente. Si esa segunda consulta vuelve a usar consultas preparadas, el ataque fracasa de nuevo. El fallo en Second-Order no es de las sentencias preparadas, sino de omitir su uso en la consulta secundaria."*

### Pregunta 2: "¿Qué sobrecarga de rendimiento (overhead) añade eBPF al monitorear sockets en producción?"
> **Tu Respuesta:**  
> *"eBPF añade un overhead prácticamente despreciable (generalmente inferior al 1.5% de CPU), muy por debajo de métodos tradicionales como activar el General Query Log de MySQL (que puede degradar el rendimiento un 30% a 50%) o usar proxies de red en espacio de usuario. Como los programas eBPF son verificados y compilados a código de máquina nativo en el Kernel (JIT), la inspección ocurre en nanosegundos."*

### Pregunta 3: "¿Cómo previene su Worker Pool de Go las condiciones de carrera (Race Conditions)?"
> **Tu Respuesta:**  
> *"Utilizamos el principio idiomático de Go: 'No te comuniques compartiendo memoria; comparte memoria comunicándote'. Las tareas viajan por canales concurrentemente seguros (`chan models.ScanTask`). Para la recolección de errores compartidos, protegemos el slice mediante un cerrojo de exclusión mutua (`sync.Mutex`), y la sincronización general la gestiona `sync.WaitGroup`, eliminando cualquier riesgo de race condition en tiempo de compilación y ejecución."*
