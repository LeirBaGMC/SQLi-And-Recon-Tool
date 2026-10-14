# SQLi Studio · Workshop con DVWA

Aplicación educativa para seguir una prueba de inyección SQL desde el formulario
hasta la evidencia HTTP, los resultados y la comprobación de una corrección.
Incluye un frontend React, una API en Go y un laboratorio DVWA con una variante
vulnerable y otra corregida con consultas preparadas.

El workshop utiliza el laboratorio local. La opción **URL autorizada** permite
analizar otros objetivos sobre los que tengas autorización.

## Preparar el workshop

Necesitas Git y Docker con el complemento Docker Compose. En Windows, inicia
Docker Desktop con contenedores Linux. Para este arranque no necesitas instalar
Go, Node.js, PHP ni MySQL en tu equipo.

### 1. Descargar el proyecto

```sh
git clone --branch refactor/sandbox-infrastructure https://github.com/LeirBaGMC/SQLi-And-Recon-Tool.git
cd SQLi-And-Recon-Tool
```

### 2. Crear la configuración local

Desde la raíz, copia el ejemplo solo si todavía no tienes `.env`.

En PowerShell:

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

En macOS o Linux:

```sh
test -f .env || cp .env.example .env
```

Los valores de `.env.example` corresponden al laboratorio local. `.env` queda
fuera de Git. Si cambias las credenciales de una base que ya tiene datos, debes
actualizarlas también en esa base; editar `.env` no cambia usuarios existentes.

### 3. Levantar la aplicación

```sh
docker compose -f compose.yaml up -d --build
docker compose -f compose.yaml ps -a
```

La primera ejecución descarga las imágenes, compila la aplicación e inicializa
las bases. Espera a que frontend, backend, DVWA y las dos bases aparezcan como
`healthy`. El servicio `dvwa-init` debe terminar con `Exited (0)`: indica que
la inicialización finalizó correctamente.

| Servicio | Dirección predeterminada | Para qué sirve |
| --- | --- | --- |
| SQLi Studio | [localhost:3000](http://localhost:3000) | Iniciar escaneos y revisar evidencia |
| Salud de la API | [localhost:8080/health](http://localhost:8080/health) | Comprobar backend y su conexión a la base |
| DVWA | [localhost:8000](http://localhost:8000) | Laboratorio de entrenamiento |

La cuenta inicial de DVWA es `admin` / `password`. El escáner inicia sesión
automáticamente con las credenciales configuradas. Los puertos se publican solo
en `127.0.0.1`; las bases están en redes internas de Docker.

## Recorrido de la demostración

1. Abre SQLi Studio y elige **Laboratorio**.
2. Selecciona nivel **Medium**, **1 worker** y variante **Vulnerable**.
3. Inicia el escaneo. Revisa su estado, la consola y los resultados.
4. Abre la sección de corrección para comparar el código vulnerable con la
   consulta preparada.
5. Pulsa **Probar variante corregida**. Se crea otro escaneo con el mismo nivel
   y número de workers; el anterior queda como referencia para la comparación.
6. Revisa la evidencia de la nueva ejecución y su reporte. Puedes descargarlo
   como JSON.

En DVWA se realizan seis sondas: una respuesta de referencia, una prueba con
comilla y dos pares de condiciones verdaderas y falsas. Alimentan dos resultados:
error SQL y comparación booleana.

**Low** envía el valor con GET; **Medium**, con POST; y **High** lo guarda primero
en la sesión y después consulta el módulo. Los workers permiten ejecutar varias
sondas a la vez, cada uno con su propia sesión. Se admiten 1, 2 o 4; más workers
no garantizan un menor tiempo total.

### Cómo leer los resultados

| Indicador | Significado |
| --- | --- |
| `QUEUED` / `RUNNING` | Escaneo pendiente / en ejecución |
| `COMPLETED` / `FAILED` | La ejecución terminó / tuvo un fallo operativo |
| `DETECTED` | La prueba encontró evidencia que cumple su criterio de detección |
| `NOT_DETECTED` | Esa prueba no detectó la señal buscada |
| `INCONCLUSIVE` | La evidencia no permite concluir |

`COMPLETED` describe la ejecución; no certifica que el objetivo sea seguro.
La ausencia de hallazgos tampoco demuestra por sí sola que una corrección funcione.

La **Reprueba HTTP aprobada** exige un escaneo completado, dos resultados reales
sin detección, ningún hallazgo y seis respuestas HTTP 200 válidas: `id=1` debe devolver
un registro aceptado, y las otras cinco entradas deben rechazarse explícitamente
sin devolver registros. El módulo corregido valida un entero positivo, usa
consultas preparadas con `mysqli` y codifica la salida HTML.

La evidencia disponible es HTTP. La opción de observabilidad eBPF presenta un
siguiente paso del proyecto: el sensor figura como **no conectado** y no instala
ni activa un sensor.

## Análisis de una URL autorizada

Selecciona **URL autorizada** e introduce una dirección HTTP o HTTPS de un
objetivo para el que tengas permiso. Si contiene parámetros, el escáner los analiza directamente;
si no encuentra candidatos, busca enlaces dentro del mismo origen.

El recorrido está limitado a cinco páginas, profundidad uno, ocho candidatos y
respuestas de hasta 1 MiB. El plan depende del valor del parámetro: tres solicitudes
para texto y siete para valores numéricos. Un cambio de tamaño en la respuesta
o un error HTTP no bastan para afirmar que existe inyección SQL.

La dirección se consulta desde el contenedor del backend. `localhost` en esa
dirección se refiere al propio contenedor. En Docker Desktop puedes usar
`host.docker.internal` para llegar a un servicio autorizado en tu equipo,
o el nombre de un servicio si comparte la red Docker.

## Organización del código

| Carpeta | Responsabilidad |
| --- | --- |
| [`backend/`](backend/) | API, validación del objetivo, motor, resultados y persistencia |
| [`frontend/`](frontend/) | Formulario, seguimiento, consola y presentación de evidencia |
| [`infrastructure/`](infrastructure/) | Esquema MySQL, inicialización de DVWA y módulo PHP corregido |

El flujo principal es:

```text
Formulario → POST /api/scans → router → handler → validación del objetivo
          → guardar escaneo → iniciar análisis en segundo plano
          → devolver scan_id → consultar estado, eventos y resultados
```

| Método y ruta | Función |
| --- | --- |
| `POST /api/scans` | Crear el escaneo; responde HTTP 202 con su identificador |
| `GET /api/scans/:id` | Consultar estado y fechas |
| `GET /api/scans/:id/events` | Consultar actividad y evidencia |
| `GET /api/scans/:id/results` | Consultar hallazgos y reporte |
| `GET /health` | Comprobar backend y acceso a la base del escáner |

`scanner-db` guarda escaneos, eventos y hallazgos en MySQL. `dvwa-db` es la base
MariaDB del laboratorio. Conservan sus datos en volúmenes separados.

Si una consulta del navegador falla, el frontend conserva el mismo identificador
y la evidencia y reintenta con esperas de 1 a 10 segundos. Al reiniciar el backend,
los escaneos antiguos que quedaron pendientes o ejecutándose se marcan como
fallidos, conservando su evidencia. No se reanudan automáticamente. Este arranque
está diseñado para una sola instancia del backend.

## Comandos para el taller

Desde la raíz del repositorio:

```sh
# Ver el estado, incluido el inicializador
docker compose -f compose.yaml ps -a

# Revisar los últimos mensajes del backend
docker compose -f compose.yaml logs --tail=100 backend

# Revisar la inicialización del laboratorio
docker compose -f compose.yaml logs --tail=100 dvwa-init

# Detener el entorno conservando los volúmenes de datos
docker compose -f compose.yaml down

# Volver a levantarlo
docker compose -f compose.yaml up -d
```

`compose.yaml` es la configuración principal. `docker-compose.yml` la incluye
como entrada de compatibilidad.

Si Docker no puede conectarse al motor, abre Docker Desktop y espera a que termine
de iniciar. Si un puerto está ocupado, cambia `FRONTEND_PORT`, `BACKEND_PORT` o
`DVWA_PORT` en `.env`, repite el comando de arranque y abre la dirección con el
nuevo puerto.

## Desarrollo local

Para trabajar en el frontend con Vite, levanta las dependencias y libera el puerto
del frontend de Docker:

```sh
docker compose -f compose.yaml up -d --build backend
docker compose -f compose.yaml stop frontend
```

Después, desde `frontend/`, con Node.js compatible con Vite 7 (20.19+ o 22.12+):

```sh
npm ci
npm run dev
```

Vite utiliza el puerto 3000 y conecta con `http://127.0.0.1:8080`.
`BACKEND_PROXY_URL` permite cambiar ese destino.

Las comprobaciones internas del frontend se ejecutan con `npm test`, `npm run lint`
y `npm run build`. En `backend/`, utiliza `go test ./...` con Go 1.25 o superior;
la construcción Docker también ejecuta estas pruebas antes de compilar.

Proyecto de laboratorio basado en [DVWA oficial](https://github.com/digininja/DVWA).
