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

- **DVWA · SQL Injection (Low / Medium):** el panel propone Medium y permite
  seleccionar Low. Login con cookies y token CSRF, nivel confirmado en una sesión
  propia, petición base, sonda de error SQL y pares booleanos repetidos. Low utiliza
  GET y condiciones entre comillas; Medium utiliza POST y condiciones numéricas.
  El motor compara registros HTML, ignorando la entrada reflejada y tokens dinámicos.
- **Análisis por URL:** admite dominios, IP y hosts locales mediante HTTP/HTTPS,
  con credenciales Basic y puertos personalizados. Analiza directamente los parámetros de la URL indicada.
  Si no contiene parámetros, busca enlaces en hasta cinco páginas del mismo origen.
  Muestra cada petición GET y distingue fallos de conexión de pruebas sin detección.
  El comportamiento está documentado en `docs/authorized-http-tests.md`.

Las peticiones y hallazgos son reales. La evidencia es HTTP; no hay un sensor eBPF
integrado. Una respuesta bloqueada, inestable o una sesión inválida no se interpreta
como protección. El panel distingue bytes recibidos de registros observados.

El laboratorio Go anterior y sus servicios `vulnerable-app`, `secure-app` y `lab-db`
fueron sustituidos por DVWA. Los datos históricos del escáner se conservan.

El laboratorio registra el inicio y la respuesta de cada petición con método,
estado HTTP, duración, bytes y número de registros. El panel agrupa ambos eventos
en una fila; las URL y entradas se despliegan al abrirla. Nunca registra contraseñas,
cookies, tokens CSRF ni nombres de usuarios devueltos por DVWA. El indicador de
avance cuenta las seis peticiones de prueba, separadas de la autenticación. El
botón «Pausar» detiene el desplazamiento automático y «Reanudar» lo activa.

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
  hallazgo. Añade `-Level low` para comprobar Low.
- `tests/integration/infrastructure.sh` comprueba los servicios Docker.
- `./tests/integration/authorized-url.ps1` verifica el flujo externo real, incluyendo
  errores persistidos, logs HTTP y ausencia de rastreo previo para una URL con parámetros.
  Por defecto utiliza el endpoint local de salud del backend; `-TargetURL` permite
  elegir otra URL de prueba con parámetros. El endpoint de salud comprueba el flujo
  HTTP, sin demostrar una vulnerabilidad SQL.

## Comparación con sqlmap

El panel abre con dos accesos: Laboratorio e Inyección a una página real. El
laboratorio muestra logs, resultados y tiempo total hasta recibirlos en el navegador.
La evidencia y la remediación se despliegan solo al solicitarlas. Ese cronómetro
incluye las actualizaciones del panel y no es la medida utilizada en el benchmark.

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
en `GET /api/scans/:id/results`. Las sondas de cada escaneo son secuenciales.
No hay parámetro de worker pool ni telemetría de kernel en el código activo.

[DVWA oficial](https://github.com/digininja/DVWA). El material en `docs/workshop`
corresponde a la arquitectura anterior y se conserva como referencia histórica.
