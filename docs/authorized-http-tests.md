# Pruebas del objetivo autorizado

El modo por URL ejecuta pruebas HTTP reales sobre el destino indicado: dominios,
direcciones IP y hosts locales. No utiliza una lista de dominios permitidos ni
`ALLOWED_EXTERNAL_HOSTS`. Una URL con parámetros se analiza
directamente, sin rastrear otras páginas. Para una URL sin parámetros, el
descubrimiento visita hasta cinco páginas a profundidad uno. Después analiza hasta
ocho candidatos GET secuencialmente: dos respuestas base, una sonda de error SQL y,
para parámetros numéricos, dos pares booleanos. Cada petición espera 300 ms antes de salir.
Las redirecciones permanecen en el mismo origen. No ejecuta extracción, escrituras
ni sondas de retardo contra el sitio externo.

Se permiten puertos personalizados y autenticación HTTP Basic mediante
`http://usuario:contraseña@tu-sitio:8080/ruta?cat=1`. Las credenciales se
separan de la URL antes de guardarla, permanecen en memoria durante ese escaneo y
se envían en la cabecera de autenticación al origen seleccionado. No aparecen en
eventos, hallazgos ni respuestas de la API. Las redirecciones a otro puerto o
protocolo no se siguen; para probarlos hay que indicarlos en la URL inicial.

La evidencia externa es HTTP, sin telemetría del kernel. Las respuestas inestables
se marcan como no concluyentes. Una línea base bloqueada o sin HTTP 200 detiene el
análisis antes de enviar sondas SQL. Las longitudes mostradas son bytes,
no cantidades de registros. Un timeout marca el escaneo como `FAILED`, conserva
los resultados que ya terminaron y no emite un veredicto para la prueba interrumpida. Una prueba sin
detección no certifica la protección del sitio.

Los eventos `HTTP_ACTIVITY` muestran cada petición en curso y su respuesta medida:
método, código HTTP, milisegundos y bytes. URL, parámetro, entrada y detalle del
error quedan desplegables. El contador corresponde a respuestas recibidas; una
petición sin respuesta no aumenta el contador. El descubrimiento ya no convierte
fallos de la página inicial en un éxito sin parámetros.

Al desplegar una petición se ve el valor original, el payload, la query codificada
y la URL final si hubo una redirección. Las respuestas posteriores se comparan
con el cuerpo completo de la primera base: igualdad del contenido, diferencia
de bytes y firma SQL reconocida. La evidencia del resultado incluye estabilidad
de las dos bases y los criterios de detección; la prueba booleana detalla cada
condición y su reproducibilidad. No se almacenan los cuerpos HTML.

Por ejemplo, `flag=failed` se transforma en `flag=failed%27`: `failed` es el valor
original y `%27` representa la comilla añadida. HTTP 200 indica una respuesta
recibida; no acredita la ejecución de una consulta SQL. Si no aparece una firma
SQL nueva, la prueba queda sin detección. La comparación booleana se registra
como omitida para valores de texto, porque el motor externo solo la aplica a
valores numéricos. Igual número de bytes no implica igual contenido. Los eventos
de escaneos anteriores conservan su evidencia original; las nuevas comparaciones
solo están disponibles en escaneos nuevos.

El 4 de octubre de 2026, la comprobación desde este equipo y desde el backend
agotó el tiempo de espera contra el endpoint de ejemplo. HTTP y HTTPS fallaron
desde el equipo. Esto verifica el manejo de fallos, pero no confirma una
vulnerabilidad ni permite asegurar si la causa está en el sitio o en la ruta de red.
DVWA sigue disponible para demostrar el motor con respuestas reales locales.

Desde `backend`, ejecuta `go test ./...` para validar localmente. La prueba real
es opcional: en PowerShell establece `$env:RUN_AUTHORIZED_LIVE_TEST='1'` y ejecuta
`go test ./scanner -run TestLiveAuthorizedTarget -v -count=1`. Envía hasta siete
peticiones al endpoint `listproducts.php?cat=1`.

Si Docker ya estaba ejecutándose, recrea el servicio backend para cargar el motor
actualizado. En Docker, `localhost` apunta al contenedor del backend; para un
servicio del equipo anfitrión, utiliza `host.docker.internal` y su puerto publicado.
Ejemplo de lectura local: `http://host.docker.internal:8000/login.php?id=1`. Esta
página comprueba conectividad y peticiones reales; el login no es el módulo SQLi
y no debe interpretarse como una demostración de vulnerabilidad.
