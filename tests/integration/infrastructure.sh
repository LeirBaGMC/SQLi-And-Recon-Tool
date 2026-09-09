#!/usr/bin/env sh

set -eu

COMPOSE_FILE="compose.yaml"

echo "======================================================"
echo " PRUEBA DE INFRAESTRUCTURA DEL SQLI WORKSHOP"
echo "======================================================"
echo ""

echo "[1/6] Validando Docker Compose..."
docker compose -f "$COMPOSE_FILE" config --quiet

echo "[2/6] Verificando servicios esperados..."
SERVICES="$(docker compose -f "$COMPOSE_FILE" config --services)"

for SERVICE in \
    scanner-db \
    lab-db \
    backend-placeholder \
    vulnerable-app \
    secure-app
do
    echo "$SERVICES" | grep -qx "$SERVICE" || {
        echo "ERROR: No se encontro el servicio $SERVICE"
        exit 1
    }
done

echo "[3/6] Verificando contenedores activos..."
for SERVICE in \
    scanner-db \
    lab-db \
    backend-placeholder \
    vulnerable-app \
    secure-app
do
    CONTAINER_ID="$(docker compose -f "$COMPOSE_FILE" ps -q "$SERVICE")"

    if [ -z "$CONTAINER_ID" ]; then
        echo "ERROR: El servicio $SERVICE no tiene un contenedor activo"
        exit 1
    fi

    RUNNING="$(docker inspect -f '{{.State.Running}}' "$CONTAINER_ID")"

    if [ "$RUNNING" != "true" ]; then
        echo "ERROR: El servicio $SERVICE no esta en ejecucion"
        exit 1
    fi
done

echo "[4/6] Verificando tablas de scanner-db..."
docker compose -f "$COMPOSE_FILE" exec -T scanner-db sh -c \
    'mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" -Nse "
        SELECT COUNT(*)
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
        AND table_name IN (
            '\''scans'\'',
            '\''findings'\'',
            '\''scan_events'\''
        );
    "' | grep -qx "3" || {
        echo "ERROR: scanner-db no contiene las tres tablas esperadas"
        exit 1
    }

echo "[5/6] Verificando tablas y datos de lab-db..."
docker compose -f "$COMPOSE_FILE" exec -T lab-db sh -c \
    'mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" -Nse "
        SELECT COUNT(*)
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
        AND table_name IN (
            '\''products'\'',
            '\''workshop_users'\''
        );
    "' | grep -qx "2" || {
        echo "ERROR: lab-db no contiene las dos tablas esperadas"
        exit 1
    }

PRODUCT_COUNT="$(
    docker compose -f "$COMPOSE_FILE" exec -T lab-db sh -c \
        'mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" -Nse "
            SELECT COUNT(*) FROM products;
        "'
)"

if [ "$PRODUCT_COUNT" -ne 3 ]; then
    echo "ERROR: Se esperaban 3 productos, pero se encontraron $PRODUCT_COUNT"
    exit 1
fi

echo "[6/6] Verificando acceso publico del backend..."
curl --fail --silent --output /dev/null http://localhost:8080

echo ""
echo "======================================================"
echo " RESULTADO: INFRAESTRUCTURA VALIDADA CORRECTAMENTE"
echo "======================================================"
