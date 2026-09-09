#!/usr/bin/env sh

set -eu

COMPOSE_FILE="compose.yaml"

echo "======================================================"
echo " PRUEBA DE MODOS DEL LABORATORIO"
echo "======================================================"
echo ""

echo "[1/6] Validando Docker Compose..."

docker compose -f "$COMPOSE_FILE" config --quiet

echo "[2/6] Verificando vulnerable-app..."

VULNERABLE_HEALTH="$(
    docker compose -f "$COMPOSE_FILE" exec -T backend-placeholder \
        wget -qO- "http://vulnerable-app:8081/health"
)"

echo "$VULNERABLE_HEALTH" | grep -q '"status":"ok"' || {
    echo "ERROR: vulnerable-app no esta saludable"
    exit 1
}

echo "$VULNERABLE_HEALTH" | grep -q '"mode":"vulnerable"' || {
    echo "ERROR: vulnerable-app no esta en modo vulnerable"
    exit 1
}

echo "$VULNERABLE_HEALTH" | grep -q '"database":"connected"' || {
    echo "ERROR: vulnerable-app no esta conectada con lab-db"
    exit 1
}

echo "[3/6] Verificando secure-app..."

SECURE_HEALTH="$(
    docker compose -f "$COMPOSE_FILE" exec -T backend-placeholder \
        wget -qO- "http://secure-app:8081/health"
)"

echo "$SECURE_HEALTH" | grep -q '"status":"ok"' || {
    echo "ERROR: secure-app no esta saludable"
    exit 1
}

echo "$SECURE_HEALTH" | grep -q '"mode":"secure"' || {
    echo "ERROR: secure-app no esta en modo seguro"
    exit 1
}

echo "$SECURE_HEALTH" | grep -q '"database":"connected"' || {
    echo "ERROR: secure-app no esta conectada con lab-db"
    exit 1
}

echo "[4/6] Verificando endpoint vulnerable..."

VULNERABLE_RESPONSE="$(
    docker compose -f "$COMPOSE_FILE" exec -T backend-placeholder \
        wget -qO- \
        "http://vulnerable-app:8081/api/vulnerable/products?id=1"
)"

echo "$VULNERABLE_RESPONSE" |
    grep -q '"security_mode":"unsafe_concatenation"' || {
        echo "ERROR: el endpoint vulnerable no utiliza el modo esperado"
        exit 1
    }

echo "$VULNERABLE_RESPONSE" | grep -q '"id":1' || {
    echo "ERROR: el endpoint vulnerable no devolvio el producto esperado"
    exit 1
}

echo "$VULNERABLE_RESPONSE" | grep -q '"received_input":"1"' || {
    echo "ERROR: el endpoint vulnerable no muestra la entrada recibida"
    exit 1
}

echo "$VULNERABLE_RESPONSE" | grep -q '"query_template":' || {
    echo "ERROR: el endpoint vulnerable no muestra la plantilla SQL"
    exit 1
}

echo "$VULNERABLE_RESPONSE" | grep -q '"executed_query":' || {
    echo "ERROR: el endpoint vulnerable no muestra la consulta ejecutada"
    exit 1
}

echo "$VULNERABLE_RESPONSE" | grep -q '"risk":' || {
    echo "ERROR: el endpoint vulnerable no describe el riesgo"
    exit 1
}

echo "$VULNERABLE_RESPONSE" | grep -q '"recommendation":' || {
    echo "ERROR: el endpoint vulnerable no incluye una recomendacion"
    exit 1
}

echo "[5/6] Verificando consulta preparada..."

SECURE_RESPONSE="$(
    docker compose -f "$COMPOSE_FILE" exec -T backend-placeholder \
        wget -qO- \
        "http://secure-app:8081/api/secure/products/1"
)"

echo "$SECURE_RESPONSE" |
    grep -q '"security_mode":"prepared_statement"' || {
        echo "ERROR: el endpoint seguro no utiliza consulta preparada"
        exit 1
    }

echo "$SECURE_RESPONSE" | grep -q '"id":1' || {
    echo "ERROR: el endpoint seguro no devolvio el producto esperado"
    exit 1
}

echo "$SECURE_RESPONSE" | grep -q '"received_input":"1"' || {
    echo "ERROR: el endpoint seguro no muestra la entrada recibida"
    exit 1
}

echo "$SECURE_RESPONSE" | grep -q '"query_template":' || {
    echo "ERROR: el endpoint seguro no muestra la plantilla SQL"
    exit 1
}

echo "$SECURE_RESPONSE" | grep -q '"parameters":{"id":1}' || {
    echo "ERROR: el endpoint seguro no separa correctamente el parametro"
    exit 1
}

echo "$SECURE_RESPONSE" | grep -q '"risk":' || {
    echo "ERROR: el endpoint seguro no describe el riesgo"
    exit 1
}

echo "$SECURE_RESPONSE" | grep -q '"recommendation":' || {
    echo "ERROR: el endpoint seguro no incluye una recomendacion"
    exit 1
}

echo "[6/6] Verificando bloqueo del endpoint vulnerable en secure-app..."

BLOCK_RESPONSE="$(
    docker compose -f "$COMPOSE_FILE" exec -T backend-placeholder \
        sh -c '
            wget -S -O /dev/null \
                "http://secure-app:8081/api/vulnerable/products?id=1" \
                2>&1 || true
        '
)"

echo "$BLOCK_RESPONSE" | grep -q "404 Not Found" || {
    echo "ERROR: secure-app no respondio con estado 404"
    echo "$BLOCK_RESPONSE"
    exit 1
}

echo ""
echo "======================================================"
echo " RESULTADO: MODOS DEL LABORATORIO VALIDADOS"
echo "======================================================"