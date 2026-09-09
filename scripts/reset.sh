#!/usr/bin/env sh

set -eu

COMPOSE_FILE="compose.yaml"

echo "======================================================"
echo " REINICIO COMPLETO DEL SQLI WORKSHOP SANDBOX"
echo "======================================================"
echo ""
echo "Esta accion eliminara:"
echo "  - Los contenedores del sandbox"
echo "  - Los volumenes de scanner-db"
echo "  - Los volumenes de lab-db"
echo "  - Los datos generados durante el workshop"
echo ""
printf "Escribe RESET para continuar: "
read -r CONFIRMATION

if [ "$CONFIRMATION" != "RESET" ]; then
    echo "Operacion cancelada. No se elimino ningun dato."
    exit 0
fi

echo ""
echo "[1/4] Validando Docker Compose..."
docker compose -f "$COMPOSE_FILE" config --quiet

echo "[2/4] Eliminando contenedores y volumenes..."
docker compose -f "$COMPOSE_FILE" down --volumes --remove-orphans

echo "[3/4] Reconstruyendo el sandbox..."
docker compose -f "$COMPOSE_FILE" up -d

echo "[4/4] Estado inicial de los servicios:"
docker compose -f "$COMPOSE_FILE" ps

echo ""
echo "El sandbox fue reiniciado."
echo "Los servicios pueden tardar unos segundos en aparecer como healthy."
