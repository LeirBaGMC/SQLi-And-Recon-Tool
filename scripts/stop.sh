#!/usr/bin/env sh

set -eu

COMPOSE_FILE="compose.yaml"

echo "Deteniendo SQLi Workshop DVWA..."
docker compose -f "$COMPOSE_FILE" down

echo "Entorno DVWA detenido correctamente."
