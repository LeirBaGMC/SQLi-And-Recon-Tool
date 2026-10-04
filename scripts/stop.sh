#!/usr/bin/env sh

set -eu

COMPOSE_FILE="compose.yaml"

echo "Deteniendo SQLi Workshop Sandbox..."
docker compose -f "$COMPOSE_FILE" down

echo "Sandbox detenido correctamente."
