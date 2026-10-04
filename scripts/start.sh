#!/usr/bin/env sh

set -eu

COMPOSE_FILE="compose.yaml"

echo "[1/3] Validando la configuracion Docker Compose..."
docker compose -f "$COMPOSE_FILE" config --quiet

echo "[2/3] Iniciando SQLi Workshop Sandbox..."
docker compose -f "$COMPOSE_FILE" up -d

echo "[3/3] Estado de los servicios:"
docker compose -f "$COMPOSE_FILE" ps
