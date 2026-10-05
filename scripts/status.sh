#!/usr/bin/env sh

set -eu

COMPOSE_FILE="compose.yaml"

echo "Estado de SQLi Workshop DVWA:"
docker compose -f "$COMPOSE_FILE" ps
