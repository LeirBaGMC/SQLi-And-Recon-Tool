#!/usr/bin/env sh
set -eu
COMPOSE_FILE="compose.yaml"
docker compose -f "$COMPOSE_FILE" config --quiet
for SERVICE in scanner-db dvwa-db dvwa backend; do
    CONTAINER_ID="$(docker compose -f "$COMPOSE_FILE" ps -q "$SERVICE")"
    [ -n "$CONTAINER_ID" ] || { echo "Missing service: $SERVICE"; exit 1; }
    [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER_ID")" = "true" ] || exit 1
done
docker compose -f "$COMPOSE_FILE" exec -T scanner-db sh -c \
    'mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" -Nse "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name IN ('\''scans'\'','\''findings'\'','\''scan_events'\'');"' | grep -qx 3
docker compose -f "$COMPOSE_FILE" exec -T dvwa-db sh -c \
    'mariadb -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" -Nse "SELECT COUNT(*) FROM users;"' | grep -qx 5
curl --fail --silent --output /dev/null http://127.0.0.1:8080/health
curl --fail --silent --output /dev/null http://127.0.0.1:8000/login.php
echo "DVWA infrastructure validated."
