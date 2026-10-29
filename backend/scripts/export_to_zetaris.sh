#!/bin/sh
# Copies CyberShield's own SOC data (the zetaris_export views, no credentials, sessions or personal records) into a LOCAL
# Zetaris instance as a Lightning database, so Zetaris can query it next to the raw logs. It is a snapshot: run it again to refresh.
#
#   ZETARIS_DIR=~/zetaris-platform CS_DB_CONTAINER=cybersheild--db-1 sh backend/scripts/export_to_zetaris.sh
#
# Needs: docker, java (the bundle's JDBC jar), the CyberShield stack running, and zetaris_export.sql applied
# (docker exec -i $CS_DB_CONTAINER psql -U cybershield -d cybershield < backend/scripts/zetaris_export.sql).
set -eu
ZETARIS_DIR="${ZETARIS_DIR:-$HOME/zetaris-platform}"
CS_DB_CONTAINER="${CS_DB_CONTAINER:-cybersheild--db-1}"
DRIVER="${ZETARIS_DRIVER_CONTAINER:-zetaris-driver-1}"
DBNAME="${ZETARIS_TARGET_DB:-cybershield_soc}"
HERE="$(cd "$(dirname "$0")" && pwd)"
JAR="$(ls "$ZETARIS_DIR"/jdbc/*.jar | head -1)"
TABLES="security_events incidents decision_requests agent_runs response_actions response_jobs blocklist_entries threat_analyses audit_logs"
OUT="$(mktemp -d)"
export ZURL="${ZURL:-jdbc:zetaris:lightning@localhost:10000}"
export ZUSER="$(grep '^ZETARIS_ADMIN_EMAIL=' "$ZETARIS_DIR/.env" | cut -d= -f2)"
export ZPASS="$(grep '^ZETARIS_ADMIN_PASSWORD=' "$ZETARIS_DIR/.env" | cut -d= -f2)"

for t in $TABLES; do
  docker exec "$CS_DB_CONTAINER" psql -U cybershield -d cybershield -c "\copy (select * from zetaris_export.$t) to stdout with (format csv, header true)" > "$OUT/$t.csv"
  echo "exported $t: $(($(wc -l < "$OUT/$t.csv") - 1)) line(s) (multi-line fields may count more)"
done
docker exec "$DRIVER" mkdir -p /home/zetaris/customer-data/shared/cybershield_soc
for t in $TABLES; do docker cp "$OUT/$t.csv" "$DRIVER:/home/zetaris/customer-data/shared/cybershield_soc/$t.csv"; done
rm -rf "$OUT"

STMTS="DROP LIGHTNING DATABASE $DBNAME"   # fails harmlessly the first time
set -- "CREATE LIGHTNING DATABASE $DBNAME DESCRIBE BY \"CyberShield own SOC data - snapshot of the zetaris_export views\""
for t in $TABLES; do
  set -- "$@" "CREATE LIGHTNING FILESTORE TABLE $t FROM $DBNAME FORMAT CSV OPTIONS (path \"/home/zetaris/customer-data/shared/cybershield_soc/$t.csv\", header \"true\", inferSchema \"true\", multiLine \"true\", escape \"\\\"\")"
done
java -cp "$JAR:$HERE" "$HERE/ZetarisSql.java" "$STMTS" "$@" 2>&1 | grep -v SLF4J
