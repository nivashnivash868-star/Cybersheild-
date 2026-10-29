#!/bin/sh
# One-stop helper for recording the demo video. Everything runs locally; nothing here is used in production.
#
#   demo/demo.sh up           build and start CyberShield (PostgreSQL, mail catcher, app) wired to the local Zetaris bundle
#   demo/demo.sh refresh-data regenerate the synthetic logs with fresh timestamps and put them into Zetaris
#   demo/demo.sh export       copy CyberShield's own SOC data into Zetaris (database cybershield_soc)
#   demo/demo.sh code         print the current two-step verification code for the demo administrator
#   demo/demo.sh open         open the demo tabs in the Chrome profile nitikasria@gmail.com
#   demo/demo.sh receiver     show the response receiver's log (for the isolation scene)
#   demo/demo.sh status       what is running
#   demo/demo.sh down         stop CyberShield (Zetaris is left running)
#
# Login details are written to ~/.cybershield-demo/credentials.txt (mode 600). They are throwaway demo values.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE="$HOME/.cybershield-demo"
ZDIR="${ZETARIS_DIR:-$HOME/zetaris-platform}"
APP=cybersheild--app-1
DB=cybersheild--db-1
PORT=8088
CHROME_PROFILE="${CHROME_PROFILE:-Profile 10}"     # nitikasria@gmail.com
mkdir -p "$STATE" && chmod 700 "$STATE"

# Docker Desktop's credential helper can hang pulls and builds; an empty client config avoids it.
export DOCKER_CONFIG="$STATE/dockercfg"
if [ ! -d "$DOCKER_CONFIG" ]; then
  mkdir -p "$DOCKER_CONFIG/cli-plugins"; echo '{}' > "$DOCKER_CONFIG/config.json"
  for p in docker-buildx docker-compose; do ln -sf "$HOME/.docker/cli-plugins/$p" "$DOCKER_CONFIG/cli-plugins/$p"; done
fi
compose() { (cd "$ROOT" && docker compose -f docker-compose.yml -f docker-compose.zetaris.yml --profile dev "$@"); }
rnd() { python3 -c "import secrets;print(secrets.token_urlsafe($1))"; }

write_env() {
  [ -f "$STATE/env" ] && return
  ADMIN_PW="Demo-$(rnd 9)-2026"
  {
    echo "ENVIRONMENT=production"; echo "APP_PORT=$PORT"; echo "PUBLIC_BASE_URL=http://127.0.0.1:8000"; echo "COOKIE_SECURE=false"
    echo "SECRET_KEY=$(rnd 48)"; echo "POSTGRES_PASSWORD=$(rnd 18)"
    echo "BOOTSTRAP_ADMIN_EMAIL=admin@cybershield.demo"; echo "BOOTSTRAP_ADMIN_PASSWORD=Bootstrap-$(rnd 9)-Tmp1"
    echo "SESSION_IDLE_MINUTES=480"; echo "SESSION_ABSOLUTE_HOURS=24"
    echo "SMTP_HOST=mailpit"; echo "SMTP_PORT=1025"; echo "SMTP_SECURITY=none"; echo "SMTP_FROM=alerts@cybershield.local"; echo 'ALERT_SOC_EMAILS=["soc@cybershield.demo"]'
    echo "ZETARIS_BASE_URL=http://host.docker.internal:8888"; echo "ZETARIS_ORG_ID=1"
    echo "ZETARIS_USERNAME=$(grep '^ZETARIS_ADMIN_EMAIL=' "$ZDIR/.env" | cut -d= -f2)"
    echo "ZETARIS_PASSWORD=$(grep '^ZETARIS_ADMIN_PASSWORD=' "$ZDIR/.env" | cut -d= -f2)"
    echo "ZETARIS_TABLE_AUTH=cybershield.auth_logs"; echo "ZETARIS_TABLE_NETWORK=cybershield.network_flows"; echo "ZETARIS_TABLE_EMAIL=cybershield.email_logs"
    echo "ZETARIS_DATA_IS_SYNTHETIC=true"; echo "ZETARIS_INGEST_INTERVAL_SECONDS=120"; echo "ZETARIS_INITIAL_LOOKBACK_HOURS=24"
    echo "RESPONSE_WEBHOOK_URL=http://127.0.0.1:9009/hook"; echo "RESPONSE_WEBHOOK_SECRET=$(rnd 40)"
  } > "$STATE/env"; chmod 600 "$STATE/env"
  echo "DEMO_ADMIN_PASSWORD=$ADMIN_PW" > "$STATE/admin.pw"; chmod 600 "$STATE/admin.pw"
}

cmd_up() {
  write_env
  cp "$STATE/env" "$ROOT/.env"                                   # .env is git-ignored
  compose up -d --build
  echo "waiting for the app..."; i=0
  until curl -sf "http://127.0.0.1:$PORT/api/v1/system/health" >/dev/null; do i=$((i+1)); [ $i -gt 60 ] && { echo "app did not come up"; exit 1; }; sleep 2; done
  docker exec -i "$DB" psql -U cybershield -d cybershield -v ON_ERROR_STOP=1 -q < "$ROOT/backend/scripts/zetaris_export.sql" >/dev/null
  setup_admin
  docker exec -i "$APP" sh -c 'cat > /tmp/receiver.py' < "$ROOT/backend/scripts/example_response_receiver.py"
  docker exec -d "$APP" sh -c "python -u /tmp/receiver.py --port 9009 > /tmp/receiver.log 2>&1"
  echo; echo "Ready: http://127.0.0.1:$PORT   (login details: $STATE/credentials.txt, code: demo/demo.sh code)"
}

setup_admin() {
  [ -s "$STATE/totp.secret" ] && return
  . "$STATE/admin.pw"
  BOOT=$(grep '^BOOTSTRAP_ADMIN_PASSWORD=' "$STATE/env" | cut -d= -f2); EMAIL=$(grep '^BOOTSTRAP_ADMIN_EMAIL=' "$STATE/env" | cut -d= -f2)
  docker exec -i -e E="$EMAIL" -e B="$BOOT" -e N="$DEMO_ADMIN_PASSWORD" "$APP" python - > "$STATE/totp.secret" <<'PY'
import os, httpx, pyotp
c = httpx.Client(base_url="http://127.0.0.1:8000/api/v1", timeout=30)
c.post("/auth/login", json={"email": os.environ["E"], "password": os.environ["B"]}).raise_for_status()
h = lambda: {"X-CSRF-Token": c.cookies.get("cs_csrf")}
secret = c.post("/auth/mfa/setup", headers=h()).json()["secret"]
c.post("/auth/mfa/enable", json={"code": pyotp.TOTP(secret).now()}, headers=h()).raise_for_status()
c.post("/auth/change-password", json={"current_password": os.environ["B"], "new_password": os.environ["N"]}, headers=h()).raise_for_status()
print(secret)
PY
  [ -s "$STATE/totp.secret" ] || { echo "could not enrol the demo administrator"; rm -f "$STATE/totp.secret"; exit 1; }
  chmod 600 "$STATE/totp.secret"
  printf 'CyberShield demo administrator\nURL:      http://127.0.0.1:%s\nEmail:    %s\nPassword: %s\nCode:     run  demo/demo.sh code   (changes every 30 s)\n' "$PORT" "$EMAIL" "$DEMO_ADMIN_PASSWORD" > "$STATE/credentials.txt"
  chmod 600 "$STATE/credentials.txt"
}

cmd_code() { docker exec -e S="$(cat "$STATE/totp.secret")" "$APP" python -c "import os,pyotp;print(pyotp.TOTP(os.environ['S']).now())"; }

cmd_refresh() {
  OUT="$(mktemp -d)"
  python3 "$ROOT/backend/scripts/generate_synthetic_logs.py" --out "$OUT" --seed "${SEED:-7}" >/dev/null
  for f in synthetic_auth_logs synthetic_network_flows synthetic_email_logs; do docker cp "$OUT/$f.csv" "zetaris-driver-1:/home/zetaris/customer-data/shared/synthetic/$f.csv"; done
  rm -rf "$OUT"; echo "Zetaris tables now hold logs generated just now (the attack story is placed in the last 5 hours)."
}

cmd_export() { ZETARIS_DIR="$ZDIR" CS_DB_CONTAINER="$DB" sh "$ROOT/backend/scripts/export_to_zetaris.sh"; }

cmd_open() {
  open -na "Google Chrome" --args --profile-directory="$CHROME_PROFILE" --new-window \
    "http://127.0.0.1:$PORT" "http://localhost:3100" "http://127.0.0.1:8025"
}

cmd_receiver() { docker exec "$APP" tail -f /tmp/receiver.log; }
cmd_status() { docker ps --format '{{.Names}}\t{{.Status}}' | grep -E "cybersheild|zetaris" || true; }
cmd_down() { compose down; }

case "${1:-}" in
  up) cmd_up;; admin) write_env; setup_admin;; code) cmd_code;; refresh-data) cmd_refresh;; export) cmd_export;; open) cmd_open;; status) cmd_status;; receiver) cmd_receiver;; down) cmd_down;;
  *) sed -n 2,12p "$0";;
esac
