#!/usr/bin/env bash
#
# NASWatch live attack demonstration.
#
# Launches the IDS live-capture sensor against the N2/SCTP :38412 signaling
# interface and then fires a real 5G NAS attack from the terminal using the
# Scapy-based tool in scripts/attack_5g.py. The SOC dashboard reflects the
# detections in real time.
#
# Usage:
#   scripts/live_attack_demo.sh                 # legitimate baseline + all attacks
#   scripts/live_attack_demo.sh rogue           # baseline + a single scenario
#   scripts/live_attack_demo.sh slice-intrusion
#
# Scenarios: legitimate, rogue, suspended, sim-clone, slice-intrusion, flood, all
#
set -euo pipefail

SCENARIO="${1:-all}"
API_CONTAINER="${API_CONTAINER:-naswatch-api}"
CAPTURE_SECONDS="${CAPTURE_SECONDS:-45}"

cd "$(dirname "$0")/.."

dc() { docker compose "$@"; }

echo "==================================================================="
echo " NASWatch — live 5G signaling attack demo (scenario: $SCENARIO)"
echo "==================================================================="

# 0. Make sure the stack is up.
if ! dc exec -T "$API_CONTAINER" true 2>/dev/null; then
  echo "[!] Container '$API_CONTAINER' is not running. Start it with: docker compose up -d"
  exit 1
fi

# 1. Stop any leftover capture sensor from a previous run.
echo "[*] Cleaning up any previous capture sensor..."
dc exec -u 0 -T "$API_CONTAINER" sh -c '
  for p in /proc/[0-9]*; do
    pid=${p#/proc/}
    [ "$pid" = "$$" ] && continue
    c=$(tr "\0" " " < "$p/cmdline" 2>/dev/null || true)
    case "$c" in python*run_pipeline*|timeout*run_pipeline*) kill -9 "$pid" 2>/dev/null || true;; esac
  done
  true' || true
sleep 1

# 2. Record the alert count before the attack.
BEFORE=$(dc exec -T "$API_CONTAINER" python -c \
  "from naswatch.storage.sqlite_repo import SQLiteRepository as R; print(R('/app/data/inventory.db').count_alerts())" \
  2>/dev/null | tr -dc '0-9')
echo "[*] Alerts before attack: ${BEFORE:-?}"

# 3. Start the live capture sensor. Capture needs raw-socket privileges, so the
#    sensor runs as root inside the container; ownership of the data volume is
#    restored to the app user afterwards.
echo "[*] Starting live N2 capture sensor (interface lo, bpf 'sctp or port 38412')..."
dc exec -u 0 -d "$API_CONTAINER" sh -c \
  "cd /app && timeout ${CAPTURE_SECONDS} python /app/scripts/run_pipeline.py --mode live --interface lo > /tmp/naswatch_live.log 2>&1"

echo "[*] Waiting for the sensor to arm..."
for i in $(seq 1 15); do
  if dc exec -T "$API_CONTAINER" sh -c 'grep -q "Starting live capture" /tmp/naswatch_live.log 2>/dev/null'; then
    break
  fi
  sleep 1
done
echo "[*] Sensor armed."

# 4. Fire the attack.
echo
echo "-------------------------------------------------------------------"
echo " ATTACK — running from the terminal:"
echo "   docker compose exec -u 0 $API_CONTAINER python /app/scripts/attack_5g.py --scenario $SCENARIO"
echo "-------------------------------------------------------------------"
dc exec -u 0 -T "$API_CONTAINER" python /app/scripts/attack_5g.py --scenario "$SCENARIO"

# 5. Let the sensor evaluate the signaling.
echo
echo "[*] Letting the IDS evaluate the signaling..."
sleep 6

# 6. Stop the sensor and restore data ownership.
dc exec -u 0 -T "$API_CONTAINER" sh -c '
  for p in /proc/[0-9]*; do
    pid=${p#/proc/}
    [ "$pid" = "$$" ] && continue
    c=$(tr "\0" " " < "$p/cmdline" 2>/dev/null || true)
    case "$c" in python*run_pipeline*|timeout*run_pipeline*) kill -9 "$pid" 2>/dev/null || true;; esac
  done
  true' || true
dc exec -u 0 -T "$API_CONTAINER" sh -c 'chown -R 10001:10001 /app/data' || true

# 7. Report the new alerts.
AFTER=$(dc exec -T "$API_CONTAINER" python -c \
  "from naswatch.storage.sqlite_repo import SQLiteRepository as R; print(R('/app/data/inventory.db').count_alerts())" \
  2>/dev/null | tr -dc '0-9')
echo
echo "==================================================================="
echo " DETECTION RESULT"
echo "==================================================================="
echo " Alerts before: ${BEFORE:-?}"
echo " Alerts after : ${AFTER:-?}"
echo " New this run : $(( ${AFTER:-0} - ${BEFORE:-0} ))"
echo
dc exec -T "$API_CONTAINER" python -c "
from naswatch.storage.sqlite_repo import SQLiteRepository as R
r = R('/app/data/inventory.db')
print('Newest detections:')
for a in r.get_alerts(limit=15)[::-1]:
    d = vars(a)
    print('  ', d.get('timestamp'), '|', d.get('severity'), '|', d.get('title'),
          '| imsi=', d.get('imsi'), 'imei=', d.get('imei'))
" 2>/dev/null | grep -v '"level"' || true
echo
echo " Open the SOC dashboard: http://localhost:8501 -> Incidents"
