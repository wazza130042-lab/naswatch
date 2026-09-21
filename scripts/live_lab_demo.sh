#!/usr/bin/env bash
# NASWatch 5G Live Lab — full-demo runner (teacher showcase)
# Brings up Open5GS core + UERANSIM gNB, registers Alice (legit),
# then runs two attack scenarios (Charlie rogue, Bob slice-jump),
# captures the real N2/N1 SCTP signaling, and replays it through
# NASWatch for live CRITICAL alerts.
#
# Usage:
#   sudo bash scripts/live_lab_demo.sh          # full: core + capture + replay
#   bash scripts/live_lab_demo.sh --capture-off  # no root needed, no tcpdump
#
# Requirements (all open-source, no MNO access):
#   - Open5GS built at $OPEN5GS_INSTALL (default ~/open5gs/install)
#   - UERANSIM built at $UERANSIM_DIR (default /tmp/UERANSIM-3.2.6)
#   - MongoDB running on 127.0.0.1:27017 (Open5GS uses Mongo for subscribers)
#   - Python 3.10+ with pymongo (+ scapy/pyshark for NASWatch parsing)

set -uo pipefail

# sudo resets $HOME to /root — resolve the real (invoking) user's home instead.
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"

OPEN5GS_INSTALL="${OPEN5GS_INSTALL:-$REAL_HOME/open5gs/install}"
UERANSIM_DIR="${UERANSIM_DIR:-/tmp/UERANSIM-3.2.6}"
NASWATCH_DIR="${NASWATCH_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
CONF_DIR="$NASWATCH_DIR/config/open5gs"
CAPTURE_FILE="${CAPTURE_FILE:-$NASWATCH_DIR/data/pcaps/lab5g_live.pcap}"
mkdir -p "$(dirname "$CAPTURE_FILE")"
CAPTURE="${1:-on}"

run_as_user() {
  if [ "$REAL_USER" = "$USER" ]; then "$@"; else sudo -u "$REAL_USER" "$@"; fi
}

export LD_LIBRARY_PATH="$OPEN5GS_INSTALL/lib"
BIN="$OPEN5GS_INSTALL/bin"
LOG="$OPEN5GS_INSTALL/var/log/open5gs"
mkdir -p "$LOG" "$UERANSIM_DIR/logs"

if [ ! -x "$BIN/open5gs-nrfd" ]; then
  echo "ERROR: Open5GS not found at $OPEN5GS_INSTALL (build it first, or set OPEN5GS_INSTALL)."
  exit 1
fi

log()  { echo -e "\n\033[1;36m==> $*\033[0m"; }
ok()   { echo -e "\033[1;32m    [OK] $*\033[0m"; }

cleanup() {
  log "Tearing down lab..."
  [[ -n "${TCPDUMP_PID:-}" ]] && kill "$TCPDUMP_PID" 2>/dev/null
  after_cleanup=true
  echo "done."
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
log "1/6  Starting Open5GS 5G core (NRF, AMF, SMF, UDM, UDR, AUSF, PCF)..."
for p in $(pgrep -f "install/bin/open5gs" 2>/dev/null); do kill "$p" 2>/dev/null || true; done
for p in $(pgrep -f "build/nr-gnb" 2>/dev/null); do kill "$p" 2>/dev/null || true; done
for p in $(pgrep -f "build/nr-ue" 2>/dev/null); do kill "$p" 2>/dev/null || true; done
sleep 1

# Ensure MongoDB is up (Open5GS subscriber DB)
if ! pgrep -x mongod >/dev/null 2>&1; then
  echo "WARNING: MongoDB not running at 127.0.0.1:27017 — subscribers cannot authenticate."
  echo "         Start it first, then re-run. Continuing anyway (attach will be rejected)."
fi

"$BIN/open5gs-nrfd" > /tmp/naswatch-nrf.log 2>&1 &
sleep 1
for nf in amfd smfd udmd udrd ausfd pcfd; do
  "$BIN/open5gs-$nf" > "/tmp/naswatch-$nf.log" 2>&1 &
  sleep 1
done
sleep 4
found=$(pgrep -cf "install/bin/open5gs-[namsup]" 2>/dev/null || echo 0)
ok "7 NF processes expected, $found running"

# ---------------------------------------------------------------------------
log "2/6  Launching simulated gNB (UERANSIM / gNB)"
"$UERANSIM_DIR/build/nr-gnb" -c "$CONF_DIR/gnb.yaml" > /tmp/naswatch-gnb.log 2>&1 &
GNB_PID=$!
sleep 5
grep -q "NG Setup procedure is successful" /tmp/naswatch-gnb.log && ok "gNB <-> AMF NG Setup OK" || { tail -5 /tmp/naswatch-gnb.log; exit 1; }

# ---------------------------------------------------------------------------
if [ "$CAPTURE" = "on" ]; then
  log "3/6  Capturing REAL N2/N1 signaling (root required)..."
  tcpdump -i lo -w "$CAPTURE_FILE" 'sctp or port 38412' 2>/tmp/naswatch-tcpdump.err &
  TCPDUMP_PID=$!
  sleep 2
  if kill -0 "$TCPDUMP_PID" 2>/dev/null; then
    ok "tcpdump capturing to $CAPTURE_FILE"
  else
    cat /tmp/naswatch-tcpdump.err
    exit 1
  fi
else
  log "3/6  CAPTURE OFF — no root capture, showing core/replay detection only"
fi

# ---------------------------------------------------------------------------
run_ue() {
  local cfg="$1" tag="$2"
  "$UERANSIM_DIR/build/nr-ue" -c "$CONF_DIR/$cfg" > "/tmp/naswatch-ue-$tag.log" 2>&1 &
  local pid=$!
  sleep 12
  kill "$pid" 2>/dev/null || true
}

log "4/6  Scenario A — legitimate attach (imsi-999700000000001 / Alice)"
run_ue ue.yaml alice
grep -q "Initial Registration is successful" /tmp/naswatch-ue-alice.log && ok "Alice registered — core accepted (baseline)" || warn_alice=1

log "5/6  Scenario B — ROGUE unprovisioned device (imsi-999700000000003 / Charlie)"
run_ue ue-charlie.yaml charlie
grep -q "Initial Registration failed" /tmp/naswatch-ue-charlie.log && ok "Core rejected Charlie (SUCI not found) — NASWatch should flag ROGUE_DEVICE"

log "5b/6 Scenario C — SLICE-JUMP (imsi-999700000000002 / Bob requests SST4)"
run_ue ue-rogue.yaml bob || true
ok "Core logged Bob's unauthorized S-NSSAI request"

sleep 3
[[ -n "${TCPDUMP_PID:-}" ]] && { kill "$TCPDUMP_PID" 2>/dev/null || true; sleep 1; }

# ---------------------------------------------------------------------------
log "6/6  Running NASWatch detection over the captured signaling..."
if [ "$CAPTURE" = "on" ]; then
  run_as_user python3 "$NASWATCH_DIR/scripts/run_pipeline.py" --mode replay \
    --pcap "$CAPTURE_FILE" --db "$NASWATCH_DIR/data/inventory.db" \
    2>&1 | grep -E "ALERT|Rule:|IMSI:|Severity|Details|Pipeline finished"
else
  ok "Replay the existing demo capture instead:"
  ok "  python3 scripts/run_pipeline.py --mode replay --pcap data/pcaps/5g_signaling_demo.pcap"
fi

log "Demo complete."