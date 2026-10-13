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

mongo_eval() {
  local js="$1"
  if command -v mongosh >/dev/null 2>&1; then
    mongosh --quiet --host 127.0.0.1 --port 27017 open5gs --eval "$js"
  elif command -v docker >/dev/null 2>&1 && [[ "$(docker inspect -f '{{.State.Running}}' open5gs-mongodb 2>/dev/null)" == "true" ]]; then
    docker exec open5gs-mongodb mongosh --quiet open5gs --eval "$js"
  else
    return 1
  fi
}

cleanup() {
  log "Tearing down lab..."
  [[ -n "${TCPDUMP_PID:-}" ]] && kill "$TCPDUMP_PID" 2>/dev/null
  after_cleanup=true
  echo "done."
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
log "1/6  Starting Open5GS 5G core (NRF, SCP, AMF, SMF, UDM, UDR, AUSF, PCF)..."
for p in $(pgrep -f "install/bin/open5gs" 2>/dev/null); do kill "$p" 2>/dev/null || true; done
for p in $(pgrep -f "build/nr-gnb" 2>/dev/null); do kill "$p" 2>/dev/null || true; done
for p in $(pgrep -f "build/nr-ue" 2>/dev/null); do kill "$p" 2>/dev/null || true; done
sleep 1

# Ensure MongoDB is reachable and provision the synthetic lab subscribers.
if ! mongo_eval 'if (db.runCommand({ping: 1}).ok !== 1) quit(1)' >/dev/null 2>&1; then
  echo "ERROR: MongoDB is not reachable at 127.0.0.1:27017. Start MongoDB and re-run."
  exit 1
fi
mongo_eval '
function makeSession() {
  return {
    name: "internet", type: NumberInt(3),
    qos: { index: NumberInt(9), arp: {
      priority_level: NumberInt(8),
      pre_emption_capability: NumberInt(1),
      pre_emption_vulnerability: NumberInt(2)
    }},
    ambr: {
      downlink: { value: NumberInt(1000000000), unit: NumberInt(0) },
      uplink: { value: NumberInt(1000000000), unit: NumberInt(0) }
    },
    pcc_rule: [], _id: new ObjectId()
  };
}
function makeSlice(sst, sd, isDefault) {
  return { sst: NumberInt(sst), sd, default_indicator: isDefault,
    session: [makeSession()], _id: new ObjectId() };
}
function provision(imsi, slices) {
  db.subscribers.updateOne({ imsi }, { $set: {
    schema_version: NumberInt(1), imsi, msisdn: [], imeisv: [],
    mme_host: [], mm_realm: [], purge_flag: [], slice: slices,
    security: {
      k: "465B5CE8B199B49FAA5F0A2EE238A6BC",
      op: null,
      opc: "2E001F1DF0A0BB769940A2C6342CF795",
      amf: "8000"
    },
    ambr: {
      downlink: { value: NumberInt(1000000000), unit: NumberInt(0) },
      uplink: { value: NumberInt(1000000000), unit: NumberInt(0) }
    },
    access_restriction_data: NumberInt(32),
    network_access_mode: NumberInt(0), subscriber_status: NumberInt(0),
    operator_determined_barring: NumberInt(0),
    subscribed_rau_tau_timer: NumberInt(12), __v: 0
  }}, { upsert: true });
}
provision("999700000000001", [makeSlice(1, "000001", true)]);
provision("999700000000002", [makeSlice(1, "000001", true), makeSlice(3, "000003", false)]);
print("Provisioned Alice and Bob for the NASWatch lab; Charlie remains unprovisioned.");
' >/dev/null || { echo "ERROR: Could not provision Open5GS lab subscribers."; exit 1; }

"$BIN/open5gs-nrfd" -c "$OPEN5GS_INSTALL/etc/open5gs/nrf.yaml" > /tmp/naswatch-nrf.log 2>&1 &
sleep 1
"$BIN/open5gs-scpd" -c "$OPEN5GS_INSTALL/etc/open5gs/scp.yaml" > /tmp/naswatch-scpd.log 2>&1 &
sleep 1
for nf in amfd smfd udmd udrd ausfd pcfd; do
  case "$nf" in
    amfd) "$BIN/open5gs-$nf" -c "$CONF_DIR/amf.yaml" > "/tmp/naswatch-$nf.log" 2>&1 & ;;
    smfd) "$BIN/open5gs-$nf" -c "$CONF_DIR/smf.yaml" > "/tmp/naswatch-$nf.log" 2>&1 & ;;
    *)    "$BIN/open5gs-$nf" > "/tmp/naswatch-$nf.log" 2>&1 & ;;
  esac
  sleep 1
done
sleep 4
found=$(pgrep -cf "install/bin/open5gs-[namsup]" 2>/dev/null || echo 0)
ok "8 NF processes expected, $found running"

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
if grep -q "Initial Registration is successful" /tmp/naswatch-ue-alice.log; then
  ok "Alice registered — core accepted (baseline)"
else
  echo "ERROR: Alice could not register; see /tmp/naswatch-ue-alice.log and /tmp/naswatch-amfd.log."
  tail -8 /tmp/naswatch-ue-alice.log
  exit 1
fi

log "5/6  Scenario B — ROGUE unprovisioned device (imsi-999700000000003 / Charlie)"
run_ue ue-charlie.yaml charlie
if grep -q "Initial Registration failed" /tmp/naswatch-ue-charlie.log && \
   grep -q "Unknown UE by SUCI" /tmp/naswatch-amfd.log; then
  ok "Core rejected the unprovisioned Charlie — NASWatch should flag ROGUE_DEVICE"
else
  echo "ERROR: Charlie's expected unknown-subscriber rejection was not confirmed."
  tail -8 /tmp/naswatch-ue-charlie.log
  exit 1
fi

log "5b/6 Scenario C — SLICE-JUMP (imsi-999700000000002 / Bob requests SST4)"
run_ue ue-rogue.yaml bob || true
if grep -Fq 'imsi-999700000000002] Ue requested DNN "internet" Not Supported OR Not Subscribed in the Slice' /tmp/naswatch-amfd.log; then
  ok "AMF rejected Bob's session request against his slice subscription"
else
  echo "ERROR: AMF did not confirm Bob's unauthorized-slice rejection; see /tmp/naswatch-amfd.log."
  exit 1
fi

sleep 3
[[ -n "${TCPDUMP_PID:-}" ]] && { kill "$TCPDUMP_PID" 2>/dev/null || true; sleep 1; }

# ---------------------------------------------------------------------------
log "6/6  Running NASWatch detection over the captured signaling..."
if [ "$CAPTURE" = "on" ]; then
  PIPELINE_OUTPUT="$(run_as_user env "PYTHONPATH=$NASWATCH_DIR/src${PYTHONPATH:+:$PYTHONPATH}" \
    python3 "$NASWATCH_DIR/scripts/run_pipeline.py" --mode replay \
    --pcap "$CAPTURE_FILE" --db "$NASWATCH_DIR/data/inventory.db" 2>&1)"
  PIPELINE_STATUS=$?
  printf '%s\n' "$PIPELINE_OUTPUT"

  if [ "$PIPELINE_STATUS" -ne 0 ]; then
    echo "ERROR: NASWatch replay failed (exit $PIPELINE_STATUS)."
    exit 1
  fi

  if ! grep -Eq 'Processed [1-9][0-9]* signaling events' <<<"$PIPELINE_OUTPUT"; then
    echo "ERROR: NASWatch parsed no signaling events."
    exit 1
  fi
  if ! grep -q 'ROGUE_DEVICE' <<<"$PIPELINE_OUTPUT"; then
    echo "ERROR: NASWatch did not report Charlie's rogue-device alert."
    exit 1
  fi
  if ! grep -q 'SLICE_INTRUSION' <<<"$PIPELINE_OUTPUT"; then
    echo "ERROR: NASWatch did not report Bob's unauthorized-slice alert."
    exit 1
  fi
  ok "Replay parsed signaling and reported rogue-device plus slice-intrusion alerts."
else
  ok "Replay the existing demo capture instead:"
  ok "  python3 scripts/run_pipeline.py --mode replay --pcap data/pcaps/5g_signaling_demo.pcap"
fi

log "Demo complete."
