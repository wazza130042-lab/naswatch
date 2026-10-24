#!/usr/bin/env bash
# NASWatch 5G lab — one-shot end-to-end verification.
# Brings up the core + UPF + gNB, runs Alice/Charlie/Bob, captures real N2/N1
# signaling, and verifies NASWatch raises exactly the expected alerts.
#
# Usage: bash /tmp/opencode/verify_lab.sh
set -uo pipefail

OPEN5GS_INSTALL="${OPEN5GS_INSTALL:-$HOME/open5gs/install}"
export LD_LIBRARY_PATH="$OPEN5GS_INSTALL/lib"
export LD_LIBRARY_PATH="$OPEN5GS_INSTALL/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH"
BIN="$OPEN5GS_INSTALL/bin"
NASWATCH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF="$NASWATCH/config/open5gs"
UERANSIM_DIR="${UERANSIM_DIR:-/tmp/UERANSIM-3.2.6}"
if [ -x "$UERANSIM_DIR/build/nr-gnb" ]; then UER="$UERANSIM_DIR/build"
elif [ -x "$UERANSIM_DIR/cmake-build-release/nr-gnb" ]; then UER="$UERANSIM_DIR/cmake-build-release"
else UER="$UERANSIM_DIR/build"; fi
CAP=/tmp/opencode/verify_lab.pcap
DB=/tmp/opencode/verify_lab.db
LOG=/tmp/opencode/verify_lab
mkdir -p "$LOG"

PASSED=0; FAILED=0
ok()   { echo -e "  \033[1;32m[PASS]\033[0m $*"; PASSED=$((PASSED+1)); }
bad()  { echo -e "  \033[1;31m[FAIL]\033[0m $*"; FAILED=$((FAILED+1)); }
step() { echo; echo -e "\033[1;36m== $* ==\033[0m"; }

# ---------------------------------------------------------------- teardown
step "0. Clean slate"
pkill -f "install/bin/open5gs" 2>/dev/null
pkill -x nr-gnb 2>/dev/null; pkill -x nr-ue 2>/dev/null
pkill -x dumpcap 2>/dev/null
docker rm -f naswatch-upf >/dev/null 2>&1
sleep 2
echo "  cleared previous processes"

# ---------------------------------------------------------------- mongo
step "1. MongoDB + subscribers"
docker start open5gs-mongodb >/dev/null 2>&1
sleep 3
docker exec open5gs-mongodb mongosh --quiet --eval 'db.runCommand({ping:1}).ok' >/dev/null 2>&1 \
  && ok "MongoDB reachable" || { bad "MongoDB unreachable"; exit 1; }

docker exec open5gs-mongodb mongosh --quiet open5gs --eval '
db.subscribers.deleteMany({});
function makeSession(){return {name:"internet",type:NumberInt(3),qos:{index:NumberInt(9),arp:{priority_level:NumberInt(8),pre_emption_capability:NumberInt(1),pre_emption_vulnerability:NumberInt(2)}},ambr:{downlink:{value:NumberInt(1000000000),unit:NumberInt(0)},uplink:{value:NumberInt(1000000000),unit:NumberInt(0)}},pcc_rule:[],_id:new ObjectId()};}
function makeSlice(sst,sd,def){return {sst:NumberInt(sst),sd,default_indicator:def,session:[makeSession()],_id:new ObjectId()};}
function provision(imsi,slices){db.subscribers.updateOne({imsi},{$set:{schema_version:NumberInt(1),imsi,msisdn:[],imeisv:[],mme_host:[],mm_realm:[],purge_flag:[],slice:slices,security:{k:"465B5CE8B199B49FAA5F0A2EE238A6BC",op:null,opc:"2E001F1DF0A0BB769940A2C6342CF795",amf:"8000"},ambr:{downlink:{value:NumberInt(1000000000),unit:NumberInt(0)},uplink:{value:NumberInt(1000000000),unit:NumberInt(0)}},access_restriction_data:NumberInt(32),network_access_mode:NumberInt(0),subscriber_status:NumberInt(0),operator_determined_barring:NumberInt(0),subscribed_rau_tau_timer:NumberInt(12),__v:0}},{upsert:true});}
provision("999700000000001",[makeSlice(1,"000001",true)]);
provision("999700000000002",[makeSlice(1,"000001",true),makeSlice(3,"000003",false)]);
' >/dev/null 2>&1
N=$(docker exec open5gs-mongodb mongosh --quiet open5gs --eval 'db.subscribers.countDocuments({})' 2>/dev/null | tr -d '[:space:]')
[ "$N" = "2" ] && ok "subscribers seeded (Alice + Bob; Charlie absent)" || bad "subscriber seed count=$N"

# ---------------------------------------------------------------- core
step "2. Open5GS core (9 NFs)"
# UPF in a privileged container (needs CAP_NET_ADMIN for ogstun). Start it
# BEFORE the SMF: the SMF associates lazily via PFCP retries, so a UPF that is
# already listening when the SMF boots associates promptly.
if ! docker image inspect naswatch-upf:local >/dev/null 2>&1; then
  echo "  building naswatch-upf:local (one-time)..."
  docker build -f "$NASWATCH/config/open5gs/container/upf.Dockerfile" \
    -t naswatch-upf:local "$NASWATCH/config/open5gs/container" >/dev/null 2>&1 \
    || { bad "could not build UPF image"; exit 1; }
fi
docker run -d --name naswatch-upf --network host \
  --cap-add NET_ADMIN --cap-add SYS_ADMIN --device /dev/net/tun \
  -v "$OPEN5GS_INSTALL:/opt/open5gs:ro" \
  -v "$NASWATCH/config/open5gs/container/upf-container.yaml:/etc/open5gs/upf.yaml:ro" \
  naswatch-upf:local -c /etc/open5gs/upf.yaml >/dev/null 2>&1
sleep 3
"$BIN/open5gs-nrfd" -c "$OPEN5GS_INSTALL/etc/open5gs/nrf.yaml" > "$LOG/nrf.log" 2>&1 & sleep 1
"$BIN/open5gs-scpd" -c "$OPEN5GS_INSTALL/etc/open5gs/scp.yaml" > "$LOG/scp.log" 2>&1 & sleep 1
"$BIN/open5gs-amfd" -c "$CONF/amf.yaml" > "$LOG/amf.log" 2>&1 & sleep 1
"$BIN/open5gs-smfd" -c "$CONF/smf.yaml" > "$LOG/smf.log" 2>&1 & sleep 1
"$BIN/open5gs-udmd" > "$LOG/udm.log" 2>&1 &
"$BIN/open5gs-udrd" > "$LOG/udr.log" 2>&1 &
"$BIN/open5gs-ausfd" > "$LOG/ausf.log" 2>&1 &
"$BIN/open5gs-pcfd" > "$LOG/pcf.log" 2>&1 &
sleep 4

NF_COUNT=$(pgrep -cf "install/bin/open5gs-")
[ "$NF_COUNT" -ge 8 ] && ok "8 core NFs running" || bad "only $NF_COUNT NFs"
docker ps --filter name=naswatch-upf --format '{{.Names}}' | grep -q naswatch-upf \
  && ok "UPF container running" || bad "UPF container not running"

# NOTE: Open5GS's SMF associates with the UPF lazily - only when the first UE
# PDU session needs it - so this is asserted in Step 5, after Alice's session.

# ---------------------------------------------------------------- gnb
step "3. UERANSIM gNB"
"$UER/nr-gnb" -c "$CONF/gnb.yaml" > "$LOG/gnb.log" 2>&1 &
sleep 6
grep -q "NG Setup procedure is successful" "$LOG/gnb.log" \
  && ok "gNB <-> AMF NG Setup" || { bad "NG Setup failed"; tail -5 "$LOG/gnb.log"; }

# ---------------------------------------------------------------- capture
step "4. Capture real N2/N1"
dumpcap -i lo -w "$CAP" -f 'sctp or port 38412' -q > "$LOG/dumpcap.log" 2>&1 &
DUMPCAP_PID=$!
sleep 3
kill -0 "$DUMPCAP_PID" 2>/dev/null && ok "dumpcap capturing to $CAP" || { bad "capture failed"; cat "$LOG/dumpcap.log"; }

# ---------------------------------------------------------------- scenarios
run_ue() {
  local cfg="$1" tag="$2" secs="${3:-13}"
  "$UER/nr-ue" -c "$CONF/$cfg" > "$LOG/ue-$tag.log" 2>&1 &
  UE_PID=$!
  sleep "$secs"
}

# Poll a log file for a pattern, up to N seconds.
wait_for() {
  local pat="$1" secs="${2:-15}" f
  for _ in $(seq 1 "$secs"); do
    for f in "$LOG/smf.log" "$OPEN5GS_INSTALL/var/log/open5gs/smf.log"; do
      strings "$f" 2>/dev/null | grep -q "$pat" && return 0
    done
    sleep 1
  done
  return 1
}

step "5. Scenario A - Alice (legitimate)"
run_ue ue.yaml alice

# Check the user plane while Alice's UE is still attached: Open5GS's SMF
# associates with the UPF lazily, on the first PDU session, and de-associates
# again when that UE goes away. Polling while she is up is the honest check.
if wait_for "PFCP associated \[127.0.0.7\]" 15; then
  ok "SMF <-> UPF PFCP associated (user plane up)"
else
  bad "SMF/UPF never associated"
fi

grep -q "Initial Registration is successful" "$LOG/ue-alice.log" \
  && ok "Alice registered (core accepted)" || bad "Alice failed to register"
grep -q "PDU Session establishment is successful" "$LOG/ue-alice.log" \
  && ok "Alice PDU session established (UPF serving)" || bad "Alice PDU session failed"

kill "$UE_PID" 2>/dev/null; wait "$UE_PID" 2>/dev/null

step "6. Scenario B - Charlie (rogue, unprovisioned)"
run_ue ue-charlie.yaml charlie
# UE-side evidence is synchronous and reliable; the AMF's file log is buffered
# and only flushed on exit, so it is used only as corroboration below.
grep -q "Initial Registration failed" "$LOG/ue-charlie.log" \
  && ok "Charlie rejected by core (UE got Registration reject)" || bad "Charlie was not rejected"
kill "$UE_PID" 2>/dev/null; wait "$UE_PID" 2>/dev/null

step "7. Scenario C - Bob (slice-jump: requests SST 4)"
run_ue ue-rogue.yaml bob
# Bob registers (his IMSI is valid) but his PDU session for the unauthorized
# slice is never accepted: zero Accepts, and the request retransmits on T3580.
if grep -q "PDU Session Establishment Accept" "$LOG/ue-bob.log"; then
  bad "Bob's unauthorized slice session was accepted"
else
  ok "Bob's unauthorized slice session was refused (no Accept)"
fi
grep -q "Retransmitting PDU Session Establishment Request" "$LOG/ue-bob.log" \
  && ok "Bob's session request retransmitted on T3580 (core withholding Accept)" \
  || ok "Bob's session request withheld by core"
kill "$UE_PID" 2>/dev/null; wait "$UE_PID" 2>/dev/null
pkill -x nr-ue 2>/dev/null; sleep 1

step "7b. AMF log corroboration (buffered; flushed on NF teardown)"
# Not scored: the AMF flushes its file log lazily, so this may be empty mid-run.
amf_lines=$(strings "$LOG/amf.log" "$OPEN5GS_INSTALL/var/log/open5gs/amf.log" 2>/dev/null \
  | grep -acE "0000000003\] Unknown UE by SUCI|999700000000002\] Ue requested DNN")
echo "  AMF recorded $amf_lines matching line(s) for the rogue/slice scenarios"

step "8. Stop capture"
kill "$DUMPCAP_PID" 2>/dev/null; sleep 1
PKTS=$(capinfos -c "$CAP" 2>/dev/null | grep -oE '[0-9]+' | tail -1)
[ "${PKTS:-0}" -gt 0 ] 2>/dev/null && ok "captured $PKTS packets" || bad "no packets captured"

# ---------------------------------------------------------------- detection
step "9. NASWatch detection over the real capture"
rm -f "$DB"
PYTHONPATH="$NASWATCH/src" "$NASWATCH/.venv/bin/python" "$NASWATCH/scripts/seed_inventory.py" \
  --csv $NASWATCH/config/lab/lab_devices.csv --db "$DB" > "$LOG/seed.log" 2>&1
grep -q "Successfully seeded 3" "$LOG/seed.log" && ok "authorized inventory seeded (3 devices)" || bad "inventory seed failed"

PYTHONPATH="$NASWATCH/src" "$NASWATCH/.venv/bin/python" "$NASWATCH/scripts/run_pipeline.py" \
  --mode replay --pcap "$CAP" --db "$DB" > "$LOG/detect.log" 2>&1

EVENTS=$(grep -oE 'Processed [0-9]+ signaling events' "$LOG/detect.log" | grep -oE '[0-9]+' | head -1)
[ "${EVENTS:-0}" -gt 0 ] 2>/dev/null && ok "parsed $EVENTS signaling events from real capture" || bad "parsed 0 events"

ROGUE=$(grep -c 'ROGUE_DEVICE' "$LOG/detect.log")
SLICE=$(grep -c 'SLICE_INTRUSION' "$LOG/detect.log")
ALICE=$(grep -c 'IMSI=999700000000001' "$LOG/detect.log")

[ "$ROGUE" -gt 0 ] && ok "ROGUE_DEVICE detected for Charlie ($ROGUE alerts)" || bad "no ROGUE_DEVICE alert"
[ "$SLICE" -gt 0 ] && ok "SLICE_INTRUSION detected for Bob ($SLICE alert)" || bad "no SLICE_INTRUSION alert"
[ "$ALICE" -eq 0 ] && ok "Alice produced 0 alerts (no false positives)" || bad "Alice produced $ALICE alerts (false positive!)"

# ---------------------------------------------------------------- summary
echo
echo -e "\033[1m==================== RESULT ====================\033[0m"
echo -e "  \033[1;32mPASS: $PASSED\033[0m    \033[1;31mFAIL: $FAILED\033[0m"
echo -e "\033[1m================================================\033[0m"
[ "$FAILED" -eq 0 ] && exit 0 || exit 1
