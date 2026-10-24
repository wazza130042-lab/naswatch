# NASWatch — Live 5G Demo: Step-by-Step Presenter Runbook

This is the **same flow as `scripts/live_lab_demo.sh`**, but split into individual
steps so you run, show and explain each one to your audience instead of firing a
single one-shot script.

It uses a **real 5G core** (Open5GS — real 3GPP network functions, real NGAP/NAS
over SCTP, real 5G-AKA authentication) with **UERANSIM** as the software gNB and
phones. NASWatch watches the gNB↔AMF interface and raises the alerts.

> **One-shot verification:** `scripts/verify_lab.sh` runs the whole flow from a
> cold start — core + UPF + gNB, all three UEs, packet capture, and NASWatch
> detection — printing a PASS/FAIL line per check. Run it to confirm the lab
> works before presenting: `scripts/verify_lab.sh`. It exits non-zero on any
> failure. Use the step-by-step runbook below when you want to narrate.

---

## How this maps to `live_lab_demo.sh`

| Script phase | Runbook step | What the audience sees |
|---|---|---|
| `1/6 Starting Open5GS 5G core` | Step 1 | 8 real network-function processes |
| (subscriber seeding inside phase 1) | Step 2 | Alice & Bob in the subscriber DB, Charlie absent |
| `2/6 Launching simulated gNB` | Step 3 | gNB ⇄ AMF **NG Setup OK** |
| `3/6 Capturing REAL N2/N1` | Step 4 | tcpdump writing a pcap of SCTP :38412 |
| `4/6 Scenario A — Alice` | Step 5 | legit registration accepted by the core |
| `5/6 Scenario B — Charlie (rogue)` | Step 6 | core rejects Unknown UE by SUCI |
| `5b/6 Scenario C — Bob (slice-jump)` | Step 7 | AMF rejects the unauthorized slice |
| `6/6 NASWatch detection over capture` | Step 8 | ROGUE_DEVICE + SLICE_INTRUSION alerts |

> Tell your audience up front: **the core, the protocols (NGAP TS 38.413 / NAS
> TS 24.501) and the 5G-AKA authentication are real 3GPP**; only the tower and
> phones are simulated (UERANSIM). No carrier, no SIM cards, one laptop.

---

## Terminal layout

- **Terminal 1** — the 5G core + gNB + packet capture (this is the "network").
- **Terminal 2** — NASWatch detection/dashboard.
- Keep the **SOC dashboard open in a browser** at `http://localhost:8501`.

---

## Phase 0 — Prerequisites (one-time)

Paste these helpers into **Terminal 1** so every later command is short:

```bash
export OPEN5GS_INSTALL="$HOME/open5gs/install"
export LD_LIBRARY_PATH="$OPEN5GS_INSTALL/lib"
export BIN="$OPEN5GS_INSTALL/bin"
export CONF="$HOME/Documents/naswatch/config/open5gs"
export UERANSIM_DIR=/tmp/UERANSIM-3.2.6
export CAP=/home/megbaru/Documents/naswatch/data/pcaps/lab5g_live.pcap
```

### 0a. MongoDB must be reachable on 127.0.0.1:27017

Open5GS stores subscribers in MongoDB. Bring up the lab's Mongo container with a
host port (the existing container has no published port, so the host core can't
reach it):

```bash
docker rm -f open5gs-mongodb 2>/dev/null
docker run -d --name open5gs-mongodb -p 127.0.0.1:27017:27017 mongo:8
sleep 2
docker exec open5gs-mongodb mongosh --quiet --eval 'db.runCommand({ping:1})'
# expect: { ok: 1 }
```

### 0b. UERANSIM must be built (tower + phones)

```bash
wget -q -O /tmp/usim.tgz "https://codeload.github.com/aligungr/UERANSIM/tar.gz/refs/tags/v3.2.6"
cd /tmp && tar xzf usim.tgz && cd UERANSIM-3.2.6

# GCC-15 compatibility patches (adds missing #include directives)
sed -i '/#include <sstream>/a #include <cstdint>'                    src/ext/yaml-cpp/emitterutils.cpp
sed -i '/#include <initializer_list>/a #include <cstddef>\n#include <cstdint>' src/utils/json.hpp
sed -i '/#include "nts.hpp"/a #include <cstdio>\n#include <cstring>\n#include <string>' src/utils/logger.hpp
sed -i '/#include "common.hpp"/a #include <cstdio>\n#include <cstdlib>\n#include <cstring>' src/utils/common.cpp
sed -i '/#include <cstring>/a #include <cstdint>'                    src/lib/rlc/utils.hpp
sed -i '/#include "rlc.hpp"/a #include <cstdio>\n#include <cstring>\n#include <string>' src/lib/rlc/test.cpp
sed -i '/#include <string>/a #include <cstdint>'                     src/lib/sctp/server.hpp

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -G Ninja
cmake --build build -j"$(nproc)"
ls "$UERANSIM_DIR/build/nr-gnb" "$UERANSIM_DIR/build/nr-ue"   # both must exist
```

### 0c. Open5GS is built

```bash
ls "$BIN/open5gs-amfd" "$BIN/open5gs-scpd" "$BIN/open5gs-upfd"   # must exist
```

> **Current state of this machine (verified during a full lab run):** Open5GS ✅
> installed at `~/open5gs/install`; UERANSIM ✅ built under
> `/tmp/UERANSIM-3.2.6/cmake-build-release/`; MongoDB ✅ published on
> `127.0.0.1:27017`. The binaries may live in `cmake-build-release/` rather than
> `build/` depending on how cmake was invoked — point your `$UERANSIM_DIR` at
> whichever directory actually contains `nr-gnb` and `nr-ue`.
>
> **Host capture note:** if `tcpdump` reports *"You don't have permission to
> perform this capture"*, use `dumpcap` instead — it ships with
> `cap_net_admin,cap_net_raw` and works as a normal user in the `wireshark`
> group. Write the pcap somewhere your user owns (e.g. `/tmp/`), not into a
> root-owned directory.

---

## Step 1 — Start the 5G core (7 network functions)

Run each NF as its own process so you can point at the process list.

```bash
# clean any leftovers from a previous run
pkill -f "$BIN/open5gs" 2>/dev/null; sleep 1

# NRF (registry) then SCP (service comms proxy)
"$BIN/open5gs-nrfd" -c "$OPEN5GS_INSTALL/etc/open5gs/nrf.yaml" > /tmp/naswatch-nrf.log  2>&1 & sleep 1
"$BIN/open5gs-scpd" -c "$OPEN5GS_INSTALL/etc/open5gs/scp.yaml" > /tmp/naswatch-scpd.log 2>&1 &
sleep 1

"$BIN/open5gs-amfd" -c "$CONF/amf.yaml" > /tmp/naswatch-amfd.log 2>&1 &
sleep 1
"$BIN/open5gs-smfd" -c "$CONF/smf.yaml" > /tmp/naswatch-smfd.log 2>&1 &
sleep 1
"$BIN/open5gs-upfd" > /tmp/naswatch-upfd.log 2>&1 &
sleep 1
"$BIN/open5gs-udmd" > /tmp/naswatch-udmd.log 2>&1 &
"$BIN/open5gs-udrd" > /tmp/naswatch-udrd.log 2>&1 &
"$BIN/open5gs-ausfd" > /tmp/naswatch-ausfd.log 2>&1 &
"$BIN/open5gs-pcfd" > /tmp/naswatch-pcfd.log 2>&1 &
sleep 3
```

**If `open5gs-upfd` dies immediately**, check its log. Creating the `ogstun`
device needs `CAP_NET_ADMIN`, so an unprivileged run fails with:

```
[upf] ERROR: tun_open(dev:ogstun) failed
[app] ERROR: Failed to initialize UPF
```

Either run it under `sudo` (`sudo "$BIN/open5gs-upfd"`), or run it in a
privileged container that shares the host network namespace — no root needed
on the host. Working artifacts live in `config/open5gs/container/`:

```bash
# one-time: image with the Open5GS runtime libraries
docker build -f config/open5gs/container/upf.Dockerfile \
  -t naswatch-upf:local config/open5gs/container

docker run -d --name naswatch-upf --network host \
  --cap-add NET_ADMIN --cap-add SYS_ADMIN --device /dev/net/tun \
  -v "$OPEN5GS_INSTALL:/opt/open5gs:ro" \
  -v "$PWD/config/open5gs/container/upf-container.yaml:/etc/open5gs/upf.yaml:ro" \
  naswatch-upf:local -c /etc/open5gs/upf.yaml
```

Two details that will bite you otherwise:

- The image must match the host's shared libraries. On Kali/rolling build it
  `FROM kalilinux/kali-rolling`; `debian:bookworm` fails on `libtins` version.
- Mount the UPF config with the logger path rewritten. A `:ro` mount of the
  install tree means Open5GS cannot open its default log file and the UPF
  exits with *"cannot open log file"*. `upf-container.yaml` removes the
  `logger.file` block so it logs to stdout.

**Confirm the control plane is happy** — the SMF must show PFCP associated with
the UPF, otherwise PDU sessions are rejected with *"No associated UPF"*:

```bash
grep -i "PFCP associated" "$OPEN5GS_INSTALL/var/log/open5gs/smf.log" | tail -1
```

**Show the audience it's real:**

```bash
pgrep -af "install/bin/open5gs"   # ~9 separate 3GPP network functions
```

**What to say:** *"This is a real 5G core — NRF, SCP, AMF, SMF, UPF, UDM, UDR,
AUSF, PCF — each is a genuine 3GPP network function, running on this laptop."*

---

## Step 1b — Seed the subscribers (the core's UDM/UDR data)

```bash
docker exec open5gs-mongodb mongosh --quiet open5gs --eval '
db.subscribers.deleteMany({});
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
// NOTE: the field must be named "slice" (not "slices"). Open5GS 2.x reads
// subscribers.slice; a document with "slices" is treated as an unknown UE and
// 5G-AKA then fails with a SEP-BIT / Non-5GS-authentication-unacceptable error.
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
provision("999700000000001", [makeSlice(1, "000001", true)]);                 // Alice -> SST 1
provision("999700000000002", [makeSlice(1, "000001", true), makeSlice(3, "000003", false)]); // Bob: SST 1+3 only
print("Seeded: Alice (1), Bob (1,3).  Charlie (…003) intentionally NOT provisioned.");
db.subscribers.find({},{imsi:1,"slice.sst":1,"slice.sd":1,_id:0}).forEach(printjson);
'
```

**What to say:** *"Alice and Bob are real subscribers with real 5G-AKA keys.
Charlie's IMSI is deliberately absent — he represents a deprovisioned / rogue
device."*

---

## Step 2 — Start the cell tower (UERANSIM gNB)

```bash
"$UERANSIM_DIR/build/nr-gnb" -c "$CONF/gnb.yaml" > /tmp/naswatch-gnb.log 2>&1 &
sleep 5
grep -i "NG Setup procedure is successful" /tmp/naswatch-gnb.log \
  && echo "  [OK] gNB <-> AMF NG Setup OK"
tail -3 /tmp/naswatch-gnb.log
```

**What to say:** *"The tower just completed the NG Setup handshake with the AMF
over SCTP — that's the N2 interface NASWatch monitors."*

---

## Step 2b — Start the packet capture (the passive tap)

Needs root for the capture only:

```bash
sudo tcpdump -i lo -w "$CAP" 'sctp or port 38412' 2>/tmp/naswatch-tcpdump.err &
sleep 2
sudo tcpdump -r "$CAP" -c 1 >/dev/null 2>&1 && echo "capture live -> $CAP"
```

**What to say:** *"We're recording the raw N2/N1 signaling on loopback port
38412 — exactly what a passive sensor sees in a real network."*

---

## Step 3 — Scenario A: Alice (legitimate device)

```bash
"$UERANSIM_DIR/build/nr-ue" -c "$CONF/ue.yaml" > /tmp/naswatch-ue-alice.log 2>&1 &
ALICE=$!
sleep 12
grep -i "Initial Registration is successful" /tmp/naswatch-ue-alice.log \
  && echo "  [OK] Alice registered — core accepted"
kill $ALICE 2>/dev/null
```

**Show the core's view (AMF log):**

```bash
grep -i "accept" /tmp/naswatch-amfd.log | tail -2
```

**What to say:** *"Alice authenticates with real 5G-AKA and the AMF accepts her —
the baseline. NASWatch should stay silent."*

---

## Step 4 — Scenario B: Charlie (rogue / unprovisioned device)

```bash
"$UERANSIM_DIR/build/nr-ue" -c "$CONF/ue-charlie.yaml" > /tmp/naswatch-ue-charlie.log 2>&1 &
CHARLIE=$!
sleep 12
grep -i "Initial Registration failed" /tmp/naswatch-ue-charlie.log \
  && echo "  [OK] core rejected Charlie"
kill $CHARLIE 2>/dev/null
```

**Show the core's view:**

```bash
grep -i "Unknown UE by SUCI" /tmp/naswatch-amfd.log | tail -2
```

**What to say:** *"Charlie's device isn't in the subscriber DB, so the AMF rejects
him — 'Unknown UE by SUCI'. This is the rogue-device attack."*

---

## Step 5 — Scenario C: Bob (slice-jump / slice intrusion)

```bash
"$UERANSIM_DIR/build/nr-ue" -c "$CONF/ue-rogue.yaml" > /tmp/naswatch-ue-bob.log 2>&1 &
BOB=$!
sleep 12
grep -F 'Ue requested DNN "internet" Not Supported OR Not Subscribed in the Slice' \
  /tmp/naswatch-amfd.log | tail -2
kill $BOB 2>/dev/null
```

**What to say:** *"Bob is authorized only for slices 1 and 3, but his UE asks to
establish a session on slice 4. The AMF rejects it — that's the slice-intrusion
attack."*

---

## Step 5b — Stop the capture

```bash
sudo pkill -f "tcpdump -i lo" 2>/dev/null; sleep 1
ls -lh "$CAP"     # real captured N2/N1 traffic
```

---

## Step 6 — Run NASWatch detection over the captured signaling

In **Terminal 2** (or same terminal):

```bash
cd ~/Documents/naswatch
PYTHONPATH=src python3 scripts/run_pipeline.py \
  --mode replay \
  --pcap "$CAP" \
  --db data/inventory.db
```

**Expected output:** `Processed N signaling events` plus alerts including
`ROGUE_DEVICE` (Charlie) and `SLICE_INTRUSION` (Bob).

**What to say:** *"NASWatch replayed the real captured N2/N1 signaling through
its detection rules and produced the alerts a SOC would see."*

---

## Step 6b — Show them in the SOC dashboard

Open `http://localhost:8501`, sign in, and walk through:

1. **Incidents** — the new ROGUE_DEVICE / SLICE_INTRUSION rows, with RAW EVENT evidence.
2. **Network topology** — `0x10` Central-Site-A lighting up; a rogue cell in red.
3. **Asset inventory** — the subscribers and their slice entitlements.
4. **Launch response** on an incident → **Quarantine** / **Revoke UDM**, then show
   the device status change + the audit entry.

---

## Teardown

```bash
pkill -af "install/bin/open5gs" 2>/dev/null
pkill -af "nr-gnb|nr-ue" 2>/dev/null
docker stop open5gs-mongodb 2>/dev/null
echo "lab down."
```

---

## If the prerequisites can't be restored in time

Fall back to the **synthetic** demo (already working in Docker, no rebuild):

- **Terminal 1 (sensor):** `docker compose exec naswatch-api python scripts/run_pipeline.py --mode live --interface lo`
- **Terminal 2 (attacker):** `docker compose exec naswatch-api python scripts/attack_5g.py --scenario rogue`, then `--scenario slice-intrusion`, then `--scenario flood`

Same detection rules and same SOC alerts — just protocol-accurate injected
traffic instead of a live Open5GS core. Be transparent about which one you're
showing.
