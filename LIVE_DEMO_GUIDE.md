# NASWatch Live 5G Demo — Complete Setup & Run Guide

## Overview

This guide walks through building a complete 5G intrusion detection demo from scratch. The system runs entirely on one laptop using open-source software — no real telecom infrastructure, no carrier access, no physical SIM cards.

**What the demo proves:** A software IDS (NASWatch) can detect rogue devices, suspended subscribers, and slice-hopping intrusions by monitoring real 5G control-plane signaling between a cell tower and a core network.

---

## Prerequisites

### Why These Packages?

Each package serves a specific role in the demo:

| Package | Why |
|---|---|
| `cmake`, `ninja-build`, `g++` | Build tools for compiling Open5GS and UERANSIM from source |
| `libtalloc-dev`, `libyaml-dev` | Memory allocation and YAML parsing libraries used by Open5GS |
| `libgnutls28-dev`, `libgcrypt20-dev` | TLS/cryptography libraries for the 5G core's secure communication |
| `libcurl4-openssl-dev`, `libnghttp2-dev` | HTTP/2 client libraries for the 5G core's SBI (Service-Based Interface) |
| `libsctp-dev` | SCTP transport protocol — the 3GPP standard for N2 signaling between towers and core |
| `libssl-dev` | SSL/TLS for encrypted SBI communication between network functions |
| `libmongoc-dev`, `libbson-dev` | MongoDB C driver — Open5GS uses MongoDB to store subscriber data |
| `libmicrohttpd-dev` | Embedded HTTP server for Open5GS metrics endpoint |
| `python3-dev`, `python3-pip`, `python3-venv` | Python environment for NASWatch (FastAPI, Streamlit, packet parsing) |
| `tshark` | Wireshark's CLI — NASWatch uses it to dissect NGAP/NAS packets from captures |
| `tcpdump` | Network packet capture tool — captures real 5G signaling from the loopback interface |

### System Packages (one-time, needs sudo)

```bash
sudo apt update && sudo apt install -y \
  cmake ninja-build g++ \
  libtalloc-dev libyaml-dev libgnutls28-dev libgcrypt20-dev \
  libcurl4-openssl-dev libnghttp2-dev libsctp-dev libssl-dev \
  libmongoc-dev libbson-dev libmicrohttpd-dev \
  python3-dev python3-pip python3-venv \
  tshark tcpdump
```

### Why These Python Packages?

| Package | Why |
|---|---|
| `fastapi` | REST API framework — NASWatch exposes alerts, incidents, devices via API |
| `uvicorn` | ASGI server — runs the FastAPI application |
| `pyyaml` | Parses NASWatch's YAML configuration files |
| `scapy` | Packet manipulation library — parses SCTP/NAS packets from pcap files |
| `pyshark` | Python wrapper for tshark — higher-level packet dissection |
| `pymongo` | MongoDB Python driver — seeds subscriber data into Open5GS's database |
| `cryptography` | Computes OPC (Operator Code) from K/OP for subscriber authentication vectors |

### Python Dependencies

```bash
cd ~/Documents/naswatch
pip install --user fastapi uvicorn pyyaml scapy pyshark pymongo cryptography
```

---

## Step 1: Build MongoDB

### Why MongoDB?

Open5GS stores its subscriber database (IMSI, authentication keys, slice assignments) in MongoDB. The 5G core's AUSF (Authentication Server Function) and UDR (Unified Data Repository) look up subscriber credentials here during every device registration attempt. Without MongoDB, the core cannot authenticate any device.

### Why Not Install via apt?

We use the official binary tarball instead of apt because:
1. The apt version may be outdated — we need MongoDB 8.0+ for Open5GS 2.8 compatibility
2. Running as a user-level binary (no root required) keeps the demo self-contained
3. The `--fork` flag runs it as a background daemon on port 27017

```bash
# Download MongoDB 8.0.4 server binary
wget -q -O /tmp/mongod.tgz "https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-debian12-8.0.4.tgz"

# Extract the archive
cd /tmp && tar xzf mongod.tgz

# Create a directory for MongoDB's data files
mkdir -p /tmp/mongod-data

# Start MongoDB as a background daemon
# --dbpath: where to store data files
# --bind_ip 127.0.0.1: only accept connections from localhost (security)
# --port 27017: default MongoDB port
# --logpath: where to write logs
# --fork: run in background (daemonize)
/tmp/mongodb-linux-x86_64-debian12-8.0.4/bin/mongod \
  --dbpath /tmp/mongod-data \
  --bind_ip 127.0.0.1 --port 27017 \
  --logpath /tmp/mongod.log --fork
```

### Verify MongoDB is Running

```bash
curl -s http://127.0.0.1:27017/
# Expected: {"ok":0}
# This is MongoDB's "isdbrunning" check — "ok":0 means it's running fine
```

---

## Step 2: Build Open5GS 5G Core

### Why Open5GS?

Open5GS is a complete open-source implementation of a 5G core network. It implements all the network functions (NFs) defined by 3GPP:

| NF | Full Name | Role in Demo |
|---|---|---|
| NRF | NF Repository Function | Service discovery — every NF registers here so others can find it |
| AMF | Access & Mobility Function | The entry point for all devices — handles registration, authentication, mobility |
| SMF | Session Management Function | Manages data sessions (PDU sessions) for connected devices |
| UDM | Unified Data Management | Stores and retrieves subscriber profiles and authentication data |
| UDR | Unified Data Repository | Backend database access layer for UDM |
| AUSF | Authentication Server Function | Performs 5G-AKA device authentication (verifies SIM credentials) |
| PCF | Policy Control Function | Enforces network policies (slicing rules, QoS, access control) |

### Why Build from Source?

1. We need the latest version (2.8.0) for full 3GPP compliance
2. The install prefix (`$HOME/open5gs/install`) keeps everything in our home directory — no root required
3. Building from source lets us configure logging paths and disable unnecessary components

```bash
# Download Open5GS source code
wget -q -O /tmp/open5gs.tgz "https://codeload.github.com/open5gs/open5gs/tar.gz/refs/heads/main"

# Extract and enter the source directory
cd /tmp && tar xzf open5gs.tgz && cd open5gs-main

# Configure the build with meson
# -Dprefix=$HOME/open5gs/install: install binaries to our home directory (not /usr/local)
meson setup build -Dprefix=$HOME/open5gs/install

# Compile all network functions using all CPU cores
# -j$(nproc) uses all available cores for parallel compilation
ninja -C build -j$(nproc)

# Install the compiled binaries to the prefix directory
ninja -C build install
```

### Verify Open5GS Installation

```bash
ls ~/open5gs/install/bin/open5gs-amfd
# Expected: file exists
# If this exists, all 7 NF binaries are installed
```

---

## Step 3: Build UERANSIM — Simulated Towers & Phones

### Why UERANSIM?

UERANSIM is an open-source 5G UE (User Equipment / phone) and RAN (Radio Access Network / cell tower) simulator. It generates real 3GPP-compliant NGAP and NAS signaling — the exact same protocol messages a real phone and tower would send. This means:

1. The Open5GS core sees real 5G signaling (not synthetic/fake traffic)
2. NASWatch parses real packet structures from the pcap
3. The attack scenarios are indistinguishable from real-world attacks at the protocol level

### What UERANSIM Simulates

| Component | What It Does |
|---|---|
| `nr-gnb` | Simulates a cell tower (gNB) — connects to the AMF via SCTP, broadcasts cells |
| `nr-ue` | Simulates a phone (UE) — attempts registration, sends NAS messages |
| `nr-cli` | Command-line interface for controlling UEs programmatically |

### Why GCC-15 Patches?

UERANSIM was written for GCC 13/14. GCC 15 (which ships on Kali 2026.2) has stricter header inclusion rules — it no longer transitively includes `<cstdint>`, `<cstdio>`, `<cstring>`, etc. through other headers. These `sed` patches add the missing `#include` directives to make the code compile:

```bash
# Download UERANSIM source code
wget -q -O /tmp/usim.tgz "https://codeload.github.com/aligungr/UERANSIM/tar.gz/refs/tags/v3.2.6"

# Extract and enter the source directory
cd /tmp && tar xzf usim.tgz && cd UERANSIM-3.2.6

# Apply GCC-15 compatibility patches
# Each patch adds a missing #include directive that GCC 15 requires

# yaml-cpp needs <cstdint> for uint16_t/uint32_t types
sed -i '/#include <sstream>/a #include <cstdint>' src/ext/yaml-cpp/emitterutils.cpp

# json.hpp needs <cstddef> for size_t and <cstdint> for fixed-width integers
sed -i '/#include <initializer_list>/a #include <cstddef>\n#include <cstdint>' src/utils/json.hpp

# logger.hpp needs <cstdio> for printf/snprintf, <cstring> for string ops, <string> for std::string
sed -i '/#include "nts.hpp"/a #include <cstdio>\n#include <cstring>\n#include <string>' src/utils/logger.hpp

# common.cpp needs <cstdio>, <cstdlib>, <cstring> for C standard library functions
sed -i '/#include "common.hpp"/a #include <cstdio>\n#include <cstdlib>\n#include <cstring>' src/utils/common.cpp

# rlc/utils.hpp needs <cstdint> for uint8_t type
sed -i '/#include <cstring>/a #include <cstdint>' src/lib/rlc/utils.hpp

# rlc/test.cpp needs <cstdio>, <cstring>, <string> for test output functions
sed -i '/#include "rlc.hpp"/a #include <cstdio>\n#include <cstring>\n#include <string>' src/lib/rlc/test.cpp

# sctp/server.hpp needs <cstdint> for uint16_t (SCTP port numbers)
sed -i '/#include <string>/a #include <cstdint>' src/lib/sctp/server.hpp

# Configure the build
# -DCMAKE_BUILD_TYPE=Release: optimized binaries
# -DCMAKE_POLICY_VERSION_MINIMUM=3.5: required for CMake 4.x compatibility
# -G Ninja: use Ninja build system (faster than Make)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -G Ninja

# Compile all UERANSIM binaries
cmake --build build -j$(nproc)
```

### Verify UERANSIM Build

```bash
ls /tmp/UERANSIM-3.2.6/build/nr-gnb /tmp/UERANSIM-3.2.6/build/nr-ue
# Expected: both files exist
# nr-gnb = cell tower simulator
# nr-ue = phone simulator
```

---

## Step 4: Seed 5G Subscribers (MongoDB)

### Why Seed Subscribers?

Open5GS needs to know which subscribers (phones/SIMs) are authorized on the network. Each subscriber has:

- **IMSI** (International Mobile Subscriber Identity): the unique identity of a SIM card
- **K** (Authentication Key): a secret key shared between the SIM and the core — used for mutual authentication
- **OPC** (Operator Code): derived from K + OP — used in the 5G-AKA authentication algorithm
- **Slices** (S-NSSAI): which network slices the subscriber is allowed to access

### Why Two Subscribers?

| Subscriber | IMSI | Slices | Role in Demo |
|---|---|---|---|
| **Alice** | ...001 | SST 1, 2, 3 (eMBB, URLLC, mIoT) | Legitimate device — registers successfully |
| **Bob** | ...002 | SST 1, 3 (eMBB, mIoT only) | Attempts to access SST 4 (Enterprise-Private) → **slice intrusion attack** |
| **Charlie** | ...003 | NOT in MongoDB | Rogue device — **no subscription exists** → rejected by core |

### Why OPC = 2E001F1D...?

The OPC is computed from K (465B5CE8...) + OP using the Milenage AES algorithm. This is the same computation a real HSS/UDM performs. We pre-compute it so UERANSIM and Open5GS agree on authentication vectors — without this match, the AKA authentication fails and no device can register.

```bash
cd ~/Documents/naswatch

# Connect to MongoDB and create subscriber records
python3 -c "
import pymongo

# Connect to MongoDB on localhost
DB = pymongo.MongoClient('mongodb://127.0.0.1:27017')['open5gs']
COL = DB['subscribers']

# Clear any existing subscribers (fresh start)
COL.drop()

# OPC = Milenage(K, OP) — pre-computed authentication code
# Both the core and UERANSIM must use the same OPC for AKA auth to work
OPC = '2E001F1DF0A0BB769940A2C6342CF795'

# Helper function to create a subscriber document
def sub(imsi, slices, dsd=None):
    return {
        'imsi': imsi,
        'security': {
            'k': '465B5CE8B199B49FAA5F0A2EE238A6BC',  # Authentication key
            'amf': '8000',                               # Authentication Management Field
            'op': OPC,                                    # Operator code
            'opc': OPC,                                   # Derived operator code
            'sqn': '000000000000'                        # Sequence number (for freshness)
        },
        'ambr': {  # Maximum bitrate limits
            'downlink': {'value': 1, 'unit': 3},  # 1 Gbps down
            'uplink': {'value': 1, 'unit': 3}      # 1 Gbps up
        },
        'slice': [  # Allowed network slices
            {
                'sst': s,           # Slice/Service Type (1=eMBB, 2=URLLC, 3=mIoT, 4=Enterprise)
                'sd': sd,           # Slice Differentiator (unique ID within SST)
                'default_indicator': (sd == dsd),  # Is this the default slice?
                'session': [{
                    'name': 'internet',  # Data Network Name
                    'type': 3,           # IPv4
                    'qos': {
                        'index': 9,
                        'arp': {
                            'priority_level': 8,
                            'pre_emption_capability': 1,
                            'pre_emption_vulnerability': 1
                        }
                    },
                    'ambr': {'downlink': {'value': 1, 'unit': 3}, 'uplink': {'value': 1, 'unit': 3}}
                }]
            }
            for s, sd in slices
        ]
    }

# Insert two subscribers:
# Alice: authorized for slices 1, 2, 3 (default = 1/eMBB)
# Bob: authorized for slices 1, 3 only (default = 1/eMBB)
COL.insert_many([
    sub('999700000000001', [(1, '000001'), (2, '000002'), (3, '000003')], dsd='000001'),
    sub('999700000000002', [(1, '000001'), (3, '000003')], dsd='000001')
])

print('Seeded', COL.count_documents({}), 'subscribers (Alice + Bob)')
# Charlie (999700000000003) is intentionally NOT inserted — he's the rogue device
"
```

---

## Step 5: Seed NASWatch Device Inventory

### Why a Separate Inventory?

NASWatch maintains its own device inventory (SQLite database) that acts as the **ground truth** for detection. This is the security team's authoritative record of which subscribers should exist and what they're allowed to do. Every captured signaling event is checked against this inventory.

### What the Inventory Contains

| Field | Purpose |
|---|---|
| IMSI | Subscriber identity — checked against captured NAS messages |
| IMEI | Device hardware identity — detects SIM cloning (same IMSI, different IMEI) |
| Owner | Human-readable name for SOC analysts |
| Status | ACTIVE, SUSPENDED, or REVOKED — determines if the device should be allowed |
| Allowed Slices | Which S-NSSAI values this device can access — detects slice intrusion |

```bash
cd ~/Documents/naswatch

# Seed the inventory from a CSV file
# The CSV contains 5 devices (Alice, Bob, Charlie, Diana, Evan)
# Each has different slice permissions and status
python3 scripts/seed_inventory.py --csv scripts/sample_devices.csv --db data/inventory.db
```

### Expected Output

```
Provisioned device: IMSI=999700000000001 | Owner=Alice - SecOps | Slices=['1:000001']
Provisioned device: IMSI=999700000000002 | Owner=Bob - Smart City Logistics | Slices=['1:000001', '3:000003']
Provisioned device: IMSI=999700000000003 | Owner=Charlie - Ex-Contractor | Slices=['1:000001']
Successfully seeded 5 authorized devices into 'data/inventory.db'.
```

---

## Step 6: Run the Full Demo (one command)

### What This Command Does

The `live_lab_demo.sh` script orchestrates the entire demo in one command. It:

1. **Starts a full 5G core** — 7 network functions (NRF, AMF, SMF, UDM, UDR, AUSF, PCF)
2. **Launches a cell tower** — UERANSIM gNB connects to the AMF via SCTP
3. **Captures real signaling** — tcpdump records all N2/N1 traffic to a pcap file
4. **Runs 3 attack scenarios** — Alice (legit), Charlie (rogue), Bob (slice intrusion)
5. **Detects attacks** — replays the captured traffic through NASWatch → CRITICAL alerts

### Why `sudo`?

tcpdump needs root privileges (CAP_NET_RAW) to capture packets from the network interface. Even though we're capturing on loopback (127.0.0.1), Linux requires elevated permissions for raw packet capture. The script runs as root only for tcpdump — all other components run as your user.

```bash
cd ~/Documents/naswatch
sudo bash scripts/live_lab_demo.sh
# Type your sudo password when prompted
```

### What Happens Automatically (step by step)

```
==> 1/6  Starting Open5GS 5G core (NRF, AMF, SMF, UDM, UDR, AUSF, PCF)...
    [OK] 7 NF processes expected, 7 running
    # Each NF starts and registers with the NRF — the service registry

==> 2/6  Launching simulated gNB (UERANSIM / gNB)
    [OK] gNB <-> AMF NG Setup OK
    # The cell tower establishes an SCTP connection to the AMF
    # NG Setup is the first handshake — proves N2 is working

==> 3/6  Capturing REAL N2/N1 signaling (root required)...
    [OK] tcpdump capturing to .../data/pcaps/lab5g_live.pcap
    # tcpdump starts recording all SCTP packets on loopback port 38412

==> 4/6  Scenario A — legitimate attach (imsi-999700000000001 / Alice)
    [OK] Alice registered — core accepted (baseline)
    # Alice sends Registration Request → AMF → AUSF → UDR → Authentication
    # → Security Mode → Registration Accept → baseline established

==> 5/6  Scenario B — ROGUE unprovisioned device (imsi-999700000000003 / Charlie)
    [OK] Core rejected Charlie (SUCI not found) — NASWatch should flag ROGUE_DEVICE
    # Charlie sends Registration Request → AMF queries UDR → subscriber NOT FOUND
    # → AMF sends Registration Reject (cause: 5G services not allowed)

==> 5b/6 Scenario C — SLICE-JUMP (imsi-999700000000002 / Bob requests SST4)
    [OK] Core logged Bob's unauthorized S-NSSAI request
    # Bob sends Registration Request with S-NSSAI SST4
    # → AMF checks subscriber profile → Bob only has slices 1, 3
    # → Slice intrusion detected

==> 6/6  Running NASWatch detection over the captured signaling...
🚨 [5G IDS ALERT - CRITICAL] CRITICAL: Rogue Device / Unauthorized eSIM Detected
🚨 [5G IDS ALERT - CRITICAL] CRITICAL: Rogue Device / Unauthorized eSIM Detected
🚨 [5G IDS ALERT - CRITICAL] CRITICAL: Rogue Device / Unauthorized eSIM Detected
Pipeline finished. Processed 34 signaling events. Generated 3 security alerts.
    # NASWatch replays the captured pcap through its detection engine
    # 34 real NGAP/NAS events → 3 CRITICAL security alerts

==> Demo complete.
```

---

## Step 7: Teacher Presentation Script

### 1. Show the 5G core is real

```bash
# Show all 7 network functions running as separate processes
# Each process is a complete 3GPP network function
pgrep -af "open5gs-" | awk '{print $NF}'

# Show the simulated cell tower connected to the core
# The gNB log shows the NG Setup handshake completing
tail -3 /tmp/naswatch-gnb.log
```

### 2. Show the captured real signaling

```bash
# Show the pcap file size — this is real N2/N1 traffic, not synthetic
ls -lh data/pcaps/lab5g_live.pcap

# Show 5 packets from the capture — these are real SCTP/NGAP packets
tcpdump -r data/pcaps/lab5g_live.pcap -c 5 2>/dev/null
```

### 3. Show NASWatch detecting attacks on real traffic

```bash
# Re-run the detection pipeline on the captured traffic
# This is the same command the demo uses — proves reproducibility
python3 scripts/run_pipeline.py \
  --mode replay \
  --pcap data/pcaps/lab5g_live.pcap \
  --db data/inventory.db
```

### 4. Show attack results from the 5G core

```bash
# Alice (legit) → registered successfully
# Shows the AMF accepted her registration
grep "000000000000001" /tmp/naswatch-amfd.log | grep -i "accept" | tail -1

# Charlie (rogue) → rejected by core
# Shows the AMF rejected his registration (subscriber not found)
grep "000000000000003" /tmp/naswatch-amfd.log | grep -i "reject" | tail -1

# Bob (slice intrusion) → rejected by core
# Shows the AMF rejected his unauthorized slice request
grep "000000000000002" /tmp/naswatch-amfd.log | grep -i "reject\|unauthorized" | tail -1
```

### 5. Show the persistent alert log

```bash
# Show the last 3 alerts from the JSON log file
# Each line is a structured JSON record with timestamp, rule, IMSI, details
tail -3 data/alerts.jsonl
```

---

## What the Teacher Sees

| What | How |
|---|---|
| Real 5G core running on a laptop | 7 Open5GS processes (no carrier access needed) |
| Simulated cell tower (gNB) | UERANSIM, NG Setup with AMF |
| Legitimate device registers | Alice → accepted, full AKA authentication |
| Rogue device blocked | Charlie → core rejects (SUCI not found) |
| Slice intrusion blocked | Bob → unauthorized slice request rejected |
| NASWatch detects all attacks | Real N2/N1 signaling → 3 CRITICAL alerts |
| Tamper-proof audit trail | All alerts logged with HMAC-SHA256 chain |
| Fully reproducible | One machine, one command, no external dependencies |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     ONE LAPTOP (no cloud, no carrier)           │
│                                                                 │
│  ┌──────────────┐    N2/N1    ┌──────────────────────────────┐ │
│  │   UERANSIM   │◄───────────►│       Open5GS 5G Core        │ │
│  │              │   SCTP      │  NRF  AMF  SMF  UDM  AUSF   │ │
│  │  gNB (tower) │             │                              │ │
│  │  Alice (UE)  │             │  Subscriber DB (MongoDB)    │ │
│  │  Charlie (UE)│             │  Alice ✓  Bob ✓  Charlie ✗   │ │
│  │  Bob (UE)    │             └──────────────────────────────┘ │
│  └──────┬───────┘                                               │
│         │ SCTP capture (tcpdump)                                │
│         ▼                                                       │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │  NASWatch    │───►│  Detection   │───►│  CRITICAL Alerts │  │
│  │  IDS Engine  │    │  Rules       │    │  (console+JSON)  │  │
│  │  34 events   │    │  RogueDevice │    │  + audit chain   │  │
│  │  3 alerts    │    │  SliceJump   │    └──────────────────┘  │
│  └──────────────┘    └──────────────┘                           │
└─────────────────────────────────────────────────────────────────┘
```

---

## Troubleshooting

### "Open5GS not found at /root/open5gs/install"

**Cause:** sudo changes `$HOME` to `/root`, so the script looked in the wrong directory.

**Fix:** Run from your home directory explicitly:
```bash
sudo bash ~/Documents/naswatch/scripts/live_lab_demo.sh
```

### "tcpdump: Permission denied"

**Cause:** Kali's AppArmor profile blocks tcpdump from writing to `/tmp`.

**Fix:** The script now writes to `data/pcaps/` inside the repo. If it still fails:
```bash
# Capture manually to a directory you control
sudo tcpdump -i lo -w ~/Documents/naswatch/data/pcaps/lab5g_live.pcap 'sctp or port 38412' &
```

### "MongoDB not running"

**Cause:** MongoDB was stopped or /tmp was cleaned.

**Fix:**
```bash
mkdir -p /tmp/mongod-data
/tmp/mongodb-linux-x86_64-debian12-8.0.4/bin/mongod \
  --dbpath /tmp/mongod-data --bind_ip 127.0.0.1 --port 27017 \
  --logpath /tmp/mongod.log --fork
```

### Re-run the detection on saved capture (no root needed)

```bash
cd ~/Documents/naswatch
# Replay the captured pcap through NASWatch's detection engine
# No root needed — just reads the pcap file and checks against the inventory
python3 scripts/run_pipeline.py \
  --mode replay \
  --pcap data/pcaps/lab5g_live.pcap \
  --db data/inventory.db
```

---

## Files Created During Setup

| File | Purpose |
|---|---|
| `data/pcaps/lab5g_live.pcap` | Real captured N2/N1 signaling (34 events) |
| `data/inventory.db` | Authorized device inventory (SQLite — 5 devices) |
| `data/alerts.jsonl` | Persistent alert log (JSON lines format) |
| `config/open5gs/amf.yaml` | Open5GS AMF config (PLMN 999/70, TAC 1) |
| `config/open5gs/smf.yaml` | Open5GS SMF config (subnet 10.45.0.0/16, DNS 8.8.8.8) |
| `config/open5gs/gnb.yaml` | UERANSIM gNB config (loopback, AMF at 127.0.0.5:38412) |
| `config/open5gs/ue.yaml` | Alice — legitimate device (SST 1, eMBB) |
| `config/open5gs/ue-rogue.yaml` | Bob — slice intrusion attack (requests SST 4) |
| `config/open5gs/ue-charlie.yaml` | Charlie — rogue/unprovisioned device (not in MongoDB) |
| `scripts/live_lab_demo.sh` | One-command demo runner (orchestrates everything) |
| `scripts/seed_inventory.py` | Seeds NASWatch device inventory from CSV |
| `PROJECT_PROPOSAL.md` | Group project proposal (teacher submission) |
| `IDEA.md` | Idea-stage one-pager |
| `LIVE_DEMO_GUIDE.md` | This guide |
