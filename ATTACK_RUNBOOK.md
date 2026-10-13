# NASWatch — Real Terminal Attack Runbook

Attack the 5G control-plane from the **terminal** (not the SOC "Attack simulator"
buttons) and watch NASWatch detect it live.

Two things are involved:

| Role | What it is | Where it runs |
|------|------------|---------------|
| **Attack tool** | `scripts/attack_5g.py` — a Scapy-based rogue-UE that forges real **5G NAS** signaling over **SCTP :38412** (the N2 / gNB↔AMF interface) | terminal → inside `naswatch-api` container |
| **Sensor** | NASWatch `run_pipeline.py --mode live` — sniffs the interface, parses NGAP/NAS, runs the detection rules, writes alerts to the DB | terminal → inside `naswatch-api` container |

The sensor and the attacker share the container's network namespace, so every
forged NAS frame the attacker puts on the wire is seen by the IDS and scored.
Alerts land in the same SQLite database the **SOC dashboard** reads, so they
appear on the *Incidents* page within seconds.

> The tool only sends 5G NAS control-plane signaling on the loopback interface
> `lo` of the lab container. It is for authorised testing of this lab only.

---

## 1. Prerequisites

```bash
cd /home/megbaru/Documents/naswatch
docker compose up -d
docker compose ps          # naswatch-api, naswatch-ui, naswatch-prometheus healthy
```

Open the dashboard: <http://localhost:8501> and sign in as `admin@naswatch.io`.
If the account has two-factor authentication enrolled (**Settings ⚙ → Security**), the login form
asks for the 6-digit authenticator-app code after the password.

> **Why root?** Sending raw/SCTP frames and sniffing the interface both need the
> `NET_RAW` capability. The containers run as an unprivileged user, so the
> sensor and the tool are launched with `docker compose exec -u 0 ...`. The
> script restores `/app/data` ownership to the app user afterwards.

---

## 2. One-command demo (recommended)

```bash
# legitimate baseline, then every attack scenario, with live detection
scripts/live_attack_demo.sh

# or a single scenario
scripts/live_attack_demo.sh rogue
scripts/live_attack_demo.sh slice-intrusion
```

The script arms the sensor, fires the attack, stops the sensor, restores file
ownership, and prints the alert delta and the newest detections.

---

## 3. Step-by-step (run each command yourself)

### Step 1 — Arm the live sensor

```bash
docker compose exec -u 0 -d naswatch-api sh -c \
  'cd /app && timeout 90 python /app/scripts/run_pipeline.py \
     --mode live --interface lo > /tmp/naswatch_live.log 2>&1'
```

Wait until it reports it is listening:

```bash
docker compose exec -T naswatch-api tail -1 /tmp/naswatch_live.log
# ... "Starting live capture on interface 'lo' (BPF: 'sctp or port 38412')"
```

### Step 2 — Legitimate baseline (should NOT alert)

```bash
docker compose exec -u 0 -T naswatch-api \
  python /app/scripts/attack_5g.py --scenario legitimate
```

A known subscriber (`999700000000001`) with the **correct** IMEI registers.
No alert is generated — this proves the IDS does not fire on normal traffic.

### Step 3 — Fire the attack

```bash
docker compose exec -u 0 -T naswatch-api \
  python /app/scripts/attack_5g.py --scenario all
```

### Step 4 — Watch the detections

```bash
# live sensor log (pretty-printed alerts)
docker compose exec -T naswatch-api sh -c 'tail -f /tmp/naswatch_live.log'
```

…or open the dashboard **Incidents** page.

### Step 5 — Stop the sensor and tidy up

```bash
# the sensor runs as root, so stop it as root (SIGKILL); plain `kill` is ignored
docker compose exec -u 0 -T naswatch-api sh -c 'for p in /proc/[0-9]*; do
  pid=${p#/proc/}; [ "$pid" = "$$" ] && continue
  c=$(tr "\0" " " < "$p/cmdline" 2>/dev/null || true)
  case "$c" in python*run_pipeline*|timeout*run_pipeline*) kill -9 "$pid" 2>/dev/null || true;; esac
done'

docker compose exec -u 0 -T naswatch-api chown -R 10001:10001 /app/data
```

---

## 4. Attack scenarios → expected NASWatch detections

`scripts/attack_5g.py` sends plaintext 5GS NAS messages (Registration Request,
Identity Response, Security Mode Complete, PDU Session Establishment Request)
carrying crafted subscriber identities. Each scenario maps to a detector:

| Scenario | What is forged | Expected alert | Severity |
|----------|----------------|----------------|----------|
| `legitimate` | Known IMSI `...001` + correct IMEI `860123456789012` | *(none)* | — |
| `rogue` | Unknown IMSI `999700000000999` registers | `Rogue Device / Unauthorized eSIM` | **CRITICAL** |
| `suspended` | IMSI `999700000000003` (provisioned as SUSPENDED) attaches | `SUSPENDED Subscriber Access Attempt` | **CRITICAL** |
| `sim-clone` | Known IMSI `...001` presented with spoofed IMEI `869999999999999` | `Identity Spoofing / SIM Cloning` | **HIGH** |
| `slice-intrusion` | Subscriber `...002` requests unowned slice **SST 2 / SD 000002** | `Unauthorized 5G Network-Slice Access` | **MEDIUM** |
| `flood` | 25 rapid registrations from `...001` | `Signaling Flooding / Registration Storm` | **HIGH** |
| *(all)* | — | all of the above | — |

### Verified results (this lab)

* Baseline (`--scenario legitimate`): **0 new alerts** — no false positive.
* Full run (`--scenario all`): **+21 alerts**, one class per scenario:

```
  CRITICAL  Rogue Device / Unauthorized eSIM Detected        imsi=999700000000999
  CRITICAL  SUSPENDED Subscriber Access Attempt              imsi=999700000000003
  HIGH      Identity Spoofing / SIM Cloning Detected         imsi=999700000000001  imei=869999999999999
  MEDIUM    Unauthorized 5G Network-Slice Access Attempt     imsi=999700000000002
  HIGH      Signaling Flooding / Registration Storm Detected imsi=999700000000001  (burst)
```

The SOC *Overview* counters and the *Incidents* queue update as the alerts land;
open any case to read the decoded evidence (IMSI, IMEI, S-NSSAI, cell ID) and
triage/respond.

---

## 5. Custom / targeted attacks

```bash
# one rogue subscriber with your own IMSI
docker compose exec -u 0 -T naswatch-api python - <<'PY'
import sys; sys.path.insert(0, "/app/scripts")
import importlib, attack_5g as a
from types import SimpleNamespace
args = SimpleNamespace(iface="lo", src="127.0.0.11", dst="127.0.0.5", tag=1)
a.send_nas(a.nas_registration_request("999700000000123"), args)
PY

# a bigger storm
docker compose exec -u 0 -T naswatch-api \
  python /app/scripts/attack_5g.py --scenario flood --flood-count 200
```

---

## 6. Advanced: real Open5GS core + UERANSIM rogue UE

For a full standards-compliant core (Open5GS) with a real software gNB/UE
(UERANSIM) — including a genuine Registration handshake against the AMF — see
`LIVE_DEMO_GUIDE.md` and `scripts/live_lab_demo.sh`.

UERANSIM is built on this host at `/tmp/UERANSIM-3.2.6/build/{nr-gnb,nr-ue}`
and the Open5GS core is installed under `~/open5gs/install`. That path produces
real N2/NAS traffic you can capture on `lo` and feed to NASWatch (the runbook
there covers capture → replay). Use it when you want the attack carried by an
actual 5G core rather than by forged signaling frames.

---

## 7. How it works (files touched)

| File | Purpose |
|------|---------|
| `scripts/attack_5g.py` | The terminal attack tool (5G NAS forgery). |
| `scripts/live_attack_demo.sh` | Arms the sensor, runs the attack, reports detections. |
| `src/naswatch/ingestion/live_capture.py` | Live sensor; falls back to the raw-bytes NAS parser when tshark cannot dissect a forged frame. |
| `src/naswatch/detection/engine.py`, `rules.py` | The detection rules that raise the alerts. |
| `data/inventory.db` (volume `naswatch-data`) | Shared store the dashboard reads. |
