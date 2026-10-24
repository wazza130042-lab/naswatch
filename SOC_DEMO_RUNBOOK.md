# NASWatch — SOC Demo Runbook

**Scenario:** *Give the organization its network structure → upload it → run live 5G attacks → watch the alerts appear in the SOC.*

Three acts. Each is short, and every step shows something on screen.

| Ask | Where |
|---|---|
| The org's network structure | `network_structure_demo.yaml` (repo root) |
| Upload it | SOC → **Network topology** → *⇪ Upload network structure* → **Save structure** |
| Launch attacks | terminal (`scripts/attack_5g.py`) |
| See the alerts | SOC → **Incidents** |

Before you start: the stack is up.

```bash
cd ~/Documents/naswatch
docker compose ps            # naswatch-ui + naswatch-api must be healthy
```

---

# ACT 1 — Upload the organization's network structure

The dashboard is *aware of the org*: its cells, its AMF(s), its slices. We give it
`network_structure_demo.yaml` (Northwind Telecom — 3 cells, 2 AMF, 4 slices).

1. Open **http://localhost:8501** and sign in
   (`admin@naswatch.io` / `naswatch-admin-password` + authenticator code).

2. Sidebar → **Network topology**.

3. Open the expander **⇪ Upload network structure**.

4. **Browse** to `/home/megbaru/Documents/naswatch/network_structure_demo.yaml`
   (or drag it onto the uploader).

5. You should now see a preview line like:

   > **Northwind Telecom — 5G SA Network** — 3 cells · 2 AMF · 4 slices

   If any red error appears, fix that line in the file and re-drop it.

6. Click **Save structure**.

7. The page header now reads **Northwind Telecom · uploaded network structure**,
   and the table lists `Central-Cell-A`, `North-Cell-B`, `South-Cell-C`.

> This is the point to say: *"NASWatch was told the org's actual topology. From
> now on, a cell that isn't on this list is drawn as ROGUE — and the radio cells
> here are what the later alerts map back to."*

---

# ACT 2 — Run the attack (terminal)

Everything here is typed in a terminal — open **two** terminals.

## Terminal — the IDS sensor (starts a live passive capture)

```bash
cd ~/Documents/naswatch
docker compose exec naswatch-api python -c \
  "from naswatch.storage.sqlite_repo import SQLiteRepository as R; print('alerts before:', R('/app/data/inventory.db').count_alerts())"
```

Start the sensor (leave it running; it is the N2/SCTP :38412 tap):

```bash
docker compose exec -u 0 naswatch-api \
  python /app/scripts/run_pipeline.py --mode live --interface lo
```

> If you prefer a self-cleaning one-shot, use:
> `docker compose exec -u 0 naswatch-api sh -c 'timeout 60 python /app/scripts/run_pipeline.py --mode live --interface lo' > /tmp/sensor.log 2>&1 &`

## Second terminal — fire the scenarios

Attacks go one at a time so each alert is attributable.

```bash
cd ~/Documents/naswatch
```

> The container has the attacker script baked in; run it via `docker compose exec`.

### Baseline (should produce **no** alert)

```bash
docker compose exec naswatch-api python scripts/attack_5g.py --scenario legitimate
```

### 1) Unknown subscriber → **ROGUE_DEVICE** (CRITICAL)

```bash
docker compose exec naswatch-api python scripts/attack_5g.py --scenario rogue
```

NasWatch should log `Rogue device alert … IMSI=999700000000999`.

### 2) Suspended ex-contractor → **ROGUE_DEVICE** (CRITICAL)

```bash
docker compose exec naswatch-api python scripts/attack_5g.py --scenario suspended
```

(Device `…003`, "Charlie — Ex-Contractor".)

### 2) SIM clone (known IMSI, spoofed IMEI) → **IDENTITY_SPOOFING** (HIGH)

```bash
docker compose exec naswatch-api python scripts/attack_5g.py --scenario sim-clone
```

### 3) Unauthorized slice → **SLICE_INTRUSION** (MEDIUM)

This asks for the **uRLLC-Critical** slice (`SST 2 / SD 000002`) that the
operator is not entitled to — the alert maps back to the org's slice list.

```bash
docker compose exec naswatch-api python scripts/attack_5g.py --scenario slice-intrusion
```

### 2) Registration flood → **SIGNALING_FLOOD** (HIGH)

```bash
docker compose exec naswatch-api python scripts/attack_5g.py --scenario flood
```

### Or all at once

```bash
docker compose exec naswatch-api python scripts/attack_5g.py --scenario all
```

---

# ACT 3 — See the alerts in the SOC

Back in the browser (no need to reload the nav manually — the sidebar keeps the
session):

1. **Incidents** — the new rows, newest first. Each shows severity, rule, the
   IMSI/IMEI, the cell, a RAW-EVENT excerpt, and a status.

   Expected after ACT 2:

   | Rule | Severity | Trigger |
   |---|---|---|
   | `ROGUE_DEVICE` | CRITICAL | unknown IMSI `…999` / suspended `…003` |
   | `IDENTITY_SPOOFING` | HIGH | known IMSI on a spoofed IMEI |
   | `SLICE_INTRUSION` | MEDIUM | `…002` asking for SST 2 / SD 000002 |
   | `SIGNALING_FLOOD` | HIGH | the registration burst |

2. **Network topology** — Central-Cell-A / North-Cell-B / South-Cell-C as
   uploaded, and the slice matrix (`Consumer-eMBB`, `uRLLC-Critical`, …).

3. **Launch response** on an incident → **Quarantine** / **Revoke UDM**, then show
   the device status change and the audit entry.

---

# Teardown / reset

```bash
# stop the sensor (ctrl-C, or kill the timeout'd process)
pkill -f "run_pipeline.py --mode live" || true
```

To clear the topology and go back to the settings fallback:

> Network topology → *⇪ Upload network structure* → **Remove uploaded structure**.

---

## Reference

- Topology file: `network_structure_demo.yaml` (copy of `network_inventory.template()`).
- Template lives in `src/naswatch/network_inventory.py` (`TEMPLATE`).
- Attacker: `scripts/attack_5g.py` (scenarios above).
- One-shot script: `scripts/live_attack_demo.sh` (wraps all of the above).
