# NASWatch — Project Overview and How It Works

A from-the-code description of what NASWatch is, what it does, and how the
pieces fit together. Every claim here is checkable against the repository.

## Where this document sits

| Document | Purpose |
|---|---|
| `README.md` | Pitch, feature list, quick start |
| **`PROJECT_OVERVIEW.md`** (this) | **What the system is and how it actually works, end to end** |
| `LIVE_DEMO_STEPS.md` | Presenter runbook for the 5G lab, step by step |
| `GLOSSARY.md` | 5G/security terminology |
| `ATTACK_RUNBOOK.md`, `PENTEST_RUNBOOK.md`, `SOC_DEMO_RUNBOOK.md` | Scenario-specific playbooks |

---

## 1. What NASWatch is, in one paragraph

NASWatch is a **passive 5G control-plane Intrusion Detection and Response
system**. It listens to the signaling conversation between a 5G radio (gNB) and
the core network's Access and Mobility Management Function (AMF) — the **N2/N1
interface**, carried as NGAP (3GPP TS 38.413) inside SCTP on port 38412, with
NAS messages (3GPP TS 24.501) nested inside. It decodes those messages, compares
what it sees against an inventory of **authorized subscribers and radio cells**,
and raises alerts when something doesn't belong. It never transmits on the
network and never sits in the traffic path: it watches a copy.

The problem it addresses is that 5G network slicing lets one physical network
host many logical ones (public broadband, emergency services, industrial IoT,
isolated enterprise). That tracking is enforced mostly by the core — so
misbehavior, unauthorized devices, and downgrade attacks are hard to *see*.
NASWatch makes them visible.

---

## 2. The threat model — what it looks for

Six detection rules, defined in `src/naswatch/detection/rules.py`:

| Rule | Severity | Fires when | Real-world analogue |
|---|---|---|---|
| `ROGUE_DEVICE` | CRITICAL | An IMSI is seen that isn't in inventory, **or** a known device is `REVOKED`/`SUSPENDED` yet is still signaling | Unprovisioned eSIM, stolen/retired IoT module |
| `IDENTITY_SPOOFING` | HIGH | IMSI matches inventory but the reported IMEI/PEI doesn't match the provisioned hardware | SIM cloning / SIM swapping |
| `SLICE_INTRUSION` | MEDIUM | A subscriber asks for an S-NSSAI (a slice) it has no entitlement to | A sensor trying to reach the emergency slice |
| `CIPHER_DOWNGRADE` | HIGH | NEA0 (null ciphering) or NIA0 (null integrity) is negotiated | "Bidding-down", IMSI-catcher / MitM setup |
| `FALSE_BASE_STATION` | CRITICAL | Signaling arrives from a Cell ID not in the authorized cell list | Rogue gNB |
| `SIGNALING_FLOOD` | HIGH | One IMSI exceeds a threshold of registration attempts in a time window | Registration storm, AMF DoS precursor |

The rules are **pure functions** — they take a parsed event plus an optional
device record, and return an alert or `None`. There is no I/O and no database
access inside `rules.py`, which is what makes them trivially unit-testable. All
the orchestration lives in `detection/engine.py`.

---

## 3. How it works — the pipeline

```
                      ┌─────────────────────────────────────────────┐
  traffic source      │  INGESTION                                  │
  ──────────────►     │  live_capture.py   (PyShark, live iface)    │
  live iface /        │  pcap_replay.py    (tshark -r, stored file) │
  .pcap file /        │  REST: POST /api/v1/ingest/event            │
  REST event          └───────────────────┬─────────────────────────┘
                                          │ raw packets / JSON
                                          ▼
                      ┌─────────────────────────────────────────────┐
                      │  PARSING                                    │
                      │  ngap_parser.py  → NGAP procedures, IDs,    │
                      │                    NR Cell ID, TAC; unpacks │
                      │                    the embedded NAS-PDU      │
                      │  nas_parser.py   → IMSI/SUPI, SUCI, 5G-GUTI,│
                      │                    IMEI/PEI, S-NSSAI (SST+SD)│
                      └───────────────────┬─────────────────────────┘
                                          │ ParsedSignalingEvent
                                          ▼
                      ┌─────────────────────────────────────────────┐
                      │  DETECTION  (detection/engine.py)           │
                      │  1. look up device by IMSI in the repository│
                      │  2. run the 6 rules                         │
                      │  3. attach full packet context to each alert│
                      └───────────────────┬─────────────────────────┘
                                          │ Alert objects
                          ┌───────────────┼───────────────┐
                          ▼               ▼               ▼
                   ┌───────────┐  ┌─────────────┐  ┌──────────────┐
                   │ ALERTING  │  │ CORRELATION │  │ SOAR         │
                   │ console   │  │ folds alerts│  │ quarantine / │
                   │ sqlite    │  │ into        │  │ revoke,      │
                   │ file      │  │ incidents   │  │ firewall rule│
                   │ webhook   │  │ + escalate  │  │              │
                   │ syslog    │  └─────────────┘  └──────────────┘
                   └───────────┘
```

### 3.1 Ingestion

Two sources, both in `src/naswatch/ingestion/`:

- **`live_capture.py`** — live capture from a network interface via PyShark,
  filtered with a BPF expression (default `sctp or port 38412`).
- **`pcap_replay.py`** — replays a stored `.pcap`/`.pcapng` by shelling out to
  `tshark -r` with a display filter (default `ngap || nas_5gs || sctp`), then
  yields events one at a time. This is what makes the system testable and
  demoable offline, and it is what the lab verification uses.

There is also a **REST ingestion path** (`POST /api/v1/ingest/event`) so an
external sensor can push a pre-decoded event.

### 3.2 Parsing

`ngap_parser.py` reads NGAP elementary procedures (Initial UE Message, Uplink/
Downlink NAS Transport, PDU Session Resource Setup, and so on — the codes are
tabulated at the top of the file), pulls out `RAN-UE-NGAP-ID`,
`AMF-UE-NGAP-ID`, NR Cell ID and TAC, and then hands the **embedded NAS-PDU**
to `nas_parser.py`.

`nas_parser.py` decodes 5GS NAS message types (Registration Request/Accept/
Reject, Authentication Response/Failure, PDU Session Establishment
Request/Accept/Reject, …) and extracts subscriber identity. Crucially it
implements **BCD nibble-swap decoding** (`decode_bcd_digits`), because 3GPP
encodes IMSIs as swapped BCD with an `f` filler nibble — getting this wrong is a
classic source of "why is the IMSI garbage" bugs.

Output is a single normalized `ParsedSignalingEvent` (in
`storage/models.py`) carrying IMSI, IMEI, GUTI, Cell ID, TAC, requested
SST/SD, negotiated cipher/integrity algorithms, procedure name, and the
NGAP/TAC identifiers.

### 3.3 Detection

`DetectionEngine.process_event()` is the heart of the system:

1. If the event has **no subscriber identity**, it only runs the
   `FALSE_BASE_STATION` check — a cell anomaly is still meaningful even
   without an IMSI.
2. Otherwise it looks the device up in the repository by IMSI (or IMEI).
3. It runs the rules. `ROGUE_DEVICE`, `CIPHER_DOWNGRADE`, `FALSE_BASE_STATION`
   and `SIGNALING_FLOOD` run regardless of whether the device is known.
   `IDENTITY_SPOOFING` and `SLICE_INTRUSION` only run when the device **is**
   known — you can't spoof or exceed the entitlement of a subscriber you
   haven't provisioned.
4. Every alert then gets **full packet context** attached by
   `_attach_event_context()`. This is deliberate: a replay session is
   in-memory, so without this the evidence behind an alert vanishes the moment
   the run ends. The alert's own rule-specific evidence is preserved, with the
   shared context merged underneath it (`{**context, **(alert.raw_event or {})}`).

   > **Note on sync state:** `_attach_event_context` is present in the working
   > tree but is not yet in `HEAD` — it is an uncommitted enhancement. A fresh
   > clone will not have it until that change is committed.

The flood rule is **stateful**: `_rate_tracker` keeps a `deque` of timestamps
per IMSI, evicts anything older than the window, and fires when the count
exceeds the threshold. It only counts `InitialUEMessage` and
`RegistrationRequest` — genuine registration events, not any stray packet.

### 3.4 Alerting

`alerting/notifier.py` fans an alert out to whichever sinks are enabled in
`config/settings.yaml`: console, SQLite, JSONL file, webhook, syslog. Multiple
sinks can be active at once.

### 3.5 Correlation

`correlation/engine.py` collapses related alerts into **incidents** so an
operator isn't buried. Alerts are grouped when they share an IMSI or a Cell ID
within a 5-minute window (`CORRELATION_WINDOW_SECONDS = 300`). It also encodes
**escalation chains** — pairs of rules that, occurring together, mean something
worse than either alone:

```
SIGNALING_FLOOD + ROGUE_DEVICE        → escalation
SIGNALING_FLOOD + IDENTITY_SPOOFING   → escalation
FALSE_BASE_STATION + CIPHER_DOWNGRADE → escalation
ROGUE_DEVICE + SLICE_INTRUSION        → escalation
```

A flood that precedes a rogue device is a campaign, not two alerts.

### 3.6 SOAR (response)

`mitigation/soar.py` provides:

- `quarantine_device(imsi)` — marks the device quarantined in inventory.
- `revoke_subscriber(imsi, reason)` — revokes the subscriber.
- `generate_firewall_drop_rule(source_ip, port=38412)` — emits a drop rule.
- `generate_forensic_report(alert)` — renders an incident report.

`revoke_subscriber` calls an optional **core revocation adapter**
(`_request_core_revocation`). **Important:** by default that adapter is not
configured, so a revoke updates NASWatch's own inventory but does **not** alter
the real subscriber database in the core. Treat it as "the SOC's record of
intent" unless you wire the adapter up.

---

## 4. Storage and multi-tenancy

A single factory (`storage/factory.py`) picks the backend from one environment
variable:

| `NASWATCH_DB_URL` | Backend |
|---|---|
| `postgres://…` or `postgresql://…` | `PostgresRepository` |
| unset | `SQLiteRepository` at `NASWATCH_DB_PATH` (default `data/inventory.db`) |

Both implement the same `DeviceRepository` interface
(`storage/repository.py`), so detection code is backend-agnostic. The factory
also builds the user store and refresh-token store on the same engine, so
identity data lives next to inventory rather than in a second database.

Records are **tenant-scoped by `org_id`**. Cross-tenant reads are blocked;
`org_id = "*"` denotes a super-admin who may see across tenants. This is
enforced in the API layer, not just the UI.

---

## 5. Security model of NASWatch itself

It's an IDS, so its own access control matters:

- **Auth**: JWT access + refresh tokens (`auth/jwt_handler.py`), plus OIDC
  (`auth/oidc.py`) and TOTP two-factor (`auth/totp.py`).
- **Passwords**: policy module (`auth/password_policy.py`) and a strength meter
  in the UI (`ui/password_strength.py`).
- **RBAC**: four roles in `auth/rbac.py` —
  `admin`, `analyst`, `viewer`, `auditor` — with an explicit permission set per
  role (e.g. only `admin` has `users:manage` and `devices:delete`; `auditor`
  gets `audit:read` and nothing operationally dangerous).
- **API keys**: `auth/api_keys.py`, with `apikeys:manage` gating creation and
  revocation.
- **Audit trail**: `audit/logger.py` writes an append-only, **hash-chained**
  log. Each entry's HMAC is keyed from `SECRET_KEY` in `auth/jwt_handler.py`,
  read **once at import**. Two consequences worth knowing:
  - If you change the secret, old entries stop verifying.
  - The dev fallback is a random per-process key, so a chain written by one
    process won't verify in another. Tests pin a stable secret for this reason.
  Endpoints `GET /api/v1/audit/verify` (whole chain) and
  `GET /api/v1/audit/{id}/verify` (one record) expose the check.

---

## 6. Interfaces

### 6.1 REST API (`src/naswatch/api/server.py`, FastAPI, port 8000)

Grouped by area:

- **General**: `/`, `/health`, `/metrics` (Prometheus), `/api/v1/license`
- **Auth**: `/api/v1/auth/login`, `/refresh`, `/logout`, `/me`, plus OIDC
  `/config` and `/assert`
- **Users**: `GET/POST /api/v1/users`, `PUT /api/v1/users/{id}`,
  `POST /api/v1/users/{id}/reset-password`, `DELETE /api/v1/users/{id}`
- **API keys**: `POST/GET /api/v1/apikeys`, `DELETE /api/v1/apikeys/{id}`
- **Alerts**: `GET /api/v1/alerts`, `GET /api/v1/alerts/{id}`, plus
  `POST …/claim`, `POST …/release`, `PUT …/assignment` (analyst workflow)
- **Response**: `POST /api/v1/alerts/{id}/mitigate`
- **Incidents**: `GET /api/v1/incidents` (correlated)
- **Inventory**: `GET/POST /api/v1/devices`, `DELETE /api/v1/devices/{imsi}`
- **Ingestion**: `POST /api/v1/ingest/event`
- **Audit**: `GET /api/v1/audit`, `GET /api/v1/audit/verify`,
  `GET /api/v1/audit/{id}/verify`

Every route is guarded by a permission dependency (`_require(...)`) and an
actor-resolution step that applies tenant scoping.

### 6.2 SOC dashboard (`ui/`, Streamlit, port 8501)

Views in `ui/views/`: `overview`, `incidents`, `inventory`, `topology`,
`event_search`, `reports`, `security`, `users`, `audit_log`. Navigation and
access control live in `ui/rbac.py`, `ui/routing.py`, `ui/session.py`.

### 6.3 Headless CLI (`scripts/run_pipeline.py`)

Runs the whole pipeline without the UI — for edge nodes or gNB hosts:

```bash
python scripts/run_pipeline.py --mode replay --pcap capture.pcap --db data/inventory.db
python scripts/run_pipeline.py --mode live   --interface any
```

Useful flags: `--delay` (seconds between replayed packets), `--loop`,
`--config` (settings file).

---

## 7. Deployment

`docker-compose.yml` defines four services, all bound to `127.0.0.1`:

| Service | Container | Port | Role |
|---|---|---|---|
| `naswatch-api` | `naswatch-api` | 8000 | FastAPI detection/response API |
| `naswatch-ui` | `naswatch-ui` | 8501 | Streamlit SOC dashboard |
| `db` | `naswatch-postgres` | 5432 (internal) | PostgreSQL backend |
| `prometheus` | `naswatch-prometheus` | 9090 | metrics scraping |

Prometheus config is `config/prometheus.yml`; Grafana dashboards are provisioned
from `config/grafana/`; TLS/reverse-proxy is `config/caddy/Caddyfile`.
`docker-compose.prod.yml` is the hardened production variant.

---

## 8. The 5G lab (proving it on real signaling)

The repository ships a complete, real testbed — not a mock:

- `config/open5gs/` — Open5GS configs: `amf.yaml`, `smf.yaml`, `gnb.yaml`,
  and UE profiles `ue.yaml` (Alice), `ue-rogue.yaml` (Bob), `ue-charlie.yaml`.
- `scripts/live_lab_demo.sh` — narrated bring-up of the whole lab.
- `scripts/verify_lab.sh` — **one-shot end-to-end verifier**: cold start, core
  + UPF + gNB, all three UEs, packet capture, NASWatch detection, PASS/FAIL per
  check, non-zero exit on failure.
- `LIVE_DEMO_STEPS.md` — step-by-step presenter runbook.
- `config/lab/lab_devices.csv` — inventory matched to the UEs' real IMEIs.
- `config/open5gs/container/` — the privileged UPF container (Dockerfile +
  config) needed because creating the `ogstun` device requires `CAP_NET_ADMIN`.

The lab uses MCC/MNC `999/70` and IMSIs `999700000000001-3`, which are
reserved for test use — deliberately, so the lab can never collide with a real
network.

### The three scenarios

| Scenario | Subscriber | What happens | Expected detection |
|---|---|---|---|
| Legitimate | Alice `…001` | Authenticates, registers, gets a PDU session | **nothing** |
| Rogue | Charlie `…003` | Never provisioned; core rejects with "Unknown UE by SUCI" | `ROGUE_DEVICE` |
| Slice-jump | Bob `…002` | Registers, then requests SST 4 which he isn't entitled to; core withholds the session Accept | `SLICE_INTRUSION` |

The legitimate case producing **zero** alerts is as important as the other two
— it's the false-positive check.

### Two behaviours that surprise people

Both were confirmed while running the lab, and both are upstream Open5GS
behavior rather than NASWatch bugs:

1. **The SMF associates with the UPF lazily** — only when the first PDU session
   needs it — and de-associates when that UE goes away. So "is the user plane
   up?" is only a meaningful question *while a session is active*.
2. **The AMF buffers its file log** and flushes on teardown, so grepping its log
   mid-run can miss lines that are genuinely there. Assert on UE-side
   observations (did the UE get an Accept? did registration fail?) rather than
   on a buffered log.

---

## 9. Tests

`tests/unit/` covers parsers, rules, repository/backends, API+SOAR, TOTP,
password policy, enterprise and commercial feature surfaces, and a PostgreSQL
integration suite.

```bash
python -m pytest -q                 # default: SQLite backend
NASWATCH_TEST_PG_URL=postgresql://… python -m pytest -q   # adds the PG suite
```

`tests/conftest.py` sets a **stable JWT secret and an isolated temp DB path
before importing `naswatch`**. This matters: the audit chain is HMAC-keyed from
that secret at import time, so without pinning it, a per-process random key
makes every audit row look tampered-with. That's a test-environment
requirement, not a production concern.

Expected results on this machine: **78 passed, 4 skipped** (SQLite); **82
passed, 0 skipped** with PostgreSQL available.

---

## 10. Repository layout

```
src/naswatch/
  ingestion/      live_capture.py, pcap_replay.py
  parsing/        ngap_parser.py, nas_parser.py
  detection/      engine.py (orchestration), rules.py (pure rules)
  correlation/    engine.py (incidents, escalation)
  mitigation/     soar.py (quarantine, revoke, firewall rule, forensics)
  alerting/       notifier.py (console/sqlite/file/webhook/syslog)
  storage/        models.py, repository.py, sqlite_repo.py,
                  postgres_repo.py, factory.py, db.py
  auth/           jwt_handler, oidc, totp, rbac, users, api_keys,
                  password_policy
  audit/          logger.py (hash-chained)
  integrations/   pagerduty, splunk, sentinel
  api/            server.py (FastAPI)
  licensing/      validator.py
  network_inventory.py
ui/               Streamlit SOC dashboard (views/, rbac, routing, session, theme)
scripts/          run_pipeline, seed_inventory, verify_lab, live_lab_demo,
                  attack_5g, backup, create_admin, migrate_sqlite_to_postgres
config/           settings.yaml, open5gs/, lab/, grafana/, caddy/,
                  prometheus.yml
tests/            unit/ suites + fixtures/
```

Roughly 15,000 lines of Python across source, UI, scripts and tests.

---

## 11. Running it — three entry points

**Offline, synthetic (no core needed):**
```bash
python scripts/seed_inventory.py --csv scripts/sample_devices.csv --db data/inventory.db
python scripts/run_pipeline.py --mode replay --pcap data/pcaps/demo.pcap --db data/inventory.db
```

**Live, against the Open5GS lab:**
```bash
scripts/verify_lab.sh          # whole thing, cold start, PASS/FAIL
scripts/live_lab_demo.sh       # narrated version for presenting
```

**As a service:**
```bash
docker compose up -d           # API :8000, dashboard :8501, Prometheus :9090
```

---

## 12. Honest limitations

- **Passive only.** It cannot block, drop, or delay a packet. Response is
  advisory plus whatever you wire into the SOAR adapter.
- **Core revocation is stubbed by default.** See §3.6.
- **The AMF in the lab is configured with `NEA0` first** so NAS payloads stay
  readable to the passive parser. That is a deliberate lab-only setting and is
  commented as such in `config/open5gs/amf.yaml`; it must not be copied into a
  production network. Against a real network with mandatory ciphering, NAS-level
  parsing is limited and detection must lean on NGAP-visible fields.
- **UE user-plane TUN needs root**, so the lab's UEs log a TUN setup error. This
  does not affect control-plane signaling, which is all NASWatch inspects.
- **The audit chain is key-bound.** Rotating `SECRET_KEY` invalidates prior
  entries unless key history is managed.
