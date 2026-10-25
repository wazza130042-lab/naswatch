# NASWatch — Glossary & Terminology

Plain-English definitions for every term you'll meet in the NASWatch UI, logs, alerts,
runbooks and configuration. Where a term has a formal 3GPP name, both are given.

> **How to read this:** each entry is *term* — what it really is, and *what it means inside
> NASWatch*. Terms are grouped by topic, and the last section is a one-line acronym table.

---

## 1. The network NASWatch watches

| Term | Meaning |
|------|---------|
| **5G Core (5GC)** | The central part of a 5G network: authentication, session setup, mobility, policy. Made of functions like AMF, SMF, UPF, UDM. NASWatch does **not** replace it — it watches the signaling going into it. |
| **gNB** | *next-generation NodeB* — the 5G base station / radio tower. The gNB talks to phones over the air and to the core over the **N2** interface. |
| **UE** | *User Equipment* — any phone, CPE router, IoT sensor or modem connected to the network. |
| **AMF** | *Access and Mobility Management Function* — the core function that handles registration, authentication and mobility. The gNB's main signaling partner; NASWatch decodes the traffic they exchange. |
| **N1** | The logical interface between the **UE and the AMF** — it carries **NAS** signaling (the phone's own messages). Physically those messages travel through the gNB and N2. |
| **N2** | The interface between the **gNB and the AMF**, carried over **SCTP port 38412**. It carries **NGAP** messages. **This is NASWatch's primary inspection point.** |
| **N3** | The data-plane (user traffic) interface between gNB and UPF. **NASWatch does not watch N3** — it is control-plane only. |
| **Control plane** | The "signaling" side: registration, authentication, session requests. NASWatch monitors this. |
| **User plane** | The "payload" side: actual internet traffic. Not monitored by NASWatch. |
| **SCTP** | *Stream Control Transmission Protocol* — the transport used for N2 signaling (instead of TCP/UDP). Rogue signaling is forged onto SCTP :38412. |
| **38412** | The standard SCTP port for N2 / NGAP. A common BPF filter in this project is `sctp or port 38412`. |
| **NGAP** | *NG Application Protocol* (3GPP TS 38.413) — the gNB↔AMF signaling conversation (e.g. *InitialUEMessage*, *NG Setup*). |
| **NAS** | *Non-Access Stratum* (3GPP TS 24.501) — the UE↔AMF signaling carried inside NGAP: registration, authentication, security mode. |
| **PCAP / PCAPNG** | A saved packet-capture file. NASWatch can **replay** one instead of sniffing live, which makes testing reproducible on any laptop. |
| **Live capture** | Sniffing real packets off a network interface (`--mode live`). |
| **Replay** | Feeding a stored PCAP through the same pipeline (`--mode replay`). |
| **BPF filter** | *Berkeley Packet Filter* — the capture rule that decides which packets to keep (e.g. only SCTP/38412). |
| **tshark** | Command-line Wireshark, used by the capture layer to dissect packets. |
| **SPAN / TAP / mirror port** | The physical way to get a passive copy of N2 traffic: a switch mirror port (SPAN) or a hardware network TAP. NASWatch is **passive** — it never sits inline and cannot drop traffic by itself. |
| **SENSOR ONLINE** | The dashboard indicator that the capture pipeline is up and feeding events. |

---

## 2. Subscriber identities (who is on the network)

| Term | Meaning |
|------|---------|
| **IMSI** | *International Mobile Subscriber Identity* — the permanent ID stored on the SIM/eSIM. Practically the subscriber's "account number". |
| **SUPI** | *Subscription Permanent Identifier* — the 5G name for the same concept. In NASWatch, **IMSI and SUPI are used interchangeably**. |
| **SUCI** | *Subscription Concealed Identifier* — the **encrypted** form of the SUPI sent over the air so the IMSI isn't broadcast in the clear. You may see `SUCI:` in the live event feed. |
| **IMEI** | *International Mobile Equipment Identity* — the hardware serial of the device (the **phone**, not the SIM). 15 digits. |
| **PEI** | *Permanent Equipment Identifier* — the 5G name for the hardware identity (IMEI/IMEISV). Used interchangeably in NASWatch. |
| **IMEISV** | IMEI + *Software Version*, 16 digits. Rules compare only the first 14 digits so a software-version bump doesn't look like a new device. |
| **GUTI** | *Globally Unique Temporary Identifier* — a temporary, privacy-preserving ID assigned after registration so the IMSI isn't reused constantly. |
| **TMSI** | The older (4G) temporary ID; you may see `TMSI` in tooling. |
| **eSIM / SIM** | The physical or embedded chip holding the subscriber credentials. |
| **Subscriber** | A provisioned subscriber account = one IMSI + its owner + allowed slices. |
| **Provisioning** | Adding a device/subscriber to the authorized inventory so the network (and NASWatch) knows it is legitimate. |
| **UDM / UDR** | *Unified Data Management / Repository* — the core's subscriber database where credentials live. Referenced in SOAR remediation advice. |

> **Why the IMSI/IMEI pairing matters:** a legitimate IMSI attached to an unexpected IMEI is the
> signature of a **cloned SIM** — see *Identity spoofing*.

---

## 3. Slices, cells and topology

| Term | Meaning |
|------|---------|
| **Network slice** | A logically separate network on shared hardware, tuned for a purpose (e.g. consumer broadband vs emergency services). |
| **S-NSSAI** | *Single Network Slice Selection Assistance Information* — the identifier a device requests for a slice. Made of **SST** + **SD**. Shown as `SST:SD`, e.g. `1:000001`. |
| **SST** | *Slice/Service Type* — the main number. `1`=eMBB, `2`=uRLLC, `3`=mIoT, `4`=V2X, and so on. |
| **SD** | *Slice Differentiator* — optional 6-hex-digit refinement of an SST (e.g. `000002`). |
| **eMBB** | *Enhanced Mobile Broadband* — high-throughput consumer traffic (video, browsing). |
| **uRLLC** | *Ultra-Reliable Low-Latency Communication* — time-critical traffic such as emergency services or industrial control. |
| **mIoT** | *Massive IoT* — huge numbers of low-power sensors. |
| **V2X** | *Vehicle-to-Everything* — connected-vehicle slice type. |
| **Cell ID** | The identifier of a radio cell as reported in signaling. Used by the **False base station** rule. |
| **TAC** | *Tracking Area Code* — a group of cells; part of where a device is located. |
| **Authorized cells** | The list of **your** real gNB cells, uploaded on the **Network topology** page. Anything else is treated as rogue. |
| **Authorized slices** | The list of **your** real S-NSSAI slices. A device requesting one it isn't entitled to triggers *Slice intrusion*. |
| **Rogue / unauthorized** | Not in your uploaded inventory. On the topology page, cells you didn't list are drawn as **ROGUE**. |
| **Network structure file** | The YAML/JSON file describing your organization's real `amf`, `cells` and `slices`. Uploaded once, stored under `data/`, survives rebuilds. |
| **Asset inventory** | The dashboard page listing provisioned **devices** (IMSI, IMEI, owner, allowed slices, status). |
| **Provisioned device** | A `Device` record in the inventory: by default `ACTIVE`; can be `SUSPENDED` or `REVOKED`. |

---

## 4. Security concepts & attack names

| Term | Meaning |
|------|---------|
| **NEA0 / NEA1–3** | 5G **ciphering** (encryption) algorithms. `NEA0` = **null ciphering**, i.e. no encryption. |
| **NIA0 / NIA1–3** | 5G **integrity** algorithms (message authentication). `NIA0` = **null integrity**, i.e. no protection. |
| **Null ciphering / null integrity** | A session negotiating NEA0/NIA0 — traffic is unprotected. A red flag on a normal (non-emergency) connection. |
| **Bidding-down / downgrade** | Forcing a device to negotiate a weaker (or null) algorithm than it supports, so the attacker can read or tamper with traffic. |
| **IMSI catcher** | A fake base station that tricks phones into connecting to it, revealing their IMSI. Also called **Stingray**. |
| **False base station / rogue gNB** | An unauthorized cell broadcasting as if it were part of your network. Detected by an unknown Cell ID. |
| **SIM cloning** | Copying a subscriber's credentials onto another SIM so two devices share one IMSI. |
| **SIM swapping** | Moving a subscriber's identity to attacker-controlled hardware. |
| **Identity spoofing** | Using a legitimate IMSI on **different hardware** (detected by IMEI mismatch). Covers cloning/swapping. |
| **MitM** | *Man-in-the-Middle* — an attacker relaying/altering traffic between two parties. |
| **DoS** | *Denial of Service* — flooding a system so it stops serving real users. |
| **Registration storm / signaling flood** | A device (or botnet) sending a huge burst of registration requests to overload the AMF. |
| **Emergency connection** | A special-case service; null ciphering is *expected* there, so the cipher rule only flags **non-emergency** connections. |

---

## 5. Detection rules

Each rule is a pure function in `src/naswatch/detection/rules.py`; the orchestrator in
`detection/engine.py` runs them over every parsed event. Rules can be individually
enabled/disabled and their thresholds set in `config/settings.yaml`.

| Rule (`AlertRuleType`) | Severity | Triggers when… |
|-----------------------|----------|----------------|
| `ROGUE_DEVICE` | **CRITICAL** | An IMSI is **not in the inventory**, or a provisioned device that is `REVOKED`/`SUSPENDED` tries to connect. |
| `IDENTITY_SPOOFING` | **HIGH** | A known IMSI appears on an **IMEI that doesn't match** the provisioned hardware. |
| `SLICE_INTRUSION` | **MEDIUM** | A known device requests an **S-NSSAI** it isn't entitled to. |
| `CIPHER_DOWNGRADE` | **HIGH** | A session negotiates **NEA0 (null ciphering)** or **NIA0** (null integrity) on a non-emergency connection. |
| `FALSE_BASE_STATION` | **CRITICAL** | Signaling comes from a **Cell ID not in the authorized list**. |
| `SIGNALING_FLOOD` | **HIGH** | One IMSI sends more registration requests than `flood_threshold` within `flood_window_seconds` (config default: 10 within 60 s; engine default 15 within 5 s). |

*Conflated terminology:* "bidding-down", "downgrade" and "null ciphering exploit" all describe
`CIPHER_DOWNGRADE`. "Rogue gNB", "IMSI catcher" and "false base station" all mean `FALSE_BASE_STATION`.

---

## 6. Alerts, incidents & correlation

| Term | Meaning |
|------|---------|
| **Alert** | One detection event produced by a rule: rule type, severity, title, description, IMSI/IMEI/cell/slice, timestamp, status. |
| **Event** | One parsed signaling message. Many events can produce an alert, and one event can raise several alerts. |
| **Severity** | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` — how urgently a human should look. |
| **Mitigation status** | The triage state of an alert: `NEW` → `INVESTIGATING` → `BLOCKED` / `RESOLVED`. |
| **Incident** | Several related alerts grouped together (same IMSI or same cell within a time window). Given an ID like `INC-000001`. |
| **Correlation** | The process of grouping alerts into incidents so operators aren't spammed with duplicates. |
| **Correlation window** | How close in time alerts must be to join one incident — **300 s (5 minutes)**. |
| **Escalation chain** | Two rules that, when they co-occur, mark the incident **CRITICAL** (e.g. *Signaling flood* → *Rogue device*, or *False base station* + *Cipher downgrade*). |
| **Alert fatigue** | Operators drowning in repetitive alerts. Correlation collapses flood alerts into one incident to fight this. |
| **Event search** | The dashboard page for filtering raw/parsed signaling by IMSI, rule, cell, slice, severity. |

---

## 6b. Severity levels at a glance

| Level | Usually means |
|-------|---------------|
| **CRITICAL** | Active, high-confidence compromise (rogue device, false base station). Treat first. |
| **HIGH** | Strong compromise indicator (identity spoofing, cipher downgrade, flood). |
| **MEDIUM** | Policy violation / reconnaissance (unauthorized slice access). |
| **LOW / INFO** | Context, not a direct threat. |

---

## 7. Response — SOAR & mitigation

| Term | Meaning |
|------|---------|
| **SOAR** | *Security Orchestration, Automation and Response* — the part of NASWatch that **acts** on alerts, not just raises them. |
| **Mitigation** | Any response action taken against an alert/device. |
| **Revoke** | Set a subscriber's device status to `REVOKED` — block it from the inventory. |
| **Quarantine** | Set a device status to `SUSPENDED` — temporarily isolate it for investigation. |
| **Firewall drop rule** | A generated `iptables`/`nftables` line to drop a rogue source at the edge (e.g. SCTP to :38412). |
| **Forensic report** | A generated Markdown/JSON incident report: summary, telemetry, raw event snapshot and a recommended playbook. |
| **Playbook / runbook** | A step-by-step procedure. See `ATTACK_RUNBOOK.md` and `PENTEST_RUNBOOK.md`. |
| **Mitigation status** | See above: `NEW → INVESTIGATING → BLOCKED → RESOLVED`. |

---

## 8. Accounts, roles & permissions (RBAC)

| Term | Meaning |
|------|---------|
| **RBAC** | *Role-Based Access Control* — what you can do depends on your **role**. |
| **Role** | One of `admin`, `analyst`, `viewer`. |
| **admin** | Full control: manage users, devices, ingest, audit, mitigations, topology. |
| **analyst** | Read alerts + run **SOAR mitigations** (revoke/quarantine) + forensic reports. |
| **viewer** | Read-only. Unauthorized actions are **hidden**, not merely disabled. |
| **Permission** | A fine-grained capability such as `alerts:read`, `alerts:mitigate`, `devices:write`, `ingest:write`, `users` (manage accounts), `audit`. |
| **`org_id` / tenant** | The organization an account, device or alert belongs to. Enables **multi-tenant** separation. |
| **Multi-tenant** | One deployment safely serving more than one organization, with data scoped by `org_id`. |

### Dashboard pages

| Page | What it's for |
|------|---------------|
| **Overview** | SOC landing page — live counters, severity mix, recent activity. |
| **Event search** | Query raw/parsed signaling (IMSI, rule, cell, slice, severity). |
| **Incidents** | Correlated incidents with real logs/evidence and triage. |
| **Network topology** | Upload/view your gNB cells, AMF(s) and slices; unknown cells show as ROGUE. |
| **Asset inventory** | Provisioned devices (IMSI/IMEI/owner/slices/status). |
| **Reports** | Exports and summary reporting. |
| **Security** | Your own account's 2FA (authenticator app) settings. |
| **User management** | Admin-only: create accounts, set roles, reset passwords and 2FA. |

---

## 9. Sign-in, passwords & 2FA

| Term | Meaning |
|------|---------|
| **Authentication** | Proving who you are (password + second factor). |
| **First-run setup** | On a fresh install with no accounts, the first **admin** is created from the login screen (or `scripts/create_admin.py`, or `NASWATCH_ADMIN_EMAIL`/`NASWATCH_ADMIN_PASSWORD`). |
| **Password policy** | Enforced everywhere (UI, API, CLI): **≥ 12 characters**, **≤ 72 bytes**, **at least 2 of** lowercase/uppercase/digits/symbols, not a common password, and not equal to your account name. |
| **bcrypt** | The password-hashing algorithm. It only reads the **first 72 bytes**, which is why the policy caps length there. |
| **Strength meter** | The live "very weak → strong" indicator while typing a new password. |
| **2FA** | *Two-Factor Authentication* — password **plus** a one-time code. **Mandatory** in NASWatch. |
| **TOTP** | *Time-based One-Time Password* (RFC 6238) — the 6-digit code your authenticator app shows, changing every **30 seconds**. |
| **Authenticator app** | Google Authenticator, Authy, Microsoft Authenticator, 1Password, Bitwarden, FreeOTP, etc. |
| **Enrolment** | The one-time setup: scan the QR (or type the setup key) and confirm a code. **Forced on first sign-in** — you cannot reach any page until it's done. |
| **Setup key / secret** | The base32 string shared between the server and your app (it's what the QR encodes). |
| **otpauth URI** | The `otpauth://totp/…` link alternative to scanning the QR. |
| **Drift window** | How far from the current 30 s step a code may be. NASWatch uses `window=0`: only the step the code was generated for is accepted, so a code dies the moment the app rolls over. Keep the device clock synced. |
| **Reset 2FA** | Admin action in **User management**: clears a lost device's secret so the operator re-enrols at next sign-in. |
| **Session cookie** | The signed token stored in the browser that keeps you signed in across refreshes (7-day expiry). |
| **JWT** | *JSON Web Token* — the signed token format used for sessions and the API. |
| **Access token** | Short-lived credential for API calls. |
| **Refresh token** | Longer-lived credential used to get new access tokens; **rotated** on every use. |
| **`jti`** | *JWT ID* — a unique ID per token, tracked server-side so a stolen/refreshed token is rejected. |
| **Session revocation** | Server-side invalidation of all of a user's refresh tokens (e.g. forced sign-out). |

---

## 10. Integrations, metrics & observability

| Term | Meaning |
|------|---------|
| **SIEM** | *Security Information and Event Management* — a central log/alert platform (Splunk, Microsoft Sentinel…). NASWatch forwards alerts to it. |
| **Webhook** | An HTTP POST NASWatch sends to a URL when an alert fires — the generic SIEM/SOAR/Slack integration. |
| **Syslog** | The classic UDP/TCP logging protocol; configurable as an alert channel. |
| **Splunk / Sentinel / PagerDuty** | Specific forwarders bundled in `src/naswatch/integrations/`. |
| **Prometheus** | The metrics/monitoring service bundled with the deployment (scrapes NASWatch metrics). |
| **Metrics** | Numeric counters such as `naswatch_packets_inspected_total`, login success/failure counts. |
| **JSONL** | One JSON object per line (`data/alerts.jsonl`) — the file-based alert channel. |
| **Audit log** | An append-only record of security-significant actions: logins, SOAR actions, account changes. |

---

## 11. Deployment & configuration terms

| Term / variable | Meaning |
|-----------------|---------|
| **Compose / container** | The services run as Docker containers: `naswatch-ui`, `naswatch-api`, `naswatch-prometheus`. |
| **Volume** | Persistent storage that survives rebuilds. The database and uploaded topology live here. |
| **`NASWATCH_DB_PATH`** | Filesystem path to the SQLite database (default `data/inventory.db`). |
| **`NASWATCH_DB_URL`** | If set to a `postgres://` URL, NASWatch uses PostgreSQL instead of SQLite. |
| **`NASWATCH_ADMIN_EMAIL` / `NASWATCH_ADMIN_PASSWORD`** | Optional unattended first-admin seed (both required). |
| **`NASWATCH_TOTP_ISSUER`** | The label your authenticator app shows for the TOTP entry (default `NASWatch`). |
| **`NASWATCH_NETWORK_FILE`** | Override path for the uploaded network-structure (topology) file. |
| **`NASWATCH_OIDC_ENFORCED`** | Enterprise SSO switch: when true, password login is disabled org-wide. |
| **`?page=<slug>`** | The query parameter that gives each dashboard page its own bookmarkable URL. |

---

## 12. Acronym quick reference

| Acronym | Expansion |
|---------|-----------|
| **5GC** | 5G Core |
| **AMF** | Access and Mobility Management Function |
| **BPF** | Berkeley Packet Filter |
| **DoS** | Denial of Service |
| **eMBB** | Enhanced Mobile Broadband |
| **eSIM** | Embedded SIM |
| **gNB** | next-generation NodeB (5G base station) |
| **GUTI** | Globally Unique Temporary Identifier |
| **IDS / NDR** | Intrusion Detection System / Network Detection & Response |
| **IMEI / IMEISV** | International Mobile Equipment Identity / +Software Version |
| **IMSI** | International Mobile Subscriber Identity |
| **JWT** | JSON Web Token |
| **mIoT** | Massive IoT |
| **MitM** | Man-in-the-Middle |
| **NAS** | Non-Access Stratum |
| **NEA0–3** | 5G ciphering (encryption) algorithms |
| **NGAP** | NG Application Protocol |
| **NIA0–3** | 5G integrity algorithms |
| **NSSAI / S-NSSAI** | (Single) Network Slice Selection Assistance Information |
| **PCAP** | Packet CAPture file |
| **PEI** | Permanent Equipment Identifier |
| **RBAC** | Role-Based Access Control |
| **RBAC role** | admin / analyst / viewer |
| **SD** | Slice Differentiator |
| **SCTP** | Stream Control Transmission Protocol |
| **SD** | Slice Differentiator |
| **SIEM** | Security Information and Event Management |
| **SOAR** | Security Orchestration, Automation and Response |
| **SOC** | Security Operations Centre |
| **SPAN / TAP** | Switch mirror port / hardware network tap |
| **SST** | Slice/Service Type |
| **SUCI / SUPI** | Subscription Concealed / Permanent Identifier |
| **SST/SD** | Slice identifier pair |
| **TAC** | Tracking Area Code |
| **TAP** | Test Access Point (hardware capture device) |
| **TOTP** | Time-based One-Time Password |
| **TMSI** | Temporary Mobile Subscriber Identity |
| **TAP** | see above |
| **uRLLC** | Ultra-Reliable Low-Latency Communication |
| **UE** | User Equipment |
| **UDM / UDR** | Unified Data Management / Repository |
| **UPF** | User Plane Function |
| **V2X** | Vehicle-to-Everything |

---

*Grounded in the current source: `src/naswatch/detection/rules.py`, `detection/engine.py`,
`correlation/engine.py`, `mitigation/soar.py`, `storage/models.py`, `auth/users.py`,
`auth/password_policy.py`, `network_inventory.py` and `config/settings.yaml`.*
