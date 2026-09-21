# Group Project Idea Submission

## Project Title
**NASWatch — 5G Control-Plane Intrusion Detection & Response (IDS/IR) Platform**

## Category
Cybersecurity / Telecommunication Network Security

## Team
_(Team members, Section, Group #)_

---

## 1. Problem Statement

5G networks introduce a control-plane signaling interface (the **N2/N1** interface between the cell tower/gNB and the Access & Mobility Function/AMF) that carries every subscriber's registration attempts. Standard IT security software **does not understand this signaling**. As a result, private-5G enterprises cannot detect attacks happening on the control plane:

- **Rogue eSIM / cloned-IMSI devices** attaching to the network without legitimate subscription state.
- **Suspended / deactivated subscribers** (e.g., a fired employee with a company SIM) successfully re-attaching.
- **Slice-hopping intrusions** where a device joins a slice it is not provisioned for, crossing tenant boundaries inside the same physical core.
- **Signaling floods** that overload the AMF to take down the network.

These attacks happen **between the tower and the core**, in a place most security tools have zero visibility.

> **Important note on infrastructure:** This project does **not** require access to real telecom carrier infrastructure (Ethio Telecom, Safaricom, or any MNO). The entire system — including a functional 5G core, simulated cell towers, and simulated subscriber devices — runs on a single student machine using **open-source software**. No SIM cards, no physical radios, and no carrier cooperation are needed.

## 2. Our Solution (The Idea)

**NASWatch** is a **control-plane security monitoring and response platform** that sits at a passive inspection point on the **N2/N1 (NGAP/NAS) interface** and:

1. **Watches** every attach / registration message as it flows in real time.
2. **Cross-checks it against a provisioned subscriber & slice inventory** (ground truth at IMSI level).
3. **Detects** rogue, suspended, mis-sliced, or flood-based intrusions.
4. **Responds** by triggering core-side actions — blocking/quarantining the offending subscriber, revoking its sessions, and generating firewall drop rules against the offending cell.

It is a **software probe + detection engine + SOC dashboard** running entirely on open-source software. It validates against a self-contained lab built from **Open5GS** (open-source 5G core) and **UERANSIM** (simulated phones and cell towers) — no real carrier infrastructure is needed.

## 3. Key Features (Detailed)

### 3.1 5G Control-Plane Signaling Monitoring
- Captures and decodes **NGAP/NAS** signaling (3GPP TS 38.413 / TS 24.501) exchanged over the **N2/N1 interface**.
- Inspects attach/registration flows with fine-grained fields (IMSI, PLMN, cell ID, requested slice / NSSAI) rather than raw IP heuristics.
- Supports both **live capture** and **PCAP replay** for testing without a physical RAN.

### 3.2 Subscriber Inventory & Slice Matrix (Ground Truth)
- Seeded directory of authorized subscribers keyed by **IMSI**, status (`ACTIVE` / `SUSPENDED` / `REVOKED`), IMEI, and owner.
- Assigns each subscriber a permitted **network slice** (enterprise-private, URLLC, eMBB, etc.) used to enforce isolation.
- Every control-plane event is correlated against this matrix — the core reason false positives stay low.

### 3.3 Detection Rules
| Rule | What it catches |
|---|---|
| **Rogue Device** | Unprovisioned, suspended, or revoked IMSI attempting network attach → CRITICAL alert. |
| **Slice Intrusion / Tenant Crossing** | Device attaching to a slice it is not provisioned for → cross-tenant boundary violation. |
| **Signaling Flood** | Registration/attach storm exceeding a per-window threshold → DDoS of the control plane. |

### 3.4 Alerting, Correlation & Incident Management
- Alerts tagged with severity (INFO → CRITICAL) and rule type.
- **Correlation engine** groups repeated/near-simultaneous alerts into a single **Security Incident** and escalates severity when rules co-occur (e.g., flood + rogue device = CRITICAL).
- Triage workflow with per-alert forensic detail (time, IMSI, cell, slice, raw context).

### 3.5 Automated Response (SOAR)
- **Revoke subscriber** at the core level (UDM/AMF credential invalidation).
- **Quarantine IMSI** — freeze device authentication state for investigation.
- **Firewall rule generation** — iptables drop rules against rogue cell IDs to block the attack source at the RAN.
- **Forensic evidence bundle** — exports a structured JSON report per incident for audit & legal retention.

### 3.6 SOC Dashboard & REST API
- Live **Streamlit SOC dashboard**: alerts feed, inventory matrix, incidents, device status.
- Full **REST API** with OpenAPI docs: authentication, alerts, incidents, devices, audit, license.
- Real-time telemetry ingestion endpoint for the probe.

### 3.7 Enterprise Security & Tenancy
- **RBAC roles** — `admin`, `analyst`, `viewer` with permission-mapped API access.
- **Tenant isolation** — data scoped by organization (`org_id`); organizations cannot see each other's alerts/devices/audit.
- **JWT access + rotating refresh sessions** with replay detection.
- **SSO / OIDC** integration for enterprise identity providers.

### 3.8 Immutable, Tamper-Evident Audit Trail
- Every admin/auth/response action is logged with actor, timestamp, IP, and a **keyed HMAC-SHA256 hash chain**.
- Each entry stores the hash of its predecessor → any modification or reordering is detectable; the `/audit/verify` endpoint reports exactly which entries were tampered with.

### 3.9 SIEM / Alerting Integrations
- Streams alerts to **Splunk** HEC, **Microsoft Sentinel**, and **PagerDuty** (severity-mapped escalation with dedupe).

### 3.10 Deployment & Production Readiness
- Dual storage: **SQLite** (lightweight/dev) or **PostgreSQL** (production), auto-selected.
- **TLS edge** via Caddy (self-signed for demo / real certs for prod).
- **Scheduled backup/restore** for disaster recovery.
- **Prometheus metrics + Grafana dashboards** for SOC monitoring.

### 3.11 Primary & Secondary Market
- **Primary (best fit):** private 5G networks and industrial enterprises — factories, ports, hospitals, campuses, mines, warehouses — that run their own on-premises 5G core (frequently open-source, such as Open5GS). They have the real pain (ex-contractor access, IoT/eSIM theft, cross-tenant slice abuse) and can actually deploy a probe + server on their network.
- **Secondary (future/phase two):** telecom — small MNOs, MVNOs, neutral hosts, carrier labs and pre-production networks that run open or vendor-neutral cores.

## 4. Scope & Applicability — Where It Works / Where It Doesn't

### 4.1 Where NASWatch works (deployable today / in our roadmap)
| Scenario | Status | Why |
|---|---|---|
| Private 5G enterprise / industrial campus running its own standalone 5G core | ✅ **Best fit** | Open cores (Open5GS) give us the N2/N1 capture point; low signaling volumes; concrete security pain. |
| Carrier labs, R&D / test / pre-production networks (incl. major MNOs) | ✅ **Works** | Same stack as the demo lab; a trial network is the normal pilot home for new security tooling. |
| Small MNOs, MVNOs & neutral hosts on open / vendor-neutral cores | ✅ **Works** | Non-proprietary cores expose the signaling path we monitor. |
| Large MNO production cores over open interfaces (pilot-scale) | 🟡 **Phase two** | Needs the operator to grant a passive capture on its AMF-facing N2, plus carrier hardening. |

### 4.2 Where NASWatch does NOT work (out of scope)
| Scenario | Reason |
|---|---|
| **Full carrier production stack (Nokia / Ericsson / Huawei)** | Proprietary cores; N2 is typically carried over **IPSec/TLS-encrypted transport**, so a passive probe sees no readable signaling; no vendor integration. |
| **Disaggregated / O-RAN & split-RAN layouts** | N2 terminates at a differently placed CU-CP; capture points vary per vendor and need customization. |
| **Carrier-grade compliance environments** | Lawful-interception rules, 7x24 SLAs, MNO-scale throughput and certification are beyond an academic/startup scope. |
| **Non-SA networks** (4G-only, 5G NSA, Wi-Fi calling, non-3GPP access) | Our detection targets 5G **Standalone** control-plane procedures; these paths use different interfaces. |
| **ISPs / resellers with no radio-core of their own** | There is no N2/N1 to monitor. |
| **Other attack surfaces** | NASWatch watches the **control plane (N2/N1) only** — it does not see N3/UPF data-plane attacks, roaming interconnects (N8/N10/N5), or application-layer threats. |

**Summary:** strongest and most realistic home is the **private-5G / industrial enterprise**; telecom is an achievable second phase via labs, trials and open-core operators — while full production-MNO deployment is explicitly out of scope for this project.

## 5. Originality & Creativity

- **NOT a vulnerability web scanner** — this project targets a completely different, under-served surface: the **5G control plane**.
- **Domain-specialized detection**: instead of generic IP-packet signatures, NASWatch speaks actual 5G signaling semantics and validates against provisioning truth — a genuinely different IDS design.
- **Fully open-source and self-contained**: uses only free tools (Open5GS, UERANSIM, Python) — anyone can reproduce the entire setup from a laptop with no paid subscriptions or hardware.
- **Real-world relevance**: aligned with 3GPP network-slicing security and telco zero-trust trends happening right now.
- **Demonstrable, not theoretical**: a working lab with real attach/attack flows on an open 5G core.

## 6. Feasibility & Resources (Why We Can Actually Build It)

- **No real RAN hardware or telecom carrier access is required.** The entire testbed runs on a single laptop or desktop:
  - **Open5GS** — a free, open-source 5G core (NRF/AMF/SMF/UDM/UDR/AUSF/PCF) running locally.
  - **UERANSIM** — open-source software that simulates both cell towers (gNBs) and mobile phones (UEs), generating real 3GPP-compliant signaling.
  - **No physical SIM cards, radios, or spectrum licenses** — subscriber identities and attack scenarios are simulated entirely in software.
  - The system captures and replays PCAP traffic locally for testing — fully reproducible on any laptop.
- **Everything runs from a single repository** — a classmate can clone, build, and run the demo in under an hour.
- **Familiar Python stack** (FastAPI, Streamlit, packet parsing, SQL, HTTP integrations) — every group member can contribute without steep tooling cost.
- **Modular design** — each feature above is an independently testable module, so work divides cleanly across the team.

## 7. Scope & Roadmap (to Graduation)

| Phase | Deliverable | Focus |
|---|---|---|
| 1 | **Prototype core** | PCAP replay + three detection rules + subscriber inventory + alert output — runs on a single laptop |
| 2 | **Product surface** | REST API, SOC dashboard, RBAC, incident correlation |
| 3 | **Response & integrations** | SOAR actions, SIEM forwarding, audit chain |
| 4 | **Hardening & showcase** | PostgreSQL, TLS, SSO, backup/DR, metrics; final live lab demo + report |

The phasing is explicitly sized so the team can deliver a working, screencast-demoable system **long before** graduation, with the later phases being polish/enterprise additions. Everything is built and testable on a single student machine — no external dependencies at any phase.

## 8. What We Will Demonstrate at Showcase

A live/screencast demo running **entirely on a student laptop with no external dependencies**:

1. An **Open5GS** 5G core starts locally (NRF, AMF, SMF, UDM, AUSF, PCF — all open-source).
2. **UERANSIM** launches a simulated cell tower (gNB) and a legitimate subscriber phone.
3. The subscriber **registers successfully** — NASWatch logs it as AUTHORIZED.
4. A **rogue/suspended phone** attempts to register — NASWatch raises a **CRITICAL alert** in real time.
5. The alert correlates into an **incident**, triggers a **quarantine/revoke response**, and logs it in a **tamper-evident audit trail**.

All components run from a single repository on a single machine. No real telecom infrastructure, SIM cards, or carrier cooperation is involved.

## 9. Why This Project Deserves Selection

1. **Creative and original** — an under-explored security niche with genuine market relevance (not another web scanner).
2. **Authentic own work** — every module is built and tested by our team, from packet decoding to response actions.
3. **Deterministic and demonstrable** — the open 5G lab gives us a rigorous, repeatable way to prove the system works.
4. **Sustainable to graduation** — a phased plan that always has something working to show, with clear-cut modules for each team member.