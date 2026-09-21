# NASWatch — Project Idea Overview

> **Stage:** Idea / concept validation
> **Status:** Not yet built; design and threat-model reasoning only

---

## One-Liner

**NASWatch** is an idea for a 5G control-plane intrusion-detection and response (IDS/IR) platform that watches the signaling between cell towers and the core network — and can spot, block, and evict rogue subscribers, suspended-device abuse, and signaling floods in real time.

## The Problem

Standard IT security tooling does not understand 5G networks. Telco and private-5G operators are exposed to attacks that normal SOC (Security Operations Center) tools miss:

- **Rogue eSIMs / IMSI abuse** — cloned or stolen subscriber identities that attach to the network carrying no valid credential state.
- **Suspended / ex-contractor access** — deactivated subscribers attempting network attach and being admitted.
- **Network-slize intrusion** — a device attaching to a different slice (e.g., an enterprise-private slice) than it is provisioned for, crossing tenant boundaries inside the same physical core.
- **Signaling floods** — SS7-era-style attacks moved to the 5G control plane (registration storms) aimed at knocking out the N2/N1 signaling interface.

Attackers prosecute these attacks *between* the gNB and the AMF — on the N2/N1 interface. Most operators have no visibility there.

## The Idea

Attach a passive inspection point at the **N2/N1 interface** (gNB ↔ AMF) — via eBPF capture on the transport, or a mirror port — that decodes the 5G control-plane signaling (NGAP/NAS, 3GPP TS 38.413 / TS 24.501) and applies detection logic in real time:

1. **Watch** every attach/register message as it flows.
2. **Match** it against the operator's provisioned subscriber inventory (IMSI → authorized status, allowed slices).
3. **Alert** on rogue/suspended/mis-sliced subscribers and flood patterns.
4. **Respond** by pushing revocations/quarantines into the core (UDM/AMF) or generating firewall rules against offending RAN cells.

Rather than shipping a hardware appliance, the plan is a **software probe + analysis engine + SOC dashboard** that plugs into existing open 5G cores (Open5GS) and commercial NEs, exposing REST APIs and streaming alerts to established SIEM tools (Splunk, Sentinel, PagerDuty).

## Why Now

- **5G standalone (SA) is scaling** with network slicing (3GPP TS 23.501), which widens the attack surface and the blast radius of a cross-tenant intrusion.
- **Open source cores (Open5GS) and testbeds (UERANSIM)** make 5G control-plane traffic cheaply reproducible, testable, and sellable — validation no longer requires a lab with a real RAN.
- **N2/N1 is still a blind spot** for existing NDR/IDS vendors; early movers own a new monitoring category inside telecom security budgets.

## Target Users

| Segment | Need |
|---|---|
| Telco MNOs | Detect 5G slice/rogue-device intrusions and signaling floods; respond inside the core |
| Private 5G / industrial enterprises | Enforce tenant isolation on their on-premises slice; keep ex-contractors out |
| MSSPs / SOCs serving telco | A 5G-aware visibility feed into their existing SIEM workflows |

## Differentiators

- **Control-plane focus** — not IP-packet heuristics, but actual NGAP/NAS signaling semantics.
- **Subscriber-truth correlation** — every control-plane event is checked against real provisioning state; false positives are dramatically lower than signature-only IDS.
- **Programmatic response** — revoke/quarantine/push firewall rules, not just "an alert in a dashboard."
- **Open-to-proprietary path** — works against Open5GS lab/trials today, targets commercial interfaces in production.

## Proposed Architecture (conceptual)

```
[ gNB ] --(N2/N1, SCTP)--> [ AMF ]
                             |
Enhanced eBPF / mirror probe --+---> NASWatch Analysis Engine
                                        |  detection rules
                                        |  correlation + incident grouping
                                        |  SOAR actions (revoke/quarantine/floodwall)
                                        +---> REST API, SOC dashboard, SIEM forwarders
```

High-level components of the idea:

1. **Signaling Probe** — capture layer on N2/N1 with NGAP/NAS decoding.
2. **Detection Engine** — rule set: rogue device, suspended/unauthorized access, slice mismatch, registration floods; severity and escalation.
3. **Correlation** — group repeated events into incidents; escalate on rule co-occurrence.
4. **Response (SOAR)** — subscriber credential revocation, IMSI quarantine, cell-level firewall drop rules.
5. **Inventory & Tenancy** — provisioned subscriber/slice matrix used as ground truth, tenant-scoped by `org_id`.
6. **Interface** — REST API, live SOC dashboard, alert streaming to SIEM.

## MVP Scope (first build)

- Decode and replay 5G signaling test traffic (captured PCAP from a lab testbed).
- Detect the four headline rules against a seeded subscriber inventory.
- Provide the API + dashboard + SIEM forwarders.
- Validate on a fully open-stack lab: Open5GS core + UERANSIM UEs running a real attach/attack scenario.

## Roadmap (idea → production)

- **Phase 0 — Concept:** repo + threat model + this document.
- **Phase 1 — Prototype:** pcap replay, core rules, sub inventory, CLI pipeline.
- **Phase 2 — Product surface:** REST API, SOC dashboard, RBAC, audit trail.
- **Phase 3 — Enterprise hardening:** encryption/TLS edge, PostgreSQL backend, keyed integrity-protected audit chain, SSO/OIDC, backup/DR, monitoring/metrics.
- **Phase 4 — Production:** live capture probe (eBPF), commercial MPN integration, scaling, certification.

## Open Questions (for validation)

- Do operators prefer passive mirror port vs. inline eBPF for real deployments? Impact on capture of encrypted/disaggregated RAN (O-RAN interfaces)?
- Which commercial core (Nokia / Ericsson / Mavenir / oracle cloud) should define the first native integration?
- Pricing model: per-subscriber, per-cell, or annual enterprise license?

## Ask / Next Step

Validate the concept with 2–3 private-5G/telco security leads to confirm the pain, then build the **Phase 1 prototype** — scripted detection pipeline replaying 5G attack PCAPs against a seeded inventory, with sample alerts as demonstrable proof.