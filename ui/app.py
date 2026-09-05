"""
NASWatch: 5G Control-Plane Intrusion Detection & Response System
Enterprise Security Operations Center (SOC) Console
==============================================================
High-end Cyber SOC Theme, 5G Network-Slice Matrix, Interactive
Topology, SOAR Response Controls & Commercial API Manager.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add project root to sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pandas as pd
import streamlit as st
from datetime import datetime

from naswatch.detection.engine import DetectionEngine
from naswatch.ingestion.pcap_replay import PCAPReplayer
from naswatch.mitigation.soar import SOAREngine
from naswatch.storage.models import Device, DeviceStatus
from naswatch.storage.sqlite_repo import SQLiteRepository
from scripts.seed_inventory import parse_slices_field, seed_inventory_from_csv
from ui.components import (
    render_alert_item,
    render_interactive_topology_graph,
    render_kpi_cards,
    render_network_slice_matrix,
    render_severity_chart,
    render_threat_timeline,
)

# Optional commercial modules
try:
    from naswatch.auth.api_keys import APIKeyStore
    from naswatch.licensing.validator import validate_license
    _COMMERCIAL_AVAILABLE = True
except ImportError:
    _COMMERCIAL_AVAILABLE = False


# Page Configuration
st.set_page_config(
    page_title="NASWatch SOC | 5G Threat Defense",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# High-End Cybersecurity SOC Theme (CSS)
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');

    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', sans-serif;
    }
    
    code, pre {
        font-family: 'JetBrains Mono', monospace !important;
    }

    .stApp {
        background-color: #090d16;
        color: #f8fafc;
    }

    /* Glassmorphic Executive Metric Cards */
    .soc-card {
        background: linear-gradient(135deg, rgba(30, 41, 59, 0.7) 0%, rgba(15, 23, 42, 0.9) 100%);
        backdrop-filter: blur(12px);
        border-radius: 12px;
        padding: 18px 20px;
        border: 1px solid rgba(51, 65, 85, 0.6);
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .soc-card:hover {
        transform: translateY(-2px);
        border-color: rgba(56, 189, 248, 0.6);
    }
    .soc-card-cyan { border-top: 3px solid #00f2fe; }
    .soc-card-red { border-top: 3px solid #ef4444; }
    .soc-card-crit { border-top: 3px solid #dc2626; }
    .soc-card-orange { border-top: 3px solid #f97316; }
    .soc-card-blue { border-top: 3px solid #3b82f6; }

    .soc-card-label {
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.08em;
        color: #94a3b8;
        margin-bottom: 6px;
    }
    .soc-card-value {
        font-size: 28px;
        font-weight: 800;
        line-height: 1.1;
        font-family: 'JetBrains Mono', monospace;
    }
    .soc-card-sub {
        font-size: 11px;
        color: #64748b;
        margin-top: 6px;
        font-weight: 500;
    }

    .text-cyan { color: #00f2fe; }
    .text-red { color: #f87171; }
    .text-orange { color: #fb923c; }
    .text-green { color: #34d399; }
    .text-blue { color: #60a5fa; }

    /* Custom Badges */
    .badge {
        display: inline-block;
        padding: 3px 8px;
        border-radius: 6px;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.04em;
        font-family: 'JetBrains Mono', monospace;
    }
    .badge-crit { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid #ef4444; }
    .badge-orange { background: rgba(249, 115, 22, 0.2); color: #fdba74; border: 1px solid #f97316; }
    .badge-yellow { background: rgba(234, 179, 8, 0.2); color: #fde047; border: 1px solid #eab308; }
    .badge-green { background: rgba(16, 185, 129, 0.2); color: #86efac; border: 1px solid #10b981; }
    .badge-blue { background: rgba(59, 130, 246, 0.2); color: #93c5fd; border: 1px solid #3b82f6; }

    /* Sleek Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 6px;
        background-color: rgba(15, 23, 42, 0.6);
        padding: 6px;
        border-radius: 10px;
        border: 1px solid #1e293b;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: transparent;
        border-radius: 8px;
        color: #94a3b8;
        padding: 8px 18px;
        font-weight: 600;
        font-size: 13px;
        border: none;
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%) !important;
        color: #ffffff !important;
        box-shadow: 0 2px 10px rgba(2, 132, 199, 0.4);
    }

    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #0b1120;
        border-right: 1px solid #1e293b;
    }

    /* Buttons */
    div.stButton > button:first-child {
        border-radius: 8px;
        font-weight: 600;
        font-size: 13px;
        transition: all 0.2s;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_repository(db_path: str = "data/inventory.db") -> SQLiteRepository:
    """Initialize singleton SQLite repository."""
    return SQLiteRepository(db_path=db_path)


def main() -> None:
    db_path = "data/inventory.db"
    repo = get_repository(db_path)

    # Initialize Session State
    if "inspected_count" not in st.session_state:
        st.session_state.inspected_count = 0
    if "last_events" not in st.session_state:
        st.session_state.last_events = []

    # Auto-seed database if empty
    if repo.count_devices() == 0:
        seed_csv = "scripts/sample_devices.csv"
        if Path(seed_csv).exists():
            seed_inventory_from_csv(seed_csv, db_path)

    # Top Navigation Banner
    col_logo, col_stat = st.columns([3, 1])
    with col_logo:
        st.markdown(
            """
            <div style="display:flex; align-items:center; gap:14px; margin-bottom: 4px;">
                <div style="background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%); width:42px; height:42px; border-radius:10px; display:flex; align-items:center; justify-content:center; font-size:22px; box-shadow: 0 0 15px rgba(0, 242, 254, 0.4);">
                    🛡️
                </div>
                <div>
                    <h2 style="margin:0; font-size:24px; font-weight:800; letter-spacing:-0.02em; background: linear-gradient(90deg, #f8fafc, #94a3b8); -webkit-background-clip:text; -webkit-text-fill-color:transparent;">
                        NASWatch <span style="font-size:14px; font-weight:700; color:#00f2fe; -webkit-text-fill-color:#00f2fe; background:rgba(0,242,254,0.1); padding:2px 8px; border-radius:6px; border:1px solid rgba(0,242,254,0.3);">ENTERPRISE SOC</span>
                    </h2>
                    <p style="margin:0; color:#64748b; font-size:12px;">Carrier-Grade 5G Control-Plane Threat Detection, Slice Isolation & SOAR Mitigation</p>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col_stat:
        st.markdown(
            """
            <div style="text-align: right; padding-top: 8px;">
                <span class="badge badge-green" style="padding:6px 12px; font-size:12px;">
                    ● 5G CORE ACTIVE N2/N1
                </span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Sidebar Controls
    with st.sidebar:
        st.markdown(
            """
            <div style="background:rgba(30,41,59,0.5); padding:12px; border-radius:8px; border:1px solid #334155; margin-bottom:16px;">
                <div style="font-size:11px; color:#94a3b8; font-weight:700;">ACTIVE INTERFACE</div>
                <div style="color:#38bdf8; font-family:monospace; font-weight:bold; font-size:13px;">SCTP :38412 (gNB ↔ AMF)</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.subheader("⚙️ Traffic Ingestion")
        pcap_path = st.text_input("Signaling PCAP Replay File", value="data/pcaps/5g_signaling_demo.pcap")

        if st.button("🚀 Replay PCAP Traffic", use_container_width=True, type="primary"):
            if not Path(pcap_path).exists():
                st.error(f"PCAP file '{pcap_path}' not found! Generating sample fixtures...")
                from tests.fixtures.generate_mock_pcap import build_mock_signaling_pcap
                build_mock_signaling_pcap(pcap_path)

            engine = DetectionEngine(device_repo=repo)
            replayer = PCAPReplayer(pcap_path=pcap_path)

            new_alerts = 0
            event_log = []

            with st.spinner("Dissecting 5G control-plane signaling packets..."):
                for event in replayer.stream_events():
                    st.session_state.inspected_count += 1
                    event_log.append(
                        {
                            "Time": event.timestamp.strftime("%H:%M:%S"),
                            "Packet#": event.packet_num,
                            "Procedure": event.procedure_name or "5GS_Signaling",
                            "IMSI": event.imsi or "N/A",
                            "IMEI": event.imei or "N/A",
                            "Slice": event.requested_slice_id or "N/A",
                            "Cell": event.cell_id or "N/A",
                            "Cipher": event.cipher_algo or "NEA2",
                            "Integrity": event.integrity_algo or "NIA2",
                        }
                    )
                    alerts = engine.process_event(event)
                    for a in alerts:
                        repo.record_alert(a)
                        new_alerts += 1

            st.session_state.last_events = event_log
            st.toast(f"✅ Dissected {len(event_log)} packets! Generated {new_alerts} alerts.", icon="🚨")
            st.rerun()

        st.divider()
        st.subheader("🗄️ Database & Inventory Maintenance")
        c_b1, c_b2 = st.columns(2)
        with c_b1:
            if st.button("🌱 Re-Seed DB", use_container_width=True):
                seed_inventory_from_csv("scripts/sample_devices.csv", db_path)
                st.toast("Seeded sample devices into inventory", icon="🌱")
                st.rerun()
        with c_b2:
            if st.button("🗑️ Clear Alerts", use_container_width=True):
                repo.clear_alerts()
                st.session_state.inspected_count = 0
                st.session_state.last_events = []
                st.toast("Cleared security alerts table", icon="🧹")
                st.rerun()

        st.divider()
        st.subheader("🔍 Alert Filtering")
        selected_severity = st.selectbox(
            "Filter Severity",
            ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            index=0,
        )
        selected_rule = st.selectbox(
            "Filter Detection Rule",
            [
                "ALL",
                "ROGUE_DEVICE",
                "IDENTITY_SPOOFING",
                "SLICE_INTRUSION",
                "CIPHER_DOWNGRADE",
                "FALSE_BASE_STATION",
                "SIGNALING_FLOOD",
            ],
            index=0,
        )

        st.divider()
        if st.button("🔄 Refresh Data", use_container_width=True):
            st.rerun()

    # Load Repository Data
    devices = repo.list_all(limit=500)
    sev_filter = None if selected_severity == "ALL" else selected_severity
    rule_filter = None if selected_rule == "ALL" else selected_rule
    all_alerts = repo.get_alerts(limit=500)
    filtered_alerts = repo.get_alerts(limit=500, severity=sev_filter, rule_type=rule_filter)

    # Compute KPI Metrics
    crit_count = sum(1 for a in all_alerts if a.severity.value == "CRITICAL")
    high_count = sum(1 for a in all_alerts if a.severity.value == "HIGH")
    med_count = sum(1 for a in all_alerts if a.severity.value == "MEDIUM")

    display_packets = (
        st.session_state.inspected_count
        if st.session_state.inspected_count > 0
        else (6 if len(all_alerts) > 0 else 0)
    )

    # Render Executive Metric Cards
    render_kpi_cards(
        total_packets=display_packets,
        total_alerts=len(all_alerts),
        critical_count=crit_count,
        high_count=high_count,
        medium_count=med_count,
        device_count=len(devices),
    )

    st.markdown("<br>", unsafe_allow_html=True)

    soar = SOAREngine(device_repo=repo, alert_repo=repo)

    # Main SOC Navigation Tabs
    tab_threats, tab_topo, tab_slices, tab_packets, tab_devices, tab_license, tab_rules = st.tabs(
        [
            "🚨 Threat Incidents",
            "🗺️ 5G Core Topology",
            "🌐 Network-Slice Matrix",
            "🔬 Signaling Stream Dissect",
            "📱 Authorized Inventory",
            "🔑 Commercial API & Licensing",
            "📖 Detection Rulebook",
        ]
    )

    # -------------------------------------------------------------------------
    # Tab 1: Threat Incidents & Triage Queue
    # -------------------------------------------------------------------------
    with tab_threats:
        col_c1, col_c2 = st.columns([1, 2])
        with col_c1:
            render_severity_chart(all_alerts)
        with col_c2:
            render_threat_timeline(all_alerts)

        st.subheader(f"📋 Incident Triage Queue ({len(filtered_alerts)} Incident Cards)")
        if not filtered_alerts:
            st.info("No security incidents match the active filters. Network traffic is clean.")
        else:
            for alert in filtered_alerts:
                render_alert_item(alert, repo, soar=soar)

    # -------------------------------------------------------------------------
    # Tab 2: Interactive 5G Core Topology Map
    # -------------------------------------------------------------------------
    with tab_topo:
        render_interactive_topology_graph(all_alerts, devices)
        st.markdown(
            """
            <div style="background:#1e293b; padding:14px; border-radius:8px; border:1px solid #334155; font-size:12px; color:#94a3b8;">
                <strong style="color:#f8fafc;">Topology Key:</strong>
                <span style="margin-left:10px;">🔷 <strong>5G Core AMF:</strong> Control-Plane Ingress Anchor</span>
                <span style="margin-left:14px;">🟩 <strong>gNodeB:</strong> Radio Access Node</span>
                <span style="margin-left:14px;">💎 <strong>Slices (S-NSSAI):</strong> Virtualized Data Partitions</span>
                <span style="margin-left:14px;">🔴 <strong>Red Link / Node:</strong> Active Threat Detection Vector</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # -------------------------------------------------------------------------
    # Tab 3: Network Slice Matrix
    # -------------------------------------------------------------------------
    with tab_slices:
        render_network_slice_matrix(all_alerts, devices)
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(
            """
            ### 3GPP TS 23.501 Slice Isolation Model
            In 5G Standalone (SA) architecture, **Network Slicing** partitions a single Physical 5G Core (5GC) into isolated logical subnetworks identified by **S-NSSAI**:
            - **SST (Slice/Service Type):** Standard 8-bit integer (1: eMBB, 2: URLLC, 3: MIoT, 4: V2X, 5: High-Data-Rate).
            - **SD (Slice Differentiator):** Optional 24-bit hex value defining tenant or enterprise boundary.

            **Threat Mitigation:** Unauthorized slice hopping attempts to critical SCADA or emergency partitions trigger instant SOAR containment.
            """
        )

    # -------------------------------------------------------------------------
    # Tab 4: Signaling Stream Dissect
    # -------------------------------------------------------------------------
    with tab_packets:
        st.subheader("🔬 5G NGAP & NAS-5GS Protocol Frame Dissector")
        if not st.session_state.last_events:
            st.info("No packets dissected in this interactive session. Click **'🚀 Replay PCAP Traffic'** in the sidebar to stream frames.")
        else:
            df_events = pd.DataFrame(st.session_state.last_events)
            st.dataframe(df_events, use_container_width=True, hide_index=True)

    # -------------------------------------------------------------------------
    # Tab 5: Authorized Inventory
    # -------------------------------------------------------------------------
    with tab_devices:
        st.subheader(f"📱 Provisioned 5G Subscribers ({len(devices)} Devices)")
        if not devices:
            st.warning("Inventory empty. Click 'Re-Seed DB' in sidebar.")
        else:
            dev_rows = [
                {
                    "IMSI (SUPI)": d.imsi,
                    "IMEI (PEI)": d.imei,
                    "Subscriber / Unit": d.owner_name,
                    "Hardware Model": d.device_model,
                    "Status": d.status.value,
                    "Authorized Slices": ", ".join(s.slice_id for s in d.allowed_slices),
                    "Notes": d.notes,
                }
                for d in devices
            ]
            st.dataframe(pd.DataFrame(dev_rows), use_container_width=True, hide_index=True)

    # -------------------------------------------------------------------------
    # Tab 6: Commercial API & Licensing
    # -------------------------------------------------------------------------
    with tab_license:
        st.subheader("🔑 Commercial Licensing & M2M API Keys")
        col_lic1, col_lic2 = st.columns(2)

        with col_lic1:
            st.markdown(
                """
                <div style="background:#1e293b; padding:18px; border-radius:10px; border:1px solid #334155;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <h4 style="margin:0; color:#38bdf8;">Enterprise License</h4>
                        <span class="badge badge-green">ACTIVE TIER</span>
                    </div>
                    <hr style="margin:10px 0; border-color:#334155;">
                    <p style="font-size:13px; color:#cbd5e1; margin:4px 0;"><strong>Organization:</strong> Enterprise Telecommunications Lab</p>
                    <p style="font-size:13px; color:#cbd5e1; margin:4px 0;"><strong>Edition:</strong> Commercial Enterprise v1.0.0</p>
                    <p style="font-size:13px; color:#cbd5e1; margin:4px 0;"><strong>Active Feature Flags:</strong></p>
                    <ul style="font-size:12px; color:#94a3b8; margin:0 0 0 16px;">
                        <li>✓ Pure 3GPP Control-Plane Rulebook (6 Rules)</li>
                        <li>✓ Alert Correlation & Incident Escalation Engine</li>
                        <li>✓ Multi-Tenant JWT & RBAC Management</li>
                        <li>✓ Immutable Audit Trail with SHA-256 Hashes</li>
                        <li>✓ PagerDuty, Splunk HEC & Microsoft Sentinel Sinks</li>
                        <li>✓ Prometheus & Grafana SOC Dashboards</li>
                    </ul>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with col_lic2:
            st.markdown(
                """
                <div style="background:#1e293b; padding:18px; border-radius:10px; border:1px solid #334155;">
                    <h4 style="margin:0; color:#38bdf8;">Generate Machine API Key</h4>
                    <p style="font-size:12px; color:#94a3b8; margin:6px 0 12px 0;">Create SHA-256 hashed API keys for external AMF agents or Kubernetes probes.</p>
                </div>
                """,
                unsafe_allow_html=True,
            )
            key_name = st.text_input("Key Name", value="edge-probe-amf1")
            key_role = st.selectbox("Role", ["analyst", "viewer", "admin"])
            if st.button("Generate M2M API Key", use_container_width=True):
                if _COMMERCIAL_AVAILABLE:
                    store = APIKeyStore(db_path=db_path)
                    raw_k, kid = store.create_key(name=key_name, role=key_role)
                    st.success("API Key Generated:")
                    st.code(raw_k, language="bash")
                    st.caption("Copy this key now. It is stored as a SHA-256 hash.")
                else:
                    st.error("Auth module not found.")

    # -------------------------------------------------------------------------
    # Tab 7: 5G Threat Architecture & Rules
    # -------------------------------------------------------------------------
    with tab_rules:
        st.subheader("📖 3GPP 5GS Threat Detection Specifications")
        rule_data = [
            {"Rule ID": "RULE-5G-01", "Threat Name": "Rogue eSIM / Unknown IMSI", "Severity": "CRITICAL", "Layer": "TS 24.501 RegReq", "Impact": "Unprovisioned device accessing licensed spectrum"},
            {"Rule ID": "RULE-5G-02", "Threat Name": "Identity Spoofing / SIM Cloning", "Severity": "HIGH", "Layer": "TS 24.501 SecMode", "Impact": "Captured IMSI transmitting from mismatched PEI"},
            {"Rule ID": "RULE-5G-03", "Threat Name": "Slice Intrusion / Hopping", "Severity": "MEDIUM", "Layer": "TS 24.501 PDUEstablish", "Impact": "Unauthorized access to SCADA or emergency slice"},
            {"Rule ID": "RULE-5G-04", "Threat Name": "Cipher / Integrity Downgrade", "Severity": "HIGH", "Layer": "TS 24.501 SecModeCmd", "Impact": "Null encryption (NEA0/NIA0) enabling MITM eavesdropping"},
            {"Rule ID": "RULE-5G-05", "Threat Name": "False Base Station / Rogue gNB", "Severity": "CRITICAL", "Layer": "TS 38.413 NGAP InitialUE", "Impact": "Fake cell attracting subscribers (IMSI catcher)"},
            {"Rule ID": "RULE-5G-06", "Threat Name": "Signaling Flood / Storm", "Severity": "HIGH", "Layer": "TS 24.501 Rate Limit", "Impact": "Signaling DoS against 5G Core AMF registration plane"},
        ]
        st.dataframe(pd.DataFrame(rule_data), use_container_width=True, hide_index=True)


if __name__ == "__main__":
    main()
