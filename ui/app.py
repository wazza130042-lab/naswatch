"""
NASWatch: 5G Control-Plane Intrusion Detection System
Streamlit Security Operations Center (SOC) Dashboard.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add project root to sys.path so scripts and naswatch packages resolve when run via Streamlit
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pandas as pd
import streamlit as st

from naswatch.detection.engine import DetectionEngine
from naswatch.ingestion.pcap_replay import PCAPReplayer
from naswatch.mitigation.soar import SOAREngine
from naswatch.storage.models import Device, DeviceStatus
from naswatch.storage.sqlite_repo import SQLiteRepository
from scripts.seed_inventory import parse_slices_field, seed_inventory_from_csv
from ui.components import (
    render_alert_item,
    render_kpi_cards,
    render_network_slice_matrix,
    render_severity_chart,
    render_threat_timeline,
)

# Set Streamlit Page Config
st.set_page_config(
    page_title="NASWatch | 5G Control-Plane IDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling (Cybersecurity Dark SOC Theme)
st.markdown(
    """
    <style>
    .stApp {
        background-color: #0f172a;
        color: #f8fafc;
    }
    .metric-card {
        background-color: #1e293b;
        border-radius: 8px;
        padding: 16px;
        border: 1px solid #334155;
    }
    div[data-testid="stMetric"] {
        background-color: #1e293b;
        border-radius: 8px;
        padding: 12px;
        border: 1px solid #334155;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: #1e293b;
        border-radius: 6px;
        color: #94a3b8;
        padding: 8px 16px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #38bdf8 !important;
        color: #0f172a !important;
        font-weight: bold;
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

    # Header
    col_title, col_status = st.columns([3, 1])
    with col_title:
        st.title("🛡️ NASWatch: 5G Control-Plane IDS")
        st.caption("Passive NGAP / NAS-5GS Signaling Inspector for Rogue eSIMs & Network-Slice Intrusions")
    with col_status:
        st.markdown(
            """
            <div style="text-align: right; padding-top: 15px;">
                <span style="background-color: #065f46; color: #34d399; padding: 6px 14px; border-radius: 20px; font-weight: bold; font-size: 13px;">
                    ● ACTIVE MONITORING
                </span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Sidebar Controls
    with st.sidebar:
        st.image("https://img.icons8.com/color/96/5g.png", width=64)
        st.header("⚙️ Pipeline Controls")

        st.subheader("Traffic Ingestion")
        pcap_path = st.text_input("PCAP Replay Source", value="data/pcaps/5g_signaling_demo.pcap")

        if st.button("🚀 Replay PCAP Traffic", use_container_width=True, type="primary"):
            if not Path(pcap_path).exists():
                st.error(f"PCAP file '{pcap_path}' not found! Generating sample fixtures...")
                from tests.fixtures.generate_mock_pcap import build_mock_signaling_pcap
                build_mock_signaling_pcap(pcap_path)

            engine = DetectionEngine(device_repo=repo)
            replayer = PCAPReplayer(pcap_path=pcap_path)

            new_alerts = 0
            event_log = []

            with st.spinner("Streaming & dissecting 5G control-plane packets..."):
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
                        }
                    )
                    alerts = engine.process_event(event)
                    for a in alerts:
                        repo.record_alert(a)
                        new_alerts += 1

            st.session_state.last_events = event_log
            st.success(f"Dissected {len(event_log)} packets! Generated {new_alerts} new threat alerts.")
            st.rerun()

        st.divider()
        st.subheader("Inventory & DB Maintenance")
        col_s1, col_s2 = st.columns(2)
        with col_s1:
            if st.button("🌱 Re-Seed DB", use_container_width=True):
                seed_inventory_from_csv("scripts/sample_devices.csv", db_path)
                st.success("Seeded sample devices.")
                st.rerun()
        with col_s2:
            if st.button("🗑️ Clear Alerts", use_container_width=True):
                repo.clear_alerts()
                st.session_state.inspected_count = 0
                st.session_state.last_events = []
                st.info("Cleared all alerts.")
                st.rerun()

        st.divider()
        st.subheader("Filter Security Alerts")
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

    # Fetch Data
    devices = repo.list_all(limit=500)
    sev_filter = None if selected_severity == "ALL" else selected_severity
    rule_filter = None if selected_rule == "ALL" else selected_rule
    all_alerts = repo.get_alerts(limit=500)
    filtered_alerts = repo.get_alerts(limit=500, severity=sev_filter, rule_type=rule_filter)

    # Calculate Metrics
    crit_count = sum(1 for a in all_alerts if a.severity.value == "CRITICAL")
    high_count = sum(1 for a in all_alerts if a.severity.value == "HIGH")
    med_count = sum(1 for a in all_alerts if a.severity.value == "MEDIUM")

    # Determine display packet count
    effective_packets = (
        st.session_state.inspected_count
        if st.session_state.inspected_count > 0
        else (6 if len(all_alerts) > 0 else 0)
    )

    # Render KPI Cards
    render_kpi_cards(
        total_packets=effective_packets,
        total_alerts=len(all_alerts),
        critical_count=crit_count,
        high_count=high_count,
        medium_count=med_count,
        device_count=len(devices),
    )

    st.markdown("<br>", unsafe_allow_html=True)

    soar = SOAREngine(device_repo=repo, alert_repo=repo)

    # Main Tabs
    tab_threats, tab_slices, tab_devices, tab_packets, tab_api, tab_architecture = st.tabs(
        [
            "🚨 Real-Time Threat Alerts",
            "🌐 5G Network-Slice Matrix",
            "📱 Authorized eSIM Inventory",
            "📡 Packet Stream Inspector",
            "⚡ Enterprise API & SOAR",
            "📖 5G Threat Architecture & Rules",
        ]
    )

    # Tab 1: Real-Time Threat Alerts
    with tab_threats:
        col_c1, col_c2 = st.columns([1, 2])
        with col_c1:
            render_severity_chart(all_alerts)
        with col_c2:
            render_threat_timeline(all_alerts)

        st.subheader(f"📋 Incident Triage Queue ({len(filtered_alerts)} Alerts)")
        if not filtered_alerts:
            st.info("No security incidents match the active filters. Network traffic is clean.")
        else:
            for alert in filtered_alerts:
                render_alert_item(alert, repo, soar=soar)

    # Tab 2: 5G Network Slice Matrix
    with tab_slices:
        render_network_slice_matrix(all_alerts, devices)

        st.markdown("<br>", unsafe_allow_html=True)
        st.subheader("3GPP 5G Network Slicing Isolation Model")
        st.markdown(
            """
            In 5G Standalone (SA) architecture, **Network Slicing** partitions a single Physical 5G Core (5GC) into isolated logical subnetworks identified by **S-NSSAI** (Single Network Slice Selection Assistance Information):
            - **SST (Slice/Service Type):** Standard 8-bit integer (1: eMBB, 2: URLLC, 3: MIoT, 4: V2X, 5: High-Data-Rate).
            - **SD (Slice Differentiator):** Optional 24-bit hex value defining tenant or enterprise boundary.

            **Threat Model:** A compromised device or malicious insider provisioning their eSIM for an enterprise or emergency slice without authorization can compromise critical low-latency SCADA operations or exfiltrate private intranet data. **NASWatch flags slice hopping in real time at the signaling layer.**
            """
        )

    # Tab 3: Authorized eSIM Inventory
    with tab_devices:
        st.subheader(f"📱 Authorized Device Inventory ({len(devices)} Provisioned Subscribers)")

        device_data = [
            {
                "IMSI (SUPI)": d.imsi,
                "IMEI (PEI)": d.imei,
                "Subscriber / Owner": d.owner_name,
                "Hardware Model": d.device_model,
                "Status": d.status.value,
                "Authorized Slices": ", ".join([s.slice_id for s in d.allowed_slices]) or "None",
                "Notes": d.notes,
            }
            for d in devices
        ]
        df_devices = pd.DataFrame(device_data)
        st.dataframe(df_devices, use_container_width=True)

        with st.expander("➕ Provision New 5G Subscriber"):
            with st.form("form_add_device"):
                c1, c2 = st.columns(2)
                with c1:
                    new_imsi = st.text_input("IMSI / SUPI", value="999700000000006")
                    new_owner = st.text_input("Owner / Organization", value="Finance Dept Gateway")
                    new_status = st.selectbox("Status", ["ACTIVE", "SUSPENDED", "REVOKED"])
                with c2:
                    new_imei = st.text_input("IMEI / PEI", value="860123456789066")
                    new_model = st.text_input("Device Model", value="Sierra Wireless 5G Module")
                    new_slices_str = st.text_input("Allowed Slices (e.g. 1:000001;4:010203)", value="1:000001")

                submitted = st.form_submit_button("Provision Device")
                if submitted:
                    new_dev = Device(
                        imsi=new_imsi.strip(),
                        imei=new_imei.strip(),
                        owner_name=new_owner.strip(),
                        device_model=new_model.strip(),
                        status=DeviceStatus(new_status),
                        allowed_slices=parse_slices_field(new_slices_str),
                    )
                    repo.add(new_dev)
                    st.success(f"Device IMSI {new_imsi} provisioned successfully!")
                    st.rerun()

    # Tab 4: Packet Stream Inspector
    with tab_packets:
        st.subheader("📡 Decoded 5G Signaling Stream Inspector")
        if st.session_state.last_events:
            df_packets = pd.DataFrame(st.session_state.last_events)
            st.dataframe(df_packets, use_container_width=True)
        else:
            st.info("Click 'Replay PCAP Traffic' in the sidebar to run the dissector and inspect packets.")

    # Tab 5: Enterprise REST API & SOAR Control
    with tab_api:
        st.subheader("⚡ Enterprise REST API & Prometheus Telemetry")

        col_a1, col_a2 = st.columns(2)
        with col_a1:
            st.markdown(
                """
                ### 🚀 FastAPI Integration Endpoints
                NASWatch exposes a high-performance **FastAPI microservice** on port `8000`:
                - **Interactive OpenAPI Swagger Docs:** [`http://localhost:8000/docs`](http://localhost:8000/docs)
                - **Health Probe:** `GET /health` (Kubernetes Liveness / Readiness)
                - **Incident Stream:** `GET /api/v1/alerts` (JSON feed for SIEM / Splunk / Wazuh)
                - **Automated SOAR Action:** `POST /api/v1/alerts/{id}/mitigate`
                - **Subscriber Inventory:** `GET /api/v1/devices` & `POST /api/v1/devices`
                - **Direct Ingestion:** `POST /api/v1/ingest/event` (AMF eBPF Sidecar Probe)
                """
            )
            st.code("uvicorn naswatch.api.server:app --host 0.0.0.0 --port 8000", language="bash")

        with col_a2:
            st.markdown(
                """
                ### 📊 Prometheus Metrics Exporter
                Real-time metrics are scraped via standard OpenMetrics format on `/metrics`:
                - `naswatch_packets_inspected_total`: Rate of NGAP/NAS signaling traffic.
                - `naswatch_alerts_generated_total{rule_type, severity}`: Incident velocity counters.
                - `naswatch_provisioned_devices_total`: Current inventory gauge.
                """
            )
            st.code("curl -s http://localhost:8000/metrics | head -n 15", language="bash")

    # Tab 6: 5G Threat Architecture & Rules Guide
    with tab_architecture:
        st.subheader("📖 5G Threat Architecture & Detection Rule Specifications")
        st.markdown(
            """
            ### Detection Rule Blueprint

            | Rule ID | Rule Name | Trigger Condition | 3GPP Reference Layer | Severity |
            |---|---|---|---|---|
            | `RULE-5G-01` | **Rogue Device / Unauthorized eSIM** | Captured IMSI/SUPI does not exist in authorized inventory or is REVOKED | 3GPP TS 24.501 NAS Registration / TS 38.413 InitialUEMessage | **CRITICAL** |
            | `RULE-5G-02` | **Identity Spoofing / SIM Cloning** | IMSI matches authorized inventory, but transmitting IMEI/PEI does not match provisioned hardware | 3GPP TS 24.501 SecurityModeComplete / IdentityResponse | **HIGH** |
            | `RULE-5G-03` | **Network-Slice Intrusion** | Authenticated device attempts connection to S-NSSAI (SST/SD) slice not in provisioned entitlement | 3GPP TS 24.501 PDUSessionEstablishmentRequest | **MEDIUM** |

            ---

            ### Architectural Design Patterns
            - **Separation of Concerns:** The pure detection rules in `naswatch.detection.rules` have zero database, network, or UI dependencies for instantaneous, deterministic unit testing.
            - **Repository Pattern:** Swappable database backends (`DeviceRepository`, `AlertRepository`) allow migrating from SQLite to enterprise PostgreSQL or DynamoDB with zero changes to detection logic.
            - **Pluggable Alert Sinks:** Dispatches to Webhook (SIEM/SOAR/Slack), Syslog (RFC 5424), JSON Lines log files, and live UI streams.
            - **Defensive Packet Parsing:** Multi-layered decoding (PyShark/tshark with Scapy binary fallback) ensures bad or corrupted packets never crash the capture pipeline.
            """
        )


if __name__ == "__main__":
    main()
