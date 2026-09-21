"""
NASWatch — 5G Control-Plane Threat Detection Dashboard
Matches naswatch_redesign.html
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pandas as pd
import streamlit as st

from naswatch.storage.sqlite_repo import SQLiteRepository

st.set_page_config(page_title="NASWatch", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")


@st.cache_resource
def get_repository(db_path: str = "data/inventory.db") -> SQLiteRepository:
    return SQLiteRepository(db_path=db_path)


def get_user_store():
    try:
        from naswatch.auth.users import UserStore
        return UserStore(db_path="data/inventory.db")
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  CSS — matches naswatch_redesign.html exactly
# ══════════════════════════════════════════════════════════════════════════════
CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

:root{
  --bg-base:#0A0D12; --bg-panel:#10141B; --bg-raised:#161B24; --bg-input:#0D1117;
  --border:#212733; --border-soft:#191E28;
  --text-1:#E7EAEE; --text-2:#8B93A3; --text-3:#525A69;
  --signal:#3DDC97; --signal-dim:#1F5E48;
  --crit:#E5484D; --high:#F5A524; --med:#E8C468; --low:#5B8DEF;
  --mono:'IBM Plex Mono', ui-monospace, monospace;
  --sans:'IBM Plex Sans', system-ui, sans-serif;
}

html, body, [class*="css"] { font-family: var(--sans) !important; color: var(--text-1); }
code, pre, [class*="code"], .stCode { font-family: var(--mono) !important; }
.stApp { background: var(--bg-base) !important; }

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
  background: var(--bg-panel) !important;
  border-right: 1px solid var(--border-soft) !important;
  padding-top: 0 !important;
}
section[data-testid="stSidebar"] .stMarkdown { color: var(--text-2); }
section[data-testid="stSidebar"] .stMarkdown h3,
section[data-testid="stSidebar"] .stMarkdown h4,
section[data-testid="stSidebar"] .stMarkdown h5 {
  color: var(--text-3) !important; font-size: 10px !important; font-weight: 600 !important;
  letter-spacing: 0.06em !important; text-transform: uppercase !important; margin-bottom: 6px !important;
}

/* ── Sidebar nav links — styled as .navlink from redesign ── */
[data-testid="stSidebar"] .stRadio { margin-bottom: 0; }
[data-testid="stSidebar"] .stRadio > div { gap: 0 !important; }
[data-testid="stSidebar"] .stRadio > div > label {
  display: flex !important; align-items: center; gap: 10px;
  padding: 9px 10px !important; border-radius: 4px;
  color: var(--text-2) !important; font-size: 13.5px !important; font-weight: 500 !important;
  border-left: 2px solid transparent; margin-bottom: 2px;
  background: transparent !important;
  transition: all 0.12s ease;
}
[data-testid="stSidebar"] .stRadio > div > label:hover {
  color: var(--text-1) !important; background: var(--bg-raised) !important;
}
[data-testid="stSidebar"] .stRadio > div > label:has(input:checked) {
  color: var(--text-1) !important; background: var(--bg-raised) !important;
  border-left-color: var(--signal) !important; font-weight: 600 !important;
}
/* hide the default radio circle */
[data-testid="stSidebar"] .stRadio > div > label > span:first-child {
  display: none !important;
}

/* ── Inputs ── */
.stTextInput input, .stSelectbox select, .stMultiSelect [data-baseweb="select"] {
  background: var(--bg-input) !important;
  border: 1px solid var(--border-soft) !important;
  color: var(--text-1) !important;
  border-radius: 3px !important;
  font-family: var(--mono) !important;
  font-size: 12px !important;
}
.stTextInput input:focus, .stSelectbox select:focus {
  border-color: var(--border) !important;
}
.stTextInput label, .stSelectbox label, .stMultiSelect label {
  color: var(--text-3) !important; font-size: 10px !important; font-weight: 600 !important;
  letter-spacing: 0.05em !important; text-transform: uppercase !important;
}

/* ── Buttons — red replay, green deploy ── */
.stButton > button {
  background: transparent !important;
  border: 1px solid var(--border) !important;
  color: var(--text-1) !important;
  border-radius: 3px !important;
  font-weight: 600 !important;
  font-size: 12px !important;
  font-family: var(--sans) !important;
  transition: all 0.12s ease;
}
.stButton > button:hover { border-color: var(--text-3) !important; background: var(--bg-raised) !important; }
.stButton > button[kind="primary"] {
  background: var(--crit) !important; border-color: var(--crit) !important; color: #fff !important;
}
.stButton > button[kind="primary"]:hover { background: #c93c40 !important; }
.btn-deploy {
  background: var(--signal) !important; border: none !important;
  color: #06110C !important; font-weight: 600 !important; font-size: 12.5px !important;
  padding: 8px 15px !important; border-radius: 3px !important;
}

/* ── Expanders ── */
details[data-testid="stExpander"] {
  background: var(--bg-panel) !important; border: 1px solid var(--border-soft) !important; border-radius: 4px !important;
}
details[data-testid="stExpander"] summary { color: var(--text-1) !important; font-weight: 500 !important; }

/* ── DataFrames ── */
.stDataFrame { border: 1px solid var(--border-soft) !important; border-radius: 4px !important; }

/* ── Forms ── */
.stForm { background: var(--bg-panel) !important; border: 1px solid var(--border-soft) !important; border-radius: 4px !important; }

/* ── Divider ── */
hr { border-color: var(--border-soft) !important; }

/* ── Toast ── */
.stToast { background: var(--bg-panel) !important; border: 1px solid var(--border-soft) !important; }

/* ── Download ── */
.stDownloadButton > button {
  background: var(--bg-raised) !important; border: 1px solid var(--border) !important; color: var(--text-1) !important;
}
.stDownloadButton > button:hover { border-color: var(--text-3) !important; }

/* ══════════════════════════════════════════════════════════════════════════════ */
/*  COMPONENTS — matching naswatch_redesign.html                               */
/* ══════════════════════════════════════════════════════════════════════════════ */

/* ── KPI strip ── */
.kpi-strip {
  border: 1px solid var(--border-soft); border-radius: 4px; display: grid;
  grid-template-columns: repeat(5, 1fr); background: var(--bg-panel); margin-bottom: 24px;
}
.kpi { padding: 16px 20px; border-right: 1px solid var(--border-soft); }
.kpi:last-child { border-right: none; }
.kpi-label { color: var(--text-3); font-size: 10.5px; font-weight: 600; letter-spacing: 0.04em; margin-bottom: 8px; }
.kpi-value { font-family: var(--mono); font-size: 27px; font-weight: 500; line-height: 1; }
.kpi-detail { color: var(--text-3); font-size: 11.5px; margin-top: 7px; }
.kpi.c-signal { box-shadow: inset 2px 0 0 var(--signal); }
.kpi.c-signal .kpi-value { color: var(--text-1); }
.kpi.c-alert { box-shadow: inset 2px 0 0 var(--text-2); }
.kpi.c-alert .kpi-value { color: var(--text-1); }
.kpi.c-crit { box-shadow: inset 2px 0 0 var(--crit); }
.kpi.c-crit .kpi-value { color: var(--crit); }
.kpi.c-high { box-shadow: inset 2px 0 0 var(--high); }
.kpi.c-high .kpi-value { color: var(--high); }
.kpi.c-low { box-shadow: inset 2px 0 0 var(--low); }
.kpi.c-low .kpi-value { color: var(--low); }

/* ── Grid ── */
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }

/* ── Section card ── */
.section-card {
  border: 1px solid var(--border-soft); border-radius: 4px; padding: 20px;
  background: var(--bg-panel);
}
.section-card h3 { margin: 0 0 18px; font-size: 13px; font-weight: 600; }

/* ── Page layout ── */
.page-title { font-size: 20px; font-weight: 700; letter-spacing: -0.01em; margin: 0 0 5px; }
.page-sub { color: var(--text-2); font-size: 13px; max-width: 560px; line-height: 1.5; }
.page-head { display: flex; align-items: flex-end; justify-content: space-between; margin-bottom: 22px; flex-wrap: wrap; gap: 14px; }
.page-stats { display: flex; gap: 22px; }
.pstat { text-align: right; }
.pstat-val { font-family: var(--mono); font-size: 20px; font-weight: 500; }
.pstat-label { color: var(--text-3); font-size: 10.5px; font-weight: 600; letter-spacing: 0.04em; margin-top: 2px; }

/* ── Severity tags ── */
.sev-tag {
  font-family: var(--mono); font-size: 10px; font-weight: 600; letter-spacing: 0.04em;
  padding: 3px 7px; border-radius: 2px; flex-shrink: 0;
}
.sev-critical { color: var(--crit); border: 1px solid var(--crit); }
.sev-high { color: var(--high); border: 1px solid var(--high); }
.sev-medium { color: var(--med); border: 1px solid var(--med); }
.sev-low { color: var(--low); border: 1px solid var(--low); }

/* ── Slice table ── */
.slice-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.slice-table th {
  text-align: left; color: var(--text-3); font-size: 10.5px; font-weight: 600;
  letter-spacing: 0.04em; padding: 9px 14px; border-bottom: 1px solid var(--border); background: var(--bg-raised);
}
.slice-table td { padding: 11px 14px; border-bottom: 1px solid var(--border-soft); color: var(--text-2); }
.slice-swatch { width: 8px; height: 8px; border-radius: 2px; display: inline-block; margin-right: 8px; }

/* ── Compliance grid ── */
.compliance-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
.compliance-card {
  border: 1px solid var(--border-soft); border-radius: 4px; padding: 19px 17px; background: var(--bg-panel);
}
.compliance-card .code { font-family: var(--mono); font-size: 13.5px; font-weight: 600; }
.compliance-card .desc { color: var(--text-3); font-size: 11.5px; margin: 5px 0 13px; }
.compliant-tag {
  color: var(--signal); font-size: 10.5px; font-weight: 600; letter-spacing: 0.04em;
  border: 1px solid var(--signal-dim); padding: 3px 8px; border-radius: 2px; display: inline-block;
}

/* ── Audit log ── */
.audit-log { border: 1px solid var(--border-soft); border-radius: 4px; background: var(--bg-panel); padding: 4px 0; margin-bottom: 20px; }
.audit-row {
  display: flex; align-items: center; gap: 14px; padding: 11px 18px;
  border-bottom: 1px solid var(--border-soft); font-size: 12.5px;
}
.audit-row:last-child { border-bottom: none; }
.audit-row time { font-family: var(--mono); color: var(--text-3); font-size: 11.5px; width: 150px; flex-shrink: 0; }
.audit-row .actor { color: var(--text-1); font-weight: 500; }
.audit-row .act { color: var(--text-2); }

/* ── Sidebar blocks ── */
.sidebar-block {
  background: var(--bg-raised); border: 1px solid var(--border-soft); border-radius: 4px;
  padding: 13px; margin-bottom: 14px;
}
.live-tag { display: flex; align-items: center; gap: 7px; color: var(--signal); font-size: 10.5px; font-weight: 600; letter-spacing: 0.06em; margin-bottom: 9px; }
.pulse-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--signal); box-shadow: 0 0 0 3px rgba(61,220,151,0.18); flex-shrink: 0; }
.live-port { font-family: var(--mono); font-size: 18px; font-weight: 500; color: var(--text-1); }
.live-sub { color: var(--text-3); font-size: 11.5px; margin-top: 3px; }

.sidebar-heading { display: flex; align-items: center; gap: 7px; color: var(--text-2); font-size: 12px; font-weight: 600; margin-bottom: 9px; }
.pcap-path {
  background: var(--bg-input); border: 1px solid var(--border-soft); border-radius: 3px;
  padding: 8px 9px; font-family: var(--mono); font-size: 11.5px; color: var(--text-2);
  margin-bottom: 9px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.btn-replay {
  width: 100%; background: transparent; border: 1px solid var(--crit); color: var(--crit);
  font-weight: 600; font-size: 12.5px; padding: 9px; border-radius: 3px; cursor: pointer;
}
.btn-replay:hover { background: rgba(229,72,77,0.08); }

.sidebar-footer {
  margin-top: auto; padding-top: 14px; border-top: 1px solid var(--border-soft);
  display: flex; align-items: center; gap: 9px; color: var(--text-3); font-size: 11.5px;
}
.sidebar-footer .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--signal); }

/* ── Incident cards ── */
.incident { border: 1px solid var(--border-soft); border-radius: 4px; background: var(--bg-panel); overflow: hidden; margin-bottom: 9px; }
.incident-head { display: flex; align-items: center; gap: 11px; padding: 13px 16px; cursor: pointer; }
.incident-head .chevr { margin-left: auto; color: var(--text-3); font-size: 12px; transition: transform 0.15s; }
.incident.open .incident-head .chevr { transform: rotate(90deg); }
.incident-title { font-size: 13px; color: var(--text-1); font-weight: 500; }
.incident-time { color: var(--text-3); font-size: 11.5px; font-family: var(--mono); margin-left: 10px; }
.incident-body { max-height: 0; overflow: hidden; transition: max-height 0.22s ease; border-top: 1px solid var(--border-soft); }
.incident.open .incident-body { max-height: 320px; }
.incident-body-inner { padding: 16px 20px; display: grid; grid-template-columns: 1.3fr 1fr; gap: 24px; }
.incident-desc { color: var(--text-2); font-size: 12.5px; line-height: 1.6; }
.field-table { width: 100%; border-collapse: collapse; margin-top: 14px; font-size: 12px; }
.field-table td { padding: 7px 0; border-bottom: 1px solid var(--border-soft); }
.field-table td:first-child { color: var(--text-3); font-weight: 600; width: 70px; }
.field-table td:last-child { font-family: var(--mono); color: var(--signal); }
.soar-btns { display: flex; gap: 8px; margin-bottom: 10px; }
.soar-btn { flex: 1; border: 1px solid var(--border); background: var(--bg-input); color: var(--text-1); font-size: 12px; font-weight: 600; padding: 8px; border-radius: 3px; cursor: pointer; }
.soar-btn.revoke { color: var(--crit); border-color: rgba(229,72,77,0.35); }
.soar-btn.quarantine { color: var(--high); border-color: rgba(245,165,36,0.35); }
.triage-select { width: 100%; background: var(--bg-input); border: 1px solid var(--border-soft); color: var(--text-1); font-size: 12px; font-weight: 600; padding: 8px 10px; border-radius: 3px; }
</style>
"""


# ══════════════════════════════════════════════════════════════════════════════
#  LOGIN
# ══════════════════════════════════════════════════════════════════════════════
def login_page():
    st.markdown(CSS, unsafe_allow_html=True)
    c1, c2, c3 = st.columns([1.2, 1.6, 1.2])
    with c2:
        st.markdown("<div style='height:80px'></div>", unsafe_allow_html=True)
        st.markdown(
            """
            <div style="text-align:center; margin-bottom:32px;">
                <div style="width:44px; height:44px; border-radius:8px; background:linear-gradient(160deg,rgba(61,220,151,0.08),rgba(61,220,151,0.02));
                            border:1px solid rgba(61,220,151,0.15); display:inline-flex; align-items:center;
                            justify-content:center; margin-bottom:14px;">
                    <svg viewBox="0 0 24 24" fill="none" stroke="#3DDC97" stroke-width="1.6" width="22" height="22">
                        <path d="M12 2 3 6v6c0 5 3.8 8.7 9 10 5.2-1.3 9-5 9-10V6l-9-4Z"/>
                        <path d="M9 12l2 2 4-4"/>
                    </svg>
                </div>
                <div style="font-size:20px; font-weight:700; color:var(--text-1); letter-spacing:-0.01em;">NASWatch</div>
                <div style="font-size:12px; color:var(--text-3); margin-top:3px; letter-spacing:0.02em;">5G control-plane security</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        username = st.text_input("Email", placeholder="admin@naswatch.io", label_visibility="collapsed")
        password = st.text_input("Password", type="password", placeholder="Password", label_visibility="collapsed")
        if st.button("Sign in", use_container_width=True, type="primary"):
            if not username or not password:
                st.error("Enter credentials")
                return
            store = get_user_store()
            if store is None:
                st.error("Auth unavailable")
                return
            user = store.authenticate(username, password)
            if user is None:
                st.error("Invalid credentials")
                return
            st.session_state["user"] = {
                "id": user.id, "username": user.username,
                "role": user.role.value, "org_id": user.org_id,
            }
            st.rerun()
        st.markdown(
            """
            <div style="text-align:center; margin-top:24px; padding:12px; background:var(--bg-raised);
                        border:1px solid var(--border-soft); border-radius:4px;">
                <div style="font-size:9px; font-weight:600; color:var(--text-3); text-transform:uppercase;
                            letter-spacing:0.06em; margin-bottom:6px;">Demo accounts</div>
                <div style="font-size:11px; color:var(--text-2); font-family:var(--mono); line-height:1.7;">
                    admin@naswatch.io<br>analyst@naswatch.io<br>viewer@naswatch.io
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


# ══════════════════════════════════════════════════════════════════════════════
#  PERMISSIONS
# ══════════════════════════════════════════════════════════════════════════════
def get_role() -> str:
    user = st.session_state.get("user")
    return user.get("role", "admin") if user else "admin"

def has(action: str) -> bool:
    role = get_role()
    perms = {
        "admin":   {"replay", "inject", "mitigate", "provision", "clear", "seed", "view"},
        "analyst": {"replay", "mitigate", "view"},
        "viewer":  {"view"},
    }
    return action in perms.get(role, set())


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main() -> None:
    if "user" not in st.session_state:
        login_page()
        return

    user = st.session_state["user"]
    role = user["role"]
    username = user["username"]
    db_path = "data/inventory.db"
    repo = get_repository(db_path)

    if "inspected_count" not in st.session_state:
        st.session_state.inspected_count = 0
    if "last_events" not in st.session_state:
        st.session_state.last_events = []
    if "current_page" not in st.session_state:
        st.session_state.current_page = "Overview"

    if repo.count_devices() == 0:
        seed_csv = "scripts/sample_devices.csv"
        if Path(seed_csv).exists():
            from scripts.seed_inventory import seed_inventory_from_csv
            seed_inventory_from_csv(seed_csv, db_path)

    st.markdown(CSS, unsafe_allow_html=True)

    # ── Sidebar ─────────────────────────────────────────────────────────
    with st.sidebar:
        # Brand
        st.markdown(
            """
            <div style="display:flex; align-items:center; gap:10px; padding:6px 6px 18px;
                        border-bottom:1px solid var(--border-soft); margin-bottom:16px;">
                <div style="width:30px; height:30px; border-radius:7px; background:linear-gradient(160deg,#1B2430,#0D1117);
                            border:1px solid var(--border); display:flex; align-items:center; justify-content:center; flex-shrink:0;">
                    <svg viewBox="0 0 24 24" fill="none" stroke="#3DDC97" stroke-width="1.6" width="16" height="16">
                        <path d="M12 2 3 6v6c0 5 3.8 8.7 9 10 5.2-1.3 9-5 9-10V6l-9-4Z"/>
                        <path d="M9 12l2 2 4-4"/>
                    </svg>
                </div>
                <div>
                    <div style="font-size:14.5px; font-weight:700; letter-spacing:-0.01em; color:var(--text-1);">NASWatch</div>
                    <div style="font-size:10px; color:var(--text-3); letter-spacing:0.03em;">5G control-plane</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Page navigation — matching redesign navlinks with SVG icons
        pages = ["Overview", "Network map", "Threats", "Devices", "Reports"]
        page = st.radio(
            "Navigation",
            pages,
            index=pages.index(st.session_state.current_page),
            key="nav_radio",
            label_visibility="collapsed",
        )
        st.session_state.current_page = page

        st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

        # Live monitor block
        st.markdown(
            """
            <div class="sidebar-block">
                <div class="live-tag"><span class="pulse-dot"></span>LIVE MONITOR</div>
                <div class="live-port">SCTP :38412</div>
                <div class="live-sub">gNB ↔ AMF N2/N1 signaling</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Replay section — matching redesign
        st.markdown(
            '<div class="sidebar-heading">▾ Replay traffic</div>',
            unsafe_allow_html=True,
        )
        pcap_path = st.text_input("PCAP", value="data/pcaps/5g_signaling_demo.pcap", label_visibility="collapsed")
        if has("replay"):
            if st.button("▶  Replay PCAP", use_container_width=True, type="primary", key="btn_replay"):
                if not Path(pcap_path).exists():
                    st.error(f"Not found: {pcap_path}")
                    st.stop()
                from naswatch.detection.engine import DetectionEngine
                from naswatch.ingestion.pcap_replay import PCAPReplayer
                engine = DetectionEngine(device_repo=repo)
                replayer = PCAPReplayer(pcap_path=pcap_path)
                new_alerts = 0
                event_log = []
                with st.spinner("Processing..."):
                    for event in replayer.stream_events():
                        st.session_state.inspected_count += 1
                        event_log.append({
                            "Time": event.timestamp.strftime("%H:%M:%S"),
                            "Packet": event.packet_num,
                            "Procedure": event.procedure_name or "5GS",
                            "IMSI": event.imsi or "—",
                            "IMEI": event.imei or "—",
                            "Slice": event.requested_slice_id or "—",
                            "Cell": event.cell_id or "—",
                            "Cipher": event.cipher_algo or "NEA2",
                            "Integrity": event.integrity_algo or "NIA2",
                        })
                        alerts = engine.process_event(event)
                        for a in alerts:
                            repo.record_alert(a)
                            new_alerts += 1
                st.session_state.last_events = event_log
                st.toast(f"Done — {len(event_log)} packets, {new_alerts} alerts")
                st.rerun()
        else:
            st.button("▶  Replay PCAP", use_container_width=True, disabled=True, key="btn_replay_disabled")

        st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

        # Attack simulator — compact row matching redesign
        if has("inject"):
            with st.expander("› ⚡ Attack simulator"):
                from naswatch.detection.engine import DetectionEngine
                from naswatch.storage.models import ParsedSignalingEvent
                engine = DetectionEngine(device_repo=repo)
                attacks = [
                    ("SIM Cloning", ParsedSignalingEvent(imsi="999700000000001", imei="869999999999999",
                         procedure_name="SecurityModeComplete", cell_id="0x000000010")),
                    ("Slice Intrusion", ParsedSignalingEvent(imsi="999700000000002", requested_sst=2, requested_sd="000002",
                         procedure_name="PDUSessionEstablishmentRequest", cell_id="0x000000010")),
                    ("Rogue gNB", ParsedSignalingEvent(imsi="999700000000001", cell_id="0xDEADBEEF",
                         procedure_name="RegistrationRequest")),
                    ("Cipher Downgrade", ParsedSignalingEvent(imsi="999700000000001", cipher_algo="NEA0", integrity_algo="NIA0",
                         procedure_name="SecurityModeCommand")),
                ]
                for label, evt in attacks:
                    if st.button(label, use_container_width=True, key=f"atk_{label}"):
                        alerts = engine.process_event(evt)
                        for a in alerts:
                            repo.record_alert(a)
                        st.session_state.inspected_count += 1
                        st.toast(f"{label} injected")
                        st.rerun()

        st.markdown("---")

        # Filters
        selected_severity = st.selectbox("Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"], key="sev_filter")
        selected_rule = st.selectbox("Rule", [
            "ALL", "ROGUE_DEVICE", "IDENTITY_SPOOFING", "SLICE_INTRUSION",
            "CIPHER_DOWNGRADE", "FALSE_BASE_STATION", "SIGNALING_FLOOD",
        ], key="rule_filter")

        st.markdown("---")

        # Actions
        c1, c2 = st.columns(2)
        with c1:
            if has("seed"):
                if st.button("🌱 Seed", use_container_width=True, key="btn_seed"):
                    from scripts.seed_inventory import seed_inventory_from_csv
                    seed_inventory_from_csv("scripts/sample_devices.csv", db_path)
                    st.toast("Seeded")
                    st.rerun()
            else:
                st.button("🌱 Seed", use_container_width=True, disabled=True, key="btn_seed_disabled")
        with c2:
            if has("clear"):
                if st.button("🗑 Clear", use_container_width=True, key="btn_clear"):
                    repo.clear_alerts()
                    st.session_state.inspected_count = 0
                    st.session_state.last_events = []
                    st.toast("Cleared")
                    st.rerun()
            else:
                st.button("🗑 Clear", use_container_width=True, disabled=True, key="btn_clear_disabled")

        st.markdown("---")

        # Role + sign out
        role_colors = {"admin": "var(--crit)", "analyst": "var(--high)", "viewer": "var(--low)"}
        role_hex = {"admin": "229,72,77", "analyst": "245,165,36", "viewer": "91,141,239"}
        rc = role_colors.get(role, "var(--text-2)")
        rh = role_hex.get(role, "139,147,163")
        st.markdown(
            f"""
            <div style="display:flex; align-items:center; gap:9px; padding:8px 10px;
                        background:var(--bg-raised); border:1px solid var(--border-soft); border-radius:4px; margin-bottom:10px;">
                <span style="width:7px; height:7px; border-radius:50%; background:{rc}; flex-shrink:0;"></span>
                <span style="font-size:12px; color:var(--text-1); font-weight:500; flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">{username}</span>
                <span style="padding:1px 5px; border-radius:2px; font-size:8px; font-weight:600;
                             text-transform:uppercase; letter-spacing:0.06em; background:rgba({rh},0.12);
                             color:{rc}; border:1px solid rgba({rh},0.25); flex-shrink:0;">{role}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Sign out", use_container_width=True, key="btn_logout"):
            del st.session_state["user"]
            st.rerun()

        # Footer
        st.markdown(
            """
            <div style="margin-top:14px; padding-top:14px; border-top:1px solid var(--border-soft);
                        display:flex; align-items:center; gap:9px; color:var(--text-3); font-size:11.5px;">
                <span class="pulse-dot"></span> System online
            </div>
            """,
            unsafe_allow_html=True,
        )

    # ── Topbar ──────────────────────────────────────────────────────────
    st.markdown(
        f"""
        <div style="display:flex; align-items:center; justify-content:space-between; padding:16px 32px;
                    border-bottom:1px solid var(--border-soft);">
            <div style="color:var(--text-2); font-size:13px;">
                NASWatch <span style="color:var(--text-3); margin:0 6px;">/</span>
                <b style="color:var(--text-1);">{page}</b>
            </div>
            <div style="display:flex; align-items:center; gap:14px;">
                <div style="display:flex; align-items:center; gap:7px; border:1px solid var(--signal-dim);
                            color:var(--signal); font-size:11px; font-weight:600; letter-spacing:0.04em;
                            padding:6px 12px; border-radius:3px;">
                    <span class="pulse-dot"></span>SYSTEM ONLINE
                </div>
                <button class="btn-deploy">Deploy</button>
                <span style="color:var(--text-3); font-size:18px; cursor:pointer;">⋮</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ── Data ────────────────────────────────────────────────────────────
    devices = repo.list_all(limit=500)
    sev_filter = None if selected_severity == "ALL" else selected_severity
    rule_filter = None if selected_rule == "ALL" else selected_rule
    all_alerts = repo.get_alerts(limit=500)
    filtered_alerts = repo.get_alerts(limit=500, severity=sev_filter, rule_type=rule_filter)

    crit_count = sum(1 for a in all_alerts if a.severity.value == "CRITICAL")
    high_count = sum(1 for a in all_alerts if a.severity.value == "HIGH")
    med_count = sum(1 for a in all_alerts if a.severity.value == "MEDIUM")

    display_packets = (
        st.session_state.inspected_count
        if st.session_state.inspected_count > 0
        else (len(all_alerts) * 2 if len(all_alerts) > 0 else 0)
    )

    from ui.components import (
        render_alert_item, render_interactive_topology_graph, render_kpi_cards,
        render_mitre_attack_matrix, render_network_slice_matrix,
        render_severity_chart, render_threat_timeline,
    )

    from naswatch.mitigation.soar import SOAREngine
    soar = SOAREngine(device_repo=repo, alert_repo=repo)

    st.markdown('<div style="padding:28px 32px 70px;">', unsafe_allow_html=True)

    # ── Page routing ────────────────────────────────────────────────────
    if page == "Overview":
        st.markdown(
            """
            <div class="page-head">
                <div>
                    <div class="page-title">Overview</div>
                    <div class="page-sub">Real-time monitoring of NAS-5GS signaling across gNodeB ↔ AMF interfaces. Detects rogue base stations, SIM cloning, slice intrusions and cipher downgrades.</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        render_kpi_cards(display_packets, len(all_alerts), crit_count, high_count, med_count, len(devices))

        col_a, col_b = st.columns(2)
        with col_a:
            render_severity_chart(all_alerts)
        with col_b:
            render_threat_timeline(all_alerts)

    elif page == "Network map":
        gnb_count = 2
        amf_count = 1
        active_slices = max(3, len(set(a.target_slice for a in all_alerts if a.target_slice)))

        st.markdown(
            f"""
            <div class="page-head">
                <div>
                    <div class="page-title">Network map</div>
                    <div class="page-sub">Live topology of radio and core-network elements observed in signaling traffic.</div>
                </div>
                <div class="page-stats">
                    <div class="pstat"><div class="pstat-val">{gnb_count}</div><div class="pstat-label">gNODEBS</div></div>
                    <div class="pstat"><div class="pstat-val">{amf_count}</div><div class="pstat-label">AMF</div></div>
                    <div class="pstat"><div class="pstat-val">{active_slices}</div><div class="pstat-label">ACTIVE SLICES</div></div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        render_interactive_topology_graph(all_alerts, devices)
        render_network_slice_matrix(all_alerts, devices)

    elif page == "Threats":
        sev_counts = {"ALL": len(all_alerts)}
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            sev_counts[sev] = sum(1 for a in all_alerts if a.severity.value == sev)

        st.markdown(
            """
            <div class="page-head">
                <div>
                    <div class="page-title">Threats</div>
                    <div class="page-sub">Incident queue generated from signaling anomalies. Select a severity to filter, or open a row for detail and response actions.</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Severity filter chips matching redesign
        chip_html = '<div style="display:flex; gap:8px; margin-bottom:18px;">'
        sev_active_color = {
            "ALL": "var(--text-1)", "CRITICAL": "var(--crit)", "HIGH": "var(--high)",
            "MEDIUM": "var(--med)", "LOW": "var(--low)",
        }
        sev_border = {
            "ALL": "var(--text-1)", "CRITICAL": "var(--crit)", "HIGH": "var(--high)",
            "MEDIUM": "var(--med)", "LOW": "var(--low)",
        }
        for sev_label in ["ALL", "CRITICAL", "HIGH", "MEDIUM"]:
            count = sev_counts.get(sev_label, 0)
            active = (sev_filter == sev_label) or (sev_filter is None and sev_label == "ALL")
            if active:
                bg = "var(--bg-raised)"
                color = sev_active_color[sev_label]
                border = sev_border[sev_label]
            else:
                bg = "var(--bg-input)"
                color = "var(--text-2)"
                border = "var(--border)"
            chip_html += (
                f'<div style="border:1px solid {border}; background:{bg}; color:{color}; '
                f'font-size:12px; font-weight:600; padding:7px 13px; border-radius:20px; '
                f'display:flex; align-items:center; gap:7px;">'
                f'{sev_label.title()} <span style="font-family:var(--mono);">{count}</span></div>'
            )
        chip_html += '</div>'
        st.markdown(chip_html, unsafe_allow_html=True)

        if not filtered_alerts:
            st.info("No incidents match the current filters.")
        else:
            for alert in filtered_alerts:
                render_alert_item(alert, repo, soar=soar if has("mitigate") else None)

    elif page == "Devices":
        active_count = sum(1 for d in devices if d.status.value == "ACTIVE")
        suspended_count = sum(1 for d in devices if d.status.value != "ACTIVE")

        st.markdown(
            f"""
            <div class="page-head">
                <div>
                    <div class="page-title">Devices</div>
                    <div class="page-sub">Subscribers authorized on this core network, provisioned by IMSI/IMEI pair.</div>
                </div>
                <div class="page-stats">
                    <div class="pstat"><div class="pstat-val" style="color:var(--signal)">{active_count}</div><div class="pstat-label">ACTIVE</div></div>
                    <div class="pstat"><div class="pstat-val" style="color:var(--text-3)">{suspended_count}</div><div class="pstat-label">SUSPENDED</div></div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if has("provision"):
            with st.expander("+ Provision new subscriber"):
                from naswatch.storage.models import Device, DeviceStatus, SliceAssignment
                with st.form("prov_form"):
                    f_imsi = st.text_input("IMSI (15 digits)", value="999700000000099")
                    f_imei = st.text_input("IMEI (14-16 digits)", value="860123456789099")
                    f_owner = st.text_input("Subscriber", value="New Subscriber")
                    f_model = st.text_input("Model", value="5G Device")
                    f_slices = st.multiselect("Slices", ["1:000001 (eMBB)", "2:000002 (uRLLC)", "3:000003 (mIoT)", "4:010203 (Enterprise)"], default=["1:000001 (eMBB)"])
                    if st.form_submit_button("Provision", use_container_width=True):
                        from naswatch.storage.models import SliceAssignment as SA
                        slice_objs = []
                        for s in f_slices:
                            parts = s.split(" ")[0].split(":")
                            slice_objs.append(SA(sst=int(parts[0]), sd=parts[1] if len(parts) > 1 else None, name=s))
                        repo.add(Device(imsi=f_imsi.strip(), imei=f_imei.strip(), owner_name=f_owner.strip(),
                                        device_model=f_model.strip(), status=DeviceStatus.ACTIVE, allowed_slices=slice_objs))
                        st.toast(f"Provisioned {f_imsi}")
                        st.rerun()

        if devices:
            dev_rows = [{"IMSI": d.imsi, "IMEI": d.imei, "Subscriber": d.owner_name, "Model": d.device_model,
                         "Status": d.status.value, "Slices": ", ".join(s.slice_id for s in d.allowed_slices)} for d in devices]
            st.dataframe(pd.DataFrame(dev_rows), use_container_width=True, hide_index=True)
        else:
            st.warning("No devices. Seed the database.")

    elif page == "Reports":
        compliant_count = 4
        st.markdown(
            f"""
            <div class="page-head">
                <div>
                    <div class="page-title">Reports</div>
                    <div class="page-sub">Compliance posture and the audit trail behind it.</div>
                </div>
                <div class="page-stats">
                    <div class="pstat"><div class="pstat-val" style="color:var(--signal)">{compliant_count}/4</div><div class="pstat-label">COMPLIANT</div></div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Compliance cards
        standards = [
            ("3GPP TS 33.501", "5G security architecture"),
            ("GSMA FS.31", "Network slice isolation"),
            ("GSMA FS.34", "Rogue base station defense"),
            ("ISO 27001", "Audit trail integrity"),
        ]
        comp_html = '<div class="compliance-grid">'
        for name, desc in standards:
            comp_html += f"""
            <div class="compliance-card">
                <div style="color:var(--signal); margin-bottom:13px;">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="15" height="15">
                        <path d="M20 6 9 17l-5-5"/>
                    </svg>
                </div>
                <div class="code">{name}</div>
                <div class="desc">{desc}</div>
                <span class="compliant-tag">COMPLIANT</span>
            </div>"""
        comp_html += '</div>'
        st.markdown(comp_html, unsafe_allow_html=True)

        # Audit log
        st.markdown('<h3 style="font-size:13px; margin:0 0 12px;">Audit log</h3>', unsafe_allow_html=True)
        audit_entries = ""
        for a in all_alerts[:6]:
            audit_entries += (
                f'<div class="audit-row"><time>{a.timestamp.strftime("%Y-%m-%d %H:%M:%S")}</time>'
                f'<span class="actor">System</span>'
                f'<span class="act">{a.rule_type.value.lower().replace("_"," ")} — IMSI {a.imsi or "N/A"}</span></div>'
            )
        if not audit_entries:
            audit_entries = '<div class="audit-row"><time>—</time><span class="actor">System</span><span class="act">No events yet</span></div>'
        st.markdown(f'<div class="audit-log">{audit_entries}</div>', unsafe_allow_html=True)

        # Download
        audit = [
            "# NASWatch Audit Report",
            f"**Date:** {datetime.now(UTC).isoformat()}",
            f"**Operator:** {username} ({role})",
            "",
            f"Packets: {display_packets} | Alerts: {len(all_alerts)} | Critical: {crit_count} | High: {high_count}",
            "",
            "## Incidents",
        ]
        for a in all_alerts:
            audit.append(f"- [{a.severity.value}] {a.rule_type.value} | {a.imsi} | {a.timestamp.isoformat()} | {a.mitigation_status}")

        st.download_button("Download audit report", data="\n".join(audit),
                           file_name=f"audit_{datetime.now(UTC).strftime('%Y%m%d_%H%M')}.md",
                           mime="text/markdown", use_container_width=True)

    st.markdown("</div>", unsafe_allow_html=True)


if __name__ == "__main__":
    main()
