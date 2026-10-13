"""NASWatch — 5G Control-Plane Threat Detection Dashboard.

This module is the **orchestrator** only: session restore, sidebar, command bar,
data loading, and dispatch to the selected page. The interesting code lives in:

  * ``ui/theme.py``    — SOC theme CSS
  * ``ui/rbac.py``     — role → permission map (single source of truth)
  * ``ui/session.py``  — cookie-backed session persistence
  * ``ui/store.py``    — cached data-store accessors
  * ``ui/login.py``    — login screen
  * ``ui/sidebar.py``  — navigation, ingestion, filters, operator actions
  * ``ui/views/*``     — one module per page (Overview, Incidents, ...)
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import streamlit as st

st.set_page_config(page_title="NASWatch", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

from ui.login import login_page
from ui.views import event_search, incidents, inventory, overview, reports, topology, users
from ui.session import (
    _clear_session_cookie,
    _restore_session,
    _session_token,
    _write_session_cookie,
)
from ui.sidebar import render_sidebar
from ui.store import get_repository
from ui.theme import CSS


def main() -> None:
    _restore_session()
    # A sign out defers the cookie clear to this run so its frame actually renders
    # (an in-flight st.rerun() would cancel the clearing frame otherwise).
    if st.session_state.pop("_clear_cookie_pending", False):
        _clear_session_cookie()
    if "user" not in st.session_state:
        login_page()
        return

    user = st.session_state["user"]
    role = user["role"]
    username = user["username"]
    db_path = "data/inventory.db"
    repo = get_repository(db_path)

    # Freshly authenticated: persist the session cookie on the first signed-in run.
    if st.session_state.pop("_persist_session", False):
        _write_session_cookie(_session_token(user))

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
    page, selected_severity, selected_rule = render_sidebar(repo, db_path, username, role)
    # ── Global investigation command bar ───────────────────────────────
    page_slug = page.lower().replace(" ", "-")
    with st.container(key="command-bar", border=False):
        crumb, scope_time_col, scope_search_col, status_col = st.columns(
            [1.12, 0.72, 1.18, 0.58], gap="small", vertical_alignment="center"
        )
        with crumb:
            st.markdown(
                f'<div class="soc-crumb">SOC-01 <span>/</span> {page_slug}</div>',
                unsafe_allow_html=True,
            )
        with scope_time_col:
            time_range = st.selectbox(
                "TIME RANGE", ["Last 24 hours", "Last 7 days", "All time"],
                key="global_time_range", label_visibility="collapsed",
            )
        with scope_search_col:
            search_query = st.text_input(
                "GLOBAL SEARCH", placeholder="Search IMSI, rule, cell, slice…",
                key="global_search", help="Search the incidents and packet events in the current view.",
                label_visibility="collapsed",
            )
        with status_col:
            st.markdown(
                '<div class="sensor-status"><i></i><span>SENSOR ONLINE</span></div>',
                unsafe_allow_html=True,
            )

    # ── Data and global investigation scope ────────────────────────────
    devices = repo.list_all(limit=500)
    sev_filter = None if selected_severity == "ALL" else selected_severity
    rule_filter = None if selected_rule == "ALL" else selected_rule
    now = datetime.now(UTC)
    all_alerts = repo.get_alerts(limit=500)
    if time_range != "All time":
        window = timedelta(hours=24) if time_range == "Last 24 hours" else timedelta(days=7)
        cutoff = now - window
        all_alerts = [
            alert for alert in all_alerts
            if (alert.timestamp.replace(tzinfo=UTC) if alert.timestamp.tzinfo is None else alert.timestamp) >= cutoff
        ]

    def matches_search(alert) -> bool:
        if not search_query.strip():
            return True
        haystack = " ".join(str(value or "") for value in (
            alert.title, alert.description, alert.imsi, alert.imei, alert.cell_id,
            alert.target_slice, alert.rule_type.value, alert.mitigation_status,
        ))
        return search_query.casefold() in haystack.casefold()

    filtered_alerts = [
        alert for alert in all_alerts
        if (sev_filter is None or alert.severity.value == sev_filter)
        and (rule_filter is None or alert.rule_type.value == rule_filter)
        and matches_search(alert)
    ]

    crit_count = sum(1 for a in all_alerts if a.severity.value == "CRITICAL")
    high_count = sum(1 for a in all_alerts if a.severity.value == "HIGH")
    med_count = sum(1 for a in all_alerts if a.severity.value == "MEDIUM")

    # Count packets only when this process actually inspected them. Alerts are
    # not a reliable proxy for packet volume.
    display_packets = st.session_state.inspected_count
    from naswatch.mitigation.soar import SOAREngine
    soar = SOAREngine(device_repo=repo, alert_repo=repo)

    st.markdown('<div style="padding:28px 32px 70px;">', unsafe_allow_html=True)

    # ── Page routing ───────────────────────────────────────────────────
    ctx = {
        "repo": repo, "user": user, "role": role, "username": username,
        "time_range": time_range, "search_query": search_query,
        "selected_severity": selected_severity, "selected_rule": selected_rule,
        "all_alerts": all_alerts, "filtered_alerts": filtered_alerts,
        "devices": devices, "display_packets": display_packets,
        "crit_count": crit_count, "high_count": high_count, "med_count": med_count,
        "soar": soar,
    }
    if page == "Overview":
        overview.render(ctx)
    elif page == "Event search":
        event_search.render(ctx)
    elif page == "Network topology":
        topology.render(ctx)
    elif page == "Incidents":
        incidents.render(ctx)
    elif page == "Asset inventory":
        inventory.render(ctx)
    elif page == "User management":
        users.render(ctx)
    elif page == "Reports":
        reports.render(ctx)

    st.markdown("</div>", unsafe_allow_html=True)


if __name__ == "__main__":
    main()
