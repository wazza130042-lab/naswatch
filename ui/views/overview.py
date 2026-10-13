"""NASWatch UI — Overview page."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from html import escape

import pandas as pd
import streamlit as st

from ui.rbac import has
from ui.components import (
    render_alert_item, render_kpi_cards,
    render_mitre_attack_matrix,
    render_severity_chart, render_threat_timeline,
)


def render(ctx):
    repo = ctx["repo"]
    user = ctx["user"]
    role = ctx["role"]
    username = ctx["username"]
    time_range = ctx["time_range"]
    search_query = ctx["search_query"]
    selected_severity = ctx["selected_severity"]
    selected_rule = ctx["selected_rule"]
    all_alerts = ctx["all_alerts"]
    filtered_alerts = ctx["filtered_alerts"]
    devices = ctx["devices"]
    display_packets = ctx["display_packets"]
    crit_count = ctx["crit_count"]
    high_count = ctx["high_count"]
    med_count = ctx["med_count"]
    soar = ctx["soar"]

    st.markdown(
        """
        <div class="page-head">
            <div>
                <div class="page-title">Overview</div>
                <div class="page-sub">5G control-plane detections, investigation status, and subscriber risk in one analyst workspace.</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    render_kpi_cards(display_packets, len(all_alerts), crit_count, high_count, med_count, len(devices))

    if display_packets == 0 and not all_alerts:
        st.markdown(
            '<div class="empty-state-note">'
            '<div class="empty-state-icon">'
            '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.7">'
            '<path d="M4 7.5h16M7 4v7m10-7v7M5 12h14v8H5z"/><path d="M9 16h6"/>'
            '</svg></div><div><div class="empty-state-title">Monitoring has not started yet</div>'
            '<div class="empty-state-copy">There are no packet events in this workspace, so the dashboard cannot assess network risk yet. '
            'Choose a signaling PCAP under <b>Replay traffic</b> in the sidebar to populate events and detections.</div></div></div>',
            unsafe_allow_html=True,
        )

    col_a, col_b = st.columns(2)
    with col_a:
        render_severity_chart(all_alerts)
    with col_b:
        render_threat_timeline(all_alerts)

    queue_alerts = filtered_alerts[:10]
    st.markdown(
        f'<div class="queue-heading"><h3>Recent incidents</h3>'
        f'<span>Showing {len(queue_alerts)} of {len(filtered_alerts)} in scope</span></div>',
        unsafe_allow_html=True,
    )
    if queue_alerts:
        queue = pd.DataFrame([{
            "Detected (UTC)": a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "Severity": a.severity.value,
            "Detection": a.rule_type.value.replace("_", " ").title(),
            "Subscriber (IMSI)": a.imsi or "—",
            "Cell": a.cell_id or "—",
            "Response": a.mitigation_status,
        } for a in queue_alerts])
        st.dataframe(queue, hide_index=True, use_container_width=True, height=370)
    else:
        st.info("No incidents in the selected time range and search scope.")

