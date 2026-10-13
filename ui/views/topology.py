"""NASWatch UI — Network topology page."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from html import escape

import pandas as pd
import streamlit as st

from ui.rbac import has
from ui.components import (
    render_alert_item, render_interactive_topology_graph, render_kpi_cards,
    render_mitre_attack_matrix, render_network_slice_matrix,
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

    gnb_count = 2
    amf_count = 1
    active_slices = max(3, len(set(a.target_slice for a in all_alerts if a.target_slice)))

    st.markdown(
        f"""
        <div class="page-head">
            <div>
                <div class="page-title">Network topology</div>
                <div class="page-sub">Radio access, AMF, and slice relationships observed in the current alert scope.</div>
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

