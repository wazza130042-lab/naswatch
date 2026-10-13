"""NASWatch UI — Event search page."""
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

    st.markdown(
        """
        <div class="page-head"><div>
          <div class="page-title">Event search</div>
          <div class="page-sub">Inspect decoded signaling events from the most recent PCAP replay. Use global search above to narrow by subscriber, procedure, cell, or slice.</div>
        </div></div>
        """, unsafe_allow_html=True,
    )
    events = st.session_state.last_events
    st.markdown(
        f'<div class="queue-heading"><h3>Decoded packet events</h3>'
        f'<span>{len(events):,} events from latest replay</span></div>',
        unsafe_allow_html=True,
    )
    if events:
        event_frame = pd.DataFrame(events)
        if search_query.strip():
            visible = event_frame.astype(str).apply(
                lambda row: row.str.contains(search_query, case=False, regex=False).any(), axis=1
            )
            event_frame = event_frame[visible]
        visible_events = event_frame.to_dict("records")
        if visible_events:
            results_col, detail_col = st.columns([2.25, 1], gap="small")
            with results_col:
                st.markdown(
                    f'<div class="queue-heading"><h3>Results</h3><span>{len(visible_events):,} events</span></div>',
                    unsafe_allow_html=True,
                )
                st.dataframe(event_frame, hide_index=True, use_container_width=True, height=520)
            with detail_col:
                options = list(range(len(visible_events)))
                selected_event_index = st.selectbox(
                    "EVENT DETAIL", options,
                    format_func=lambda i: f"packet {visible_events[i].get('Packet', '—')} · {visible_events[i].get('Procedure', '5GS')}",
                    key="event_detail_selection", label_visibility="collapsed",
                )
                event = visible_events[selected_event_index]
                severity_match = next(
                    (a for a in filtered_alerts if str(a.imsi or "") == str(event.get("IMSI") or "")
                     and (not event.get("Cell") or a.cell_id == event.get("Cell"))),
                    None,
                )
                verdict = severity_match.severity.value if severity_match else "OBSERVED"
                verdict_color = {"CRITICAL": "#FF466B", "HIGH": "#FFB82F", "MEDIUM": "#4CA8FF", "LOW": "#11D9ED"}.get(verdict, "#11D9ED")
                detail_rows = "".join(
                    f'<div class="event-detail-row"><span>{escape(label)}</span><b>{escape(str(event.get(key) or "—"))}</b></div>'
                    for label, key in (("SUPI", "IMSI"), ("PEI", "IMEI"), ("cell", "Cell"),
                                       ("procedure", "Procedure"), ("packet", "Packet"),
                                       ("slice", "Slice"), ("cipher", "Cipher"), ("integrity", "Integrity"))
                )
                st.markdown(
                    f'<div class="event-detail-card"><div class="event-detail-heading">EVENT DETAIL</div>'
                    f'{detail_rows}<div class="event-verdict" style="color:{verdict_color}">VERDICT&nbsp;&nbsp; {escape(verdict)}</div></div>',
                    unsafe_allow_html=True,
                )
            st.caption("Packet fields are decoded from the latest replay. Replay another capture to replace this event set.")
        else:
            st.info("No events match the current search.")
    else:
        st.info("No replayed packet events yet. Choose a PCAP in the sidebar and run Replay PCAP to populate event search.")

