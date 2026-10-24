"""NASWatch UI — Event search page."""
from __future__ import annotations

from pathlib import Path
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
from ui.store import log_ui_action


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
    if has("replay"):
        with st.expander("Replay a saved PCAP", expanded=False):
            st.caption("Offline replay decodes a saved capture and records any detections in this workspace.")
            pcap_path = st.text_input(
                "PCAP file path", value="data/pcaps/5g_signaling_demo.pcap",
                key="event_search_pcap_path",
            )
            if st.button("Replay capture", type="primary", key="event_search_replay"):
                if not Path(pcap_path).is_file():
                    st.error(f"Capture file not found: {pcap_path}")
                else:
                    from naswatch.detection.engine import DetectionEngine
                    from naswatch.ingestion.pcap_replay import PCAPReplayer

                    event_log = []
                    new_alerts = 0
                    engine = DetectionEngine(device_repo=repo)
                    try:
                        with st.spinner("Decoding capture…"):
                            for event in PCAPReplayer(pcap_path=pcap_path).stream_events():
                                event_log.append({
                                    "Time": event.timestamp.strftime("%H:%M:%S"),
                                    "Timestamp": event.timestamp.isoformat(),
                                    "Packet": event.packet_num,
                                    "Procedure": event.procedure_name or "5GS",
                                    "Procedure code": event.procedure_code,
                                    "Protocol": event.protocol,
                                    "Source IP": event.source_ip,
                                    "Destination IP": event.dest_ip,
                                    "IMSI": event.imsi or "—",
                                    "IMEI": event.imei or "—",
                                    "GUTI": event.guti or "—",
                                    "Slice": event.requested_slice_id or "—",
                                    "Requested SST": event.requested_sst,
                                    "Requested SD": event.requested_sd or "—",
                                    "Requested slices": event.metadata.get("requested_slices", []),
                                    "Cell": event.cell_id or "—",
                                    "TAC": event.tac,
                                    "RAN UE NGAP ID": event.ran_ue_ngap_id,
                                    "AMF UE NGAP ID": event.amf_ue_ngap_id,
                                    "Cipher": event.cipher_algo or "—",
                                    "Integrity": event.integrity_algo or "—",
                                })
                                for alert in engine.process_event(event):
                                    repo.record_alert(alert)
                                    new_alerts += 1
                    except Exception as exc:
                        st.error(f"PCAP replay failed: {exc}")
                    else:
                        st.session_state.last_events = event_log
                        st.session_state.inspected_count += len(event_log)
                        audit_error = log_ui_action(
                            user, "traffic.replay", Path(pcap_path).name,
                            {"packets_inspected": len(event_log), "alerts_created": new_alerts},
                        )
                        if audit_error:
                            st.error(f"Replay completed, but its audit record failed: {audit_error}")
                        if not event_log:
                            st.warning("The capture was read, but no supported 5G signaling events were decoded.")
                        else:
                            st.success(f"Replay complete: {len(event_log)} events decoded, {new_alerts} alerts created.")
                            st.rerun()

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
                table_columns = [
                    "Time", "Packet", "Procedure", "IMSI", "IMEI", "Cell", "Slice", "Cipher", "Integrity",
                ]
                st.dataframe(
                    event_frame[[column for column in table_columns if column in event_frame.columns]],
                    hide_index=True, use_container_width=True, height=520,
                )
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
                    for label, key in (
                        ("Timestamp", "Timestamp"), ("Protocol", "Protocol"),
                        ("SUPI / IMSI", "IMSI"), ("PEI / IMEI", "IMEI"), ("GUTI", "GUTI"),
                        ("Procedure", "Procedure"), ("Procedure code", "Procedure code"),
                        ("Packet", "Packet"), ("Source IP", "Source IP"),
                        ("Destination IP", "Destination IP"), ("RAN UE NGAP ID", "RAN UE NGAP ID"),
                        ("AMF UE NGAP ID", "AMF UE NGAP ID"), ("Cell", "Cell"), ("TAC", "TAC"),
                        ("Slice", "Slice"), ("Requested SST", "Requested SST"),
                        ("Requested SD", "Requested SD"), ("Requested slices", "Requested slices"),
                        ("Cipher", "Cipher"), ("Integrity", "Integrity"),
                    )
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
