"""NASWatch UI — Incidents page."""
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

    can_mitigate = has("mitigate")
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sev_class = {"CRITICAL": "c", "HIGH": "h", "MEDIUM": "m", "LOW": "l", "INFO": "l"}

    def detection_label(alert) -> str:
        title = alert.title or alert.rule_type.value.replace("_", " ").title()
        prefix = f"{alert.severity.value}: "
        return title[len(prefix):] if title.startswith(prefix) else title

    incidents = sorted(
        filtered_alerts,
        key=lambda a: (sev_rank.get(a.severity.value, 9), -a.timestamp.timestamp()),
    )
    open_count = sum(1 for a in incidents if a.mitigation_status in {"NEW", "INVESTIGATING"})
    crit_total = sum(1 for a in incidents if a.severity.value == "CRITICAL")
    med_total = sum(1 for a in incidents if a.severity.value == "MEDIUM")
    new_total = sum(1 for a in incidents if a.mitigation_status == "NEW")

    st.markdown(
        """
        <div class="page-head">
            <div>
                <div class="page-title">Incident queue</div>
                <div class="page-sub">Prioritize detections, review evidence, update triage status, and launch response actions.</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="inc-kpis">'
        f'<div class="inc-kpi open"><s>OPEN</s><b>{open_count}</b></div>'
        f'<div class="inc-kpi crit"><s>CRITICAL</s><b>{crit_total}</b></div>'
        f'<div class="inc-kpi med"><s>MEDIUM</s><b>{med_total}</b></div>'
        f'<div class="inc-kpi new"><s>NEW</s><b>{new_total}</b></div>'
        '</div>',
        unsafe_allow_html=True,
    )

    if not incidents:
        st.info("No incidents match the current filters.")
    else:
        incident_ids = [a.id for a in incidents]
        if st.session_state.get("incident_selection") not in incident_ids:
            st.session_state["incident_selection"] = max(
                incidents, key=lambda a: a.timestamp
            ).id
        selected_incident_id = st.session_state["incident_selection"]

        queue_col, detail_col = st.columns([1.45, 1], gap="medium")
        with queue_col:
            with st.container(key="inc_queue_panel"):
                st.markdown(
                    f'<div class="inc-panel-head"><span>INCIDENT QUEUE</span><small>{open_count} open</small></div>',
                    unsafe_allow_html=True,
                )
                sev_on = selected_severity != "ALL"
                rule_on = selected_rule != "ALL"
                if not (sev_on or rule_on):
                    sev_on = True
                st.markdown(
                    '<div class="inc-filters">'
                    f'<span class="chip{" on" if sev_on else ""}">severity: {escape(selected_severity.lower())}</span>'
                    f'<span class="chip{" on" if rule_on else ""}">rule: {escape(selected_rule.lower())}</span>'
                    '<span class="chip">status: all</span></div>',
                    unsafe_allow_html=True,
                )
                head_cols = st.columns([1.15, 0.95, 2.85, 1.05], vertical_alignment="center", gap="small")
                for head_col, label in zip(head_cols, ("ID", "SEVERITY", "DETECTION", "STATUS")):
                    head_col.markdown(f'<div class="inc-th">{label}</div>', unsafe_allow_html=True)

                queue_limit = incidents[:40]
                for incident in queue_limit:
                    sev_cls = sev_class.get(incident.severity.value, "l")
                    with st.container(key=f"inc_row_{incident.id}"):
                        row_cols = st.columns([1.15, 0.95, 2.85, 1.05], vertical_alignment="center", gap="small")
                        with row_cols[0]:
                            if st.button(
                                incident.id[:8].upper(),
                                key=f"inc_pick_{incident.id}",
                                use_container_width=True,
                            ):
                                st.session_state["incident_selection"] = incident.id
                                st.rerun()
                        row_cols[1].markdown(
                            f'<span class="sv {sev_cls}">{escape(incident.severity.value)}</span>',
                            unsafe_allow_html=True,
                        )
                        row_cols[2].markdown(
                            f'<div class="inc-det">{escape(detection_label(incident))}</div>',
                            unsafe_allow_html=True,
                        )
                        row_cols[3].markdown(
                            f'<span class="chip{" on" if incident.mitigation_status == "NEW" else ""}">'
                            f'{escape(incident.mitigation_status.lower())}</span>',
                            unsafe_allow_html=True,
                        )
                if len(incidents) > len(queue_limit):
                    st.caption(
                        f"Showing {len(queue_limit)} of {len(incidents)} incidents — refine the filters to narrow the queue."
                    )
                st.markdown(
                    f'<style>.st-key-inc_row_{selected_incident_id}, '
                    f'.st-key-inc_row_{selected_incident_id} [data-testid="stHorizontalBlock"] '
                    '{ background:#0B2248 !important; border-radius:6px; }</style>',
                    unsafe_allow_html=True,
                )

        selected_alert = next(a for a in incidents if a.id == selected_incident_id)
        with detail_col:
            with st.container(key="inc_detail_panel"):
                sev_cls = sev_class.get(selected_alert.severity.value, "l")
                st.markdown(
                    f'<div class="inc-detail-head"><span>{selected_alert.id[:8].upper()}</span>'
                    f'<span class="sv {sev_cls}">{escape(selected_alert.severity.value)}</span></div>'
                    f'<div class="inc-detail-title">{escape(detection_label(selected_alert))}</div>'
                    '<pre class="inc-pre">rule        '
                    f'<b>{escape(selected_alert.rule_type.value)}</b>\nsubscriber  '
                    f'<b>{escape(selected_alert.imsi or "—")}</b>\ndetected    '
                    f'<b>{selected_alert.timestamp.strftime("%Y-%m-%d %H:%M")}</b>\nstatus      '
                    f'<b class="cy">{escape(selected_alert.mitigation_status.lower())}</b></pre>',
                    unsafe_allow_html=True,
                )

                raw_event = selected_alert.raw_event or {}
                raw_fields: list[tuple[str, object]] = list(raw_event.items())
                for extra_key, extra_val in (
                    ("imsi", selected_alert.imsi),
                    ("imei", selected_alert.imei),
                    ("cell_id", selected_alert.cell_id),
                    ("target_slice", selected_alert.target_slice),
                ):
                    if extra_val and extra_key not in raw_event:
                        raw_fields.append((extra_key, extra_val))

                def _render_field(value: object) -> str:
                    if value in (None, "", []):
                        return "—"
                    if isinstance(value, (list, tuple, set)):
                        return ", ".join(str(item) for item in value)
                    return str(value)

                log_lines = "".join(
                    f'<div class="inc-log-line"><span>{escape(str(key))}</span>'
                    f'<b>{escape(_render_field(value))}</b></div>'
                    for key, value in raw_fields
                )
                packet_label = raw_event.get("packet_num")
                st.markdown(
                    '<div class="inc-subhead">EVIDENCE</div>'
                    f'<div class="inc-desc">{escape(selected_alert.description)}</div>'
                    '<div class="inc-log"><div class="inc-log-head">RAW EVENT'
                    + (f' · packet #{escape(str(packet_label))}' if packet_label is not None else "")
                    + f' · {escape(selected_alert.rule_type.value)}'
                    f' · {escape(selected_alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"))}Z</div>'
                    + (log_lines or '<div class="inc-log-line"><span>event</span><b>no raw fields captured</b></div>')
                    + '</div>',
                    unsafe_allow_html=True,
                )

                st.markdown('<div class="inc-subhead">TRIAGE STATUS</div>', unsafe_allow_html=True)
                if can_mitigate:
                    triage_options = ["NEW", "INVESTIGATING", "RESOLVED"]
                    if selected_alert.mitigation_status == "BLOCKED":
                        triage_options = ["NEW", "INVESTIGATING", "BLOCKED", "RESOLVED"]
                    with st.container(key="inc_triage"):
                        triage_cols = st.columns(len(triage_options[:3]), gap="small")
                        for triage_col, option in zip(triage_cols, triage_options[:3]):
                            with triage_col:
                                if st.button(
                                    option.lower(),
                                    key=f"triage_{selected_alert.id}_{option}",
                                    use_container_width=True,
                                    type="primary" if selected_alert.mitigation_status == option else "secondary",
                                ):
                                    repo.update_mitigation_status(selected_alert.id, option)
                                    st.toast(f"Triage → {option.lower()}")
                                    st.rerun()
                else:
                    st.markdown(
                        f'<span class="chip on">{escape(selected_alert.mitigation_status.lower())}</span>',
                        unsafe_allow_html=True,
                    )

                st.markdown('<div class="inc-subhead">RESPONSE</div>', unsafe_allow_html=True)
                if can_mitigate and selected_alert.imsi:
                    if st.button(
                        "Mark investigating",
                        use_container_width=True,
                        key=f"mark_inv_{selected_alert.id}",
                    ):
                        repo.update_mitigation_status(selected_alert.id, "INVESTIGATING")
                        st.toast("Marked investigating")
                        st.rerun()
                    response_cols = st.columns(2, gap="small")
                    with response_cols[0]:
                        if st.button(
                            "Launch response",
                            use_container_width=True,
                            key=f"launch_{selected_alert.id}",
                        ):
                            soar.revoke_subscriber(selected_alert.imsi, reason=selected_alert.title)
                            repo.update_mitigation_status(selected_alert.id, "BLOCKED")
                            st.toast("Subscriber revoked")
                            st.rerun()
                    with response_cols[1]:
                        st.download_button(
                            "Export evidence",
                            data=soar.generate_forensic_report(selected_alert),
                            file_name=f"forensic_{selected_alert.id[:8]}.md",
                            mime="text/markdown",
                            key=f"export_{selected_alert.id}",
                            use_container_width=True,
                        )
                else:
                    st.markdown(
                        '<div style="color:#6F93BF;font:11px var(--mono);font-style:italic;">'
                        'View-only — sign in as analyst or admin to respond.</div>',
                        unsafe_allow_html=True,
                    )

