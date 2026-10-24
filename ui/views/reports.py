"""NASWatch UI — Reports page."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from html import escape

import pandas as pd
import streamlit as st

from ui.rbac import has
from ui.store import log_ui_action
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

    def audit_export(filename: str) -> None:
        audit_error = log_ui_action(user, "report.export", filename, {"time_range": time_range})
        if audit_error:
            st.session_state["_audit_warning"] = f"Report downloaded, but its audit record failed: {audit_error}"

    st.markdown(
        """
        <div class="page-head">
            <div>
                <div class="page-title">Reports</div>
                <div class="page-sub">Generate exports from the current NASWatch inventory and detection records.</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    generated_at = datetime.now(UTC)
    stamp = generated_at.strftime("%Y%m%d_%H%M")
    alert_rows = [{
        "timestamp_utc": a.timestamp.isoformat(), "severity": a.severity.value,
        "rule": a.rule_type.value, "title": a.title, "supi": a.imsi or "",
        "pei": a.imei or "", "cell": a.cell_id or "", "slice": a.target_slice or "",
        "status": a.mitigation_status,
    } for a in all_alerts]
    alert_csv = pd.DataFrame(alert_rows).to_csv(index=False)
    rule_csv = pd.DataFrame([
        {"rule": rule, "detections": sum(1 for a in all_alerts if a.rule_type.value == rule)}
        for rule in sorted({a.rule_type.value for a in all_alerts})
    ], columns=["rule", "detections"]).to_csv(index=False)
    risk_rows = []
    for device in devices:
        matches = [a for a in all_alerts if a.imsi == device.imsi]
        latest = max(matches, key=lambda a: a.timestamp) if matches else None
        risk_rows.append({
            "subscriber": device.owner_name, "supi": device.imsi, "pei": device.imei,
            "status": device.status.value, "authorized_slices": ";".join(s.slice_id for s in device.allowed_slices),
            "risk": latest.severity.value if latest else "NONE",
            "latest_detection": latest.timestamp.isoformat() if latest else "",
            "latest_rule": latest.rule_type.value if latest else "",
        })
    risk_csv = pd.DataFrame(risk_rows, columns=[
        "subscriber", "supi", "pei", "status", "authorized_slices", "risk", "latest_detection", "latest_rule"
    ]).to_csv(index=False)
    summary = "\n".join([
        "# NASWatch SOC summary", "", f"Generated: {generated_at.isoformat()}",
        f"Operator: {username} ({role})", f"Time range: {time_range}", "",
        f"Packets inspected this session: {display_packets}", f"Detection records in scope: {len(all_alerts)}",
        f"Critical: {crit_count} | High: {high_count} | Medium: {med_count}",
        f"Registered subscribers: {len(devices)}", "", "## Recent detections",
        *[f"- [{a.severity.value}] {a.rule_type.value}: {a.title} — {a.imsi or 'unknown SUPI'} ({a.mitigation_status})" for a in all_alerts[:20]],
    ])
    report_specs = [
        ("SOC summary", "Counts, severity totals, and recent detections for the selected time range.", summary, f"naswatch-summary-{stamp}.md", "text/markdown"),
        ("Incident report", "Detection records with timestamps, subscriber IDs, cell, and response status.", alert_csv, f"naswatch-incidents-{stamp}.csv", "text/csv"),
        ("Rule activity", "Counts for detection rules present in the selected alert records.", rule_csv, f"naswatch-rule-activity-{stamp}.csv", "text/csv"),
        ("Subscriber risk", "Inventory with each subscriber’s latest matching detection severity.", risk_csv, f"naswatch-subscriber-risk-{stamp}.csv", "text/csv"),
    ]
    report_cols = st.columns(4, gap="small")
    for col, (title, description, data, filename, mime) in zip(report_cols, report_specs):
        with col:
            st.markdown(
                f'<div class="report-card"><div class="report-card-title">{escape(title)}</div>'
                f'<div class="report-card-copy">{escape(description)}</div></div>',
                unsafe_allow_html=True,
            )
            st.download_button("Generate export", data=data, file_name=filename,
                               mime=mime, use_container_width=True, key=f"report_{title}",
                               on_click=audit_export, args=(filename,))

    recent_col, scope_col = st.columns([1.55, 1], gap="small")
    with recent_col:
        st.markdown(
            f'<div class="queue-heading"><h3>Recent detections</h3><span>{len(all_alerts)} in scope</span></div>',
            unsafe_allow_html=True,
        )
        if all_alerts:
            st.dataframe(pd.DataFrame([{
                "UTC": a.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "Severity": a.severity.value,
                "Rule": a.rule_type.value.lower(), "SUPI": a.imsi or "—", "Status": a.mitigation_status,
            } for a in all_alerts[:12]]), hide_index=True, use_container_width=True, height=320)
        else:
            st.info("No detections are available for this time range.")
    with scope_col:
        st.markdown(
            '<div class="report-scope-card"><div class="event-detail-heading">EXPORT SCOPE</div>'
            f'<div class="event-detail-row"><span>Window</span><b>{escape(time_range)}</b></div>'
            f'<div class="event-detail-row"><span>Operator</span><b>{escape(username)}</b></div>'
            f'<div class="event-detail-row"><span>Packets</span><b>{display_packets:,} this session</b></div>'
            f'<div class="event-detail-row"><span>Detections</span><b>{len(all_alerts):,}</b></div>'
            f'<div class="event-detail-row"><span>Subscribers</span><b>{len(devices):,}</b></div></div>',
            unsafe_allow_html=True,
        )
