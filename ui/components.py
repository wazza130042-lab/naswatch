"""
UI Component widgets for NASWatch Streamlit Dashboard.
KPI cards, incident tables, slice topology visualizers, and interactive incident investigation panels.
"""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from naswatch.storage.models import Alert, Device


def render_kpi_cards(
    total_packets: int,
    total_alerts: int,
    critical_count: int,
    high_count: int,
    medium_count: int,
    device_count: int,
) -> None:
    """Render top-level executive KPI metrics cards."""
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.metric(
            label="📡 Packets Inspected",
            value=f"{total_packets:,}",
            delta="5G NGAP/NAS",
        )
    with col2:
        st.metric(
            label="🚨 Total Alerts",
            value=total_alerts,
            delta=f"{critical_count + high_count} High/Crit",
            delta_color="inverse",
        )
    with col3:
        st.metric(
            label="🔴 Critical (Rogue)",
            value=critical_count,
            delta="Unregistered IMSI" if critical_count > 0 else "Clean",
            delta_color="inverse",
        )
    with col4:
        st.metric(
            label="🟠 High (Spoofing)",
            value=high_count,
            delta="IMEI Mismatch" if high_count > 0 else "Clean",
            delta_color="inverse",
        )
    with col5:
        st.metric(
            label="📱 Authorized eSIMs",
            value=device_count,
            delta="Inventory Base",
        )


def render_severity_chart(alerts: list[Alert]) -> None:
    """Render donut chart of alert severities."""
    if not alerts:
        st.info("No security alerts recorded. System operational and clean.")
        return

    sev_counts = {}
    for a in alerts:
        sev_counts[a.severity.value] = sev_counts.get(a.severity.value, 0) + 1

    colors = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#3b82f6",
        "INFO": "#10b981",
    }

    labels = list(sev_counts.keys())
    values = list(sev_counts.values())
    chart_colors = [colors.get(lbl, "#64748b") for lbl in labels]

    fig = go.Figure(
        data=[
            go.Pie(
                labels=labels,
                values=values,
                hole=0.55,
                marker=dict(colors=chart_colors),
                textinfo="label+value",
                hoverinfo="label+percent",
            )
        ]
    )
    fig.update_layout(
        title_text="Alert Distribution by Severity",
        margin=dict(t=40, b=10, l=10, r=10),
        height=280,
        showlegend=True,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#f8fafc"),
    )
    st.plotly_chart(fig, use_container_width=True)


def render_threat_timeline(alerts: list[Alert]) -> None:
    """Render incident timeline distribution chart."""
    if not alerts:
        return

    records = [
        {
            "Timestamp": a.timestamp,
            "Severity": a.severity.value,
            "Rule": a.rule_type.value,
            "IMSI": a.imsi or "N/A",
            "Target Slice": a.target_slice or "N/A",
        }
        for a in alerts
    ]
    df = pd.DataFrame(records)
    df["Count"] = 1

    color_map = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#3b82f6",
    }

    fig = px.scatter(
        df,
        x="Timestamp",
        y="Severity",
        color="Severity",
        size=[12] * len(df),
        hover_data=["Rule", "IMSI", "Target Slice"],
        color_discrete_map=color_map,
        title="Incident Timeline & Ingress Trajectory",
    )
    fig.update_layout(
        height=280,
        margin=dict(t=40, b=10, l=10, r=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#f8fafc"),
        xaxis=dict(gridcolor="#334155"),
        yaxis=dict(gridcolor="#334155"),
    )
    st.plotly_chart(fig, use_container_width=True)


def render_network_slice_matrix(alerts: list[Alert], devices: list[Device]) -> None:
    """Visualizes 5G network slices and active/intruding subscribers."""
    st.subheader("🌐 5G Network-Slice Access Matrix & Isolation Map")

    slices_def = [
        {"sst": 1, "sd": "000001", "name": "eMBB-Public", "type": "Enhanced Mobile Broadband", "desc": "Standard commercial consumer traffic"},
        {"sst": 2, "sd": "000002", "name": "uRLLC-Critical", "type": "Ultra-Reliable Low-Latency", "desc": "Emergency first-responders & SCADA automation"},
        {"sst": 3, "sd": "000003", "name": "mIoT-Sensors", "type": "Massive IoT", "desc": "Smart city environmental telemetry"},
        {"sst": 4, "sd": "010203", "name": "Enterprise-Private", "type": "Private Enterprise Intranet", "desc": "Isolated corporate ERP & database interconnect"},
    ]

    cols = st.columns(4)
    for idx, s in enumerate(slices_def):
        slice_id = f"{s['sst']}:{s['sd']}"
        with cols[idx]:
            # Count authorized devices
            authorized = [d for d in devices if d.is_slice_authorized(s["sst"], s["sd"])]
            # Count slice intrusions targeting this slice
            intrusions = [a for a in alerts if a.target_slice == slice_id and a.rule_type.value == "SLICE_INTRUSION"]

            status_text = f"🚨 {len(intrusions)} Intrusion Attempt(s)" if intrusions else "🛡️ Secure"

            st.markdown(
                f"""
                <div style="background-color: #1e293b; border-radius: 8px; padding: 14px; border: 1px solid {'#ef4444' if intrusions else '#334155'};">
                    <h4 style="margin:0; color:#38bdf8;">{s['name']}</h4>
                    <span style="font-size:12px; color:#94a3b8;">SST: {s['sst']} | SD: {s['sd']}</span>
                    <hr style="margin: 8px 0; border-color:#334155;" />
                    <p style="font-size:12px; margin:0; color:#cbd5e1;"><strong>Type:</strong> {s['type']}</p>
                    <p style="font-size:11px; margin:4px 0; color:#94a3b8;">{s['desc']}</p>
                    <div style="margin-top:10px; display:flex; justify-content:space-between; font-size:12px;">
                        <span>👥 Authorized: <strong>{len(authorized)}</strong></span>
                        <span style="color:{'#f87171' if intrusions else '#4ade80'}; font-weight:bold;">{status_text}</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )


def render_alert_item(alert: Alert, repo, soar=None) -> None:
    """Render an individual expandable incident card with actionable mitigation controls and SOAR integration."""
    header_label = f"[{alert.severity.value}] {alert.rule_type.value} | IMSI: {alert.imsi or 'N/A'} - {alert.title}"

    with st.expander(header_label, expanded=(alert.severity.value == "CRITICAL")):
        col1, col2 = st.columns([3, 2])
        with col1:
            st.markdown(f"**Description:** {alert.description}")
            st.markdown(
                f"- **Timestamp:** `{alert.timestamp.isoformat()}`\n"
                f"- **Cell ID / gNB:** `{alert.cell_id or 'Unknown'}`\n"
                f"- **Target Slice (S-NSSAI):** `{alert.target_slice or 'N/A'}`\n"
                f"- **Observed IMEI:** `{alert.imei or 'N/A'}`\n"
                f"- **Mitigation Status:** `{alert.mitigation_status}`"
            )
            if alert.raw_event:
                st.caption("Forensic Metadata Context:")
                st.json(alert.raw_event)

        with col2:
            st.markdown("🎯 **Active SOAR Containment**")
            c_act1, c_act2 = st.columns(2)
            with c_act1:
                if alert.imsi and st.button("🚫 Revoke at 5GC", key=f"btn_revoke_{alert.id}", use_container_width=True):
                    if soar:
                        res = soar.revoke_subscriber(alert.imsi, reason=f"Incident {alert.title}")
                        repo.update_mitigation_status(alert.id, "BLOCKED")
                        st.success(res.get("message", "Revoked in 5G Core"))
                        st.rerun()
            with c_act2:
                if alert.imsi and st.button("⏸️ Quarantine IMSI", key=f"btn_quarantine_{alert.id}", use_container_width=True):
                    if soar:
                        res = soar.quarantine_device(alert.imsi)
                        repo.update_mitigation_status(alert.id, "INVESTIGATING")
                        st.info(res.get("message", "Device quarantined"))
                        st.rerun()

            current_status = alert.mitigation_status
            action = st.selectbox(
                "Triage Status",
                ["NEW", "INVESTIGATING", "BLOCKED", "RESOLVED"],
                index=["NEW", "INVESTIGATING", "BLOCKED", "RESOLVED"].index(current_status)
                if current_status in ["NEW", "INVESTIGATING", "BLOCKED", "RESOLVED"]
                else 0,
                key=f"status_select_{alert.id}",
            )
            if st.button("Apply Status", key=f"btn_apply_{alert.id}", use_container_width=True):
                repo.update_mitigation_status(alert.id, action)
                st.success(f"Status updated to '{action}'")
                st.rerun()

            if soar:
                report_md = soar.generate_forensic_report(alert)
                st.download_button(
                    label="📄 Download Forensic Report",
                    data=report_md,
                    file_name=f"incident_{alert.id[:8]}_report.md",
                    mime="text/markdown",
                    key=f"btn_dl_{alert.id}",
                    use_container_width=True,
                )
