"""
NASWatch UI Components — matches naswatch_redesign.html
"""

from __future__ import annotations

from html import escape

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from naswatch.storage.models import Alert, Device

# Colors shared with the SOC console theme in ui.app
C = {
    "bg-base": "#030A14", "bg-panel": "#061226", "bg-raised": "#0A1B35", "bg-input": "#030D1B",
    "border": "#174A83", "border-soft": "#102E50",
    "text-1": "#D6E7FA", "text-2": "#8CAED3", "text-3": "#5F83AA",
    "signal": "#12D4E8", "signal-dim": "#13547B",
    "crit": "#FF466B", "high": "#FFB82F", "med": "#4CA8FF", "low": "#11D9ED",
}


# ══════════════════════════════════════════════════════════════════════════════
#  KPI STRIP
# ══════════════════════════════════════════════════════════════════════════════
def render_kpi_cards(
    total_packets: int, total_alerts: int, critical_count: int,
    high_count: int, medium_count: int, device_count: int,
    include_devices: bool = True,
) -> None:
    cards = [
        ("c-signal", "PACKETS INSPECTED", f"{total_packets:,}", "5GS NGAP / NAS-PDU"),
        ("c-alert", "SECURITY ALERTS", f"{total_alerts:,}", f"{critical_count + high_count} high / critical"),
        ("c-crit", "CRITICAL", str(critical_count), "Action required" if critical_count else "None"),
        ("c-high", "HIGH", str(high_count), "Investigating" if high_count else "None"),
    ]
    if include_devices:
        cards.append(("c-low", "DEVICES", str(device_count), "Authorized subscribers"))
    else:
        cards.append(("c-low", "SUBSCRIBER DATA", "RESTRICTED", "Analyst or admin access"))

    html = '<div class="kpi-strip">'
    for cls, label, value, detail in cards:
        html += f"""
        <div class="kpi {cls}">
            <div class="kpi-label">{label}</div>
            <div class="kpi-value">{value}</div>
            <div class="kpi-detail">{detail}</div>
        </div>"""
    html += '</div>'
    st.markdown(html, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
#  SEVERITY CHART — SVG donut matching the redesign
# ══════════════════════════════════════════════════════════════════════════════
def render_severity_chart(alerts: list[Alert]) -> None:
    with st.container(key="overview_severity_chart"):
        st.markdown('<div class="chart-panel-heading"><h3>Alerts by severity</h3><p>Distribution in the selected time scope</p></div>', unsafe_allow_html=True)
        if not alerts:
            st.info("No alert records in this time scope.")
            return

        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        colors = {"CRITICAL": C["crit"], "HIGH": C["high"], "MEDIUM": C["med"], "LOW": C["low"], "INFO": C["signal"]}
        counts = pd.Series([alert.severity.value for alert in alerts]).value_counts()
        labels = [severity for severity in order if counts.get(severity, 0)]
        values = [int(counts[severity]) for severity in labels]
        fig = go.Figure(go.Pie(
            labels=labels, values=values, hole=0.68, sort=False,
            marker={"colors": [colors[label] for label in labels], "line": {"color": C["bg-base"], "width": 3}},
            textinfo="label+value", textposition="outside", textfont={"size": 10},
            hovertemplate="%{label}: %{value} alerts (%{percent})<extra></extra>",
        ))
        fig.add_annotation(text=f"<b>{len(alerts):,}</b><br><span style='font-size:10px'>alerts</span>", x=0.5, y=0.5, showarrow=False, font={"color": C["text-1"], "size": 19})
        fig.update_layout(
            height=330, showlegend=False, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font={"family": "IBM Plex Mono, monospace", "size": 11, "color": C["text-2"]},
            margin={"l": 18, "r": 18, "t": 20, "b": 20},
            hoverlabel={"bgcolor": C["bg-raised"], "bordercolor": C["border"], "font": {"color": C["text-1"]}},
        )
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False, "responsive": True})


def render_threat_timeline(alerts: list[Alert], time_range: str = "Last 24 hours") -> None:
    with st.container(key="overview_alert_timeline"):
        title = "Alert activity by hour" if time_range == "Last 24 hours" else "Alert activity over time"
        st.markdown(f'<div class="chart-panel-heading"><h3>{title}</h3><p>Observed alert volume, split by severity</p></div>', unsafe_allow_html=True)
        if not alerts:
            st.info("No alert records in this time scope.")
            return

        frame = pd.DataFrame({
            "timestamp": pd.to_datetime([alert.timestamp for alert in alerts], utc=True, errors="coerce"),
            "severity": [alert.severity.value for alert in alerts],
        }).dropna(subset=["timestamp"])
        if frame.empty:
            st.info("Alert timestamps are unavailable for this chart.")
            return

        now = pd.Timestamp.now(tz="UTC")
        if time_range == "Last 24 hours":
            frequency = "h"
            frame["bucket"] = frame["timestamp"].dt.floor(frequency)
            buckets = pd.date_range(end=now.floor(frequency), periods=24, freq=frequency, tz="UTC")
            tick_format = "%H:%M"
        elif time_range == "Last 7 days":
            frequency = "D"
            frame["bucket"] = frame["timestamp"].dt.floor(frequency)
            buckets = pd.date_range(end=now.floor(frequency), periods=7, freq=frequency, tz="UTC")
            tick_format = "%b %d"
        else:
            span_days = max(0, (frame["timestamp"].max() - frame["timestamp"].min()).days)
            if span_days > 60:
                dates = frame["timestamp"].dt.floor("D")
                frame["bucket"] = dates - pd.to_timedelta(dates.dt.dayofweek, unit="D")
                buckets = pd.date_range(frame["bucket"].min(), frame["bucket"].max(), freq="7D", tz="UTC")
            else:
                frame["bucket"] = frame["timestamp"].dt.floor("D")
                buckets = pd.date_range(frame["bucket"].min(), frame["bucket"].max(), freq="D", tz="UTC")
            tick_format = "%b %d"

        counts = frame.groupby(["bucket", "severity"]).size().unstack(fill_value=0)
        colors = {"CRITICAL": C["crit"], "HIGH": C["high"], "MEDIUM": C["med"], "LOW": C["low"], "INFO": C["signal"]}
        fig = go.Figure()
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if severity in counts.columns:
                values = counts.reindex(index=buckets, columns=[severity], fill_value=0)[severity]
                fig.add_trace(go.Bar(
                    x=buckets, y=values, name=severity.title(), marker_color=colors[severity],
                    hovertemplate=f"%{{x|{tick_format}}}<br>{severity}: %{{y}}<extra></extra>",
                ))
        fig.update_layout(
            height=330, barmode="stack", bargap=0.24, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font={"family": "IBM Plex Mono, monospace", "size": 11, "color": C["text-2"]},
            margin={"l": 46, "r": 14, "t": 20, "b": 42},
            legend={"orientation": "h", "y": -0.22, "x": 0, "font": {"size": 10}},
            hoverlabel={"bgcolor": C["bg-raised"], "bordercolor": C["border"], "font": {"color": C["text-1"]}},
        )
        fig.update_xaxes(type="date", tickformat=tick_format, showgrid=False, linecolor=C["border-soft"])
        fig.update_yaxes(title="Alerts", rangemode="tozero", showgrid=True, gridcolor=C["border-soft"], zeroline=False, dtick=1)
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False, "responsive": True})


# ══════════════════════════════════════════════════════════════════════════════
#  TOPOLOGY — data-driven radio / AMF / slice graph
# ══════════════════════════════════════════════════════════════════════════════
def _spread(n: int, top: float, bottom: float) -> list[float]:
    """Evenly distribute n nodes between top and bottom (inclusive)."""
    if n <= 1:
        return [(top + bottom) / 2.0]
    step = (bottom - top) / (n - 1)
    return [top + i * step for i in range(n)]


def render_topology_graph(graph) -> None:
    """Draw the observed 5G topology: radio cells -> AMF -> network slices.

    ``graph`` is a ``ui.topology_data.TopologyGraph``. Authorized cells render in
    the signal colour, rogue cells (never provisioned) in red, and slices with an
    active SLICE_INTRUSION in amber. The whole block is emitted as a single line
    so Streamlit's Markdown parser treats it as one raw-HTML block instead of an
    indented code block (which used to leak the SVG source into the page).
    """
    nodes = list(graph.cells) + list(graph.rogue_cells)
    slices = list(graph.slices)

    amf_names = [str(a.get("name")) for a in (getattr(graph, "amf", None) or []) if a.get("name")]
    if amf_names:
        amf_sub = ", ".join(amf_names[:2])
        if len(amf_names) > 2:
            amf_sub += f" +{len(amf_names) - 2}"
    else:
        amf_sub = f'{graph.amf_count} instance{"" if graph.amf_count == 1 else "s"}'

    if not nodes and not slices:
        st.markdown(
            '<div class="section-card" style="padding:38px; text-align:center; color:#5F83AA;'
            ' font-family:var(--mono); font-size:12px;">No radio cells or network slices defined'
            ' yet. Upload your organization\'s network structure or replay a saved signaling capture.</div>',
            unsafe_allow_html=True,
        )
        return

    overflow = ""
    if len(nodes) > 6:
        overflow = f"+{len(nodes) - 6} more cells not shown"
        nodes = nodes[:6]
    if len(slices) > 6:
        overflow = (overflow + f" · +{len(slices) - 6} more slices not shown").strip(" ·")
        slices = slices[:6]

    cx, cy = 490.0, 180.0
    gx, sx = 118.0, 846.0
    half = 24.0
    cell_y = _spread(len(nodes), 48, 312)
    slice_y = _spread(len(slices), 48, 312)

    p: list[str] = []
    p.append('<div class="section-card" style="padding:20px 26px 10px;">')
    p.append(
        '<svg width="100%" height="360" viewBox="0 0 980 360" role="img"'
        ' aria-label="Network topology" style="display:block;">'
    )

    # links: radio cells -> AMF
    for node, y in zip(nodes, cell_y):
        rogue_edge = not node.authorized
        color = C["crit"] if rogue_edge else C["border"]
        width = 1.8 if rogue_edge else 1.3
        dash = ' stroke-dasharray="6 4"' if rogue_edge else ""
        p.append(
            f'<line x1="{gx + half:.0f}" y1="{y:.0f}" x2="{cx - 28:.0f}" y2="{cy:.0f}"'
            f' stroke="{color}" stroke-width="{width}"{dash}/>'
        )

    # links: AMF -> slices
    for sl, y in zip(slices, slice_y):
        color = C["high"] if sl.intrusions else C["border"]
        width = 1.8 if sl.intrusions else 1.3
        p.append(
            f'<line x1="{cx + 28:.0f}" y1="{cy:.0f}" x2="{sx - 18:.0f}" y2="{y:.0f}"'
            f' stroke="{color}" stroke-width="{width}"/>'
        )

    # AMF node
    p.append(
        f'<polygon points="{cx:.0f},{cy - 32:.0f} {cx + 30:.0f},{cy:.0f} {cx:.0f},{cy + 32:.0f}'
        f' {cx - 30:.0f},{cy:.0f}" fill="{C["bg-raised"]}" stroke="{C["low"]}" stroke-width="1.6"/>'
    )
    p.append(
        f'<text x="{cx:.0f}" y="{cy + 4:.0f}" text-anchor="middle" fill="{C["text-1"]}"'
        f' font-family="IBM Plex Mono" font-size="11" font-weight="600">AMF</text>'
    )
    p.append(
        f'<text x="{cx:.0f}" y="{cy + 58:.0f}" text-anchor="middle" fill="{C["text-1"]}"'
        f' font-family="IBM Plex Mono" font-size="12.5" font-weight="600">5G Core</text>'
    )
    p.append(
        f'<text x="{cx:.0f}" y="{cy + 74:.0f}" text-anchor="middle" fill="{C["text-3"]}"'
        f' font-family="IBM Plex Mono" font-size="10.5">{escape(amf_sub)}</text>'
    )

    # radio cell nodes (authorized + rogue)
    for node, y in zip(nodes, cell_y):
        stroke = C["crit"] if not node.authorized else C["signal"]
        p.append(
            f'<rect x="{gx - half:.0f}" y="{y - half:.0f}" width="{2 * half:.0f}"'
            f' height="{2 * half:.0f}" rx="9" fill="{C["bg-raised"]}" stroke="{stroke}" stroke-width="1.6"/>'
        )
        p.append(
            f'<path d="M{gx - 9:.0f} {y + 7:.0f} L{gx:.0f} {y - 8:.0f} L{gx + 9:.0f} {y + 7:.0f}"'
            f' fill="none" stroke="{stroke}" stroke-width="1.6" stroke-linecap="round"/>'
        )
        cell_title = str(node.label)
        if getattr(node, "name", ""):
            cell_title = f"{cell_title} · {node.name}"
        p.append(
            f'<text x="{gx + half + 12:.0f}" y="{y - 2:.0f}" fill="{C["text-1"]}"'
            f' font-family="IBM Plex Mono" font-size="12.5" font-weight="600">{escape(cell_title)}</text>'
        )
        if node.authorized:
            sub, sub_color = f"authorized · {node.alerts} alerts", C["text-3"]
        else:
            sub, sub_color = f"ROGUE · {node.alerts} alerts", C["crit"]
        p.append(
            f'<text x="{gx + half + 12:.0f}" y="{y + 14:.0f}" fill="{sub_color}"'
            f' font-family="IBM Plex Mono" font-size="10.5">{escape(sub)}</text>'
        )

    # slice nodes
    for sl, y in zip(slices, slice_y):
        stroke = C["high"] if sl.intrusions else C["signal"]
        p.append(
            f'<polygon points="{sx:.0f},{y - 18:.0f} {sx + 18:.0f},{y:.0f} {sx:.0f},{y + 18:.0f}'
            f' {sx - 18:.0f},{y:.0f}" fill="{C["bg-raised"]}" stroke="{stroke}" stroke-width="1.6"/>'
        )
        title = f"Slice {sl.sst}" if sl.sst else "Slice"
        p.append(
            f'<text x="{sx + 28:.0f}" y="{y - 3:.0f}" fill="{C["text-1"]}"'
            f' font-family="IBM Plex Mono" font-size="11.5" font-weight="600">{escape(title)}</text>'
        )
        p.append(
            f'<text x="{sx + 28:.0f}" y="{y + 12:.0f}" fill="{C["text-3"]}"'
            f' font-family="IBM Plex Mono" font-size="10">{escape(sl.slice_id)} · {sl.devices} dev</text>'
        )
        if sl.intrusions:
            p.append(
                f'<text x="{sx + 28:.0f}" y="{y + 27:.0f}" fill="{C["high"]}"'
                f' font-family="IBM Plex Mono" font-size="10">{sl.intrusions} intrusions</text>'
            )

    p.append("</svg>")
    if overflow:
        p.append(
            f'<div style="color:#5F83AA; font-family:var(--mono); font-size:10.5px;'
            f' padding-top:4px;">{escape(overflow)}</div>'
        )
    p.append("</div>")
    st.markdown("".join(p), unsafe_allow_html=True)


def render_cell_table(graph) -> None:
    """Compact table classifying every radio cell currently in the model."""
    rows = []
    for node in list(graph.cells) + list(graph.rogue_cells):
        tag_color = C["signal"] if node.authorized else C["crit"]
        tag = "AUTHORIZED" if node.authorized else "ROGUE"
        last = node.last_seen.strftime("%Y-%m-%d %H:%M:%S") if node.last_seen else "—"
        crit_color = C["crit"] if node.critical else C["text-3"]
        rows.append(
            "<tr>"
            f'<td style="font-family:var(--mono); color:{C["text-1"]}">{escape(str(node.label))}</td>'
            f'<td>{escape(str(getattr(node, "name", "") or "—"))}</td>'
            f'<td style="font-family:var(--mono); color:{C["text-3"]}">{escape(str(getattr(node, "tac", "") or "—"))}</td>'
            f'<td><span class="severity-pill" style="color:{tag_color}">{tag}</span></td>'
            f'<td style="font-family:var(--mono)">{node.alerts}</td>'
            f'<td style="font-family:var(--mono); color:{crit_color}">{node.critical}</td>'
            f'<td style="font-family:var(--mono); color:{C["text-3"]}">{escape(last)}</td>'
            "</tr>"
        )
    if not rows:
        return
    st.markdown(
        '<table class="slice-table">'
        "<thead><tr><th>Cell</th><th>Site</th><th>TAC</th><th>Classification</th><th>Alerts</th>"
        "<th>Critical</th><th>Last seen</th></tr></thead>"
        f'<tbody>{"".join(rows)}</tbody>'
        "</table>",
        unsafe_allow_html=True,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  NETWORK SLICE TABLE
# ══════════════════════════════════════════════════════════════════════════════
def render_slice_matrix(graph) -> None:
    """Provisioned / observed slices with device counts and intrusion state."""
    rows = []
    for sl in graph.slices:
        breaches = sl.intrusions > 0
        color = C["high"] if breaches else C["signal"]
        status = "MONITORED" if breaches else "STABLE"
        rows.append(
            "<tr>"
            f'<td style="color:{C["text-1"]}; font-family:var(--mono)">Slice {sl.sst or "-"}</td>'
            f'<td style="font-family:var(--mono)">{escape(sl.slice_id)}</td>'
            f'<td>{escape(sl.name or "-")}</td>'
            f'<td style="font-family:var(--mono)">{sl.devices}</td>'
            f'<td><span class="severity-pill" style="color:{color}">{status}</span></td>'
            "</tr>"
        )
    if not rows:
        return
    st.markdown(
        '<table class="slice-table">'
        "<thead><tr><th>Slice</th><th>S-NSSAI</th><th>Type</th><th>Devices</th><th>Status</th></tr></thead>"
        f'<tbody>{"".join(rows)}</tbody>'
        "</table>",
        unsafe_allow_html=True,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  MITRE ATT&CK
# ══════════════════════════════════════════════════════════════════════════════
def render_mitre_attack_matrix(alerts: list[Alert]) -> None:
    pass


# ══════════════════════════════════════════════════════════════════════════════
#  FIREWALL SYNTHESIZER
# ══════════════════════════════════════════════════════════════════════════════
def render_firewall_synthesizer(alert: Alert) -> None:
    imsi = alert.imsi or "001010000000001"
    t1, t2, t3, t4 = st.tabs(["iptables", "nftables", "OpenFlow", "Cisco"])
    with t1:
        st.code(f"sudo iptables -I FORWARD -p sctp --dport 38412 -m string --hex-string '{imsi}' --algo bm -j DROP", language="bash")
    with t2:
        st.code(f"nft add rule inet naswatch_filter forward sctp dport 38412 @ih,0,64 0x{imsi[:16]} drop", language="bash")
    with t3:
        st.code(f"ovs-ofctl add-flow br-n2 priority=65500,dl_type=0x0800,nw_proto=132,tp_dst=38412,actions=drop", language="bash")
    with t4:
        st.code(f"access-list 5G_N2 line 1 extended deny sctp any any eq 38412 log", language="cisco")


# ══════════════════════════════════════════════════════════════════════════════
#  ALERT ITEM — incident card matching the redesign
# ══════════════════════════════════════════════════════════════════════════════
def render_alert_item(alert: Alert, repo, soar=None) -> None:
    sev_cls = {"CRITICAL": "sev-critical", "HIGH": "sev-high", "MEDIUM": "sev-medium", "LOW": "sev-low"}.get(alert.severity.value, "sev-low")
    sev_val = alert.severity.value

    # Build the incident card matching redesign HTML
    soe = alert.raw_event or {}
    cell = alert.cell_id or "—"
    slce = alert.target_slice or "—"
    imsi = alert.imsi or "N/A"
    imei = alert.imei or "—"
    time_str = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    rule_label = alert.rule_type.value.lower().replace("_", " ")

    # SOAR buttons HTML (only if soar engine provided)
    soar_html = ""
    action_html = ""
    if soar and alert.imsi:
        soar_html = f"""
        <div class="soar-btns">
            <button class="soar-btn revoke" onclick="return false;">⊘ Revoke</button>
            <button class="soar-btn quarantine" onclick="return false;">‖ Quarantine</button>
        </div>"""
        action_html = f"""
        <select class="triage-select">
            <option{' selected' if alert.mitigation_status=='NEW' else ''}>NEW</option>
            <option{' selected' if alert.mitigation_status=='INVESTIGATING' else ''}>INVESTIGATING</option>
            <option{' selected' if alert.mitigation_status=='BLOCKED' else ''}>BLOCKED</option>
            <option{' selected' if alert.mitigation_status=='RESOLVED' else ''}>RESOLVED</option>
        </select>"""
    elif not soar:
        soar_html = '<div style="color:var(--text-3); font-size:11.5px; font-style:italic;">View-only — sign in as analyst or admin to mitigate.</div>'

    title_text = f"{alert.rule_type.value}: {alert.title}"
    subtitle_text = f"{alert.description or ''}"

    with st.expander(
        f"{sev_val} — {title_text}  ·  {imsi}  ·  {alert.timestamp.strftime('%Y-%m-%d %H:%M')}",
        expanded=(sev_val == "CRITICAL"),
    ):
        # Render the redesign-style incident body
        st.markdown(
            f"""
            <div class="incident-desc">{subtitle_text}</div>
            <table class="field-table">
                <tr><td>Time</td><td>{time_str}</td></tr>
                <tr><td>Cell</td><td>{cell}</td></tr>
                <tr><td>Slice</td><td>{slce}</td></tr>
                <tr><td>IMSI</td><td>{imsi}</td></tr>
                <tr><td>IMEI</td><td>{imei}</td></tr>
                <tr><td>Status</td><td>{alert.mitigation_status}</td></tr>
            </table>
            """,
            unsafe_allow_html=True,
        )

        if soar_html:
            st.markdown(soar_html, unsafe_allow_html=True)
        if action_html:
            st.markdown(action_html, unsafe_allow_html=True)

        # Interactive SOAR buttons (Streamlit buttons for actual functionality)
        if soar and alert.imsi:
            c1, c2 = st.columns(2)
            with c1:
                if st.button("⊘ Revoke", key=f"rev_{alert.id}", use_container_width=True):
                    soar.revoke_subscriber(alert.imsi, reason=f"Incident {alert.title}")
                    repo.update_mitigation_status(alert.id, "BLOCKED")
                    st.toast("Revoked")
                    st.rerun()
            with c2:
                if st.button("‖ Quarantine", key=f"q_{alert.id}", use_container_width=True):
                    soar.quarantine_device(alert.imsi)
                    repo.update_mitigation_status(alert.id, "INVESTIGATING")
                    st.toast("Quarantined")
                    st.rerun()

            options = ["NEW", "INVESTIGATING", "BLOCKED", "RESOLVED"]
            action = st.selectbox("Triage", options,
                index=options.index(alert.mitigation_status) if alert.mitigation_status in options else 0,
                key=f"stat_{alert.id}")
            if st.button("Update", key=f"upd_{alert.id}", use_container_width=True):
                repo.update_mitigation_status(alert.id, action)
                st.toast(f"→ {action}")
                st.rerun()

        if alert.raw_event:
            with st.expander("Protocol data"):
                st.json(alert.raw_event)

        if soar:
            with st.expander("Firewall rules"):
                render_firewall_synthesizer(alert)
            report_md = soar.generate_forensic_report(alert)
            st.download_button("Download report", data=report_md,
                file_name=f"forensic_{alert.id[:8]}.md", mime="text/markdown",
                key=f"dl_{alert.id}", use_container_width=True)
