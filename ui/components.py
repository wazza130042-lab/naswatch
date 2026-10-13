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
) -> None:
    cards = [
        ("c-signal", "PACKETS INSPECTED", f"{total_packets:,}", "5GS NGAP / NAS-PDU"),
        ("c-alert", "SECURITY ALERTS", f"{total_alerts:,}", f"{critical_count + high_count} high / critical"),
        ("c-crit", "CRITICAL", str(critical_count), "Action required" if critical_count else "None"),
        ("c-high", "HIGH", str(high_count), "Investigating" if high_count else "None"),
        ("c-low", "DEVICES", str(device_count), "Authorized subscribers"),
    ]

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
    if not alerts:
        st.markdown(
            f"""
            <div class="section-card" style="text-align:center; padding:36px 20px;">
            <div style="width:36px; height:36px; border-radius:9px; background:rgba(76,168,255,0.10);
                            border:1px solid rgba(76,168,255,0.22); display:inline-flex; align-items:center;
                            justify-content:center; margin-bottom:10px;">
                    <svg viewBox="0 0 24 24" fill="none" stroke="{C['low']}" stroke-width="1.6" width="17" height="17">
                        <path d="M12 2 3 6v6c0 5 3.8 8.7 9 10 5.2-1.3 9-5 9-10V6l-9-4Z"/>
                        <path d="M12 8v5m0 3h.01"/>
                    </svg>
                </div>
                <div style="font-size:13px; font-weight:600; color:{C['low']};">No alert data</div>
                <div style="font-size:11.5px; color:{C['text-3']}; margin-top:3px;">Replay a signaling capture to begin checking for threats</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    sev_counts = {}
    for a in alerts:
        sev_counts[a.severity.value] = sev_counts.get(a.severity.value, 0) + 1

    total = sum(sev_counts.values())
    colors_map = {"CRITICAL": C["crit"], "HIGH": C["high"], "MEDIUM": C["med"], "LOW": C["low"], "INFO": C["signal"]}

    # Build SVG donut
    offset = 0
    circles = ""
    legend_rows = ""
    for sev in ["CRITICAL", "MEDIUM", "HIGH", "LOW", "INFO"]:
        count = sev_counts.get(sev, 0)
        if count == 0:
            continue
        pct = (count / total) * 100
        color = colors_map.get(sev, C["text-3"])
        circles += f'<circle cx="75" cy="75" r="58" fill="none" stroke="{color}" stroke-width="18" pathLength="100" stroke-dasharray="{pct:.1f} 100" stroke-dashoffset="-{offset:.1f}" transform="rotate(-90 75 75)"/>'
        offset += pct
        legend_rows += f'<div style="display:flex; align-items:center; gap:9px; font-size:13px; margin-bottom:10px;"><span style="width:8px; height:8px; border-radius:2px; background:{color}; flex-shrink:0;"></span><span style="color:{C["text-2"]};">{sev.title()}</span><span style="font-family:var(--mono); color:{C["text-1"]}; margin-left:auto; padding-left:20px;">{count}</span></div>'

    st.markdown(
        f"""
        <div class="section-card">
            <h3>Severity breakdown</h3>
            <div style="display:flex; align-items:center; gap:26px;">
                <svg width="150" height="150" viewBox="0 0 150 150">
                    <circle cx="75" cy="75" r="58" fill="none" stroke="{C['border-soft']}" stroke-width="18"/>
                    {circles}
                    <text x="75" y="71" text-anchor="middle" fill="{C['text-1']}" font-family="IBM Plex Mono" font-size="22" font-weight="500">{total}</text>
                    <text x="75" y="88" text-anchor="middle" fill="{C['text-3']}" font-family="IBM Plex Mono" font-size="10">alerts</text>
                </svg>
                <div>{legend_rows}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  THREAT TIMELINE — horizontal dot tracks matching the redesign
# ══════════════════════════════════════════════════════════════════════════════
def render_threat_timeline(alerts: list[Alert]) -> None:
    if not alerts:
        st.markdown(
            f"""
            <div class="section-card" style="text-align:center; padding:36px 20px;">
                <div style="width:36px; height:36px; border-radius:9px; background:rgba(76,168,255,0.08);
                            border:1px solid rgba(76,168,255,0.18); display:inline-flex; align-items:center;
                            justify-content:center; margin-bottom:10px;">
                    <svg viewBox="0 0 24 24" fill="none" stroke="{C['low']}" stroke-width="1.6" width="17" height="17">
                        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                    </svg>
                </div>
                <div style="font-size:13px; font-weight:600; color:{C['low']};">Timeline Ready</div>
                <div style="font-size:11.5px; color:{C['text-3']}; margin-top:3px;">Replay a PCAP or start the live sensor</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    # Group by severity
    sev_rows = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    times = [a.timestamp for a in alerts]
    min_t = min(times).timestamp()
    max_t = max(times).timestamp()
    span = max_t - min_t if max_t > min_t else 1

    for a in alerts:
        sev = a.severity.value
        if sev in sev_rows:
            pct = ((a.timestamp.timestamp() - min_t) / span) * 100
            sev_rows[sev].append(pct)

    color_map = {"CRITICAL": C["crit"], "HIGH": C["high"], "MEDIUM": C["med"], "LOW": C["low"]}

    rows_html = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM"]:
        dots = ""
        for pct in sev_rows[sev]:
            dots += f'<div style="width:9px; height:9px; border-radius:50%; background:{color_map[sev]}; position:absolute; top:6px; left:{pct:.1f}%;"></div>'
        rows_html += f"""
        <div style="display:flex; align-items:center; gap:12px; margin-bottom:14px;">
            <div style="width:64px; font-size:11.5px; font-weight:600; color:{C['text-3']}; letter-spacing:0.03em;">{sev}</div>
            <div style="flex:1; height:20px; position:relative; border-bottom:1px dashed {C['border-soft']};">{dots}</div>
        </div>"""

    st.markdown(
        f"""
        <div class="section-card">
            <h3>Incident timeline</h3>
            {rows_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


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
            ' yet. Upload your organization\'s network structure, or replay a signaling capture /'
            ' start the live sensor to populate the topology.</div>',
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
