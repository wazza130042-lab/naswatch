"""
NASWatch UI Components — matches naswatch_redesign.html
"""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from naswatch.storage.models import Alert, Device

# CSS variables from the redesign
C = {
    "bg-base": "#0A0D12", "bg-panel": "#10141B", "bg-raised": "#161B24", "bg-input": "#0D1117",
    "border": "#212733", "border-soft": "#191E28",
    "text-1": "#E7EAEE", "text-2": "#8B93A3", "text-3": "#525A69",
    "signal": "#3DDC97", "signal-dim": "#1F5E48",
    "crit": "#E5484D", "high": "#F5A524", "med": "#E8C468", "low": "#5B8DEF",
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
                <div style="width:36px; height:36px; border-radius:50%; background:rgba(61,220,151,0.08);
                            border:1px solid rgba(61,220,151,0.15); display:inline-flex; align-items:center;
                            justify-content:center; margin-bottom:10px;">
                    <svg viewBox="0 0 24 24" fill="none" stroke="{C['signal']}" stroke-width="1.6" width="17" height="17">
                        <path d="M12 2 3 6v6c0 5 3.8 8.7 9 10 5.2-1.3 9-5 9-10V6l-9-4Z"/>
                        <path d="M9 12l2 2 4-4"/>
                    </svg>
                </div>
                <div style="font-size:13px; font-weight:600; color:{C['signal']};">All Clear</div>
                <div style="font-size:11.5px; color:{C['text-3']}; margin-top:3px;">No active threats detected</div>
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
                    <text x="75" y="88" text-anchor="middle" fill="{C['text-3']}" font-family="IBM Plex Sans" font-size="10">alerts</text>
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
                <div style="width:36px; height:36px; border-radius:50%; background:rgba(91,141,239,0.08);
                            border:1px solid rgba(91,141,239,0.15); display:inline-flex; align-items:center;
                            justify-content:center; margin-bottom:10px;">
                    <svg viewBox="0 0 24 24" fill="none" stroke="{C['low']}" stroke-width="1.6" width="17" height="17">
                        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                    </svg>
                </div>
                <div style="font-size:13px; font-weight:600; color:{C['low']};">Timeline Ready</div>
                <div style="font-size:11.5px; color:{C['text-3']}; margin-top:3px;">Replay a PCAP or inject attacks</div>
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
#  TOPOLOGY — SVG matching the redesign
# ══════════════════════════════════════════════════════════════════════════════
def render_interactive_topology_graph(alerts: list[Alert], devices: list[Device]) -> None:
    has_rogue = any(a.rule_type.value == "FALSE_BASE_STATION" for a in alerts)
    has_slice_breach = any(a.rule_type.value == "SLICE_INTRUSION" for a in alerts)

    gnb_beta_color = C["crit"] if has_rogue else C["signal"]
    slice2_color = C["crit"] if has_slice_breach else C["signal"]

    st.markdown(
        f"""
        <div class="section-card" style="padding:30px;">
            <svg width="100%" height="360" viewBox="0 0 980 360">
                <!-- Edges -->
                <line x1="140" y1="110" x2="480" y2="180" stroke="#232936" stroke-width="1.5"/>
                <line x1="140" y1="260" x2="480" y2="180" stroke="#232936" stroke-width="1.5"/>
                <line x1="480" y1="180" x2="840" y2="60"  stroke="#232936" stroke-width="1.5"/>
                <line x1="480" y1="180" x2="840" y2="180" stroke="#232936" stroke-width="1.5"/>
                <line x1="480" y1="180" x2="840" y2="300" stroke="#232936" stroke-width="1.5"/>

                <!-- gNB-Alpha -->
                <rect x="108" y="94" width="32" height="32" rx="4" fill="{C['bg-raised']}" stroke="{C['signal']}" stroke-width="1.5"/>
                <text x="150" y="105" fill="{C['text-1']}" font-family="IBM Plex Sans" font-size="13" font-weight="600">gNB-Alpha</text>
                <text x="150" y="121" fill="{C['text-3']}" font-family="IBM Plex Mono" font-size="11">0x10</text>

                <!-- gNB-Beta -->
                <rect x="108" y="244" width="32" height="32" rx="4" fill="{C['bg-raised']}" stroke="{gnb_beta_color}" stroke-width="1.5"/>
                <text x="150" y="255" fill="{C['text-1']}" font-family="IBM Plex Sans" font-size="13" font-weight="600">gNB-Beta</text>
                <text x="150" y="271" fill="{C['text-3']}" font-family="IBM Plex Mono" font-size="11">0x20</text>

                <!-- AMF -->
                <polygon points="480,150 512,180 480,210 448,180" fill="{C['bg-raised']}" stroke="{C['low']}" stroke-width="1.6"/>
                <text x="480" y="235" text-anchor="middle" fill="{C['text-1']}" font-family="IBM Plex Sans" font-size="13" font-weight="600">5G Core AMF</text>

                <!-- Slice 1 -->
                <polygon points="840,44 858,60 840,76 822,60" fill="{C['bg-raised']}" stroke="{C['low']}" stroke-width="1.5"/>
                <text x="866" y="55" fill="{C['text-1']}" font-family="IBM Plex Sans" font-size="13" font-weight="600">Slice 1</text>
                <text x="866" y="71" fill="{C['text-3']}" font-family="IBM Plex Mono" font-size="11">eMBB</text>

                <!-- Slice 2 -->
                <polygon points="840,164 858,180 840,196 822,180" fill="{C['bg-raised']}" stroke="{slice2_color}" stroke-width="1.5"/>
                <text x="866" y="175" fill="{C['text-1']}" font-family="IBM Plex Sans" font-size="13" font-weight="600">Slice 2</text>
                <text x="866" y="191" fill="{C['text-3']}" font-family="IBM Plex Mono" font-size="11">uRLLC</text>

                <!-- Slice 3 -->
                <polygon points="840,284 858,300 840,316 822,300" fill="{C['bg-raised']}" stroke="{C['signal']}" stroke-width="1.5"/>
                <text x="866" y="295" fill="{C['text-1']}" font-family="IBM Plex Sans" font-size="13" font-weight="600">Slice 3</text>
                <text x="866" y="311" fill="{C['text-3']}" font-family="IBM Plex Mono" font-size="11">mIoT</text>
            </svg>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  NETWORK SLICE TABLE
# ══════════════════════════════════════════════════════════════════════════════
def render_network_slice_matrix(alerts: list[Alert], devices: list[Device]) -> None:
    slices_def = [
        (1, "000001", "eMBB", C["low"]),
        (2, "000002", "uRLLC", C["crit"]),
        (3, "000003", "mIoT", C["signal"]),
    ]

    rows = ""
    for sst, sd, name, color in slices_def:
        sid = f"{sst}:{sd}"
        authorized = [d for d in devices if d.is_slice_authorized(sst, sd)]
        intrusions = [a for a in alerts if a.target_slice == sid and a.rule_type.value == "SLICE_INTRUSION"]
        status = "MONITORED" if intrusions else "STABLE"
        status_color = C["high"] if intrusions else C["signal"]
        status_border = C["high"] if intrusions else C["signal-dim"]

        rows += f"""
        <tr>
            <td><span class="slice-swatch" style="background:{color}"></span>Slice {sst}</td>
            <td style="font-family:var(--mono); font-size:12px;">{sid}</td>
            <td>{name}</td>
            <td>{len(authorized)}</td>
            <td><span style="font-size:10.5px; font-weight:600; padding:3px 8px; border-radius:2px; letter-spacing:0.02em;
                         color:{status_color}; border:1px solid {status_border};">{status}</span></td>
        </tr>"""

    st.markdown(
        f"""
        <table class="slice-table">
            <thead><tr><th>Slice</th><th>S-NSSAI</th><th>Type</th><th>Devices</th><th>Status</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
        """,
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
