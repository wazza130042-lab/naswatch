"""
NASWatch UI Components — World-Class Cybersecurity SOC Dashboard
================================================================
Includes:
  - Glassmorphic KPI Summary Cards with dynamic status glows
  - Interactive 2D/3D Network Slice & Core Topology Map
  - Interactive MITRE ATT&CK for 5G Threat Matrix Visualizer
  - Multi-Vendor Firewall Script Synthesizer (iptables, nftables, ovs-ofctl, Cisco)
  - Interactive SOAR Containment & Playbook Runner
  - Threat Trajectory Scatter & Severity Donut Charts
"""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from naswatch.storage.models import Alert, Device


# =============================================================================
# 1. Executive Glassmorphic KPI Cards
# =============================================================================
def render_kpi_cards(
    total_packets: int,
    total_alerts: int,
    critical_count: int,
    high_count: int,
    medium_count: int,
    device_count: int,
) -> None:
    """Render high-contrast executive SOC metric cards with neon accents."""
    c1, c2, c3, c4, c5 = st.columns(5)

    with c1:
        st.markdown(
            f"""
            <div class="soc-card soc-card-cyan">
                <div class="soc-card-label">📡 PACKETS INSPECTED</div>
                <div class="soc-card-value text-cyan">{total_packets:,}</div>
                <div class="soc-card-sub">5GS NGAP / NAS-PDU</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c2:
        badge_cls = "text-red" if total_alerts > 0 else "text-green"
        st.markdown(
            f"""
            <div class="soc-card soc-card-red">
                <div class="soc-card-label">🚨 THREAT INCIDENTS</div>
                <div class="soc-card-value {badge_cls}">{total_alerts:,}</div>
                <div class="soc-card-sub">{critical_count + high_count} High/Critical</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c3:
        st.markdown(
            f"""
            <div class="soc-card soc-card-crit">
                <div class="soc-card-label">🔴 CRITICAL (ROGUE / BS)</div>
                <div class="soc-card-value text-red">{critical_count}</div>
                <div class="soc-card-sub">{'Action Required' if critical_count > 0 else 'Zero Threats'}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c4:
        st.markdown(
            f"""
            <div class="soc-card soc-card-orange">
                <div class="soc-card-label">🟠 HIGH (SPOOF / FLOOD)</div>
                <div class="soc-card-value text-orange">{high_count}</div>
                <div class="soc-card-sub">{'Investigating' if high_count > 0 else 'All Clean'}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c5:
        st.markdown(
            f"""
            <div class="soc-card soc-card-blue">
                <div class="soc-card-label">📱 AUTHORIZED SUBSCRIBERS</div>
                <div class="soc-card-value text-blue">{device_count}</div>
                <div class="soc-card-sub">5G Core Inventory</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


# =============================================================================
# 2. Interactive 5G Network Slice & Topology Node Graph
# =============================================================================
def render_interactive_topology_graph(alerts: list[Alert], devices: list[Device]) -> None:
    """
    Renders an interactive node-link topology showing:
      - Radio Cells / gNodeBs
      - 5G Core AMF Ingress Hub
      - Slices (eMBB, uRLLC, mIoT, Enterprise Private)
      - Active threats & breach indicators
    """
    st.markdown("### 🗺️ 5G Network-Slice Live Interactive Topology")

    nodes_x = []
    nodes_y = []
    node_text = []
    node_color = []
    node_size = []
    node_symbols = []

    # 1. 5G Core AMF
    nodes_x.append(0)
    nodes_y.append(0)
    node_text.append("<b>5G Core AMF</b><br>Ingress N2/N1 Signaling Interface<br>Status: ONLINE")
    node_color.append("#00f2fe")
    node_size.append(36)
    node_symbols.append("hexagon")

    # 2. Radio Access Cells (gNodeBs)
    cell_positions = [(-2.2, 1.2), (-2.2, -1.2)]
    cell_names = ["gNB-Alpha (Cell 0x10)", "gNB-Beta (Cell 0x20)"]
    has_rogue_bs = any(a.rule_type.value == "FALSE_BASE_STATION" for a in alerts)

    for i, (cx, cy) in enumerate(cell_positions):
        nodes_x.append(cx)
        nodes_y.append(cy)
        is_rogue = (i == 1 and has_rogue_bs)
        node_text.append(f"<b>{cell_names[i]}</b><br>TAC: 1 | Status: {'🚨 ROGUE' if is_rogue else '🛡️ Authorized'}")
        node_color.append("#ef4444" if is_rogue else "#10b981")
        node_size.append(28)
        node_symbols.append("square")

    # 3. 5G Network Slices
    slices_data = [
        {"name": "Slice 1:000001 (eMBB-Public)", "pos": (2.2, 1.8), "color": "#38bdf8", "sst": 1, "sd": "000001"},
        {"name": "Slice 2:000002 (uRLLC-Critical)", "pos": (2.2, 0.6), "color": "#f59e0b", "sst": 2, "sd": "000002"},
        {"name": "Slice 3:000003 (mIoT-Sensors)", "pos": (2.2, -0.6), "color": "#10b981", "sst": 3, "sd": "000003"},
        {"name": "Slice 4:010203 (Enterprise-Private)", "pos": (2.2, -1.8), "color": "#a855f7", "sst": 4, "sd": "010203"},
    ]

    for s in slices_data:
        sx, sy = s["pos"]
        nodes_x.append(sx)
        nodes_y.append(sy)
        slice_id = f"{s['sst']}:{s['sd']}"
        intrusions = [a for a in alerts if a.target_slice == slice_id and a.rule_type.value == "SLICE_INTRUSION"]
        color = "#ef4444" if intrusions else s["color"]
        node_text.append(f"<b>{s['name']}</b><br>Intrusions: {len(intrusions)}<br>Status: {'🚨 BREACH' if intrusions else '🛡️ Isolated'}")
        node_color.append(color)
        node_size.append(30)
        node_symbols.append("diamond")

    # Edge traces
    edge_x = []
    edge_y = []

    for cx, cy in cell_positions:
        edge_x.extend([cx, 0, None])
        edge_y.extend([cy, 0, None])

    for s in slices_data:
        sx, sy = s["pos"]
        edge_x.extend([0, sx, None])
        edge_y.extend([0, sy, None])

    fig = go.Figure()

    fig.add_trace(
        go.Scatter(
            x=edge_x,
            y=edge_y,
            line=dict(width=2, color="rgba(79, 172, 254, 0.4)"),
            hoverinfo="none",
            mode="lines",
        )
    )

    fig.add_trace(
        go.Scatter(
            x=nodes_x,
            y=nodes_y,
            mode="markers+text",
            marker=dict(
                symbol=node_symbols,
                size=node_size,
                color=node_color,
                line=dict(width=2, color="#ffffff"),
            ),
            hovertext=node_text,
            hoverinfo="text",
            text=[t.split("<br>")[0].replace("<b>", "").replace("</b>", "") for t in node_text],
            textposition="top center",
            textfont=dict(color="#f8fafc", size=11),
        )
    )

    fig.update_layout(
        showlegend=False,
        hovermode="closest",
        margin=dict(b=20, l=20, r=20, t=30),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        paper_bgcolor="rgba(15, 23, 42, 0.6)",
        plot_bgcolor="rgba(15, 23, 42, 0.6)",
        height=380,
    )

    st.plotly_chart(fig, use_container_width=True)


# =============================================================================
# 3. MITRE ATT&CK for 5G & Mobile Matrix Coverage Visualizer
# =============================================================================
def render_mitre_attack_matrix(alerts: list[Alert]) -> None:
    """Render interactive MITRE ATT&CK for 5G threat coverage matrix."""
    st.markdown("### 🎯 MITRE ATT&CK for 5G & Mobile Telecommunications Coverage")
    st.caption("Real-time mapping of control-plane signaling intrusions to industry-standard adversary tactics & techniques.")

    mitre_tactics = [
        {
            "tactic": "Initial Access",
            "technique_id": "T1461",
            "technique": "Rogue Base Station / IMSI Catcher",
            "rule": "FALSE_BASE_STATION",
            "desc": "Adversary operates unauthorized cellular radio node to intercept registration.",
            "mitigation": "Cell ID Whitelisting & TAC Integrity Verification",
        },
        {
            "tactic": "Defense Evasion",
            "technique_id": "T1406",
            "technique": "SIM Cloning & Identity Spoofing",
            "rule": "IDENTITY_SPOOFING",
            "desc": "Transmitting with authorized subscriber credentials on unapproved hardware PEI.",
            "mitigation": "Hardware Binding & PEI/IMEI Cross-Validation",
        },
        {
            "tactic": "Lateral Movement",
            "technique_id": "T1437",
            "technique": "Network-Slice Hopping (S-NSSAI Intrusion)",
            "rule": "SLICE_INTRUSION",
            "desc": "Escalating from consumer eMBB slice to critical industrial uRLLC SCADA network.",
            "mitigation": "Zero-Trust S-NSSAI Subscription Policy Enforcement",
        },
        {
            "tactic": "Credential Access",
            "technique_id": "T1458",
            "technique": "Cryptographic Algorithm Downgrade (NEA0/NIA0)",
            "rule": "CIPHER_DOWNGRADE",
            "desc": "Manipulating NAS Security Mode to force null encryption and capture plaintext.",
            "mitigation": "Mandatory AS/NAS Security Policy (Reject NEA0)",
        },
        {
            "tactic": "Impact / DoS",
            "technique_id": "T1498",
            "technique": "5GC Signaling Flood & Storm",
            "rule": "SIGNALING_FLOOD",
            "desc": "Exhausting AMF authentication queue with high-rate registration storms.",
            "mitigation": "Stateful Dynamic Rate Limiting & IMSI Quarantine",
        },
        {
            "tactic": "Resource Hijacking",
            "technique_id": "T1465",
            "technique": "Rogue eSIM / Unauthorized Spectrum Access",
            "rule": "ROGUE_DEVICE",
            "desc": "Unregistered hardware transmitting on licensed carrier bands.",
            "mitigation": "Instant 5GC UDM Revocation & Edge Drop",
        },
    ]

    active_rule_types = {a.rule_type.value for a in alerts}

    cols = st.columns(3)
    for idx, item in enumerate(mitre_tactics):
        col_idx = idx % 3
        with cols[col_idx]:
            is_active = item["rule"] in active_rule_types
            card_border = "#ef4444" if is_active else "#334155"
            card_bg = "rgba(239, 68, 68, 0.12)" if is_active else "#1e293b"
            status_tag = f"<span class='badge badge-crit'>🚨 ACTIVE ({item['technique_id']})</span>" if is_active else f"<span class='badge badge-blue'>🛡️ MONITORED ({item['technique_id']})</span>"

            st.markdown(
                f"""
                <div style="background:{card_bg}; border:1px solid {card_border}; border-radius:10px; padding:16px; margin-bottom:16px; min-height:220px;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-size:11px; font-weight:700; color:#38bdf8; text-transform:uppercase;">{item['tactic']}</span>
                        {status_tag}
                    </div>
                    <h4 style="margin:8px 0 4px 0; color:#f8fafc; font-size:15px;">{item['technique']}</h4>
                    <p style="font-size:12px; color:#94a3b8; margin:0 0 10px 0;">{item['desc']}</p>
                    <div style="background:rgba(0,0,0,0.3); padding:8px 10px; border-radius:6px; font-size:11px; color:#cbd5e1;">
                        <strong>Rule:</strong> <code style="color:#00f2fe;">{item['rule']}</code><br>
                        <strong>Mitigation:</strong> {item['mitigation']}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )


# =============================================================================
# 4. Multi-Vendor Firewall Synthesizer
# =============================================================================
def render_firewall_synthesizer(alert: Alert) -> None:
    """Renders copy-pasteable firewall commands for multiple firewall / SDN vendors."""
    imsi = alert.imsi or "001010000000001"
    cell = alert.cell_id or "0x000000010"

    fw_tab1, fw_tab2, fw_tab3, fw_tab4 = st.tabs(["Linux iptables", "Linux nftables", "OpenFlow / OVS", "Cisco ASA / FTD"])

    with fw_tab1:
        iptables_cmd = (
            f"# Drop SCTP signaling frames matching IMSI {imsi}\n"
            f"sudo iptables -I FORWARD -p sctp --dport 38412 -m string --hex-string '{imsi}' --algo bm -j DROP\n"
            f"sudo iptables -I FORWARD -p sctp --dport 38412 -m string --hex-string '{imsi}' --algo bm -j LOG --log-prefix '[5G-IDS-DROP] '"
        )
        st.code(iptables_cmd, language="bash")

    with fw_tab2:
        nftables_cmd = (
            f"# Modern nftables kernel rule\n"
            f"nft add table inet naswatch_filter\n"
            f"nft add chain inet naswatch_filter forward {{ type filter hook forward priority 0 \\; }}\n"
            f"nft add rule inet naswatch_filter forward sctp dport 38412 @ih,0,64 0x{imsi[:16]} drop"
        )
        st.code(nftables_cmd, language="bash")

    with fw_tab3:
        ovs_cmd = (
            f"# Open vSwitch OpenFlow SDN drop rule (5GC NFV Core)\n"
            f"ovs-ofctl add-flow br-n2 priority=65500,dl_type=0x0800,nw_proto=132,tp_dst=38412,actions=drop\n"
            f"ovs-ofctl add-flow br-n2 priority=60000,dl_type=0x0800,in_port={cell},actions=drop"
        )
        st.code(ovs_cmd, language="bash")

    with fw_tab4:
        cisco_cmd = (
            f"! Cisco ASA / Firepower 5G Security Gateway Configuration\n"
            f"object network ROGUE_SUBSCRIBER_{imsi[:8]}\n"
            f" host 10.5.0.100\n"
            f"access-list 5G_N2_INSPECT line 1 extended deny sctp any any eq 38412 log\n"
            f"access-group 5G_N2_INSPECT in interface N2_AMF"
        )
        st.code(cisco_cmd, language="cisco")


# =============================================================================
# 5. Threat Severity Donut & Hourly Trajectory Timeline
# =============================================================================
def render_severity_chart(alerts: list[Alert]) -> None:
    """Render custom animated donut chart with Cyber dark theme."""
    if not alerts:
        st.markdown(
            """
            <div style="background:#1e293b; padding:24px; border-radius:10px; text-align:center; border:1px solid #334155;">
                <span style="font-size:32px;">🛡️</span>
                <h4 style="margin:8px 0; color:#34d399;">Zero Active Threats</h4>
                <p style="color:#94a3b8; font-size:13px; margin:0;">All signaling frames are authenticated and policy-compliant.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
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
                hole=0.62,
                marker=dict(colors=chart_colors, line=dict(color="#0f172a", width=3)),
                textinfo="label+value",
                hoverinfo="label+percent+value",
            )
        ]
    )
    fig.update_layout(
        title=dict(text="Threat Severity Breakdown", font=dict(color="#f8fafc", size=14)),
        margin=dict(t=40, b=10, l=10, r=10),
        height=280,
        showlegend=True,
        legend=dict(font=dict(color="#94a3b8"), orientation="h", yanchor="bottom", y=-0.2),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )
    st.plotly_chart(fig, use_container_width=True)


def render_threat_timeline(alerts: list[Alert]) -> None:
    """Render incident trajectory scatter timeline with rule type and slice data."""
    if not alerts:
        st.markdown(
            """
            <div style="background:#1e293b; padding:24px; border-radius:10px; text-align:center; border:1px solid #334155;">
                <span style="font-size:32px;">📈</span>
                <h4 style="margin:8px 0; color:#38bdf8;">Timeline Ready</h4>
                <p style="color:#94a3b8; font-size:13px; margin:0;">Replay PCAP or inject attack scenarios to generate trajectory points.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    records = [
        {
            "Timestamp": a.timestamp,
            "Severity": a.severity.value,
            "Rule": a.rule_type.value,
            "IMSI": a.imsi or "N/A",
            "Target Slice": a.target_slice or "N/A",
            "Cell": a.cell_id or "N/A",
        }
        for a in alerts
    ]
    df = pd.DataFrame(records)

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
        size=[14] * len(df),
        hover_data=["Rule", "IMSI", "Target Slice", "Cell"],
        color_discrete_map=color_map,
        title="Incident Ingress Trajectory",
    )
    fig.update_layout(
        height=280,
        margin=dict(t=40, b=10, l=10, r=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#f8fafc"),
        xaxis=dict(gridcolor="#334155", title="Timestamp"),
        yaxis=dict(gridcolor="#334155", title="Severity Level"),
        showlegend=False,
    )
    st.plotly_chart(fig, use_container_width=True)


# =============================================================================
# 6. 5G Slice Isolation Matrix Cards
# =============================================================================
def render_network_slice_matrix(alerts: list[Alert], devices: list[Device]) -> None:
    """Visualizes 5G network slices and active/intruding subscribers."""
    st.subheader("🌐 5G Network-Slice Access Matrix & Isolation Map")

    slices_def = [
        {"sst": 1, "sd": "000001", "name": "eMBB-Public", "type": "Enhanced Mobile Broadband", "desc": "Standard commercial subscriber data traffic", "icon": "🌍"},
        {"sst": 2, "sd": "000002", "name": "uRLLC-Critical", "type": "Ultra-Reliable Low-Latency", "desc": "Emergency first-responders & SCADA automation", "icon": "🚑"},
        {"sst": 3, "sd": "000003", "name": "mIoT-Sensors", "type": "Massive IoT", "desc": "Smart city environmental telemetry & smart metering", "icon": "🏙️"},
        {"sst": 4, "sd": "010203", "name": "Enterprise-Private", "type": "Private Enterprise Intranet", "desc": "Isolated corporate ERP, banking & DB interconnect", "icon": "🏢"},
    ]

    cols = st.columns(4)
    for idx, s in enumerate(slices_def):
        slice_id = f"{s['sst']}:{s['sd']}"
        with cols[idx]:
            authorized = [d for d in devices if d.is_slice_authorized(s["sst"], s["sd"])]
            intrusions = [a for a in alerts if a.target_slice == slice_id and a.rule_type.value == "SLICE_INTRUSION"]
            is_breached = len(intrusions) > 0

            card_border = "#ef4444" if is_breached else "#334155"
            card_bg = "rgba(239, 68, 68, 0.08)" if is_breached else "#1e293b"
            status_badge = f"<span class='badge badge-crit'>🚨 {len(intrusions)} INTRUSION(S)</span>" if is_breached else "<span class='badge badge-green'>🛡️ SECURE</span>"

            st.markdown(
                f"""
                <div style="background:{card_bg}; border:1px solid {card_border}; border-radius:10px; padding:16px; min-height:220px;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-size:24px;">{s['icon']}</span>
                        {status_badge}
                    </div>
                    <h4 style="margin:10px 0 4px 0; color:#38bdf8;">{s['name']}</h4>
                    <span style="font-size:11px; color:#94a3b8; font-family:monospace;">S-NSSAI: {s['sst']}:{s['sd']}</span>
                    <hr style="margin: 10px 0; border-color:#334155;" />
                    <p style="font-size:12px; margin:0; color:#cbd5e1;"><strong>Type:</strong> {s['type']}</p>
                    <p style="font-size:11px; margin:4px 0 10px 0; color:#94a3b8;">{s['desc']}</p>
                    <div style="font-size:12px; color:#f8fafc; background:rgba(0,0,0,0.25); padding:6px 10px; border-radius:6px;">
                        👥 Authorized Devices: <strong>{len(authorized)}</strong>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )


# =============================================================================
# 7. Advanced Incident Triage Card with SOAR, Multi-FW & 3GPP Dissect
# =============================================================================
def render_alert_item(alert: Alert, repo, soar=None) -> None:
    """Render an individual incident card with actionable SOAR mitigations, firewall script generator, and 3GPP dissection."""
    with st.expander(f"[{alert.severity.value}] {alert.rule_type.value} — {alert.title} (IMSI: {alert.imsi or 'N/A'})", expanded=(alert.severity.value == "CRITICAL")):
        c_left, c_right = st.columns([3, 2])

        with c_left:
            st.markdown(f"**Description:** {alert.description}")
            st.markdown(
                f"""
                - **⏱ Timestamp:** `{alert.timestamp.isoformat()}`
                - **📡 Cell ID / Radio Node:** `{alert.cell_id or 'Unknown'}`
                - **🌐 Target Slice (S-NSSAI):** `{alert.target_slice or 'N/A'}`
                - **📟 Observed Hardware IMEI:** `{alert.imei or 'N/A'}`
                - **⚡ Containment Status:** `{alert.mitigation_status}`
                """
            )

            # 3GPP Protocol Breakdown
            if alert.raw_event:
                with st.expander("🔍 3GPP Protocol Tree & Forensic Metadata", expanded=False):
                    st.json(alert.raw_event)

        with c_right:
            st.markdown("🎯 **Active SOAR Containment Controls**")
            b1, b2 = st.columns(2)
            with b1:
                if alert.imsi and st.button("🚫 Revoke 5GC", key=f"btn_rev_{alert.id}", use_container_width=True):
                    if soar:
                        res = soar.revoke_subscriber(alert.imsi, reason=f"Incident {alert.title}")
                        repo.update_mitigation_status(alert.id, "BLOCKED")
                        st.success(res.get("message", "Revoked"))
                        st.rerun()
            with b2:
                if alert.imsi and st.button("⏸️ Quarantine", key=f"btn_quar_{alert.id}", use_container_width=True):
                    if soar:
                        res = soar.quarantine_device(alert.imsi)
                        repo.update_mitigation_status(alert.id, "INVESTIGATING")
                        st.info(res.get("message", "Quarantined"))
                        st.rerun()

            # Multi-Vendor Firewall Synthesizer
            with st.expander("🛡️ Multi-Vendor Firewall Rules", expanded=False):
                render_firewall_synthesizer(alert)

            # Status Selector
            current_status = alert.mitigation_status
            action = st.selectbox(
                "Triage State",
                ["NEW", "INVESTIGATING", "BLOCKED", "RESOLVED"],
                index=["NEW", "INVESTIGATING", "BLOCKED", "RESOLVED"].index(current_status)
                if current_status in ["NEW", "INVESTIGATING", "BLOCKED", "RESOLVED"]
                else 0,
                key=f"status_sel_{alert.id}",
            )
            if st.button("Update Status", key=f"btn_stat_{alert.id}", use_container_width=True):
                repo.update_mitigation_status(alert.id, action)
                st.success(f"Status updated to '{action}'")
                st.rerun()

            # Forensic Report Export
            if soar:
                report_md = soar.generate_forensic_report(alert)
                st.download_button(
                    label="📄 Export Forensic Bundle",
                    data=report_md,
                    file_name=f"naswatch_forensic_{alert.id[:8]}.md",
                    mime="text/markdown",
                    key=f"btn_dl_{alert.id}",
                    use_container_width=True,
                )
