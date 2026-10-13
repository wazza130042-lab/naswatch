"""SOC sidebar: navigation, ingestion, and incident filters.

Operator account controls (identity, User management, Sign out) live in the
top-corner settings menu owned by ``ui/app.py``.
"""
from __future__ import annotations

from pathlib import Path

import streamlit as st

from ui.rbac import has


def render_sidebar(repo):
    """Render the sidebar and return (page, severity_filter, rule_filter)."""
    with st.sidebar:
        # Brand
        st.markdown(
            """
            <div style="display:flex; align-items:center; gap:10px; padding:6px 6px 18px;
                        border-bottom:1px solid var(--border-soft); margin-bottom:16px;">
                <div style="width:32px; height:32px; border-radius:8px; background:#0A1E38;
                            border:1px solid #1C5A91; display:flex; align-items:center; justify-content:center; flex-shrink:0;">
                    <svg viewBox="0 0 24 24" fill="none" stroke="#42BFFF" stroke-width="1.8" width="18" height="18">
                        <path d="M12 2 3 6v6c0 5 3.8 8.7 9 10 5.2-1.3 9-5 9-10V6l-9-4Z"/>
                        <path d="M9 12l2 2 4-4"/>
                    </svg>
                </div>
                <div>
                    <div style="font-size:14.5px; font-weight:700; letter-spacing:-0.01em; color:var(--text-1);">NASWatch</div>
                    <div style="font-size:10px; color:var(--text-3); letter-spacing:0.03em;">5G control-plane</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # SOC workspace navigation
        st.markdown('<div class="nav-section-label">SOC WORKSPACE</div>', unsafe_allow_html=True)
        pages = ["Overview", "Event search", "Incidents", "Network topology", "Asset inventory", "Reports"]
        admin_pages = ["User management"] if has("users") else []
        if st.session_state.current_page not in pages + admin_pages:
            st.session_state.current_page = "Overview"
        for nav_index, nav_page in enumerate(pages, start=1):
            if st.button(
                nav_page,
                use_container_width=True,
                type="primary" if nav_page == st.session_state.current_page else "secondary",
                key=f"soc_nav_{nav_index}",
            ):
                st.session_state.current_page = nav_page
                st.rerun()
        page = st.session_state.current_page

        st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

        st.markdown('<div class="nav-section-label" style="margin-top:10px;">INGESTION</div>', unsafe_allow_html=True)
        # Ingestion status
        st.markdown(
            """
            <div class="sidebar-block">
                <div class="live-tag"><span class="pulse-dot"></span>N2 CAPTURE CONFIGURED</div>
                <div class="live-port">SCTP :38412</div>
                <div class="live-sub">gNB ↔ AMF signaling interface</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Replay section — only roles with the replay permission see it.
        if has("replay"):
            st.markdown(
                '<div class="sidebar-heading">▾ Replay traffic</div>',
                unsafe_allow_html=True,
            )
            pcap_path = st.text_input("PCAP", value="data/pcaps/5g_signaling_demo.pcap", label_visibility="collapsed")
            if st.button("▶  Replay PCAP", use_container_width=True, type="primary", key="btn_replay"):
                if not Path(pcap_path).exists():
                    st.error(f"Not found: {pcap_path}")
                    st.stop()
                from naswatch.detection.engine import DetectionEngine
                from naswatch.ingestion.pcap_replay import PCAPReplayer
                engine = DetectionEngine(device_repo=repo)
                replayer = PCAPReplayer(pcap_path=pcap_path)
                new_alerts = 0
                event_log = []
                with st.spinner("Processing..."):
                    for event in replayer.stream_events():
                        st.session_state.inspected_count += 1
                        event_log.append({
                            "Time": event.timestamp.strftime("%H:%M:%S"),
                            "Packet": event.packet_num,
                            "Procedure": event.procedure_name or "5GS",
                            "IMSI": event.imsi or "—",
                            "IMEI": event.imei or "—",
                            "Slice": event.requested_slice_id or "—",
                            "Cell": event.cell_id or "—",
                            "Cipher": event.cipher_algo or "NEA2",
                            "Integrity": event.integrity_algo or "NIA2",
                        })
                        alerts = engine.process_event(event)
                        for a in alerts:
                            repo.record_alert(a)
                            new_alerts += 1
                st.session_state.last_events = event_log
                st.toast(f"Done — {len(event_log)} packets, {new_alerts} alerts")
                st.rerun()

        st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

        st.markdown("---")

        st.markdown('<div class="nav-section-label" style="margin-top:4px;">INCIDENT FILTERS</div>', unsafe_allow_html=True)
        # Global incident filters
        selected_severity = st.selectbox("Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"], key="sev_filter")
        selected_rule = st.selectbox("Rule", [
            "ALL", "ROGUE_DEVICE", "IDENTITY_SPOOFING", "SLICE_INTRUSION",
            "CIPHER_DOWNGRADE", "FALSE_BASE_STATION", "SIGNALING_FLOOD",
        ], key="rule_filter")

        st.markdown("---")

        # Footer
        st.markdown(
            """
            <div style="margin-top:14px; padding-top:14px; border-top:1px solid var(--border-soft);
                        display:flex; align-items:center; gap:9px; color:var(--text-3); font-size:11.5px;">
                <span class="pulse-dot"></span> Console ready
            </div>
            """,
            unsafe_allow_html=True,
        )
    return st.session_state.current_page, selected_severity, selected_rule
