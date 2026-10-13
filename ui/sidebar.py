"""SOC sidebar: navigation, ingestion controls, filters, and operator actions."""
from __future__ import annotations

from pathlib import Path

import streamlit as st

from ui.rbac import has


def render_sidebar(repo, db_path, username, role):
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

        # Attack simulator — compact row matching redesign
        if has("inject"):
            with st.expander("› ⚡ Attack simulator"):
                from naswatch.detection.engine import DetectionEngine
                from naswatch.storage.models import ParsedSignalingEvent
                # Authorized gNB cell IDs (config/settings.yaml → network.authorized_cells).
                # Required for the False Base Station rule to fire on the rogue-gNB scenario.
                authorized_cells = ["0x000000010", "0x000000011", "0x000000012"]
                engine = DetectionEngine(device_repo=repo, authorized_cells=authorized_cells)
                attacks = [
                    ("SIM Cloning", ParsedSignalingEvent(imsi="999700000000001", imei="869999999999999",
                         procedure_name="SecurityModeComplete", cell_id="0x000000010")),
                    ("Slice Intrusion", ParsedSignalingEvent(imsi="999700000000002", requested_sst=2, requested_sd="000002",
                         procedure_name="PDUSessionEstablishmentRequest", cell_id="0x000000010")),
                    ("Rogue gNB", ParsedSignalingEvent(imsi="999700000000001", cell_id="0xDEADBEEF",
                         procedure_name="RegistrationRequest")),
                    ("Cipher Downgrade", ParsedSignalingEvent(imsi="999700000000001", cipher_algo="NEA0", integrity_algo="NIA0",
                         procedure_name="SecurityModeCommand")),
                ]
                for label, evt in attacks:
                    if st.button(label, use_container_width=True, key=f"atk_{label}"):
                        alerts = engine.process_event(evt)
                        for a in alerts:
                            repo.record_alert(a)
                        st.session_state.inspected_count += 1
                        st.toast(f"{label} injected")
                        st.rerun()

        st.markdown("---")

        st.markdown('<div class="nav-section-label" style="margin-top:4px;">INCIDENT FILTERS</div>', unsafe_allow_html=True)
        # Global incident filters
        selected_severity = st.selectbox("Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"], key="sev_filter")
        selected_rule = st.selectbox("Rule", [
            "ALL", "ROGUE_DEVICE", "IDENTITY_SPOOFING", "SLICE_INTRUSION",
            "CIPHER_DOWNGRADE", "FALSE_BASE_STATION", "SIGNALING_FLOOD",
        ], key="rule_filter")

        st.markdown("---")

        # Administrative actions — hidden entirely from roles without them.
        if has("seed") or has("clear"):
            c1, c2 = st.columns(2)
            with c1:
                if has("seed"):
                    if st.button("🌱 Seed", use_container_width=True, key="btn_seed"):
                        from scripts.seed_inventory import seed_inventory_from_csv
                        seed_inventory_from_csv("scripts/sample_devices.csv", db_path)
                        st.toast("Seeded")
                        st.rerun()
            with c2:
                if has("clear"):
                    if st.button("🗑 Clear", use_container_width=True, key="btn_clear"):
                        repo.clear_alerts()
                        st.session_state.inspected_count = 0
                        st.session_state.last_events = []
                        st.toast("Cleared")
                        st.rerun()
        # Administration — account management for administrators only.
        if has("users"):
            st.markdown("---")
            st.markdown('<div class="nav-section-label" style="margin-top:10px;">ADMINISTRATION</div>', unsafe_allow_html=True)
            if st.button(
                "User management",
                use_container_width=True,
                type="primary" if st.session_state.current_page == "User management" else "secondary",
                key="nav_users",
            ):
                st.session_state.current_page = "User management"
                st.rerun()

        # Role + sign out
        role_colors = {"admin": "var(--crit)", "analyst": "var(--high)", "viewer": "var(--low)"}
        role_hex = {"admin": "229,72,77", "analyst": "245,165,36", "viewer": "91,141,239"}
        rc = role_colors.get(role, "var(--text-2)")
        rh = role_hex.get(role, "139,147,163")
        st.markdown(
            f"""
            <div style="display:flex; align-items:center; gap:9px; padding:8px 10px;
                        background:var(--bg-raised); border:1px solid var(--border-soft); border-radius:4px; margin-bottom:10px;">
                <span style="width:7px; height:7px; border-radius:50%; background:{rc}; flex-shrink:0;"></span>
                <span style="font-size:12px; color:var(--text-1); font-weight:500; flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">{username}</span>
                <span style="padding:1px 5px; border-radius:2px; font-size:8px; font-weight:600;
                             text-transform:uppercase; letter-spacing:0.06em; background:rgba({rh},0.12);
                             color:{rc}; border:1px solid rgba({rh},0.25); flex-shrink:0;">{role}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Sign out", use_container_width=True, key="btn_logout"):
            # Never restore the signed-out session again within this session.
            st.session_state["_signed_out"] = True
            # Defer the cookie clear to the next run so its clearing frame renders.
            st.session_state["_clear_cookie_pending"] = True
            st.session_state.pop("_persist_session", None)
            # Drop the previous operator's password so it is never resubmitted.
            st.session_state.pop("login_password", None)
            del st.session_state["user"]
            st.rerun()

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
