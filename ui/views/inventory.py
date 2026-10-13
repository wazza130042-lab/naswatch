"""NASWatch UI — Asset inventory page."""
from __future__ import annotations

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

    active_count = sum(1 for d in devices if d.status.value == "ACTIVE")
    suspended_count = sum(1 for d in devices if d.status.value != "ACTIVE")
    known_supis = {d.imsi for d in devices}
    alerts_by_supi = {}
    for alert in all_alerts:
        if alert.imsi:
            alerts_by_supi.setdefault(alert.imsi, []).append(alert)
    at_risk_count = sum(1 for supi in known_supis if alerts_by_supi.get(supi))
    unknown_count = len({a.imsi for a in all_alerts if a.imsi and a.imsi not in known_supis})
    events_by_supi = {}
    for event in st.session_state.last_events:
        if event.get("IMSI"):
            events_by_supi.setdefault(event["IMSI"], []).append(event)

    st.markdown(
        f"""
        <div class="page-head">
            <div>
                <div class="page-title">Asset inventory</div>
                <div class="page-sub">Authorized subscriber identities, equipment identifiers, status, and permitted network slices.</div>
            </div>
            <div class="page-stats">
                <div class="pstat"><div class="pstat-val" style="color:var(--signal)">{active_count}</div><div class="pstat-label">ACTIVE</div></div>
                <div class="pstat"><div class="pstat-val" style="color:var(--text-3)">{suspended_count}</div><div class="pstat-label">SUSPENDED</div></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        f'<div class="asset-kpis">'
        f'<div class="asset-kpi"><div>DEVICES</div><strong>{len(devices)}</strong><small>registered subscribers</small></div>'
        f'<div class="asset-kpi accent-cyan"><div>ACTIVE</div><strong>{active_count}</strong><small>authorized identities</small></div>'
        f'<div class="asset-kpi accent-amber"><div>AT RISK</div><strong>{at_risk_count}</strong><small>with matching detections</small></div>'
        f'<div class="asset-kpi accent-blue"><div>UNKNOWN SUPI</div><strong>{unknown_count}</strong><small>seen in alert records</small></div>'
        f'</div>', unsafe_allow_html=True,
    )

    if has("provision"):
        with st.expander("+ Provision new subscriber"):
            from naswatch.storage.models import Device, DeviceStatus, SliceAssignment
            with st.form("prov_form"):
                f_imsi = st.text_input("IMSI (15 digits)", value="999700000000099")
                f_imei = st.text_input("IMEI (14-16 digits)", value="860123456789099")
                f_owner = st.text_input("Subscriber", value="New Subscriber")
                f_model = st.text_input("Model", value="5G Device")
                f_slices = st.multiselect("Slices", ["1:000001 (eMBB)", "2:000002 (uRLLC)", "3:000003 (mIoT)", "4:010203 (Enterprise)"], default=["1:000001 (eMBB)"])
                if st.form_submit_button("Provision", use_container_width=True):
                    from naswatch.storage.models import SliceAssignment as SA
                    slice_objs = []
                    for s in f_slices:
                        parts = s.split(" ")[0].split(":")
                        slice_objs.append(SA(sst=int(parts[0]), sd=parts[1] if len(parts) > 1 else None, name=s))
                    repo.add(Device(imsi=f_imsi.strip(), imei=f_imei.strip(), owner_name=f_owner.strip(),
                                    device_model=f_model.strip(), status=DeviceStatus.ACTIVE, allowed_slices=slice_objs))
                    st.toast(f"Provisioned {f_imsi}")
                    st.rerun()

    if devices:
        dev_rows = []
        for d in devices:
            device_alerts = alerts_by_supi.get(d.imsi, [])
            latest_alert = max(device_alerts, key=lambda a: a.timestamp) if device_alerts else None
            device_events = events_by_supi.get(d.imsi, [])
            last_event = device_events[-1] if device_events else None
            risk = latest_alert.severity.value if latest_alert else "NONE"
            dev_rows.append({
                "Subscriber": d.owner_name or "—", "SUPI": d.imsi, "PEI": d.imei or "—",
                "Cell": latest_alert.cell_id if latest_alert and latest_alert.cell_id else "—",
                "Slice": ", ".join(s.slice_id for s in d.allowed_slices) or "—",
                "Last seen": last_event.get("Time", "—") if last_event else "—",
                "Risk": risk, "Status": d.status.value,
            })
        st.dataframe(pd.DataFrame(dev_rows), use_container_width=True, hide_index=True)
    else:
        st.warning("No devices provisioned yet.")

