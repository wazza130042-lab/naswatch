"""NASWatch UI — Incidents page."""
from __future__ import annotations

import json
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
from ui.store import get_user_store, log_ui_action
from ui.routing import goto


def render(ctx):
    repo = ctx["repo"]
    user = ctx["user"]
    role = ctx["role"]
    username = ctx["username"]
    time_range = ctx["time_range"]
    search_query = ctx["search_query"]
    all_alerts = ctx["all_alerts"]
    filtered_alerts = ctx["filtered_alerts"]
    devices = ctx["devices"]
    display_packets = ctx["display_packets"]
    crit_count = ctx["crit_count"]
    high_count = ctx["high_count"]
    med_count = ctx["med_count"]
    soar = ctx["soar"]

    can_mitigate = has("mitigate")
    is_admin = role == "admin"
    actor_id = user.get("id", "")
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sev_class = {"CRITICAL": "c", "HIGH": "h", "MEDIUM": "m", "LOW": "l", "INFO": "l"}

    def detection_label(alert) -> str:
        title = alert.title or alert.rule_type.value.replace("_", " ").title()
        prefix = f"{alert.severity.value}: "
        return title[len(prefix):] if title.startswith(prefix) else title

    incidents = list(filtered_alerts)

    def open_incident(incident_id: str) -> None:
        st.session_state["incident_selection"] = incident_id
        goto("Incident detail")
        st.rerun()

    # Local queue filters complement the shared time/severity/rule scope.
    filter_cols = st.columns([1.35, 0.85, 1.1, 1, 1, 1.1], gap="small")
    with filter_cols[0]:
        queue_query = st.text_input(
            "QUEUE SEARCH", placeholder="Search incident ID or detection…",
            key="incident_queue_search", label_visibility="collapsed",
        )
    with filter_cols[1]:
        status_filter = st.selectbox(
            "STATUS", ["All statuses", "NEW", "INVESTIGATING", "BLOCKED", "RESOLVED"],
            key="incident_status_filter", label_visibility="collapsed",
        )
    with filter_cols[2]:
        owner_filter = st.selectbox(
            "ASSIGNEE", ["Anyone", "Unclaimed", "Assigned to me"],
            key="incident_owner_filter", label_visibility="collapsed",
        )
    with filter_cols[3]:
        severity_filter = st.selectbox(
            "SEVERITY", ["All severities", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            key="incident_severity_filter", label_visibility="collapsed",
        )
    with filter_cols[4]:
        rule_filter = st.selectbox(
            "RULE", ["All rules", "ROGUE_DEVICE", "IDENTITY_SPOOFING", "SLICE_INTRUSION", "CIPHER_DOWNGRADE", "FALSE_BASE_STATION", "SIGNALING_FLOOD"],
            key="incident_rule_filter", label_visibility="collapsed",
        )
    with filter_cols[5]:
        sort_order = st.selectbox(
            "SORT", ["Priority", "Newest first", "Oldest first"],
            key="incident_sort_order", label_visibility="collapsed",
        )

    if status_filter != "All statuses":
        incidents = [a for a in incidents if a.mitigation_status == status_filter]
    if owner_filter == "Unclaimed":
        incidents = [a for a in incidents if not a.assigned_to_id]
    elif owner_filter == "Assigned to me":
        incidents = [a for a in incidents if a.assigned_to_id == actor_id]
    if severity_filter != "All severities":
        incidents = [a for a in incidents if a.severity.value == severity_filter]
    if rule_filter != "All rules":
        incidents = [a for a in incidents if a.rule_type.value == rule_filter]
    if queue_query.strip():
        query = queue_query.casefold().strip()
        incidents = [a for a in incidents if query in " ".join((a.id, a.title or "", a.rule_type.value)).casefold()]
    if sort_order == "Newest first":
        incidents.sort(key=lambda a: a.timestamp, reverse=True)
    elif sort_order == "Oldest first":
        incidents.sort(key=lambda a: a.timestamp)
    else:
        incidents.sort(key=lambda a: (sev_rank.get(a.severity.value, 9), -a.timestamp.timestamp()))
    open_count = sum(1 for a in incidents if a.mitigation_status != "RESOLVED")
    crit_total = sum(1 for a in incidents if a.severity.value == "CRITICAL")
    new_total = sum(1 for a in incidents if a.mitigation_status == "NEW")

    st.markdown(
        """
        <div class="page-head">
            <div>
                <div class="page-title">Incident management</div>
                <div class="page-sub">Triage the shared queue, claim ownership, investigate evidence, and record response outcomes.</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="inc-kpis">'
        f'<div class="inc-kpi open"><s>OPEN</s><b>{open_count}</b></div>'
        f'<div class="inc-kpi crit"><s>CRITICAL</s><b>{crit_total}</b></div>'
        f'<div class="inc-kpi high"><s>HIGH</s><b>{sum(1 for a in incidents if a.severity.value == "HIGH")}</b></div>'
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

        with st.container(key="inc_queue_panel"):
            st.markdown(
                f'<div class="inc-panel-head"><span>TEAM INCIDENT QUEUE</span><small>{len(incidents)} matching · {open_count} open</small></div>',
                unsafe_allow_html=True,
            )
            sev_on = severity_filter != "All severities"
            rule_on = rule_filter != "All rules"
            st.markdown(
                '<div class="inc-filters">'
                f'<span class="chip{" on" if sev_on else ""}">severity: {escape(severity_filter.lower())}</span>'
                f'<span class="chip{" on" if rule_on else ""}">rule: {escape(rule_filter.lower())}</span>'
                f'<span class="chip">status: {escape(status_filter.lower().replace("_", " "))}</span>'
                f'<span class="chip">assignee: {escape(owner_filter.lower())}</span></div>',
                unsafe_allow_html=True,
            )
            head_cols = st.columns([1.05, 0.85, 2.3, 0.9, 1.25], vertical_alignment="center", gap="small")
            for head_col, label in zip(head_cols, ("ID", "SEVERITY", "DETECTION", "STATUS", "ASSIGNEE")):
                head_col.markdown(f'<div class="inc-th">{label}</div>', unsafe_allow_html=True)

            queue_limit = incidents[:40]
            for incident in queue_limit:
                sev_cls = sev_class.get(incident.severity.value, "l")
                with st.container(key=f"inc_row_{incident.id}"):
                    row_cols = st.columns([1.05, 0.85, 2.3, 0.9, 1.25], vertical_alignment="center", gap="small")
                    with row_cols[0]:
                            st.button(
                                incident.id[:8].upper(), key=f"inc_pick_{incident.id}",
                                use_container_width=True,
                                on_click=open_incident, args=(incident.id,),
                            )
                    row_cols[1].markdown(
                        f'<span class="sv {sev_cls}">{escape(incident.severity.value)}</span>',
                        unsafe_allow_html=True,
                    )
                    row_cols[2].button(
                        detection_label(incident), key=f"inc_open_{incident.id}",
                        on_click=open_incident, args=(incident.id,),
                    )
                    row_cols[3].markdown(
                        f'<span class="chip{" on" if incident.mitigation_status == "NEW" else ""}">'
                        f'{escape(incident.mitigation_status.lower())}</span>',
                        unsafe_allow_html=True,
                    )
                    row_cols[4].markdown(
                        f'<span class="inc-assignee">{escape(incident.assigned_to_name or "Unclaimed")}</span>',
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

        st.caption("Select an incident ID to open its investigation page.")


def render_detail(ctx):
    """Dedicated investigation page for one alert-backed incident record."""
    from ui.routing import goto

    repo = ctx["repo"]
    user = ctx["user"]
    role = ctx["role"]
    username = ctx["username"]
    soar = ctx["soar"]
    actor_id = user.get("id", "")
    org_id = user.get("org_id", "default")
    is_admin = role == "admin"
    can_mitigate = has("mitigate")
    can_evidence = has("evidence")
    alert_id = st.session_state.get("incident_selection")
    alert = next((item for item in ctx["all_alerts"] if item.id == alert_id), None)

    if st.button("← Back to incidents", key="incident_detail_back"):
        goto("Incidents")
        st.rerun()
    if alert is None:
        st.warning("This incident is unavailable in the current time scope or may have been removed.")
        return

    action_notice = st.session_state.pop("incident_action_notice", None)
    if action_notice:
        level, message = action_notice
        getattr(st, level)(message)

    title = alert.title or alert.rule_type.value.replace("_", " ").title()
    prefix = f"{alert.severity.value}: "
    if title.startswith(prefix):
        title = title[len(prefix):]
    severity_class = {
        "CRITICAL": "c", "HIGH": "h", "MEDIUM": "m", "LOW": "l", "INFO": "l",
    }.get(alert.severity.value, "l")
    timestamp = alert.timestamp
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    else:
        timestamp = timestamp.astimezone(UTC)

    st.markdown(
        '<div class="page-head"><div>'
        '<div class="page-title">Incident investigation</div>'
        f'<div class="page-sub">{escape(alert.id)} · {escape(title)}</div>'
        '</div></div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="inc-detail-head">'
        f'<span>{escape(alert.rule_type.value)} · {escape(timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"))}</span>'
        f'<span class="sv {severity_class}">{escape(alert.severity.value)}</span></div>'
        f'<div class="inc-detail-title">{escape(title)}</div>'
        f'<div class="inc-desc">{escape(alert.description or "No detection description was recorded.")}</div>',
        unsafe_allow_html=True,
    )

    claimed_by = alert.assigned_to_name or "Unclaimed"
    summary = [
        ("STATUS", alert.mitigation_status),
        ("OWNER", claimed_by),
        ("SUPI / IMSI", alert.imsi or "Restricted" if not can_evidence else alert.imsi or "—"),
        ("CELL", alert.cell_id or "Restricted" if not can_evidence else alert.cell_id or "—"),
        ("SLICE", alert.target_slice or "Restricted" if not can_evidence else alert.target_slice or "—"),
    ]
    summary_html = '<div class="inc-kpis inc-detail-metrics">' + "".join(
        f'<div class="inc-kpi"><s>{escape(label)}</s><b style="font-size:15px">{escape(str(value))}</b></div>'
        for label, value in summary
    ) + '</div>'
    st.markdown(summary_html, unsafe_allow_html=True)

    can_work = can_mitigate and (is_admin or alert.assigned_to_id == actor_id)
    action_left, action_right = st.columns([1.1, 2.9], vertical_alignment="center")
    with action_left:
        if can_mitigate and alert.assigned_to_id is None:
            if st.button("Claim incident", type="primary", use_container_width=True, key=f"detail_claim_{alert.id}"):
                if repo.claim_alert(alert.id, actor_id, username, org_id):
                    error = log_ui_action(user, "alert.claim", alert.id, {"assignee": username})
                    if error:
                        st.error(f"Claim saved, but its audit record failed: {error}")
                    st.toast("Incident claimed.")
                else:
                    st.warning("Another analyst claimed this incident first. Refresh to see the owner.")
                st.rerun()
        elif can_mitigate and alert.assigned_to_id == actor_id:
            st.markdown('<span class="chip on">CLAIMED BY YOU</span>', unsafe_allow_html=True)
            if st.button("Release claim", key=f"detail_release_{alert.id}", use_container_width=True):
                repo.release_alert(alert.id, actor_id, org_id)
                error = log_ui_action(user, "alert.release", alert.id, {"previous_assignee": username})
                if error:
                    st.error(f"Claim released, but its audit record failed: {error}")
                st.rerun()
        elif can_mitigate:
            st.markdown(f'<span class="chip">OWNED BY {escape(claimed_by)}</span>', unsafe_allow_html=True)
    with action_right:
        if is_admin:
            store = get_user_store()
            operators = [
                account for account in (store.list_users(org_id=org_id) if store else [])
                if account.active and account.role.value in {"admin", "analyst"}
            ]
            if operators:
                by_id = {account.id: account for account in operators}
                ids = list(by_id)
                default_index = ids.index(alert.assigned_to_id) if alert.assigned_to_id in ids else 0
                assign_col, save_col = st.columns([2.2, 1])
                with assign_col:
                    assignee_id = st.selectbox(
                        "Assign incident", ids, index=default_index,
                        format_func=lambda item: f"{by_id[item].username} · {by_id[item].role.value}",
                        key=f"detail_assign_{alert.id}",
                    )
                with save_col:
                    if st.button("Save owner", key=f"detail_assign_save_{alert.id}", use_container_width=True):
                        target = by_id[assignee_id]
                        if repo.assign_alert(alert.id, target.id, target.username, org_id, allow_reassign=True):
                            error = log_ui_action(user, "alert.reassign", alert.id, {"previous_assignee": claimed_by, "assignee": target.username})
                            if error:
                                st.error(f"Assignment saved, but its audit record failed: {error}")
                        st.rerun()

    raw_event = alert.raw_event or {}
    related = []
    if can_evidence:
        for event in st.session_state.get("last_events", []):
            event_imsi = str(event.get("IMSI") or "").strip()
            event_cell = str(event.get("Cell") or "").strip()
            if (alert.imsi and event_imsi == alert.imsi) or (
                not alert.imsi and alert.cell_id and event_cell == alert.cell_id
            ):
                related.append(event)
        related.sort(key=lambda item: str(item.get("Timestamp") or ""))

    alert_record = alert.to_dict()
    detail_record = {"incident": alert_record, "related_packets": related}
    view_mode = st.radio(
        "DETAIL FORMAT", ["Readable", "JSON"], horizontal=True,
        key=f"detail_format_{alert.id}", label_visibility="collapsed",
    )

    if view_mode == "JSON":
        st.json(detail_record, expanded=True)
    else:
        if not can_evidence:
            st.info("Detailed subscriber identifiers and packet evidence are restricted to SOC analysts and administrators.")
        else:
            evidence_rows = []
            ordered_fields = [
                ("Captured at", "event_timestamp"), ("Protocol", "protocol"),
                ("Packet number", "packet_num"), ("Procedure", "procedure_name"),
                ("Procedure code", "procedure_code"), ("Source IP", "source_ip"),
                ("Destination IP", "dest_ip"), ("RAN UE NGAP ID", "ran_ue_ngap_id"),
                ("AMF UE NGAP ID", "amf_ue_ngap_id"), ("SUPI / IMSI", "imsi"),
                ("PEI / IMEI", "imei"), ("GUTI", "guti"), ("Cell ID", "cell_id"),
                ("TAC", "tac"), ("Requested slice SST", "requested_sst"),
                ("Requested slice SD", "requested_sd"), ("Cipher algorithm", "cipher_algo"),
                ("Integrity algorithm", "integrity_algo"),
            ]
            included = set()
            for label, key in ordered_fields:
                value = raw_event.get(key)
                if value not in (None, "", [], {}):
                    included.add(key)
                    evidence_rows.append({"Field": label, "Value": json.dumps(value, ensure_ascii=False, default=str) if isinstance(value, (dict, list)) else str(value)})
            for key, value in raw_event.items():
                if key not in included and value not in (None, "", [], {}):
                    evidence_rows.append({"Field": key.replace("_", " ").title(), "Value": json.dumps(value, ensure_ascii=False, default=str) if isinstance(value, (dict, list)) else str(value)})
            for label, value in (("Incident ID", alert.id), ("Severity", alert.severity.value), ("Rule", alert.rule_type.value), ("Status", alert.mitigation_status)):
                evidence_rows.append({"Field": label, "Value": value})
            st.markdown('<div class="inc-subhead">DETECTION EVIDENCE</div>', unsafe_allow_html=True)
            if evidence_rows:
                st.dataframe(pd.DataFrame(evidence_rows), use_container_width=True, hide_index=True)
            else:
                st.info("No packet-level fields were saved with this alert.")
            if raw_event:
                with st.expander("Complete decoded event payload"):
                    st.json(raw_event, expanded=True)
            if related:
                packet_rows = [{
                    "Time": item.get("Timestamp") or item.get("Time") or "—",
                    "Packet": item.get("Packet") or "—",
                    "Procedure": item.get("Procedure") or "—",
                    "Source → destination": f'{item.get("Source IP") or "—"} → {item.get("Destination IP") or "—"}',
                    "Cell": item.get("Cell") or "—",
                    "Slice": item.get("Slice") or "—",
                } for item in related[-100:]]
                st.markdown('<div class="inc-subhead">RELATED PACKETS</div>', unsafe_allow_html=True)
                st.caption(f"{len(related)} matching decoded packets from the latest PCAP replay")
                st.dataframe(pd.DataFrame(packet_rows), use_container_width=True, hide_index=True)

    if can_work:
        st.markdown('<div class="inc-subhead">TRIAGE AND RESPONSE</div>', unsafe_allow_html=True)
        statuses = ["NEW", "INVESTIGATING", "BLOCKED", "RESOLVED"]
        status_cols = st.columns(len(statuses))
        for col, status in zip(status_cols, statuses):
            with col:
                if st.button(status.title(), key=f"detail_status_{alert.id}_{status}", use_container_width=True, type="primary" if alert.mitigation_status == status else "secondary"):
                    saved = repo.update_mitigation_status(alert.id, status, actor_id=actor_id, org_id=org_id, admin_override=is_admin)
                    if not saved:
                        st.session_state["incident_action_notice"] = ("error", "Status was not saved. Refresh the incident and check its owner.")
                        st.rerun()
                    error = log_ui_action(user, "alert.status.update", alert.id, {"from": alert.mitigation_status, "to": status})
                    st.session_state["incident_action_notice"] = (
                        "warning" if error else "success",
                        f"Status saved, but its audit record failed: {error}" if error else f"Incident status set to {status.title()}.",
                    )
                    st.rerun()
        st.caption("Blocked is an incident status. Network blocking is confirmed only when the configured core adapter succeeds.")
        response_left, response_right = st.columns(2)
        with response_left:
            if alert.imsi:
                st.warning("This revokes the subscriber in NASWatch inventory. A network-side block requires an explicitly configured core adapter.")
                revoke_confirmed = st.checkbox(
                    f"I authorize revoking subscriber {alert.imsi}",
                    key=f"detail_revoke_consent_{alert.id}",
                )
                if st.button(
                    "Confirm subscriber revocation", key=f"detail_revoke_{alert.id}",
                    use_container_width=True, disabled=not revoke_confirmed,
                ):
                    result = soar.revoke_subscriber(alert.imsi, reason=alert.title, org_id=org_id)
                    status_saved = None
                    if result.get("success"):
                        status_saved = repo.update_mitigation_status(
                            alert.id, "BLOCKED", actor_id=actor_id,
                            org_id=org_id, admin_override=is_admin,
                        )
                        if status_saved:
                            notice = ("success", "The core adapter confirmed the revoke; incident marked Blocked.")
                        else:
                            notice = ("error", "Core adapter confirmed the revoke, but the incident status could not be saved. Refresh and reconcile.")
                    elif result.get("inventory_revoked"):
                        notice = ("warning", "NASWatch inventory is marked REVOKED, but the core did not confirm a block. Incident remains open for follow-up.")
                    else:
                        notice = ("error", result.get("message", "Subscriber revocation failed."))
                    error = log_ui_action(
                        user, "alert.response.revoke", alert.id,
                        {
                            "inventory_revoked": result.get("inventory_revoked", False),
                            "core_state": (result.get("core_revocation") or {}).get("state"),
                            "success": result.get("success", False),
                            "incident_status_saved": status_saved,
                        },
                    )
                    if error:
                        notice = ("warning", f"{notice[1]} Audit record failed: {error}")
                    st.session_state["incident_action_notice"] = notice
                    st.rerun()
        with response_right:
            if can_evidence:
                filename = f"forensic_{alert.id[:8]}.md"
                st.download_button(
                    "Export evidence", data=soar.generate_forensic_report(alert),
                    file_name=filename, mime="text/markdown", key=f"detail_export_{alert.id}",
                    use_container_width=True, on_click=log_ui_action,
                    args=(user, "evidence.export", filename, {"incident_id": alert.id}),
                )
    elif can_mitigate:
        st.caption("Claim this incident to enable status and response actions.")
