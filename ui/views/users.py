"""NASWatch UI — User management page."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from html import escape

import pandas as pd
import streamlit as st

from ui.rbac import has
from ui.store import get_user_store
from ui.components import (
    render_alert_item, render_interactive_topology_graph, render_kpi_cards,
    render_mitre_attack_matrix, render_network_slice_matrix,
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

    st.markdown(
        """
        <div class="page-head">
            <div>
                <div class="page-title">User management</div>
                <div class="page-sub">Provision operator accounts and assign admin, analyst, or viewer roles for this tenant.</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not has("users"):
        st.error("Administrator role required to manage operator accounts.")
    else:
        from naswatch.storage.models import UserRole

        store = get_user_store()
        if store is None:
            st.error("Identity store is unavailable.")
        else:
            org_id = user.get("org_id", "default")
            accounts = store.list_users(org_id=org_id)

            admin_count = sum(1 for u in accounts if u.role.value == "admin")
            analyst_count = sum(1 for u in accounts if u.role.value == "analyst")
            viewer_count = sum(1 for u in accounts if u.role.value == "viewer")
            active_count = sum(1 for u in accounts if u.active)

            st.markdown(
                f'<div class="asset-kpis">'
                f'<div class="asset-kpi accent-blue"><div>ACCOUNTS</div><strong>{len(accounts)}</strong><small>in this tenant</small></div>'
                f'<div class="asset-kpi"><div>ADMIN</div><strong>{admin_count}</strong><small>full control</small></div>'
                f'<div class="asset-kpi accent-amber"><div>ANALYST</div><strong>{analyst_count}</strong><small>respond &amp; investigate</small></div>'
                f'<div class="asset-kpi accent-cyan"><div>VIEWER</div><strong>{viewer_count}</strong><small>read-only</small></div>'
                f'</div>',
                unsafe_allow_html=True,
            )

            # ── Create account ────────────────────────────────────────
            with st.expander("+ Create operator account", expanded=(len(accounts) == 0)):
                with st.form("create_user_form", clear_on_submit=False):
                    cc1, cc2 = st.columns(2)
                    with cc1:
                        new_username = st.text_input("Username / email", placeholder="operator@naswatch.io", key="new_user_name")
                    with cc2:
                        new_role = st.selectbox("Role", ["viewer", "analyst", "admin"], index=0, key="new_user_role",
                                                help="Viewer = read-only · Analyst = investigate + respond · Admin = full control")
                    new_password = st.text_input("Initial password (min 12 characters)", type="password", key="new_user_password")
                    create_submitted = st.form_submit_button("Create account", use_container_width=True, type="primary")

                if create_submitted:
                    cleaned = (new_username or "").strip()
                    if len(cleaned) < 3:
                        st.error("Username must be at least 3 characters.")
                    elif any(u.username.casefold() == cleaned.casefold() for u in store.list_users()):
                        st.error(f"An account named '{cleaned}' already exists.")
                    elif len(new_password or "") < 12:
                        st.error("Password must be at least 12 characters.")
                    else:
                        store.create_user(username=cleaned, password=new_password, role=UserRole(new_role), org_id=org_id)
                        for widget_key in ("new_user_name", "new_user_role", "new_user_password"):
                            st.session_state.pop(widget_key, None)
                        st.toast(f"Created {new_role} account: {cleaned}")
                        st.rerun()

            # ── Accounts table ────────────────────────────────────────
            st.markdown(
                f'<div class="queue-heading"><h3>Operator accounts</h3><span>{active_count} active of {len(accounts)}</span></div>',
                unsafe_allow_html=True,
            )
            if not accounts:
                st.info("No operator accounts in this tenant yet.")
            else:
                st.dataframe(pd.DataFrame([{
                    "Username": u.username,
                    "Role": u.role.value,
                    "Tenant": u.org_id,
                    "Status": "active" if u.active else "disabled",
                    "Created (UTC)": u.created_at.strftime("%Y-%m-%d %H:%M"),
                } for u in accounts]), hide_index=True, use_container_width=True)

                # ── Manage an account ─────────────────────────────────
                st.markdown('<div class="queue-heading"><h3>Manage account</h3></div>', unsafe_allow_html=True)
                by_id = {u.id: u for u in accounts}
                selected_id = st.selectbox(
                    "Account", list(by_id.keys()),
                    format_func=lambda uid: f"{by_id[uid].username} · {by_id[uid].role.value} · {'active' if by_id[uid].active else 'disabled'}",
                    key="user_mgmt_selection", label_visibility="collapsed",
                )
                target = by_id[selected_id]
                is_self = target.id == user.get("id")

                m1, m2 = st.columns(2)
                with m1:
                    role_options = ["viewer", "analyst", "admin"]
                    new_role_value = st.selectbox(
                        "Role", role_options,
                        index=role_options.index(target.role.value),
                        key=f"user_role_{target.id}",
                    )
                    if st.button("Update role", use_container_width=True, key=f"user_role_btn_{target.id}",
                                 disabled=(is_self and new_role_value != "admin")):
                        store.update_user(target.id, role=UserRole(new_role_value))
                        st.toast(f"{target.username} → {new_role_value}")
                        st.rerun()
                    if is_self and new_role_value != "admin":
                        st.caption("You cannot remove your own administrator role.")
                with m2:
                    new_status = st.checkbox("Account active", value=target.active,
                                             key=f"user_active_{target.id}", disabled=is_self)
                    if st.button("Save status", use_container_width=True, key=f"user_active_btn_{target.id}",
                                 disabled=is_self):
                        store.update_user(target.id, active=new_status)
                        st.toast(f"{target.username} {'enabled' if new_status else 'disabled'}")
                        st.rerun()
                    if is_self:
                        st.caption("You cannot deactivate your own account.")

                with st.expander("Reset password"):
                    new_pw = st.text_input("New password (min 12 characters)", type="password", key=f"user_pw_{target.id}")
                    if st.button("Reset password", use_container_width=True, key=f"user_pw_btn_{target.id}"):
                        if len(new_pw or "") < 12:
                            st.error("Password must be at least 12 characters.")
                        else:
                            store.reset_password(target.id, new_pw)
                            st.session_state.pop(f"user_pw_{target.id}", None)
                            st.toast(f"Password reset for {target.username}")
                            st.rerun()

