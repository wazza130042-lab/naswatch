"""NASWatch — 5G Control-Plane Threat Detection Dashboard.

This module is the **orchestrator** only: session restore, sidebar, command bar,
data loading, and dispatch to the selected page. The interesting code lives in:

  * ``ui/theme.py``    — SOC theme CSS
  * ``ui/rbac.py``     — role → permission map (single source of truth)
  * ``ui/session.py``  — cookie-backed session persistence
  * ``ui/store.py``    — cached data-store accessors
  * ``ui/login.py``    — login screen
  * ``ui/sidebar.py``  — navigation, ingestion, filters, operator actions
  * ``ui/views/*``     — one module per page (Overview, Incidents, ...)
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from html import escape
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import streamlit as st

st.set_page_config(page_title="NASWatch", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

from ui.login import login_page
from ui.views import event_search, incidents, inventory, overview, reports, security, topology, users
from ui.rbac import ROLE_DESCRIPTIONS, ROLE_LABELS, has
from ui.routing import ACCOUNT_PAGES, ADMIN_PAGES, AUDIT_PAGES, DETAIL_PAGES, WORKSPACE_PAGES, goto, restore_page, slug_for, sync_url
from ui.session import (
    _clear_session_cookie,
    _restore_session,
    _session_token,
    _write_session_cookie,
    sign_out,
)
from ui.sidebar import render_sidebar
from ui.store import get_repository, get_user_store
from ui.theme import CSS


def _render_settings_menu(username: str, role: str) -> None:
    """Top-corner settings menu: operator identity, User management, Sign out.

    Replaces the old sidebar account block — User management is hidden for roles
    without the permission, while Sign out is always available.
    """
    role_colors = {"admin": "var(--crit)", "analyst": "var(--high)", "viewer": "var(--low)", "auditor": "var(--signal)"}
    role_hex = {"admin": "255,70,107", "analyst": "255,184,47", "viewer": "17,217,237", "auditor": "76,168,255"}
    rc = role_colors.get(role, "var(--text-2)")
    rh = role_hex.get(role, "139,147,163")
    safe_user = escape(username or "operator")
    safe_role = escape(ROLE_LABELS.get(role, ROLE_LABELS["viewer"]))
    safe_role_description = escape(ROLE_DESCRIPTIONS.get(role, ROLE_DESCRIPTIONS["viewer"]))
    initial = (safe_user[:1] or "?").upper()

    # Streamlit keeps a popover open across reruns, so selecting an item would
    # leave the menu floating over the page it just navigated to. Bumping this
    # generation changes the host container's key, which remounts the popover in
    # its closed state.
    generation = st.session_state.get("settings_menu_generation", 0)

    with st.container(key=f"settings_menu_host_{generation}"):
        with st.popover("", icon=":material/settings:", help="Settings"):
            st.markdown(
                f"""
                <div class="settings-head">
                  <div class="settings-eyebrow">Operator session</div>
                  <div class="settings-id">
                    <span class="settings-avatar"
                          style="background:rgba({rh},0.16);border:1px solid rgba({rh},0.40);color:{rc};">{initial}</span>
                    <span class="settings-text">
                      <span class="settings-name">{safe_user}</span>
                      <span class="settings-sub">{safe_role_description}</span>
                    </span>
                    <span class="settings-role"
                          style="background:rgba({rh},0.14);border:1px solid rgba({rh},0.32);color:{rc};">{safe_role}</span>
                  </div>
                </div>
                <div class="settings-sep"></div>
                """,
                unsafe_allow_html=True,
            )
            if st.button("Security", icon=":material/security:", use_container_width=True, key="settings_security"):
                st.session_state.settings_menu_generation = generation + 1
                goto("Security")
                st.rerun()
            if has("users"):
                if st.button(
                    "User management",
                    icon=":material/manage_accounts:",
                    use_container_width=True,
                    key="settings_users",
                ):
                    st.session_state.settings_menu_generation = generation + 1
                    goto("User management")
                    st.rerun()
            if has("audit"):
                if st.button("Audit log", icon=":material/policy:", use_container_width=True, key="settings_audit"):
                    st.session_state.settings_menu_generation = generation + 1
                    goto("Audit log")
                    st.rerun()
            st.markdown('<div class="settings-sep settings-sep-gap"></div>', unsafe_allow_html=True)
            if st.button("Sign out", icon=":material/logout:", use_container_width=True, key="settings_signout"):
                sign_out()
                st.rerun()


def main() -> None:
    _restore_session()
    # A sign out defers the cookie clear to this run so its frame actually renders
    # (an in-flight st.rerun() would cancel the clearing frame otherwise).
    if st.session_state.pop("_clear_cookie_pending", False):
        _clear_session_cookie()
    if "user" not in st.session_state:
        login_notice = st.session_state.pop("_login_notice", None)
        if login_notice:
            st.info(login_notice)
        login_page()
        return

    user = st.session_state["user"]
    role = user["role"]
    username = user["username"]
    repo = get_repository()

    # Freshly authenticated: persist the session cookie on the first signed-in run.
    if st.session_state.pop("_persist_session", False):
        _write_session_cookie(_session_token(user))

    # Mandatory 2FA: an authenticated operator without an armed second factor
    # cannot reach a single page — not even a restored session from before the
    # policy, and not one whose 2FA an admin just reset.
    identity_store = get_user_store()
    gated_account = None
    try:
        gated_account = identity_store.get_by_id(user["id"]) if identity_store else None
    except Exception:
        pass
    if identity_store is None or gated_account is None or not gated_account.active:
        st.session_state["_login_notice"] = (
            "Your account could not be validated. Sign in again after identity storage is available."
        )
        sign_out()
        st.rerun()
        return
    if not gated_account.totp_enabled or not gated_account.totp_secret:
        st.session_state["_login_notice"] = (
            "Two-factor setup is required for this account. Sign in with your password to enroll an authenticator."
        )
        sign_out()
        st.rerun()
        return

    # Apply current directory values on every rerun. A role or tenant change
    # takes effect immediately instead of waiting for the cookie to expire.
    previous_identity = st.session_state.get("user") or {}
    user = {
        "id": gated_account.id,
        "username": gated_account.username,
        "role": gated_account.role.value,
        "org_id": gated_account.org_id,
    }
    if any(previous_identity.get(key) != user[key] for key in ("id", "role", "org_id")):
        for key in ("last_events", "inspected_count", "incident_selection", "global_search", "event_detail_selection"):
            st.session_state.pop(key, None)
    st.session_state["user"] = user
    role = user["role"]
    username = user["username"]

    if "inspected_count" not in st.session_state:
        st.session_state.inspected_count = 0
    if "last_events" not in st.session_state:
        st.session_state.last_events = []
    if "current_page" not in st.session_state:
        st.session_state.current_page = "Overview"
    # A ?page= deep link wins on load, but only for pages this role may open.
    if has("evidence"):
        allowed_pages = list(WORKSPACE_PAGES)
    elif has("view"):
        allowed_pages = ["Overview", "Incidents"]
    else:
        allowed_pages = []
    if has("view"):
        allowed_pages += list(DETAIL_PAGES)
    allowed_pages += list(ACCOUNT_PAGES)
    if has("users"):
        allowed_pages += list(ADMIN_PAGES)
    if has("audit"):
        allowed_pages += list(AUDIT_PAGES)
    restore_page(allowed_pages)

    st.markdown(CSS, unsafe_allow_html=True)
    audit_warning = st.session_state.pop("_audit_warning", None)
    if audit_warning:
        st.warning(audit_warning)
    # ── Sidebar ─────────────────────────────────────────────────────────
    page, selected_severity, selected_rule = render_sidebar(repo)
    # Keep the address bar in step with what actually rendered (this also
    # rewrites an unknown or unauthorised deep link back to a valid page).
    sync_url(page)
    # ── Global investigation command bar ───────────────────────────────
    page_slug = slug_for(page)
    with st.container(key="command-bar", border=False):
        crumb, scope_time_col, scope_search_col, settings_col = st.columns(
            [1.10, 0.70, 1.12, 0.26] if has("view") else [1.5, 0.05, 0.05, 0.3],
            gap="small", vertical_alignment="center"
        )
        with crumb:
            st.markdown(
                f'<div class="soc-crumb">SOC-01 <span>/</span> {page_slug}</div>',
                unsafe_allow_html=True,
            )
        if has("view"):
            with scope_time_col:
                time_range = st.selectbox(
                    "TIME RANGE", ["Last 24 hours", "Last 7 days", "All time"],
                    key="global_time_range", label_visibility="collapsed",
                )
            with scope_search_col:
                search_query = st.text_input(
                    "GLOBAL SEARCH", placeholder="Search rules and detections…",
                    key="global_search", help="Search records visible to your role.",
                    label_visibility="collapsed",
                )
        else:
            time_range, search_query = "All time", ""
        with settings_col:
            _render_settings_menu(username, role)

    # ── Data and global investigation scope ────────────────────────────
    org_id = user.get("org_id", "default")
    devices = repo.list_all(limit=500, org_id=org_id) if has("inventory") else []
    sev_filter = None if selected_severity == "ALL" else selected_severity
    rule_filter = None if selected_rule == "ALL" else selected_rule
    now = datetime.now(UTC)
    all_alerts = repo.get_alerts(limit=500, org_id=org_id) if has("alerts") else []
    if time_range != "All time":
        window = timedelta(hours=24) if time_range == "Last 24 hours" else timedelta(days=7)
        cutoff = now - window
        all_alerts = [
            alert for alert in all_alerts
            if (alert.timestamp.replace(tzinfo=UTC) if alert.timestamp.tzinfo is None else alert.timestamp) >= cutoff
        ]

    # Viewer sessions receive safe summaries only. Do not pass subscriber
    # identifiers or decoded packet fields into a renderer lacking that grant.
    if not has("evidence"):
        from dataclasses import replace
        all_alerts = [
            replace(
                alert,
                title=f"{alert.severity.value}: {alert.rule_type.value.replace('_', ' ').title()}",
                description="Detailed detection evidence is restricted to SOC analysts and administrators.",
                imsi=None, imei=None, cell_id=None, target_slice=None, raw_event={},
                assigned_to_id=None, assigned_to_name=None, claimed_at=None,
            )
            for alert in all_alerts
        ]

    def matches_search(alert) -> bool:
        if not search_query.strip():
            return True
        haystack = " ".join(str(value or "") for value in (
            alert.title, alert.description, alert.imsi, alert.imei, alert.cell_id,
            alert.target_slice, alert.rule_type.value, alert.mitigation_status,
        ))
        return search_query.casefold() in haystack.casefold()

    filtered_alerts = [
        alert for alert in all_alerts
        if (sev_filter is None or alert.severity.value == sev_filter)
        and (rule_filter is None or alert.rule_type.value == rule_filter)
        and matches_search(alert)
    ]

    crit_count = sum(1 for a in all_alerts if a.severity.value == "CRITICAL")
    high_count = sum(1 for a in all_alerts if a.severity.value == "HIGH")
    med_count = sum(1 for a in all_alerts if a.severity.value == "MEDIUM")

    # Count packets only when this process actually inspected them. Alerts are
    # not a reliable proxy for packet volume.
    display_packets = st.session_state.inspected_count
    from naswatch.mitigation.soar import SOAREngine
    soar = SOAREngine(device_repo=repo, alert_repo=repo)

    st.markdown('<div style="padding:28px 32px 70px;">', unsafe_allow_html=True)

    # ── Page routing ───────────────────────────────────────────────────
    ctx = {
        "repo": repo, "user": user, "role": role, "username": username,
        "time_range": time_range, "search_query": search_query,
        "selected_severity": selected_severity, "selected_rule": selected_rule,
        "all_alerts": all_alerts, "filtered_alerts": filtered_alerts,
        "devices": devices, "display_packets": display_packets,
        "crit_count": crit_count, "high_count": high_count, "med_count": med_count,
        "soar": soar,
    }
    if page == "Security":
        security.render(ctx)
    elif page == "Audit log":
        from ui.views import audit_log
        audit_log.render(ctx)
    elif page == "Overview":
        overview.render(ctx)
    elif page == "Event search":
        event_search.render(ctx)
    elif page == "Network topology":
        topology.render(ctx)
    elif page == "Incidents":
        incidents.render(ctx)
    elif page == "Incident detail":
        incidents.render_detail(ctx)
    elif page == "Asset inventory":
        inventory.render(ctx)
    elif page == "User management":
        users.render(ctx)
    elif page == "Reports":
        reports.render(ctx)

    st.markdown("</div>", unsafe_allow_html=True)


if __name__ == "__main__":
    main()
