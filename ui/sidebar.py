"""SOC sidebar: navigation, ingestion, and incident filters.

Operator account controls (identity, User management, Sign out) live in the
top-corner settings menu owned by ``ui/app.py``.
"""
from __future__ import annotations

import streamlit as st

from ui.rbac import has
from ui.routing import ACCOUNT_PAGES, ADMIN_PAGES, AUDIT_PAGES, DETAIL_PAGES, WORKSPACE_PAGES, goto


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
        section_label = "AUDIT & COMPLIANCE" if has("audit") and not has("view") else "SOC WORKSPACE"
        st.markdown(f'<div class="nav-section-label">{section_label}</div>', unsafe_allow_html=True)
        if has("evidence"):
            pages = list(WORKSPACE_PAGES)
        elif has("view"):
            pages = ["Overview", "Incidents"]
        else:
            pages = []
        admin_pages = list(ADMIN_PAGES) if has("users") else []
        audit_pages = list(AUDIT_PAGES) if has("audit") else []
        # Account pages are reachable from the top-corner settings menu, not the
        # sidebar, so they are valid destinations that must not be reset.
        account_pages = list(ACCOUNT_PAGES)
        allowed_detail_pages = list(DETAIL_PAGES) if has("view") else []
        if st.session_state.current_page not in pages + allowed_detail_pages + admin_pages + audit_pages + account_pages:
            st.session_state.current_page = "Overview" if pages else ("Audit log" if audit_pages else "Security")
        for nav_index, nav_page in enumerate(pages, start=1):
            if st.button(
                nav_page,
                use_container_width=True,
                type="primary" if (
                    nav_page == st.session_state.current_page
                    or (nav_page == "Incidents" and st.session_state.current_page == "Incident detail")
                ) else "secondary",
                key=f"soc_nav_{nav_index}",
            ):
                goto(nav_page)
                st.rerun()
        page = st.session_state.current_page

        selected_severity, selected_rule = "ALL", "ALL"
    return st.session_state.current_page, selected_severity, selected_rule
