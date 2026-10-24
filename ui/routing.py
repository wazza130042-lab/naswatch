"""URL ↔ dashboard-page mapping and deep-link support.

Streamlit serves a single URL, so without help every page looks like ``/`` no
matter which one is selected. We mirror the current page into the ``page`` query
parameter, which makes pages bookmarkable and shareable and lets the browser
back/forward buttons move between them.

The canonical page names live here so the sidebar, the settings menu and the
router all agree on one list.
"""

from __future__ import annotations

import streamlit as st

# Workspace pages, in display order. Keep in step with ``ui/sidebar.py``.
WORKSPACE_PAGES = [
    "Overview",
    "Event search",
    "Incidents",
    "Network topology",
    "Asset inventory",
    "Reports",
]

# Deep-link destinations opened from the incident queue; these are not separate
# sidebar entries, and the Incidents navigation remains the parent destination.
DETAIL_PAGES = ["Incident detail"]

# Account pages reachable from the settings menu (never the sidebar).
ACCOUNT_PAGES = ["Security"]

# Pages that require the ``users`` permission (granted to admins only).
ADMIN_PAGES = ["User management"]
AUDIT_PAGES = ["Audit log"]

PAGE_SLUGS = {
    name: name.lower().replace(" ", "-")
    for name in WORKSPACE_PAGES + DETAIL_PAGES + ACCOUNT_PAGES + ADMIN_PAGES + AUDIT_PAGES
}

PAGE_FOR_SLUG = {slug: name for name, slug in PAGE_SLUGS.items()}


def slug_for(page: str) -> str:
    """Return the URL slug for a page name."""
    return PAGE_SLUGS.get(page) or page.lower().replace(" ", "-")


def _requested_slug() -> str:
    raw = st.query_params.get("page")
    if isinstance(raw, list):
        raw = raw[-1] if raw else ""
    return (raw or "").strip().lower()


def restore_page(allowed_pages: list[str]) -> str | None:
    """Apply ``?page=`` on load, but only for pages the role may open.

    Unknown or unauthorised slugs are ignored (the caller keeps its default and
    :func:`sync_url` rewrites the address bar to match what actually rendered).
    """
    name = PAGE_FOR_SLUG.get(_requested_slug())
    if name and name in allowed_pages:
        st.session_state.current_page = name
        return name
    return None


def sync_url(page: str) -> None:
    """Reflect ``page`` in ``?page=`` without triggering a rerun loop."""
    slug = slug_for(page)
    if st.query_params.get("page") != slug:
        st.query_params["page"] = slug


def goto(page: str) -> None:
    """Select ``page`` and reflect it in the address bar."""
    st.session_state.current_page = page
    sync_url(page)
