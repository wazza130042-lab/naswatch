"""Tenant-scoped, read-only audit log for administrators and auditors."""
from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from ui.rbac import has
from ui.store import get_audit_store


def render(ctx) -> None:
    user = ctx["user"]
    if not has("audit"):
        st.error("Your role does not grant access to audit records.")
        return

    st.markdown(
        '<div class="page-head"><div><div class="page-title">Audit log</div>'
        '<div class="page-sub">Read-only history of security and account actions in this tenant.</div></div></div>',
        unsafe_allow_html=True,
    )
    try:
        audit = get_audit_store()
        org_id = user.get("org_id", "default")
        if user.get("role") == "admin" and org_id == "*":
            org_id = None
        entries = audit.get_entries(org_id=org_id, limit=500)
    except Exception as exc:
        st.error(f"The audit store is unavailable: {exc}")
        return

    st.caption(f"Showing the latest {len(entries)} tenant audit records. Entries are read-only.")
    if not entries:
        st.info("No audit records have been written for this tenant yet.")
        return

    rows = []
    for entry in entries:
        try:
            details = json.loads(entry.get("details") or "{}")
        except (TypeError, json.JSONDecodeError):
            details = {"raw": entry.get("details")}
        rows.append({
            "Time (UTC)": entry.get("timestamp", ""),
            **({"Tenant": entry.get("org_id", "")} if user.get("org_id") == "*" else {}),
            "Actor": entry.get("actor", ""),
            "Action": entry.get("action", ""),
            "Resource": entry.get("resource", ""),
            "Details": json.dumps(details, sort_keys=True, ensure_ascii=False),
            "Source IP": entry.get("ip_address", ""),
        })
    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True, height=560)

    if has("audit"):
        st.markdown('<div class="queue-heading"><h3>Record integrity</h3></div>', unsafe_allow_html=True)
        st.caption("This verifies the selected record’s signed contents. Full cross-tenant chain verification is reserved for a system-wide administrator.")
        entry_ids = [entry["id"] for entry in entries]
        selected_id = st.selectbox("Audit record", entry_ids, label_visibility="collapsed")
        if st.button("Verify selected record signature", key="verify_audit_record"):
            try:
                org_id = user.get("org_id", "default")
                valid = audit.verify_integrity(selected_id, org_id=None if org_id == "*" else org_id)
            except Exception as exc:
                st.error(f"Could not verify the record: {exc}")
            else:
                if valid:
                    st.success("The selected record’s stored signature is valid. This is a record-level check, not a full chain check.")
                else:
                    st.error("The selected record is missing or its stored signature is invalid.")
