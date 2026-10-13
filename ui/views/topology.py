"""NASWatch UI — Network topology page.

The topology is drawn from the organization's **uploaded network structure**
(stored on the persistent data volume, so it survives version updates). When no
structure has been uploaded yet, the page falls back to ``config/settings.yaml``.
Administrators can upload, preview, replace or remove the structure here.
"""
from __future__ import annotations

from html import escape

import streamlit as st

from naswatch import network_inventory
from ui.components import (
    render_cell_table, render_slice_matrix, render_topology_graph,
)
from ui.rbac import has
from ui.topology_data import build_topology, resolve_inventory


def _source_label(graph) -> str:
    if graph.source == "uploaded":
        org = escape(graph.organization) if graph.organization else "Uploaded structure"
        return f"<strong>{org}</strong> &middot; uploaded network structure"
    return "Default <code>config/settings.yaml</code> &middot; upload your organization's structure to replace it"


def _upload_panel(graph) -> None:
    with st.expander("⇪ Upload network structure", expanded=(graph.source != "uploaded")):
        st.caption(
            "Upload your organization's real 5G layout — radio cells (gNB), AMF and network "
            "slices. It is stored on the persistent data volume, so it survives version "
            "updates, and it drives both this topology and the false-base-station detector. "
            "Cells that are not in the file appear here as ROGUE."
        )

        col_dl, col_rm = st.columns(2)
        with col_dl:
            st.download_button(
                "Download template",
                data=network_inventory.template(),
                file_name="network_structure.yaml",
                mime="text/yaml",
                key="dl_net_tmpl",
                use_container_width=True,
            )
        with col_rm:
            if graph.source == "uploaded" and st.button(
                "Remove uploaded structure", key="rm_net", use_container_width=True
            ):
                network_inventory.clear()
                st.toast("Uploaded network structure removed")
                st.rerun()

        uploaded = st.file_uploader(
            "Network structure (YAML or JSON)",
            type=["yaml", "yml", "json", "txt"],
            key="net_structure_upload",
        )
        if uploaded is None:
            return

        text = uploaded.getvalue().decode("utf-8", "replace")
        try:
            structure = network_inventory.normalize(network_inventory.parse(text, uploaded.name))
            errors = network_inventory.validate(structure)
        except ValueError as exc:
            st.error(f"Could not read {uploaded.name}: {exc}")
            return

        org = structure.get("organization") or "(no organization name)"
        st.markdown(
            f"**{escape(str(org))}** — {len(structure.get('cells', []))} cells &middot; "
            f"{len(structure.get('amf', []))} AMF &middot; {len(structure.get('slices', []))} slices"
        )
        for err in errors:
            st.error(err)
        if errors:
            return

        if st.button("Save structure", type="primary", key="save_net"):
            network_inventory.save(structure)
            st.toast("Network structure saved")
            st.rerun()


def render(ctx):
    all_alerts = ctx["all_alerts"]
    devices = ctx["devices"]

    # Prefer the organization's uploaded structure; fall back to config/settings.yaml.
    structure, cfg, _source = resolve_inventory()
    graph = build_topology(all_alerts, devices, cfg, structure)

    rogue_stat = (
        f'<div class="pstat"><div class="pstat-val" style="color:#FF466B;">{len(graph.rogue_cells)}</div>'
        '<div class="pstat-label">ROGUE</div></div>'
        if graph.rogue_cells
        else ""
    )
    st.markdown(
        '<div class="page-head">'
        "<div>"
        '<div class="page-title">Network topology</div>'
        f'<div class="page-sub">Radio access, AMF and slice relationships &mdash; {_source_label(graph)}.</div>'
        "</div>"
        '<div class="page-stats">'
        f'<div class="pstat"><div class="pstat-val">{len(graph.cells)}</div><div class="pstat-label">gNBs</div></div>'
        f'<div class="pstat"><div class="pstat-val">{graph.amf_count}</div><div class="pstat-label">AMF</div></div>'
        f'<div class="pstat"><div class="pstat-val">{len(graph.slices)}</div><div class="pstat-label">SLICES</div></div>'
        f"{rogue_stat}"
        "</div>"
        "</div>",
        unsafe_allow_html=True,
    )

    if has("provision"):
        _upload_panel(graph)

    render_topology_graph(graph)

    st.markdown(
        '<div class="queue-heading"><h3>Radio cells</h3>'
        f'<span>{len(graph.cells)} authorized &middot; {len(graph.rogue_cells)} rogue</span></div>',
        unsafe_allow_html=True,
    )
    render_cell_table(graph)

    st.markdown(
        '<div class="queue-heading"><h3>Network slices</h3>'
        f'<span>{len(graph.slices)} provisioned / observed</span></div>',
        unsafe_allow_html=True,
    )
    render_slice_matrix(graph)
