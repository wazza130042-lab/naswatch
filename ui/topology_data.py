"""Build a Network-topology graph from live alerts, the device inventory, and config.

The topology page used to be a hand-drawn SVG mockup: two fixed gNBs (0x10/0x20),
one AMF and three fixed slices, with colours toggled by the presence of any
rogue / slice-intrusion alert. This module replaces the mockup with a graph
derived from the data the dashboard already holds:

  * radio cells  — the authorized cells from ``config/settings.yaml``
    (``network.authorized_cells``) plus any Cell ID observed in alerts that is
    not in that list (i.e. a rogue gNB).
  * slices       - the provisioned S-NSSAIs (``network_slices.authorized_slices``)
    plus any slice requested in an alert, with the number of inventory devices
    authorised for each and the number of slice-intrusion detections.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

DEFAULT_SETTINGS = "config/settings.yaml"


@dataclass
class CellNode:
    """A radio cell (gNB) seen on the N2 interface, or provisioned in config."""

    key: str  # normalised identity used for matching
    label: str  # short human label, e.g. "0x10"
    authorized: bool
    name: str = ""  # site name from the uploaded structure
    tac: str = ""   # tracking area code, when supplied
    gnb: str = ""  # parent gNB / site grouping, when supplied
    alerts: int = 0
    critical: int = 0
    last_seen: datetime | None = None


@dataclass
class SliceNode:
    """An S-NSSAI slice and its observed usage."""
    sst: int
    sd: str | None
    name: str
    slice_id: str
    devices: int = 0
    intrusions: int = 0


@dataclass
class TopologyGraph:
    cells: list[CellNode] = field(default_factory=list)        # authorized cells
    rogue_cells: list[CellNode] = field(default_factory=list)  # unauthorized cells
    slices: list[SliceNode] = field(default_factory=list)
    amf_count: int = 1
    amf: list[dict] = field(default_factory=list)              # uploaded AMF definitions
    organization: str = ""                                     # uploaded org name
    source: str = "config"                                     # "uploaded" | "config"

    @property
    def cell_count(self) -> int:
        return len(self.cells) + len(self.rogue_cells)


def normalize_cell(cell_id: str | None) -> str | None:
    """Canonicalise a Cell ID so 0x000000010 == 0x0000000000000010.

    Mirrors naswatch.detection.rules.detect_false_base_station so the UI and the
    detector agree on which cells are authorized.
    """
    if not cell_id:
        return None
    try:
        return str(int(str(cell_id), 0))
    except (ValueError, TypeError):
        return str(cell_id).strip().upper()


def cell_label(normalized: str) -> str:
    """Human display label for a normalised cell key (decimal -> 0x hex)."""
    try:
        return f"0x{int(normalized):X}"
    except (ValueError, TypeError):
        return normalized


def load_config(path: str | None = None) -> dict:
    """Load config/settings.yaml (override with $NASWATCH_SETTINGS). Never raises."""
    import os as _os

    cfg_path = path or _os.environ.get("NASWATCH_SETTINGS", "config/settings.yaml")
    try:
        import yaml
        from pathlib import Path as _Path

        p = _Path(cfg_path)
        if p.exists():
            return yaml.safe_load(p.read_text()) or {}
    except Exception:  # noqa: BLE001 - config is optional at runtime
        pass
    return {}


def _authorized_cells(cfg: dict) -> dict[str, str]:
    """Map normalised cell key -> original configured cell id."""
    raw = (cfg.get("network", {}) or {}).get("authorized_cells", []) or []
    out: dict[str, str] = {}
    for c in raw:
        key = normalize_cell(c)
        if key:
            out.setdefault(key, str(c))
    return out


def _authorized_slices(cfg: dict) -> list[dict]:
    return (cfg.get("network_slices", {}) or {}).get("authorized_slices", []) or []


def resolve_inventory() -> tuple[dict | None, dict, str]:
    """Return ``(structure, cfg, source)``.

    The organization's uploaded structure wins; when none is present we fall back
    to ``config/settings.yaml`` so a fresh install still renders a topology.
    """
    try:
        from naswatch.network_inventory import load as _load_structure

        structure = _load_structure()
    except Exception:  # noqa: BLE001 - the inventory is optional at runtime
        structure = None
    if structure:
        return structure, {}, "uploaded"
    return None, load_config(), "config"


def _cell_defs(structure: dict | None, cfg: dict) -> list[dict]:
    """Cell definitions, from the uploaded structure or the fallback config."""
    if structure:
        return [dict(c) for c in structure.get("cells", [])]
    return [{"id": raw} for raw in _authorized_cells(cfg).values()]


def _slice_defs(structure: dict | None, cfg: dict) -> list[dict]:
    """Slice definitions, from the uploaded structure or the fallback config."""
    if structure:
        return [dict(s) for s in structure.get("slices", [])]
    return [dict(s) for s in _authorized_slices(cfg)]


def build_topology(
    alerts,
    devices,
    cfg: dict | None = None,
    structure: dict | None = None,
) -> TopologyGraph:
    """Derive the topology graph from the alert scope and the site's network structure.

    Pass ``structure`` (an uploaded network inventory) to drive the graph from the
    organization's real layout; otherwise ``cfg`` (``config/settings.yaml``) is used.
    Called with neither, the uploaded structure is preferred automatically.
    """
    if cfg is None and structure is None:
        structure, cfg, source = resolve_inventory()
    else:
        cfg = cfg or {}
        source = "uploaded" if structure else "config"

    auth_cells: dict[str, dict] = {}
    for d in _cell_defs(structure, cfg):
        key = normalize_cell(d.get("id"))
        if key:
            auth_cells.setdefault(key, d)

    # ── observed cells from alerts ────────────────────────────────────────────
    observed: dict[str, CellNode] = {}
    for a in alerts:
        key = normalize_cell(getattr(a, "cell_id", None))
        if not key:
            continue
        node = observed.get(key)
        if node is None:
            node = CellNode(key=key, label=cell_label(key), authorized=key in auth_cells)
            observed[key] = node
        node.alerts += 1
        if getattr(a.severity, "value", None) == "CRITICAL":
            node.critical += 1
        ts = getattr(a, "timestamp", None)
        if ts is not None and (node.last_seen is None or ts > node.last_seen):
            node.last_seen = ts

    # Authorized cells keep inventory order (even with no traffic observed);
    # rogue cells are listed most-active first.
    cells: list[CellNode] = []
    for key, d in auth_cells.items():
        node = observed.get(key)
        if node is None:
            node = CellNode(key=key, label=cell_label(key), authorized=True)
        node.authorized = True
        node.label = cell_label(key)
        node.name = str(d.get("name") or "")
        node.tac = str(d.get("tac") or "")
        node.gnb = str(d.get("gnb") or "")
        cells.append(node)
    rogue = sorted(
        (n for n in observed.values() if n.key not in auth_cells),
        key=lambda n: (n.alerts, n.critical),
        reverse=True,
    )

    # ── slices ────────────────────────────────────────────────────────────────
    slices: list[SliceNode] = []
    seen: set[str] = set()
    for s in _slice_defs(structure, cfg):
        try:
            sst = int(s.get("sst"))
        except (TypeError, ValueError):
            continue
        sd = s.get("sd")
        sid = f"{sst}:{sd}" if sd else f"{sst}"
        intrusions = sum(
            1 for a in alerts
            if getattr(a, "target_slice", None) == sid
            and getattr(a.rule_type, "value", None) == "SLICE_INTRUSION"
        )
        dev = sum(1 for d in devices if _device_allows(d, sst, sd))
        slices.append(SliceNode(sst=sst, sd=sd, name=s.get("name") or "", slice_id=sid,
                               devices=dev, intrusions=intrusions))
        seen.add(sid)

    # Slice IDs seen in alerts but not provisioned (e.g. a private/unknown slice).
    for a in alerts:
        sid = getattr(a, "target_slice", None)
        if not sid or sid in seen:
            continue
        seen.add(sid)
        sst = 0
        if ":" in str(sid):
            try:
                sst = int(str(sid).split(":")[0])
            except ValueError:
                sst = 0
        intrusions = sum(
            1 for x in alerts
            if getattr(x, "target_slice", None) == sid
            and getattr(x.rule_type, "value", None) == "SLICE_INTRUSION"
        )
        slices.append(SliceNode(sst=sst, sd=None, name="observed", slice_id=str(sid),
                                devices=0, intrusions=intrusions))

    amf_defs = [dict(a) for a in (structure or {}).get("amf", [])]
    organization = str((structure or {}).get("organization", "") or "")

    return TopologyGraph(
        cells=cells,
        rogue_cells=rogue,
        slices=slices,
        amf_count=len(amf_defs) or 1,
        amf=amf_defs,
        organization=organization,
        source=source,
    )


def _device_allows(device, sst: int, sd: str | None) -> bool:
    try:
        return bool(device.is_slice_authorized(sst, sd))
    except AttributeError:
        return False
