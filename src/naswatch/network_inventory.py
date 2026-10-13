"""Per-site 5G network structure — the *organization's own* topology inventory.

A NASWatch deployment serves **one organization**. That organization supplies
its real radio / core / slice layout as an uploaded file. The file is stored
under ``data/`` (the persistent volume), so it survives container rebuilds and
version updates — the operator configures their network once and every later
release keeps using it.

Accepted upload formats
-----------------------
1. The native structure (YAML or JSON)::

       organization: Acme Telecom
       amf:
         - {name: AMF-01, id: "0x00B4", ip: "10.10.0.11"}
       cells:
         - {id: "0x000000010", name: Site-A, tac: "0x0001", gnb: gNB-01}
         - {id: "0x000000011", name: Site-B}
       slices:
         - {sst: 1, sd: "000001", name: eMBB-Public}
         - {sst: 2, sd: "000002", name: uRLLC-Critical}

2. The existing ``config/settings.yaml`` shape
   (``network.authorized_cells`` + ``network_slices.authorized_slices``), so a
   site can upload the settings file it already has.

This module is dependency-light (only ``yaml``) on purpose: the Streamlit UI and
the detection engine both import it, and it must never pull in heavy packages.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

DEFAULT_PATH = "data/network_structure.yaml"

TEMPLATE = """\
# NASWatch — Network structure
# Upload this on the  Network topology  page. It describes YOUR network:
# the radio cells (gNB), the core AMF(s) and the provisioned network slices.
# Cells that are NOT listed here appear on the topology as ROGUE.
organization: "Example Telecom"

# 5G core — one entry per AMF
amf:
  - name: "AMF-01"
    id: "0x00B4"
    ip: "10.10.0.11"

# Radio access — every authorized gNB / radio cell
cells:
  - id: "0x000000010"      # Cell Identity (hex or decimal, matching N2 NGAP)
    name: "Central-Site-A"
    tac: "0x0001"
    gnb: "gNB-01"
  - {id: "0x000000011", name: "North-Site-B", tac: "0x0002"}
  - {id: "0x000000012", name: "South-Group1", tac: "0x0003"}

# Network slices you have provisioned (S-NSSAI: sst + sd)
slices:
  - {sst: 1, sd: "000001", name: "eMBB-Public",   description: "Consumer mobile broadband"}
  - {sst: 2, sd: "000002", name: "uRLLC-Critical", description: "Emergency services"}
  - {sst: 3, sd: "000003", name: "mIoT-Sensors",   description: "Massive IoT"}
"""


def storage_path(path: str | Path | None = None) -> Path:
    """Location of the uploaded structure (override with $NASWATCH_NETWORK_FILE)."""
    if path is not None:
        return Path(path)
    return Path(os.environ.get("NASWATCH_NETWORK_FILE", DEFAULT_PATH))


def template() -> str:
    return TEMPLATE


def normalize_cell(cell_id: Any) -> str | None:
    """Canonicalise a Cell ID so 0x000000010 == 0x0000000000000010 == 16.

    Mirrors ``naswatch.detection.rules.normalize_cell`` so the UI, the inventory
    and the detector always agree on which cells are authorized.
    """
    if cell_id is None:
        return None
    text = str(cell_id).strip()
    if not text:
        return None
    try:
        return str(int(text, 0))
    except (ValueError, TypeError):
        return text.upper()


def _normalize_sd(sd: Any) -> str | None:
    """Best-effort S-NSSAI slice-differentiator normalisation ("0x02" -> "000002")."""
    if sd is None:
        return None
    text = str(sd).strip()
    if not text:
        return None
    text = text.replace("0x", "").replace("0X", "").replace(":", "").upper()
    if len(text) < 6:
        text = text.zfill(6)
    return text


def parse(text: str, filename: str = "") -> dict:
    """Parse uploaded YAML/JSON text into a mapping.

    Raises ``ValueError`` with a human-readable reason when the payload cannot be
    parsed or is not a mapping.
    """
    import json

    import yaml

    suffix = Path(filename).suffix.lower()
    if suffix == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"not valid JSON: {exc}") from exc
    else:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ValueError(f"not valid YAML/JSON: {exc}") from exc

    if data is None:
        raise ValueError("file is empty")
    if not isinstance(data, dict):
        raise ValueError("top level must be a mapping (e.g. 'cells:' / 'slices:')")
    return data


def _cell_entry(item: Any) -> dict | None:
    if isinstance(item, str):
        raw_id: Any = item
        name = ""
        tac = ""
        gnb = ""
    elif isinstance(item, dict):
        raw_id = (
            item.get("id")
            or item.get("cell_id")
            or item.get("cellId")
            or item.get("cell")
            or item.get("gnb_cell_id")
        )
        name = item.get("name") or item.get("label") or ""
        tac = item.get("tac") or item.get("tracking_area") or ""
        gnb = item.get("gnb") or item.get("gnb_name") or item.get("site") or ""
    else:
        return None

    key = normalize_cell(raw_id)
    if key is None:
        return None
    return {
        "id": str(raw_id).strip(),
        "key": key,
        "name": str(name),
        "tac": str(tac),
        "gnb": str(gnb),
    }


def _slice_entry(item: Any) -> dict | None:
    if not isinstance(item, dict):
        return None
    sst_raw = item.get("sst")
    if sst_raw is None:
        sst_raw = item.get("slice") or item.get("type") or item.get("sst_id")
    try:
        sst = int(sst_raw)
    except (TypeError, ValueError):
        return None
    return {
        "sst": sst,
        "sd": _normalize_sd(item.get("sd") or item.get("differentiator")),
        "name": str(item.get("name") or ""),
        "description": str(item.get("description") or ""),
    }


def _amf_entry(item: Any) -> dict | None:
    if isinstance(item, str):
        return {"name": item, "id": "", "ip": ""}
    if not isinstance(item, dict):
        return None
    return {
        "name": str(item.get("name") or item.get("id") or "AMF"),
        "id": str(item.get("id") or ""),
        "ip": str(item.get("ip") or item.get("address") or ""),
    }


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, dict):
        return list(value.values())
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def normalize(raw: dict) -> dict:
    """Turn any accepted payload into the canonical structure mapping.

    Returns ``{"organization", "amf", "cells", "slices"}`` with cells de-duplicated
    by normalised key.
    """
    network = raw.get("network") if isinstance(raw.get("network"), dict) else {}
    network_slices = raw.get("network_slices") if isinstance(raw.get("network_slices"), dict) else {}

    organization = (
        raw.get("organization")
        or raw.get("org")
        or raw.get("organization_name")
        or raw.get("operator")
        or ""
    )

    amf_raw = raw.get("amf") or raw.get("amfs") or network.get("amf") or []
    amfs = [a for a in (_amf_entry(x) for x in _as_list(amf_raw)) if a]

    cells_raw = (
        raw.get("cells")
        or raw.get("gnbs")
        or raw.get("authorized_cells")
        or network.get("authorized_cells")
        or []
    )
    cells: list[dict] = []
    seen: set[str] = set()
    for entry in (_cell_entry(x) for x in _as_list(cells_raw)):
        if entry and entry["key"] not in seen:
            seen.add(entry["key"])
            cells.append(entry)

    slices_raw = (
        raw.get("slices")
        or raw.get("authorized_slices")
        or network_slices.get("authorized_slices")
        or []
    )
    slices = []
    seen_slices: set[str] = set()
    for entry in (_slice_entry(x) for x in _as_list(slices_raw)):
        if not entry:
            continue
        sid = f"{entry['sst']}:{entry['sd']}" if entry["sd"] else f"{entry['sst']}"
        if sid in seen_slices:
            continue
        seen_slices.add(sid)
        slices.append(entry)

    return {
        "organization": str(organization),
        "amf": amfs,
        "cells": cells,
        "slices": slices,
    }


def validate(structure: dict) -> list[str]:
    """Return a list of human-readable problems (empty list means valid)."""
    errors: list[str] = []

    cells = structure.get("cells") or []
    slices = structure.get("slices") or []
    amfs = structure.get("amf") or []

    if not cells and not slices and not amfs:
        errors.append("Nothing to apply — add 'cells' and/or 'slices' (and optionally 'amf').")
    for cell in cells:
        if not normalize_cell(cell.get("id")):
            errors.append(f"Cell is missing a valid id: {cell!r}")
    for sl in slices:
        if not isinstance(sl.get("sst"), int):
            errors.append(f"Slice is missing a valid integer 'sst': {sl!r}")
    return errors


def load(path: str | Path | None = None) -> dict | None:
    """Load the uploaded structure, or ``None`` when none is configured/invalid."""
    import yaml

    p = storage_path(path)
    try:
        if not p.exists():
            return None
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            return None
        structure = normalize(raw)
        if not structure["cells"] and not structure["slices"] and not structure["amf"]:
            return None
        return structure
    except Exception:  # noqa: BLE001 - a broken file must never crash the app
        return None


def save(structure: dict, path: str | Path | None = None) -> Path:
    """Persist the canonical structure (atomic write)."""
    import yaml

    p = storage_path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = normalize(structure)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(
        yaml.safe_dump(payload, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    tmp.replace(p)
    return p


def clear(path: str | Path | None = None) -> bool:
    """Delete the uploaded structure. Returns True when a file was removed."""
    p = storage_path(path)
    try:
        p.unlink()
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return False


def authorized_cells(structure: dict | None = None) -> list[str] | None:
    """The raw authorized Cell IDs, or None when no structure is uploaded."""
    structure = structure if structure is not None else load()
    if not structure:
        return None
    ids = [c["id"] for c in structure.get("cells", []) if c.get("id")]
    return ids or None
