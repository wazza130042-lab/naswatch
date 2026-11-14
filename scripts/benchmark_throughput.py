#!/usr/bin/env python3
"""
Throughput benchmark for the NASWatch detection engine.

Measures how many already-parsed signaling events per second ``DetectionEngine.process_event``
can evaluate on THIS machine. Read-only: it imports the project and changes nothing.

What it measures
----------------
* Rule evaluation + inventory lookup, for clean traffic and for traffic with ~10% attacks.
* The inventory lookup is done twice: against an in-memory dict, and against a real
  ``SQLiteRepository`` (in memory), so you can see what a database lookup costs per event.

What it does NOT measure
------------------------
* PCAP/live capture and packet parsing (PyShark/scapy). Parsing is expected to be the slower
  stage, so these numbers are an upper bound for the whole pipeline, not its speed.
* Writing alerts to storage, correlation, SOAR actions, the API or the dashboard.

Usage
-----
    python scripts/benchmark_throughput.py
    python scripts/benchmark_throughput.py --events 200000 --devices 20000 --repeat 5
"""

from __future__ import annotations

import argparse
import logging
import platform
import random
import statistics
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from naswatch.detection.engine import DetectionEngine  # noqa: E402
from naswatch.storage.models import (  # noqa: E402
    Device,
    ParsedSignalingEvent,
    SliceAssignment,
)
from naswatch.storage.sqlite_repo import SQLiteRepository  # noqa: E402

AUTHORIZED_CELLS = ["0x000000010", "0x000000011"]
TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


class InMemoryInventory:
    def __init__(self, devices):
        self._by_imsi = {d.imsi: d for d in devices}
        self._by_imei = {d.imei: d for d in devices}

    def get_by_imsi(self, imsi, org_id=None):
        return self._by_imsi.get(imsi)

    def get_by_imei(self, imei):
        return self._by_imei.get(imei)


def make_device(i: int) -> Device:
    return Device(
        imsi=f"99970{i:010d}",
        imei=f"86012{i:010d}",
        owner_name=f"owner-{i}",
        device_model="5G-CPE",
        allowed_slices=[SliceAssignment(sst=1, sd="000001")],
    )


def clean_events(devices: list[Device], count: int) -> list[ParsedSignalingEvent]:
    """Legitimate registrations, cycling through the inventory so no single IMSI floods."""
    return [
        ParsedSignalingEvent(
            timestamp=TS, procedure_name="RegistrationRequest",
            imsi=(d := devices[i % len(devices)]).imsi, imei=d.imei,
            cell_id="0x000000010", tac=1, requested_sst=1, requested_sd="000001",
            cipher_algo="NEA2", integrity_algo="NIA2",
        )
        for i in range(count)
    ]


def attack_mix(devices: list[Device], count: int, seed: int) -> list[ParsedSignalingEvent]:
    """~10% attacks (unknown IMSI, null cipher, unauthorized cell) mixed into clean traffic."""
    rng = random.Random(seed)
    events = clean_events(devices, count)
    for i in range(0, count, 10):
        e = events[i]
        kind = rng.choice(("unknown", "cipher", "cell"))
        if kind == "unknown":
            e.imsi, e.imei = f"99971{i:010d}", f"86013{i:010d}"
        elif kind == "cipher":
            e.cipher_algo = "NEA0"
        else:
            e.cell_id = "0x0000000FF"
    return events


def run_once(repo, events) -> tuple[float, int]:
    engine = DetectionEngine(repo, authorized_cells=AUTHORIZED_CELLS)
    alerts = 0
    process = engine.process_event
    start = time.perf_counter()
    for e in events:
        alerts += len(process(e))
    return time.perf_counter() - start, alerts


def bench(label, repo, events, repeat, rows):
    runs = [run_once(repo, events) for _ in range(repeat)]
    secs = statistics.median(r[0] for r in runs)
    alerts = runs[0][1]
    rows.append((label, len(events), alerts, secs, len(events) / secs, secs / len(events) * 1e6))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--events", type=int, default=100_000)
    ap.add_argument("--devices", type=int, default=20_000)
    ap.add_argument("--sqlite-events", type=int, default=20_000,
                    help="events for the SQLite-backed run (database lookups are slower)")
    ap.add_argument("--repeat", type=int, default=3, help="runs per row; the median is reported")
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    logging.disable(logging.CRITICAL)  # alert logging is not what is being measured
    devices = [make_device(i) for i in range(args.devices)]
    memory_repo = InMemoryInventory(devices)

    sqlite_devices = devices[: min(5_000, len(devices))]
    sqlite_repo = SQLiteRepository(":memory:")
    for d in sqlite_devices:
        sqlite_repo.add(d)

    rows: list[tuple] = []
    bench("in-memory inventory, clean traffic", memory_repo,
          clean_events(devices, args.events), args.repeat, rows)
    bench("in-memory inventory, ~10% attacks", memory_repo,
          attack_mix(devices, args.events, args.seed), args.repeat, rows)
    bench("SQLite inventory, clean traffic", sqlite_repo,
          clean_events(sqlite_devices, args.sqlite_events), args.repeat, rows)
    bench("SQLite inventory, ~10% attacks", sqlite_repo,
          attack_mix(sqlite_devices, args.sqlite_events, args.seed), args.repeat, rows)

    print("# NASWatch detection-engine throughput\n")
    print(f"- python {platform.python_version()} on {platform.system()} {platform.machine()}")
    print(f"- median of {args.repeat} run(s) per row; events are already parsed\n")
    print("| Scenario | Events | Alerts | Seconds | Events/s | µs/event |")
    print("|---|---:|---:|---:|---:|---:|")
    for label, n, alerts, secs, eps, us in rows:
        print(f"| {label} | {n:,} | {alerts:,} | {secs:.3f} | {eps:,.0f} | {us:.1f} |")
    print("\n> Detection engine only. Packet capture/parsing (PyShark/scapy), alert storage,")
    print("> correlation and the API are NOT included, so this is an upper bound for the pipeline.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
