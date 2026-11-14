#!/usr/bin/env python3
"""
Detection evaluation harness for NASWatch.

Feeds labeled SYNTHETIC scenarios through the real ``DetectionEngine`` and reports, per rule,
true/false positives and negatives with precision, recall and F1. It only *imports* the project
(read-only); it changes no project file and writes nothing unless ``--json`` is given.

How the labels are made
-----------------------
Every scenario is built on purpose, so its correct answer is known by construction (a benign
registration should raise nothing; a registration from an unknown IMSI should raise ROGUE_DEVICE,
and so on). Some "hard benign" cases are included on purpose, i.e. traffic that looks unusual but
is legitimate (an IMEISV with a software-version suffix, a cell ID written in decimal instead of
hex, a slice differentiator written with ``0x``, a device that registers slowly many times).

What it does NOT prove
----------------------
These are author-written scenarios. A perfect score means the rules behave as designed on these
cases, not that they will perform as well on real operator traffic. Treat the numbers as a
regression/consistency measure, and replace the generator with labeled real captures when you
have them.

Usage
-----
    python scripts/evaluate_detection.py                  # default run
    python scripts/evaluate_detection.py --n 200 --seed 7
    python scripts/evaluate_detection.py --json results.json
    python scripts/evaluate_detection.py --wall-clock     # see the note below

Clock handling: a live feed delivers events in real time, but a script replays them instantly. To
make a rate-based rule (the signaling-flood detector) behave as it would on live traffic, the
harness drives the engine's clock from each event's own timestamp. Use ``--wall-clock`` to turn
that off and see what a rule that reads the real clock does when events are replayed at full speed.
"""

from __future__ import annotations

import argparse
import inspect
import json
import logging
import random
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import naswatch.detection.engine as engine_module  # noqa: E402
from naswatch.detection.engine import DetectionEngine  # noqa: E402
from naswatch.storage.models import (  # noqa: E402
    AlertRuleType,
    Device,
    DeviceStatus,
    ParsedSignalingEvent,
    SliceAssignment,
)

R = AlertRuleType
RULES = [
    R.ROGUE_DEVICE,
    R.IDENTITY_SPOOFING,
    R.SLICE_INTRUSION,
    R.CIPHER_DOWNGRADE,
    R.FALSE_BASE_STATION,
    R.SIGNALING_FLOOD,
]

AUTHORIZED_CELLS = ["0x000000010", "0x000000011"]
GOOD_CELL = "0x000000010"
GOOD_CELL_DECIMAL = "16"  # same cell as 0x10, written differently
BAD_CELL = "0x0000000FF"
ALLOWED_SLICE = (1, "000001")
FOREIGN_SLICE = (2, "000002")
BASE_TIME = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


# ----------------------------------------------------------------------------- inventory
class InMemoryInventory:
    """Duck-typed stand-in for the device repository (the engine only calls these two)."""

    def __init__(self, devices: list[Device]):
        self._by_imsi = {d.imsi: d for d in devices}
        self._by_imei = {d.imei: d for d in devices}

    def get_by_imsi(self, imsi: str, org_id: str | None = None) -> Device | None:
        return self._by_imsi.get(imsi)

    def get_by_imei(self, imei: str) -> Device | None:
        return self._by_imei.get(imei)


def make_device(prefix: str, i: int, status: DeviceStatus = DeviceStatus.ACTIVE) -> Device:
    return Device(
        imsi=f"{prefix}{i:010d}",  # 15 digits
        imei=f"86012{i:010d}",  # 15 digits
        owner_name=f"owner-{prefix}-{i}",
        device_model="5G-CPE",
        status=status,
        allowed_slices=[SliceAssignment(sst=ALLOWED_SLICE[0], sd=ALLOWED_SLICE[1])],
    )


# ----------------------------------------------------------------------------- scenarios
@dataclass
class Item:
    category: str
    events: list[ParsedSignalingEvent]
    expected: frozenset


def ev(ts: datetime, device: Device | None = None, **over) -> ParsedSignalingEvent:
    base = dict(
        timestamp=ts,
        procedure_name="RegistrationRequest",
        imsi=device.imsi if device else None,
        imei=device.imei if device else None,
        cell_id=GOOD_CELL,
        tac=1,
        requested_sst=ALLOWED_SLICE[0],
        requested_sd=ALLOWED_SLICE[1],
        cipher_algo="NEA2",
        integrity_algo="NIA2",
    )
    base.update(over)
    return ParsedSignalingEvent(**base)


def build_scenarios(n: int, seed: int):
    """Return (inventory, items). Fully deterministic for a given (n, seed)."""
    rng = random.Random(seed)
    pool = max(n * 2, 50)
    active = [make_device("99970", i) for i in range(pool)]
    revoked = [make_device("99972", i, DeviceStatus.REVOKED) for i in range(pool)]
    suspended = [make_device("99973", i, DeviceStatus.SUSPENDED) for i in range(pool)]
    inventory = InMemoryInventory(active + revoked + suspended)

    clock = [0]

    def next_ts() -> datetime:
        clock[0] += 1
        return BASE_TIME + timedelta(seconds=clock[0] * 60)

    def unknown(i: int) -> Device:
        return make_device("99971", i)  # never added to the inventory

    items: list[Item] = []
    seq_n = max(5, n // 5)

    def add(category, events, expected):
        items.append(Item(category, events, frozenset(expected)))

    for i in range(n):
        d = rng.choice(active)
        # ---- benign
        add("benign: normal registration", [ev(next_ts(), d)], [])
        add("benign: IMEISV suffix on same IMEI",
            [ev(next_ts(), d, imei=d.imei[:14] + "01")], [])
        add("benign: authorized cell written in decimal",
            [ev(next_ts(), d, cell_id=GOOD_CELL_DECIMAL)], [])
        add("benign: slice SD written with 0x prefix",
            [ev(next_ts(), d, requested_sd="0x" + ALLOWED_SLICE[1])], [])
        # ---- single-rule attacks
        u = unknown(i)
        add("attack: unknown IMSI", [ev(next_ts(), u)], [R.ROGUE_DEVICE])
        add("attack: revoked device", [ev(next_ts(), rng.choice(revoked))], [R.ROGUE_DEVICE])
        add("attack: suspended device", [ev(next_ts(), rng.choice(suspended))], [R.ROGUE_DEVICE])
        add("attack: IMEI does not match SIM",
            [ev(next_ts(), d, imei=f"86999{i:010d}")], [R.IDENTITY_SPOOFING])
        add("attack: unauthorized slice",
            [ev(next_ts(), d, requested_sst=FOREIGN_SLICE[0], requested_sd=FOREIGN_SLICE[1])],
            [R.SLICE_INTRUSION])
        add("attack: null ciphering (NEA0)", [ev(next_ts(), d, cipher_algo="NEA0")],
            [R.CIPHER_DOWNGRADE])
        add("attack: null integrity (NIA0)", [ev(next_ts(), d, integrity_algo="NIA0")],
            [R.CIPHER_DOWNGRADE])
        add("attack: unauthorized cell", [ev(next_ts(), d, cell_id=BAD_CELL)],
            [R.FALSE_BASE_STATION])
        # ---- combined attacks (several rules at once)
        add("combo: unknown IMSI + null cipher", [ev(next_ts(), u, cipher_algo="NEA0")],
            [R.ROGUE_DEVICE, R.CIPHER_DOWNGRADE])
        add("combo: unknown IMSI + unauthorized cell", [ev(next_ts(), u, cell_id=BAD_CELL)],
            [R.ROGUE_DEVICE, R.FALSE_BASE_STATION])

    # ---- sequences (rate-based rule)
    for _ in range(seq_n):
        d = rng.choice(active)
        t0 = next_ts()
        # 40 registrations within 2 s: a storm
        add("attack: registration storm (40 in 2 s)",
            [ev(t0 + timedelta(milliseconds=50 * k), d) for k in range(40)], [R.SIGNALING_FLOOD])
        d2 = rng.choice(active)
        t1 = next_ts()
        # 30 registrations, one every 10 s: slow, legitimate
        add("benign: slow repeated registrations (30, 1 per 10 s)",
            [ev(t1 + timedelta(seconds=10 * k), d2) for k in range(30)], [])
    return inventory, items


# ----------------------------------------------------------------------------- evaluation
class _EventClock:
    """Stand-in for the `time` module: returns whatever the harness sets."""

    def __init__(self):
        self.now = 0.0

    def time(self) -> float:
        return self.now


def evaluate(inventory, items, use_event_clock: bool):
    clock = _EventClock()
    had_attr = hasattr(engine_module, "time")
    original_time = getattr(engine_module, "time", None)
    if use_event_clock:
        engine_module.time = clock

    counts = {r: dict(tp=0, fp=0, fn=0, tn=0) for r in RULES}
    by_category = defaultdict(lambda: dict(total=0, missed=0, extra=0))
    events_processed = 0
    try:
        for item in items:
            engine = DetectionEngine(inventory, authorized_cells=AUTHORIZED_CELLS)
            predicted = set()
            for event in item.events:
                clock.now = event.timestamp.timestamp()
                predicted.update(a.rule_type for a in engine.process_event(event))
                events_processed += 1
            cat = by_category[item.category]
            cat["total"] += 1
            cat["missed"] += bool(item.expected - predicted)
            cat["extra"] += bool(predicted - item.expected)
            for r in RULES:
                actual, pred = r in item.expected, r in predicted
                key = ("tp" if pred else "fn") if actual else ("fp" if pred else "tn")
                counts[r][key] += 1
    finally:
        if use_event_clock:
            if had_attr:
                engine_module.time = original_time
            else:
                del engine_module.time
    return counts, by_category, events_processed


def ratio(a: int, b: int) -> float | None:
    return a / b if b else None


def fmt(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.3f}"


def f1(p, r):
    return None if p is None or r is None or (p + r) == 0 else 2 * p * r / (p + r)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--n", type=int, default=50, help="scenarios per single-event category")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--wall-clock", action="store_true",
                    help="do not drive the engine clock from event timestamps")
    ap.add_argument("--json", metavar="PATH", help="also write the results as JSON")
    args = ap.parse_args()

    logging.disable(logging.CRITICAL)  # the engine logs every alert; keep the report readable
    inventory, items = build_scenarios(args.n, args.seed)
    counts, by_category, n_events = evaluate(inventory, items, not args.wall_clock)

    flood_src = inspect.getsource(DetectionEngine._check_signaling_flood)
    print("# NASWatch detection evaluation (synthetic labeled scenarios)\n")
    print(f"- scenarios: {len(items)}  |  events: {n_events}  |  seed: {args.seed}")
    print(f"- clock: {'real wall clock' if args.wall_clock else 'driven by event timestamps'}")
    print(f"- flood rule source references time.time(): {'yes' if 'time.time()' in flood_src else 'no'}\n")

    print("| Rule | TP | FP | FN | TN | Precision | Recall | F1 |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|")
    total = dict(tp=0, fp=0, fn=0, tn=0)
    results = {}
    for r in RULES:
        c = counts[r]
        for k in total:
            total[k] += c[k]
        p, rec = ratio(c["tp"], c["tp"] + c["fp"]), ratio(c["tp"], c["tp"] + c["fn"])
        results[r.value] = dict(**c, precision=p, recall=rec, f1=f1(p, rec))
        print(f"| {r.value} | {c['tp']} | {c['fp']} | {c['fn']} | {c['tn']} | {fmt(p)} | {fmt(rec)} | {fmt(f1(p, rec))} |")
    p, rec = ratio(total["tp"], total["tp"] + total["fp"]), ratio(total["tp"], total["tp"] + total["fn"])
    results["OVERALL (micro)"] = dict(**total, precision=p, recall=rec, f1=f1(p, rec))
    print(f"| **Overall (micro)** | {total['tp']} | {total['fp']} | {total['fn']} | {total['tn']} | {fmt(p)} | {fmt(rec)} | {fmt(f1(p, rec))} |")

    bad = {k: v for k, v in by_category.items() if v["missed"] or v["extra"]}
    print("\n## Scenario categories with errors\n")
    if not bad:
        print("None: every scenario produced exactly the expected set of alerts.")
    else:
        print("| Category | Scenarios | Missed an expected alert | Raised an unexpected alert |")
        print("|---|---:|---:|---:|")
        for k, v in sorted(bad.items()):
            print(f"| {k} | {v['total']} | {v['missed']} | {v['extra']} |")

    print("\n> Synthetic, author-written scenarios: this checks that the rules behave as designed,")
    print("> not how they perform on real operator traffic. See docs/EVALUATION.md.")

    if args.json:
        Path(args.json).write_text(json.dumps(
            dict(seed=args.seed, scenarios=len(items), events=n_events, rules=results,
                 categories_with_errors=bad), indent=2), encoding="utf-8")
        print(f"\nWrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
