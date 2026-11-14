# Evaluating and benchmarking detection

Two read-only scripts measure the detection engine. They import the project, change nothing in
it, and need no capture files, network, database server or extra packages.

## 1. Detection quality: `scripts/evaluate_detection.py`

```bash
python scripts/evaluate_detection.py                  # default scenarios
python scripts/evaluate_detection.py --n 200 --seed 7 # more scenarios, different random draw
python scripts/evaluate_detection.py --json results.json
```

It builds labeled **synthetic** scenarios, runs each through `DetectionEngine`, and compares the
alerts raised with the alerts that *should* be raised. The report has one row per rule:

| Column | Meaning |
|---|---|
| TP | the rule fired and should have |
| FP | the rule fired but should not have (a false alarm) |
| FN | the rule did not fire but should have (a miss) |
| TN | the rule stayed quiet and should have |
| Precision | TP / (TP + FP): of the alerts raised, how many were right |
| Recall | TP / (TP + FN): of the attacks present, how many were caught |

The second table lists only scenario categories where something went wrong, so a failure points at
a specific kind of traffic.

**Scenarios covered**

- Benign: normal registrations, an IMEISV with a software suffix, an authorized cell written in
  decimal instead of hex, a slice differentiator written with `0x`, and a device that registers
  many times slowly.
- Attacks: unknown IMSI, revoked and suspended devices, IMEI that does not match the SIM,
  unauthorized slice, null ciphering, null integrity, unauthorized cell, and a registration storm.
- Combined attacks that should raise two rules at once.

**The clock option.** A live feed arrives in real time but a script replays instantly. By default
the harness sets the engine's clock from each event's timestamp so the signaling-flood rule behaves
as it would on live traffic. `--wall-clock` turns that off, which shows how a rule that reads the
real clock behaves when events are replayed at full speed.

**What the numbers mean, and do not mean.** The scenarios are written by the project authors, so
the correct answer is known by construction. A perfect score means the rules do what they were
designed to do on these cases. It does **not** show how they perform on real operator traffic, which
has different volumes, vendors and edge cases. To get a real accuracy figure, replace the scenario
generator with labeled captures (public 5G captures or lab traffic where you know which sessions
are attacks) and keep the same scoring code.

## 2. Throughput: `scripts/benchmark_throughput.py`

```bash
python scripts/benchmark_throughput.py
python scripts/benchmark_throughput.py --events 200000 --devices 20000 --repeat 5
```

It reports events per second and microseconds per event for clean traffic and for traffic with
about 10% attacks, once with an in-memory inventory and once with a real in-memory
`SQLiteRepository`, so the cost of a database lookup is visible.

It measures the **detection engine only**, on events that are already parsed. Packet
capture/parsing (PyShark/scapy), writing alerts, correlation and the API are not included, so the
result is an upper bound for the whole pipeline, not its speed. Results depend on your machine:
quote your own numbers with the Python version and hardware.

Alert counts can differ between engine versions. A version that merges repeated identical alerts
reports fewer alerts for the same input than one that raises each separately.
