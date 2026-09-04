"""
Headless CLI Pipeline runner for NASWatch 5G IDS.
Executes the full pipeline: Ingestion -> Parsing -> Detection -> Alerting.
Can run standalone without UI on edge nodes, gNB hosts, or 5G core servers.

Usage:
    python scripts/run_pipeline.py --mode replay --pcap data/pcaps/5g_signaling_demo.pcap
    python scripts/run_pipeline.py --mode live --interface any
"""

from __future__ import annotations

import argparse
import signal
import sys
from pathlib import Path
from typing import Any

import yaml

from naswatch.alerting.notifier import (
    AlertNotifier,
    ConsoleAlertSink,
    FileAlertSink,
    SQLiteAlertSink,
    SyslogAlertSink,
    WebhookAlertSink,
)
from naswatch.detection.engine import DetectionEngine
from naswatch.ingestion.live_capture import LiveCaptureEngine
from naswatch.ingestion.pcap_replay import PCAPReplayer
from naswatch.logging_config import setup_logging
from naswatch.storage.sqlite_repo import SQLiteRepository


def load_settings(config_path: str = "config/settings.yaml") -> dict[str, Any]:
    """Load settings from YAML file with fallback to defaults."""
    cfg_file = Path(config_path)
    if cfg_file.exists():
        with open(cfg_file, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


def main() -> None:
    parser = argparse.ArgumentParser(description="NASWatch 5G Control-Plane Intrusion Detection Engine")
    parser.add_argument(
        "--mode",
        choices=["replay", "live"],
        default=None,
        help="Capture mode: 'replay' from PCAP or 'live' from interface",
    )
    parser.add_argument(
        "--pcap",
        type=str,
        default=None,
        help="Path to PCAP file for replay mode",
    )
    parser.add_argument(
        "--interface",
        type=str,
        default=None,
        help="Network interface name for live mode (e.g., eth0, any)",
    )
    parser.add_argument(
        "--db",
        type=str,
        default=None,
        help="Path to SQLite inventory database",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config/settings.yaml",
        help="Path to settings.yaml configuration file",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Delay in seconds between replayed packets",
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Continuously loop replay PCAP",
    )
    args = parser.parse_args()

    # Load configuration
    cfg = load_settings(args.config)

    app_cfg = cfg.get("app", {})
    log_level = app_cfg.get("log_level", "INFO")
    log_format = app_cfg.get("log_format", "console")

    logger = setup_logging(level=log_level, log_format=log_format)
    logger.info("Initializing NASWatch 5G Control-Plane IDS Engine v0.1.0...")

    # Determine paths and settings
    db_path = args.db or cfg.get("storage", {}).get("sqlite_path", "data/inventory.db")
    mode = args.mode or cfg.get("capture", {}).get("mode", "replay")
    pcap_path = args.pcap or cfg.get("capture", {}).get("pcap_file", "data/pcaps/5g_signaling_demo.pcap")
    interface = args.interface or cfg.get("capture", {}).get("interface", "any")
    bpf_filter = cfg.get("capture", {}).get("bpf_filter", "sctp or port 38412")

    # Initialize Repository
    repo = SQLiteRepository(db_path=db_path)
    device_count = repo.count_devices()
    logger.info(f"Connected to Device Inventory ({db_path}): {device_count} authorized subscribers provisioned.")

    # Initialize Detection Rules & Engine
    det_cfg = cfg.get("detection", {}).get("rules", {})
    engine = DetectionEngine(
        device_repo=repo,
        enable_rogue_rule=det_cfg.get("rogue_device", {}).get("enabled", True),
        enable_spoofing_rule=det_cfg.get("identity_spoofing", {}).get("enabled", True),
        enable_slice_rule=det_cfg.get("slice_intrusion", {}).get("enabled", True),
    )

    # Configure Alert Sinks
    notifier = AlertNotifier()
    alert_cfg = cfg.get("alerting", {}).get("channels", {})

    if alert_cfg.get("console", {}).get("enabled", True):
        notifier.add_sink(ConsoleAlertSink())
    if alert_cfg.get("sqlite", {}).get("enabled", True):
        notifier.add_sink(SQLiteAlertSink(repo))
    if alert_cfg.get("file", {}).get("enabled", True):
        file_path = alert_cfg.get("file", {}).get("path", "data/alerts.jsonl")
        notifier.add_sink(FileAlertSink(file_path=file_path))
    if alert_cfg.get("webhook", {}).get("enabled", False):
        webhook_url = alert_cfg.get("webhook", {}).get("url", "")
        notifier.add_sink(WebhookAlertSink(url=webhook_url))
    if alert_cfg.get("syslog", {}).get("enabled", False):
        syslog_host = alert_cfg.get("syslog", {}).get("host", "127.0.0.1")
        syslog_port = alert_cfg.get("syslog", {}).get("port", 514)
        notifier.add_sink(SyslogAlertSink(host=syslog_host, port=syslog_port))

    # Ingestion Stream Setup
    if mode == "live":
        ingestion = LiveCaptureEngine(interface=interface, bpf_filter=bpf_filter)
        logger.info(f"Listening on live interface '{interface}' for 5G NGAP/NAS signaling...")
    else:
        ingestion = PCAPReplayer(
            pcap_path=pcap_path,
            delay_seconds=args.delay,
            loop=args.loop,
        )
        logger.info(f"Replaying signaling captures from '{pcap_path}' (loop={args.loop})...")

    # Graceful Shutdown Handler
    def signal_handler(sig, frame):
        logger.info("Received interrupt signal. Stopping NASWatch IDS pipeline...")
        ingestion.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Process Pipeline Stream
    total_packets = 0
    total_alerts = 0

    try:
        for event in ingestion.stream_events():
            total_packets += 1
            alerts = engine.process_event(event)
            for alert in alerts:
                total_alerts += 1
                notifier.dispatch(alert)

    except KeyboardInterrupt:
        logger.info("Pipeline terminated by user.")
    finally:
        logger.info(f"Pipeline finished. Processed {total_packets} signaling events. Generated {total_alerts} security alerts.")


if __name__ == "__main__":
    main()
