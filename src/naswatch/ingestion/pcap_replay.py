"""
PCAP Replay ingestion engine for NASWatch.
Reads and yields parsed 5G signaling events from stored .pcap / .pcapng captures for offline analysis and testing.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
from collections.abc import Generator
from pathlib import Path

from naswatch.logging_config import get_logger
from naswatch.parsing.ngap_parser import NGAPParser
from naswatch.storage.models import ParsedSignalingEvent

logger = get_logger("ingestion.pcap_replay")


class PCAPReplayer:
    """Streams and parses packets from a PCAP file."""

    def __init__(
        self,
        pcap_path: str,
        display_filter: str = "ngap || nas_5gs || sctp",
        delay_seconds: float = 0.0,
        loop: bool = False,
    ):
        self.pcap_path = Path(pcap_path)
        self.display_filter = display_filter
        self.delay_seconds = delay_seconds
        self.loop = loop
        self._stopped = False

    def stop(self) -> None:
        """Signal replay to stop immediately."""
        self._stopped = True

    def stream_events(self) -> Generator[ParsedSignalingEvent, None, None]:
        """
        Yields parsed signaling events one by one from the PCAP file.
        Uses PyShark with fallback to Scapy if PyShark/tshark encounters issues.
        """
        if not self.pcap_path.exists():
            logger.error(f"PCAP file not found: {self.pcap_path}")
            return

        self._stopped = False
        iteration = 0
        imsi_by_ran_ue_id: dict[int, str] = {}
        imsi_by_amf_ue_id: dict[int, str] = {}

        def correlate_ue_identity(event: ParsedSignalingEvent) -> ParsedSignalingEvent:
            """Carry an observed IMSI across NGAP messages for the same UE context."""
            if event.imsi:
                if event.ran_ue_ngap_id is not None:
                    imsi_by_ran_ue_id[event.ran_ue_ngap_id] = event.imsi
                if event.amf_ue_ngap_id is not None:
                    imsi_by_amf_ue_id[event.amf_ue_ngap_id] = event.imsi
                return event

            if event.ran_ue_ngap_id is not None:
                event.imsi = imsi_by_ran_ue_id.get(event.ran_ue_ngap_id)
            if event.imsi is None and event.amf_ue_ngap_id is not None:
                event.imsi = imsi_by_amf_ue_id.get(event.amf_ue_ngap_id)

            if event.imsi:
                if event.ran_ue_ngap_id is not None:
                    imsi_by_ran_ue_id[event.ran_ue_ngap_id] = event.imsi
                if event.amf_ue_ngap_id is not None:
                    imsi_by_amf_ue_id[event.amf_ue_ngap_id] = event.imsi
            return event

        while not self._stopped:
            iteration += 1
            logger.info(f"Starting PCAP replay (pass #{iteration}): {self.pcap_path}")

            # Try PyShark FileCapture first
            yielded_any = False
            if sys.version_info < (3, 14):
                try:
                    # PyShark asks asyncio for the current event loop. Python 3.14
                    # no longer creates one implicitly on the main thread.
                    try:
                        asyncio.get_event_loop()
                    except RuntimeError:
                        asyncio.set_event_loop(asyncio.new_event_loop())
                    import pyshark

                    capture = pyshark.FileCapture(
                        str(self.pcap_path),
                        display_filter=self.display_filter,
                        use_json=True,
                        include_raw=True,
                    )

                    for packet in capture:
                        if self._stopped:
                            break
                        event = NGAPParser.parse_pyshark_packet(packet)
                        if event:
                            event = correlate_ue_identity(event)
                            yielded_any = True
                            yield event
                            if self.delay_seconds > 0:
                                time.sleep(self.delay_seconds)

                    capture.close()
                except Exception as e:
                    logger.warning(
                        f"PyShark replay encountered exception ({e}); trying TShark JSON replay."
                    )

            # TShark JSON replay works with current Python versions even when
            # the installed PyShark release still uses removed asyncio APIs.
            if not yielded_any and not self._stopped:
                try:
                    result = subprocess.run(
                        [
                            "tshark",
                            "-r",
                            str(self.pcap_path),
                            "-Y",
                            self.display_filter,
                            "-T",
                            "json",
                        ],
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    for packet_num, packet in enumerate(json.loads(result.stdout), start=1):
                        if self._stopped:
                            break
                        event = NGAPParser.parse_tshark_json_packet(packet)
                        if event:
                            event = correlate_ue_identity(event)
                            yielded_any = True
                            yield event
                            if self.delay_seconds > 0:
                                time.sleep(self.delay_seconds)
                except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as tshark_err:
                    logger.error(f"TShark JSON replay failed: {tshark_err}")

            # If PyShark yielded nothing or failed, try Scapy
            if not yielded_any and not self._stopped:
                try:
                    from scapy.all import rdpcap

                    packets = rdpcap(str(self.pcap_path))
                    for i, pkt in enumerate(packets, start=1):
                        if self._stopped:
                            break
                        event = NGAPParser.parse_scapy_packet(pkt, packet_num=i)
                        if event:
                            event = correlate_ue_identity(event)
                            yield event
                            if self.delay_seconds > 0:
                                time.sleep(self.delay_seconds)
                except Exception as scapy_err:
                    logger.error(f"Scapy fallback replay failed: {scapy_err}")

            if not self.loop or self._stopped:
                break
