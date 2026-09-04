"""
PCAP Replay ingestion engine for NASWatch.
Reads and yields parsed 5G signaling events from stored .pcap / .pcapng captures for offline analysis and testing.
"""

from __future__ import annotations

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

        while not self._stopped:
            iteration += 1
            logger.info(f"Starting PCAP replay (pass #{iteration}): {self.pcap_path}")

            # Try PyShark FileCapture first
            yielded_any = False
            try:
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
                        yielded_any = True
                        yield event
                        if self.delay_seconds > 0:
                            time.sleep(self.delay_seconds)

                capture.close()
            except Exception as e:
                logger.warning(
                    f"PyShark replay encountered exception ({e}); attempting Scapy fallback."
                )

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
                            yield event
                            if self.delay_seconds > 0:
                                time.sleep(self.delay_seconds)
                except Exception as scapy_err:
                    logger.error(f"Scapy fallback replay failed: {scapy_err}")

            if not self.loop or self._stopped:
                break
