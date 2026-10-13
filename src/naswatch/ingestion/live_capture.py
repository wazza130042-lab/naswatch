"""
Live 5G signaling capture engine for NASWatch.
Sniffs live network interface (e.g. eth0, any) for SCTP/NGAP traffic.
"""

from __future__ import annotations

from collections.abc import Generator

from naswatch.logging_config import get_logger
from naswatch.parsing.ngap_parser import NGAPParser
from naswatch.storage.models import ParsedSignalingEvent

logger = get_logger("ingestion.live_capture")


class LiveCaptureEngine:
    """Sniffs live network interfaces for 5G NGAP/NAS signaling traffic."""

    def __init__(
        self,
        interface: str = "any",
        bpf_filter: str = "sctp or port 38412",
        display_filter: str = "ngap || nas_5gs || sctp",
        packet_count: int = 0,
    ):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.display_filter = display_filter
        self.packet_count = packet_count
        self._stopped = False

    def stop(self) -> None:
        """Signal capture loop to stop."""
        self._stopped = True

    def stream_events(self) -> Generator[ParsedSignalingEvent, None, None]:
        """
        Continuously sniffs the interface and yields parsed events.
        """
        self._stopped = False
        logger.info(
            f"Starting live capture on interface '{self.interface}' (BPF: '{self.bpf_filter}')"
        )

        try:
            import pyshark

            capture = pyshark.LiveCapture(
                interface=self.interface,
                bpf_filter=self.bpf_filter,
                display_filter=self.display_filter,
                use_json=True,
                include_raw=True,
            )

            count = 0
            packet_no = 0
            for packet in capture.sniff_continuously(packet_count=self.packet_count):
                if self._stopped:
                    break
                packet_no += 1

                # Primary path: full tshark/pyshark NGAP+NAS dissection.
                event = NGAPParser.parse_pyshark_packet(packet)

                # Fallback: if tshark did not expose a decodable NAS layer (e.g. a
                # forged / non-standard 5G NAS frame injected by an attacker), fall
                # back to the raw-bytes parser so the packet is still evaluated.
                if event is None:
                    try:
                        raw = packet.get_raw_packet()
                    except Exception:
                        raw = None
                    if raw and any(marker in raw for marker in (b"\x7e\x00", b"\x7e\x02", b"\x2e\x00")):
                        try:
                            from scapy.all import Ether

                            event = NGAPParser.parse_scapy_packet(Ether(raw), packet_num=packet_no)
                        except Exception:
                            event = None

                if event:
                    count += 1
                    yield event

            capture.close()
        except Exception as err:
            logger.error(f"Live capture error on interface '{self.interface}': {err}")
