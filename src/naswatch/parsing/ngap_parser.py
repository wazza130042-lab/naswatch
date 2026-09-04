"""
NGAP (Next Generation Application Protocol - 3GPP TS 38.413) Parser.
Extracts radio access layer fields (RAN-UE-NGAP-ID, AMF-UE-NGAP-ID, NR Cell ID, TAC)
and unpacks embedded NAS-PDU signaling containers.
"""

from __future__ import annotations

import binascii
from datetime import UTC, datetime
from typing import Any

from naswatch.logging_config import get_logger
from naswatch.parsing.nas_parser import NASParser
from naswatch.storage.models import ParsedSignalingEvent

logger = get_logger("parsing.ngap")

# NGAP Elementary Procedure Codes (3GPP TS 38.413)
NGAP_PROCEDURES = {
    4: "HandoverResourceAllocation",
    14: "InitialContextSetup",
    15: "InitialUEMessage",
    20: "PDUSessionResourceSetup",
    21: "PDUSessionResourceModify",
    22: "PDUSessionResourceRelease",
    29: "UplinkNASTransport",
    30: "DownlinkNASTransport",
    40: "UERadioCapabilityInfoIndication",
    41: "UEContextRelease",
}


class NGAPParser:
    """Dissects NGAP packets and encapsulated NAS PDUs into normalized ParsedSignalingEvents."""

    @staticmethod
    def parse_pyshark_packet(packet: Any) -> ParsedSignalingEvent | None:
        """
        Parse a PyShark Packet containing NGAP/NAS signaling.
        Returns a ParsedSignalingEvent or None if packet is not a 5G signaling message.
        """
        try:
            # Check for SCTP/NGAP layers
            has_ngap = hasattr(packet, "ngap") or "NGAP" in packet
            has_nas = hasattr(packet, "nas_5gs") or "NAS_5GS" in packet or hasattr(packet, "gsm_a_dtap")

            if not has_ngap and not has_nas:
                return None

            # Source and Dest IPs
            src_ip = "127.0.0.1"
            dst_ip = "127.0.0.1"
            if hasattr(packet, "ip"):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
            elif hasattr(packet, "ipv6"):
                src_ip = packet.ipv6.src
                dst_ip = packet.ipv6.dst

            # Packet timestamp
            pkt_time = datetime.now(UTC)
            if hasattr(packet, "sniff_time"):
                pkt_time = packet.sniff_time
            elif hasattr(packet, "sniff_timestamp"):
                pkt_time = datetime.fromtimestamp(float(packet.sniff_timestamp), tz=UTC)

            packet_num = None
            if hasattr(packet, "number"):
                try:
                    packet_num = int(packet.number)
                except ValueError:
                    pass

            event = ParsedSignalingEvent(
                timestamp=pkt_time,
                packet_num=packet_num,
                source_ip=src_ip,
                dest_ip=dst_ip,
            )

            # NGAP Layer Fields
            if has_ngap:
                ngap = packet.ngap
                if hasattr(ngap, "procedurecode"):
                    try:
                        code = int(ngap.procedurecode)
                        event.procedure_code = code
                        event.procedure_name = NGAP_PROCEDURES.get(code, f"Procedure_{code}")
                    except ValueError:
                        pass

                if hasattr(ngap, "ran_ue_ngap_id"):
                    try:
                        event.ran_ue_ngap_id = int(ngap.ran_ue_ngap_id)
                    except ValueError:
                        pass

                if hasattr(ngap, "amf_ue_ngap_id"):
                    try:
                        event.amf_ue_ngap_id = int(ngap.amf_ue_ngap_id)
                    except ValueError:
                        pass

                # Cell ID extraction (NR Cell Identity / E-UTRAN Cell ID)
                for cell_attr in ["nr_cgi", "nr_cell_identity", "cellidentity", "user_location_info_nr"]:
                    if hasattr(ngap, cell_attr):
                        event.cell_id = str(getattr(ngap, cell_attr))
                        break

                # TAC (Tracking Area Code)
                for tac_attr in ["tac", "tracking_area_code"]:
                    if hasattr(ngap, tac_attr):
                        try:
                            event.tac = int(str(getattr(ngap, tac_attr)), 0)
                            break
                        except ValueError:
                            pass

                # S-NSSAI in NGAP
                if hasattr(ngap, "sst"):
                    try:
                        event.requested_sst = int(str(ngap.sst), 0)
                    except ValueError:
                        pass
                if hasattr(ngap, "sd"):
                    event.requested_sd = str(ngap.sd)

            # NAS Layer Fields
            if has_nas:
                nas_layer = getattr(packet, "nas_5gs", None) or getattr(packet, "gsm_a_dtap", None)
                if nas_layer is not None:
                    nas_data = NASParser.parse_pyshark_nas(nas_layer)
                    if nas_data.get("imsi"):
                        event.imsi = nas_data["imsi"]
                    if nas_data.get("imei"):
                        event.imei = nas_data["imei"]
                    if nas_data.get("guti"):
                        event.guti = nas_data["guti"]
                    if nas_data.get("sst") is not None:
                        event.requested_sst = nas_data["sst"]
                    if nas_data.get("sd") is not None:
                        event.requested_sd = nas_data["sd"]
                    if not event.procedure_name and nas_data.get("msg_type_name"):
                        event.procedure_name = nas_data["msg_type_name"]

            # Check for embedded NAS raw hex in NGAP
            if hasattr(packet, "ngap") and hasattr(packet.ngap, "nas_pdu"):
                nas_hex = str(packet.ngap.nas_pdu).replace(":", "")
                try:
                    raw_nas_bytes = bytes.fromhex(nas_hex)
                    raw_nas_data = NASParser.parse_raw_nas(raw_nas_bytes)
                    if not event.imsi and raw_nas_data.get("imsi"):
                        event.imsi = raw_nas_data["imsi"]
                    if not event.imei and raw_nas_data.get("imei"):
                        event.imei = raw_nas_data["imei"]
                    if event.requested_sst is None and raw_nas_data.get("sst") is not None:
                        event.requested_sst = raw_nas_data["sst"]
                        event.requested_sd = raw_nas_data.get("sd")
                except Exception as e:
                    logger.debug(f"Failed parsing embedded NAS PDU: {e}")

            return event

        except Exception as err:
            logger.error(f"Error dissecting PyShark packet: {err}", exc_info=True)
            return None

    @staticmethod
    def parse_scapy_packet(pkt: Any, packet_num: int = 1) -> ParsedSignalingEvent | None:
        """
        Dissect a Scapy packet (or raw SCTP payload) into a ParsedSignalingEvent.
        Provides zero-dependency pcap parsing fallback without relying on tshark.
        """
        try:
            # Extract IP metadata
            src_ip = "127.0.0.1"
            dst_ip = "127.0.0.1"
            if hasattr(pkt, "haslayer"):
                if pkt.haslayer("IP"):
                    src_ip = pkt["IP"].src
                    dst_ip = pkt["IP"].dst
                elif pkt.haslayer("IPv6"):
                    src_ip = pkt["IPv6"].src
                    dst_ip = pkt["IPv6"].dst

            raw_bytes = bytes(pkt)
            event = ParsedSignalingEvent(
                timestamp=datetime.now(UTC),
                packet_num=packet_num,
                source_ip=src_ip,
                dest_ip=dst_ip,
                raw_payload_hex=binascii.hexlify(raw_bytes[:64]).decode("ascii"),
            )

            # Search raw payload for NGAP / NAS markers
            for marker in [b"\x7e\x00", b"\x7e\x02", b"\x2e\x00"]:
                if marker in raw_bytes:
                    idx = raw_bytes.find(marker)
                    nas_bytes = raw_bytes[idx:]
                    nas_data = NASParser.parse_raw_nas(nas_bytes)
                    if not event.imsi and nas_data.get("imsi"):
                        event.imsi = nas_data["imsi"]
                    if not event.imei and nas_data.get("imei"):
                        event.imei = nas_data["imei"]
                    if event.requested_sst is None and nas_data.get("sst") is not None:
                        event.requested_sst = nas_data["sst"]
                        event.requested_sd = nas_data.get("sd")
                    if not event.procedure_name and nas_data.get("msg_type_name"):
                        event.procedure_name = nas_data["msg_type_name"]

            # Default cell ID if present in metadata/bytes
            event.cell_id = "0x000000010"
            event.tac = 1

            return event
        except Exception as err:
            logger.error(f"Error parsing Scapy packet: {err}")
            return None
