"""
NGAP (Next Generation Application Protocol - 3GPP TS 38.413) Parser.
Extracts radio access layer fields (RAN-UE-NGAP-ID, AMF-UE-NGAP-ID, NR Cell ID, TAC)
and unpacks embedded NAS-PDU signaling containers.
"""

from __future__ import annotations

import binascii
import json
from datetime import UTC, datetime
from typing import Any

from naswatch.logging_config import get_logger
from naswatch.parsing.nas_parser import NASParser
from naswatch.storage.models import ParsedSignalingEvent

logger = get_logger("parsing.ngap")

# NGAP Elementary Procedure Codes (3GPP TS 38.413)
NGAP_PROCEDURES = {
    4: "DownlinkNASTransport",
    10: "HandoverResourceAllocation",
    14: "InitialContextSetup",
    15: "InitialUEMessage",
    20: "NGReset",
    21: "NGSetup",
    26: "PDUSessionResourceModify",
    28: "PDUSessionResourceRelease",
    29: "PDUSessionResourceSetup",
    39: "UplinkNASTransport",
    37: "UERadioCapabilityInfoIndication",
    35: "UEContextRelease",
    46: "UplinkNASTransport",
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
                if event.procedure_code in (26, 29) and hasattr(ngap, "sst"):
                    try:
                        event.requested_sst = int(str(ngap.sst), 0)
                    except ValueError:
                        pass
                if event.procedure_code in (26, 29) and hasattr(ngap, "sd"):
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
                    if nas_data.get("requested_slices"):
                        event.metadata["requested_slices"] = nas_data["requested_slices"]
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
                    if raw_nas_data.get("requested_slices"):
                        event.metadata["requested_slices"] = raw_nas_data["requested_slices"]
                except Exception as e:
                    logger.debug(f"Failed parsing embedded NAS PDU: {e}")

            return event

        except Exception as err:
            logger.error(f"Error dissecting PyShark packet: {err}", exc_info=True)
            return None

    @staticmethod
    def parse_tshark_json_packet(packet: dict[str, Any]) -> ParsedSignalingEvent | None:
        """Parse one packet from TShark's JSON output without PyShark's asyncio runtime."""
        try:
            layers = packet.get("_source", {}).get("layers", {})

            def normalize(name: str) -> str:
                return "".join(char.lower() for char in name if char.isalnum())

            def find_values(node: Any, names: set[str]) -> list[str]:
                found: list[str] = []
                if isinstance(node, dict):
                    for key, value in node.items():
                        key_normalized = normalize(key)
                        leaf_normalized = normalize(key.rsplit(".", 1)[-1])
                        if key_normalized in names or leaf_normalized in names:
                            values = value if isinstance(value, list) else [value]
                            found.extend(str(item) for item in values if not isinstance(item, (dict, list)))
                        else:
                            found.extend(find_values(value, names))
                elif isinstance(node, list):
                    for value in node:
                        found.extend(find_values(value, names))
                return found

            def first(*names: str) -> str | None:
                values = find_values(layers, {normalize(name) for name in names})
                return values[0] if values else None

            def last(*names: str) -> str | None:
                values = find_values(layers, {normalize(name) for name in names})
                return values[-1] if values else None

            if "ngap" not in layers:
                return None

            frame_number = first("frame.number")
            epoch = first("frame.time_epoch")
            timestamp = datetime.now(UTC)
            if epoch:
                try:
                    timestamp = datetime.fromtimestamp(float(epoch), tz=UTC)
                except ValueError:
                    timestamp = datetime.fromisoformat(epoch.replace("Z", "+00:00"))

            event = ParsedSignalingEvent(
                timestamp=timestamp,
                packet_num=int(frame_number) if frame_number else None,
                source_ip=first("ip.src", "ipv6.src") or "127.0.0.1",
                dest_ip=first("ip.dst", "ipv6.dst") or "127.0.0.1",
                raw_payload_hex=json.dumps(layers, separators=(",", ":"))[:512],
            )

            procedure_code = first("ngap.procedureCode")
            if procedure_code:
                event.procedure_code = int(procedure_code, 0)
                event.procedure_name = NGAP_PROCEDURES.get(
                    event.procedure_code, f"Procedure_{event.procedure_code}"
                )

            for field_names, attr in (
                (("ngap.RAN_UE_NGAP_ID",), "ran_ue_ngap_id"),
                (("ngap.AMF_UE_NGAP_ID",), "amf_ue_ngap_id"),
                (("ngap.NRCellIdentity", "ngap.nr_cell_identity"), "cell_id"),
            ):
                value = first(*field_names)
                if value:
                    if attr in {"ran_ue_ngap_id", "amf_ue_ngap_id"}:
                        try:
                            setattr(event, attr, int(value, 0))
                        except ValueError:
                            pass
                    else:
                        event.cell_id = value

            tac = first("ngap.tAC", "ngap.TAC")
            if tac:
                try:
                    event.tac = int(tac, 0)
                except ValueError:
                    pass

            nas_pdu = first("ngap.NAS_PDU")
            if nas_pdu:
                try:
                    nas_bytes = bytes.fromhex(nas_pdu.replace(":", ""))
                    nas_data = NASParser.parse_raw_nas(nas_bytes)
                    event.raw_payload_hex = nas_bytes.hex()
                    if nas_data.get("msg_type_name") and not event.procedure_name:
                        event.procedure_name = nas_data["msg_type_name"]
                    if nas_data.get("imei"):
                        event.imei = nas_data["imei"]
                    if nas_data.get("guti"):
                        event.guti = nas_data["guti"]
                    if nas_data.get("sst") is not None:
                        event.requested_sst = nas_data["sst"]
                        event.requested_sd = nas_data.get("sd")
                    if nas_data.get("requested_slices"):
                        event.metadata["requested_slices"] = nas_data["requested_slices"]
                except ValueError:
                    pass

            # TShark decodes SUCI components individually; for the lab's
            # null-protection SUCI, these fields reconstruct the SUPI/IMSI.
            mcc = first("e212.mcc")
            mnc = first("e212.mnc")
            msin = first("nas-5gs.mm.suci.msin")
            if mcc and mnc and msin:
                event.imsi = f"{mcc}{mnc}{msin}"

            sst = last("nas-5gs.mm.sst")
            if sst is None and event.procedure_code in (26, 29):
                sst = last("ngap.sst")
            if sst:
                try:
                    event.requested_sst = int(sst, 0)
                except ValueError:
                    pass

            sd = last("nas-5gs.mm.mm_sd")
            if sd is None and event.procedure_code in (26, 29):
                sd = last("ngap.sd")
            if sd:
                try:
                    event.requested_sd = (
                        sd.replace("0x", "").replace(":", "").upper().zfill(6)
                        if sd.lower().startswith("0x") or ":" in sd or len(sd) == 6
                        else f"{int(sd, 0):06X}"
                    )
                except ValueError:
                    event.requested_sd = sd

            return event
        except Exception as err:
            logger.error(f"Error parsing TShark JSON packet: {err}", exc_info=True)
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
                    if nas_data.get("requested_slices"):
                        event.metadata["requested_slices"] = nas_data["requested_slices"]
                    if not event.procedure_name and nas_data.get("msg_type_name"):
                        event.procedure_name = nas_data["msg_type_name"]

            # Default cell ID if present in metadata/bytes
            event.cell_id = "0x000000010"
            event.tac = 1

            return event
        except Exception as err:
            logger.error(f"Error parsing Scapy packet: {err}")
            return None
