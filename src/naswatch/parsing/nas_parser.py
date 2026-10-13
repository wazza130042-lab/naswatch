"""
NAS (Non-Access Stratum) 5GS Protocol Parser.
Extracts 5G subscriber identity (IMSI/SUPI, SUCI, 5G-GUTI), hardware identity (IMEI/PEI, IMEISV),
and requested Network Slice info (S-NSSAI: SST, SD) from 3GPP TS 24.501 NAS messages.
"""

from __future__ import annotations

import binascii
import re
from typing import Any

from naswatch.logging_config import get_logger

logger = get_logger("parsing.nas")

# 5GS NAS Message Types (TS 24.501)
NAS_5GS_MSG_TYPES = {
    0x41: "RegistrationRequest",
    0x42: "RegistrationAccept",
    0x43: "RegistrationComplete",
    0x44: "RegistrationReject",
    0x45: "DeregistrationRequestUEOrigin",
    0x46: "DeregistrationAcceptUEOrigin",
    0x47: "DeregistrationRequestUETerm",
    0x48: "DeregistrationAcceptUETerm",
    0x54: "ServiceRequest",
    0x56: "SecurityModeComplete",
    0x5B: "IdentityResponse",
    0x5C: "AuthenticationResponse",
    0x5D: "AuthenticationFailure",
    0xC1: "PDUSessionEstablishmentRequest",
    0xC2: "PDUSessionEstablishmentAccept",
    0xC3: "PDUSessionEstablishmentReject",
    0xC5: "PDUSessionModificationRequest",
    0xC9: "PDUSessionReleaseRequest",
}


def decode_bcd_digits(data_hex: str, length: int) -> str:
    """Decodes BCD (Binary Coded Decimal) nibbles swap format used in 3GPP identities."""
    digits = []
    for i in range(0, len(data_hex) - 1, 2):
        low = data_hex[i + 1]
        high = data_hex[i]
        digits.append(low)
        if high.lower() != "f":
            digits.append(high)
    return "".join(digits)[:length]


class NASParser:
    """Parser for 5GS NAS protocol messages from PyShark or raw bytes."""

    @staticmethod
    def parse_pyshark_nas(nas_layer: Any) -> dict[str, Any]:
        """Extract fields from a PyShark 'nas_5gs' or 'gsm_a_dtap' layer."""
        extracted: dict[str, Any] = {
            "imsi": None,
            "imei": None,
            "guti": None,
            "sst": None,
            "sd": None,
            "requested_slices": [],
            "msg_type_name": None,
        }

        try:
            # Check message type
            if hasattr(nas_layer, "mm_message_type"):
                extracted["msg_type_name"] = str(nas_layer.mm_message_type)
            elif hasattr(nas_layer, "message_type"):
                extracted["msg_type_name"] = str(nas_layer.message_type)

            # IMSI / SUPI extraction
            for attr in [
                "imsi",
                "supi_imsi",
                "e212_imsi",
                "nas_5gs_mm_supi_imsi",
                "nas_5gs_mm_suci_imsi",
            ]:
                if hasattr(nas_layer, attr):
                    val = str(getattr(nas_layer, attr)).strip().replace("-", "")
                    if val.isdigit() and len(val) >= 10:
                        extracted["imsi"] = val
                        break

            # Fallback for SUCI / Plaintext IMSI inside 5GS Mobile Identity
            if not extracted["imsi"] and hasattr(nas_layer, "5gs_mobile_id"):
                mob_id = str(getattr(nas_layer, "5gs_mobile_id"))
                m = re.search(r"(\d{14,15})", mob_id)
                if m:
                    extracted["imsi"] = m.group(1)

            # IMEI / PEI / IMEISV extraction
            for attr in [
                "imei",
                "imeisv",
                "pei_imei",
                "nas_5gs_mm_pei_imei",
                "nas_5gs_mm_imeisv",
                "nas_5gs_mm_imei",
                "gsm_a_imeisv",
            ]:
                if hasattr(nas_layer, attr):
                    val = str(getattr(nas_layer, attr)).strip().replace("-", "")
                    if val.isdigit() and len(val) >= 14:
                        extracted["imei"] = val
                        break

            # 5G GUTI extraction
            for attr in ["5gs_guti", "guti", "nas_5gs_mm_5gs_guti"]:
                if hasattr(nas_layer, attr):
                    extracted["guti"] = str(getattr(nas_layer, attr))
                    break

            # S-NSSAI (SST & SD) extraction
            for attr in ["s_nssai_sst", "sst", "nas_5gs_sm_s_nssai_sst", "sm_s_nssai_sst"]:
                if hasattr(nas_layer, attr):
                    try:
                        extracted["sst"] = int(str(getattr(nas_layer, attr)), 0)
                        break
                    except (ValueError, TypeError):
                        pass

            for attr in ["s_nssai_sd", "sd", "nas_5gs_sm_s_nssai_sd", "sm_s_nssai_sd"]:
                if hasattr(nas_layer, attr):
                    sd_val = str(getattr(nas_layer, attr)).strip()
                    extracted["sd"] = sd_val
                    break

        except Exception as err:
            logger.debug(f"PyShark NAS parsing exception: {err}")

        return extracted

    @staticmethod
    def parse_raw_nas(payload: bytes) -> dict[str, Any]:
        """
        Defensive fallback binary parser for 5GS NAS messages.
        Extracts message type, IMSI, IMEI, and S-NSSAI directly from bytes.
        """
        extracted: dict[str, Any] = {
            "imsi": None,
            "imei": None,
            "guti": None,
            "sst": None,
            "sd": None,
            "requested_slices": [],
            "msg_type_name": None,
        }

        if len(payload) < 2:
            return extracted

        try:
            extracted["requested_slices"] = NASParser._scan_requested_nssai(payload)
            # 5GS NAS header:
            # Byte 0: Extended Protocol Discriminator (0x7e for 5GS MM, 0x2e for 5GS SM)
            # Byte 1: Security Header Type
            _epd = payload[0]
            sec_header = payload[1] & 0x0F

            offset = 2
            # If plain NAS (sec_header == 0) or integrity protected
            if sec_header != 0 and len(payload) >= 7:
                # 4 bytes MAC (bytes 2..5) + 1 byte Sequence Number (byte 6)
                offset = 7

            if offset >= len(payload):
                return extracted

            msg_type = payload[offset]
            extracted["msg_type_name"] = NAS_5GS_MSG_TYPES.get(
                msg_type, f"Unknown_0x{msg_type:02x}"
            )
            offset += 1

            # Registration Request (0x41)
            if msg_type == 0x41 and offset + 2 <= len(payload):
                # 5GS Registration type & ngKSI
                offset += 1
                if offset + 2 <= len(payload):
                    id_len = int.from_bytes(payload[offset : offset + 2], "big")
                    offset += 2
                    if offset + id_len <= len(payload):
                        id_bytes = payload[offset : offset + id_len]
                        id_type_str, ident = NASParser._extract_identity_from_mobile_id(id_bytes)
                        if ident:
                            if id_type_str == "IMSI":
                                extracted["imsi"] = ident
                            elif id_type_str == "IMEI":
                                extracted["imei"] = ident
                        offset += id_len

            # Identity Response (0x5B)
            elif msg_type == 0x5B and offset + 2 <= len(payload):
                id_len = int.from_bytes(payload[offset : offset + 2], "big")
                offset += 2
                if offset + id_len <= len(payload):
                    id_bytes = payload[offset : offset + id_len]
                    id_type_str, ident = NASParser._extract_identity_from_mobile_id(id_bytes)
                    if ident:
                        if id_type_str == "IMSI":
                            extracted["imsi"] = ident
                        elif id_type_str == "IMEI":
                            extracted["imei"] = ident
                        else:
                            # Fallback based on length
                            if len(ident) == 15 and ident.startswith(("86", "35")):
                                extracted["imei"] = ident
                            else:
                                extracted["imsi"] = ident

            # Security Mode Complete (0x56) - Often carries IMEISV
            elif msg_type == 0x56:
                imei_cand = NASParser._scan_for_imei(payload)
                if imei_cand:
                    extracted["imei"] = imei_cand

            # PDU Session Establishment Request (0xC1) - Contains S-NSSAI
            elif msg_type == 0xC1:
                sst, sd = NASParser._scan_for_snssai(payload)
                extracted["sst"] = sst
                extracted["sd"] = sd

            # Global scan for IMEI / IMEISV if not yet found
            if extracted["imei"] is None:
                imei_cand = NASParser._scan_for_imei(payload)
                if imei_cand:
                    extracted["imei"] = imei_cand

        except Exception as err:
            logger.debug(f"Raw NAS parse error: {err}")

        return extracted

    @staticmethod
    def _scan_requested_nssai(payload: bytes) -> list[dict[str, int | str | None]]:
        """Decode S-NSSAIs only from a valid 5GS Registration Request IE."""
        results: list[dict[str, int | str | None]] = []
        marker = b"\x7e\x00\x41"  # Plain 5GS Registration Request
        start = 0
        while (message_start := payload.find(marker, start)) >= 0:
            start = message_start + len(marker)
            ie_offset = payload.find(b"\x2f", start)  # Requested NSSAI IEI
            if ie_offset < 0 or ie_offset + 2 > len(payload):
                continue

            ie_length = payload[ie_offset + 1]
            end = ie_offset + 2 + ie_length
            if ie_length == 0 or end > len(payload):
                continue

            cursor = ie_offset + 2
            decoded: list[dict[str, int | str | None]] = []
            while cursor < end:
                item_length = payload[cursor]
                cursor += 1
                if item_length not in (1, 4) or cursor + item_length > end:
                    decoded = []
                    break
                sst = payload[cursor]
                sd = payload[cursor + 1 : cursor + 4].hex().upper() if item_length == 4 else None
                decoded.append({"sst": sst, "sd": sd})
                cursor += item_length
            if decoded and cursor == end:
                results.extend(decoded)
        return results

    @staticmethod
    def _extract_identity_from_mobile_id(data: bytes) -> tuple[str | None, str | None]:
        """
        Extract identity type ('IMSI', 'IMEI', 'GUTI') and numeric value from 5GS Mobile Identity bytes.
        """
        if not data:
            return None, None
        # Type of identity (lowest 3 bits of byte 0)
        # 1: SUCI/SUPI (IMSI), 2: 5G-GUTI, 3: IMEI, 4: 5G-S-TMSI, 5: IMEISV
        id_type = data[0] & 0x07
        hex_str = binascii.hexlify(data).decode("ascii")

        if id_type == 1:
            # SUCI / IMSI: If length >= 6, routing indicator (2B) + protection (1B) + PKI (1B) = 4B. MSIN starts at byte 5 (hex idx 10)
            start_idx = 10 if len(data) >= 6 else 2
            digits = []
            for i in range(start_idx, len(hex_str) - 1, 2):
                low = hex_str[i + 1]
                high = hex_str[i]
                digits.append(low)
                if high.lower() != "f":
                    digits.append(high)
            cand = "".join(digits)
            clean = re.sub(r"\D", "", cand)
            if len(clean) >= 10:
                return "IMSI", clean

        elif id_type in (3, 5):
            # IMEI / IMEISV: Starts at byte index 1 (hex idx 2)
            digits = []
            for i in range(2, len(hex_str) - 1, 2):
                low = hex_str[i + 1]
                high = hex_str[i]
                digits.append(low)
                if high.lower() != "f":
                    digits.append(high)
            cand = "".join(digits)
            clean = re.sub(r"\D", "", cand)
            if len(clean) >= 14:
                return "IMEI", clean[:15]

        return None, None

    @staticmethod
    def _scan_for_imei(payload: bytes) -> str | None:
        """Scans packet bytes for an explicit IMEISV IE (0x77 or 0x5C) sequence."""
        hex_data = binascii.hexlify(payload).decode("ascii")
        for i in range(len(payload) - 8):
            # Look for IE 0x77 (IMEISV) or 0x5C
            if payload[i] in (0x77, 0x5C) and i + 9 <= len(payload):
                ie_len = payload[i + 1]
                if 8 <= ie_len <= 10:
                    imei_bcd = hex_data[(i + 2) * 2 : (i + 2 + ie_len) * 2]
                    decoded = decode_bcd_digits(imei_bcd, 16)
                    clean = re.sub(r"\D", "", decoded)
                    if len(clean) >= 14:
                        return clean[:15]

        return None

    @staticmethod
    def _scan_for_snssai(payload: bytes) -> tuple[int | None, str | None]:
        """
        Scan for S-NSSAI IE (Single Network Slice Selection Assistance Information).
        3GPP TS 24.501: Length is 1 to 4 bytes:
        [SST (1 byte)] + [Optional SD (3 bytes)]
        """
        hex_data = binascii.hexlify(payload).decode("ascii")
        # Common IE markers for NSSAI: 0x2f (NSSAI), 0x22 (S-NSSAI)
        for i in range(len(payload) - 4):
            # Look for S-NSSAI IE: Length byte = 4 (SST + 3 octets SD)
            if payload[i] == 0x22 and i + 5 <= len(payload):
                ie_len = payload[i + 1]
                if ie_len == 4:
                    sst = payload[i + 2]
                    sd = hex_data[(i + 3) * 2 : (i + 6) * 2].upper()
                    return sst, sd
                elif ie_len == 1:
                    sst = payload[i + 2]
                    return sst, None

        # Check for standard SST values (1=eMBB, 2=URLLC, 3=MIoT, 4=Enterprise)
        return None, None
