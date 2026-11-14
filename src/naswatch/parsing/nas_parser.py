"""
NAS (Non-Access Stratum) 5GS Protocol Parser.
Extracts 5G subscriber identity (IMSI/SUPI, SUCI, 5G-GUTI), hardware identity (IMEI/PEI, IMEISV),
and requested Network Slice info (S-NSSAI: SST, SD) from 3GPP TS 24.501 NAS messages.
"""

from __future__ import annotations

import re
from typing import Any

from naswatch.logging_config import get_logger

logger = get_logger("parsing.nas")

# 5GMM message types (EPD 0x7E) - TS 24.501 table 9.7.1. Verified against Wireshark's
# nas-5gs dissector.
NAS_5GS_MSG_TYPES = {
    0x41: "RegistrationRequest",
    0x42: "RegistrationAccept",
    0x43: "RegistrationComplete",
    0x44: "RegistrationReject",
    0x45: "DeregistrationRequestUEOrigin",
    0x46: "DeregistrationAcceptUEOrigin",
    0x47: "DeregistrationRequestUETerm",
    0x48: "DeregistrationAcceptUETerm",
    0x4C: "ServiceRequest",
    0x4D: "ServiceReject",
    0x4E: "ServiceAccept",
    0x54: "ConfigurationUpdateCommand",
    0x55: "ConfigurationUpdateComplete",
    0x56: "AuthenticationRequest",
    0x57: "AuthenticationResponse",
    0x58: "AuthenticationReject",
    0x59: "AuthenticationFailure",
    0x5A: "AuthenticationResult",
    0x5B: "IdentityRequest",
    0x5C: "IdentityResponse",
    0x5D: "SecurityModeCommand",
    0x5E: "SecurityModeComplete",
    0x5F: "SecurityModeReject",
    0x64: "5GMMStatus",
    0x67: "ULNASTransport",
    0x68: "DLNASTransport",
}

# 5GSM message types (EPD 0x2E) - TS 24.501 table 9.7.2. 5GSM header is
# EPD | PDU session ID | PTI | message type, so the type is the FOURTH octet.
NAS_5GSM_MSG_TYPES = {
    0xC1: "PDUSessionEstablishmentRequest",
    0xC2: "PDUSessionEstablishmentAccept",
    0xC3: "PDUSessionEstablishmentReject",
    0xC5: "PDUSessionAuthenticationCommand",
    0xC9: "PDUSessionModificationRequest",
    0xD1: "PDUSessionReleaseRequest",
    0xD3: "PDUSessionReleaseCommand",
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
            "suci_concealed": False,
            "suci_scheme": None,
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
    def _blank() -> dict[str, Any]:
        return {
            "imsi": None,
            "imei": None,
            "guti": None,
            "sst": None,
            "sd": None,
            "requested_slices": [],
            "msg_type_name": None,
            "suci_concealed": False,
            "suci_scheme": None,
        }

    @staticmethod
    def parse_raw_nas(payload: bytes) -> dict[str, Any]:
        """
        Defensive binary parser for 5GS NAS messages (TS 24.501).

        Handles plain and security-protected 5GMM messages and 5GSM messages, and
        extracts: message type, SUPI/IMSI (null-scheme SUCI), IMEI/IMEISV, and S-NSSAI
        (Requested NSSAI in Registration Request, S-NSSAI IE in UL NAS Transport).

        Concealed SUCIs (protection scheme != 0) are reported via ``suci_concealed``
        and are never turned into a fake IMSI. Messages protected with a real cipher
        cannot be read by a passive observer and simply yield no identity.

        For demo captures that pack several NAS messages into one payload, the bytes
        after the first message are scanned for further well-formed messages.
        """
        extracted = NASParser._blank()
        if len(payload) < 3:
            return extracted
        try:
            NASParser._parse_nas_message(payload, extracted, depth=0)
            NASParser._scan_embedded_messages(payload, extracted)
        except Exception as err:
            logger.debug(f"Raw NAS parse error: {err}")
        return extracted

    # Message types worth looking for inside a payload that concatenates NAS messages.
    _EMBEDDED_5GMM_TYPES = (0x41, 0x5C, 0x5E, 0x67)

    @staticmethod
    def _scan_embedded_messages(payload: bytes, extracted: dict[str, Any]) -> None:
        found = 0
        for idx in range(1, len(payload) - 2):
            if (
                payload[idx] == 0x7E
                and payload[idx + 1] == 0x00
                and payload[idx + 2] in NASParser._EMBEDDED_5GMM_TYPES
            ):
                sub = NASParser._blank()
                NASParser._parse_nas_message(payload[idx:], sub, depth=1)
                for key in ("imsi", "imei", "sst", "sd"):
                    if extracted[key] is None and sub[key] is not None:
                        extracted[key] = sub[key]
                if sub["suci_concealed"] and not extracted["suci_concealed"]:
                    extracted["suci_concealed"] = True
                    extracted["suci_scheme"] = sub["suci_scheme"]
                if not extracted["requested_slices"] and sub["requested_slices"]:
                    extracted["requested_slices"] = sub["requested_slices"]
                found += 1
                if found >= 8:
                    return

    @staticmethod
    def _parse_nas_message(payload: bytes, extracted: dict[str, Any], depth: int) -> None:
        if len(payload) < 3 or depth > 2:
            return
        epd = payload[0]

        if epd == 0x7E:  # 5GMM
            sec_header = payload[1] & 0x0F
            if sec_header != 0:
                # Security protected: EPD | SHT | MAC (4) | SQN (1) | inner NAS message
                if len(payload) >= 10:
                    NASParser._parse_nas_message(payload[7:], extracted, depth + 1)
                return
            msg_type = payload[2]
            body = payload[3:]
            if extracted["msg_type_name"] is None:
                extracted["msg_type_name"] = NAS_5GS_MSG_TYPES.get(
                    msg_type, f"Unknown_0x{msg_type:02x}"
                )
            if msg_type == 0x41:  # Registration Request
                extracted["requested_slices"] = NASParser._scan_requested_nssai(payload)
                # octet: 5GS registration type + ngKSI, then 5GS mobile identity (LV-E)
                if len(body) >= 3:
                    id_len = int.from_bytes(body[1:3], "big")
                    if 3 + id_len <= len(body):
                        NASParser._apply_mobile_identity(extracted, body[3 : 3 + id_len])
            elif msg_type == 0x5C:  # Identity Response: 5GS mobile identity (LV-E)
                if len(body) >= 2:
                    id_len = int.from_bytes(body[0:2], "big")
                    if 2 + id_len <= len(body):
                        NASParser._apply_mobile_identity(extracted, body[2 : 2 + id_len])
            elif msg_type == 0x5E:  # Security Mode Complete: optional IMEISV (IEI 0x77, TLV-E)
                if len(body) >= 3 and body[0] == 0x77:
                    id_len = int.from_bytes(body[1:3], "big")
                    if 3 + id_len <= len(body):
                        NASParser._apply_mobile_identity(extracted, body[3 : 3 + id_len])
            elif msg_type == 0x67:  # UL NAS Transport: carries the S-NSSAI of a PDU session
                NASParser._parse_ul_nas_transport(body, extracted)

        elif epd == 0x2E:  # 5GSM: EPD | PDU session ID | PTI | message type
            if len(payload) < 4:
                return
            msg_type = payload[3]
            if extracted["msg_type_name"] is None:
                extracted["msg_type_name"] = NAS_5GSM_MSG_TYPES.get(
                    msg_type, f"Unknown_0x{msg_type:02x}"
                )

    @staticmethod
    def _parse_ul_nas_transport(body: bytes, extracted: dict[str, Any]) -> None:
        """Walk UL NAS Transport (TS 24.501 8.2.10) and pull out the S-NSSAI IE (0x22)."""
        if len(body) < 3:
            return
        # octet 1: payload container type (spare nibble | type); then payload container (LV-E)
        container_len = int.from_bytes(body[1:3], "big")
        off = 3 + container_len
        while off < len(body):
            iei = body[off]
            if iei >= 0x80:  # type 1 (half-octet) IE
                off += 1
            elif iei in (0x12, 0x59):  # PDU session ID / old PDU session ID (TV, 2 octets)
                off += 2
            else:  # TLV
                if off + 2 > len(body):
                    return
                length = body[off + 1]
                if off + 2 + length > len(body):
                    return
                if iei == 0x22 and length in (1, 2, 4, 5, 8):
                    value = body[off + 2 : off + 2 + length]
                    sst = value[0]
                    sd = value[1:4].hex().upper() if length in (4, 5, 8) else None
                    extracted["sst"] = sst
                    extracted["sd"] = sd
                    extracted["requested_slices"] = [{"sst": sst, "sd": sd}]
                    return
                off += 2 + length

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
    def _decode_plmn(data: bytes) -> tuple[str, str] | None:
        """Decode the 3-octet PLMN (MCC/MNC) used in a SUCI (TS 24.501 / TS 23.003).

        Octet 1: MCC digit 2 | MCC digit 1
        Octet 2: MNC digit 3 | MCC digit 3   (MNC digit 3 == 0xF for 2-digit MNCs)
        Octet 3: MNC digit 2 | MNC digit 1
        """
        if len(data) < 3:
            return None
        mcc = f"{data[0] & 0x0F:x}{data[0] >> 4:x}{data[1] & 0x0F:x}"
        mnc = f"{data[2] & 0x0F:x}{data[2] >> 4:x}"
        if (data[1] >> 4) != 0x0F:
            mnc += f"{data[1] >> 4:x}"
        if not (mcc.isdigit() and mnc.isdigit()):
            return None
        return mcc, mnc

    @staticmethod
    def _bcd_low_first(data: bytes) -> str:
        """Decode TBCD (low nibble first), dropping 0xF filler nibbles."""
        digits: list[str] = []
        for byte in data:
            for nibble in (byte & 0x0F, byte >> 4):
                if nibble != 0x0F:
                    digits.append(f"{nibble:x}")
        return "".join(digits)

    @staticmethod
    def _extract_identity_from_mobile_id(data: bytes) -> tuple[str | None, str | int | None]:
        """
        Decode a 5GS Mobile Identity value (TS 24.501 section 9.11.3.4).

        Returns one of:
          ("IMSI", "<mcc><mnc><msin>")   SUCI with the null protection scheme
          ("SUCI_CONCEALED", <scheme>)   SUCI whose MSIN is encrypted (scheme != 0);
                                         the subscriber identity is NOT recoverable
          ("IMEI", "<15 digits>")        PEI carrying an IMEI
          ("IMEI", "<16 digits>")        PEI carrying an IMEISV (callers truncate)
          (None, None)                   unsupported or malformed
        """
        if not data:
            return None, None
        id_type = data[0] & 0x07

        if id_type == 1:  # SUCI
            # Octet 1 bits 5-7: SUPI format (0 = IMSI, 1 = network-specific identifier).
            if (data[0] >> 4) & 0x07 != 0:
                return None, None
            # Octets: 1 type | 2-4 PLMN | 5-6 routing indicator | 7 scheme | 8 home-network PKI | 9+ output
            if len(data) < 9:
                return None, None
            scheme = data[6] & 0x0F
            if scheme != 0:
                return "SUCI_CONCEALED", scheme
            plmn = NASParser._decode_plmn(data[1:4])
            if plmn is None:
                return None, None
            msin = NASParser._bcd_low_first(data[8:])
            imsi = plmn[0] + plmn[1] + msin
            if not imsi.isdigit() or not (6 <= len(imsi) <= 15):
                return None, None
            return "IMSI", imsi

        if id_type in (3, 5):  # IMEI / IMEISV
            # First digit sits in the HIGH nibble of octet 1; remaining digits are
            # TBCD (low nibble first) in the following octets. Odd/even is bit 4.
            digits = f"{data[0] >> 4:x}" + NASParser._bcd_low_first(data[1:])
            if digits.isdigit() and len(digits) in (15, 16):
                return "IMEI", digits[:15]

        return None, None

    @staticmethod
    def _apply_mobile_identity(extracted: dict[str, Any], id_bytes: bytes) -> None:
        """Decode a 5GS Mobile Identity and store the result in ``extracted``."""
        id_type, value = NASParser._extract_identity_from_mobile_id(id_bytes)
        if id_type == "IMSI":
            extracted["imsi"] = value
        elif id_type == "IMEI":
            extracted["imei"] = value
        elif id_type == "SUCI_CONCEALED":
            extracted["suci_concealed"] = True
            extracted["suci_scheme"] = value
