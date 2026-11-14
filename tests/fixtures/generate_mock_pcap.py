"""
Synthetic 5G signaling PCAP generator for NASWatch.
Generates realistic SCTP / NGAP / NAS-5GS control-plane packets with Scapy:
1. Legit Subscribers (Allowed IMSI, matching IMEI, authorized S-NSSAI)
2. Rogue Devices (Unregistered IMSI attempting access)
3. Identity Spoofing / SIM Clones (Authorized IMSI with spoofed IMEI)
4. Slice Intrusions (Authorized IMSI accessing unprovisioned slice)
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from scapy.all import IP, SCTP, Raw, wrpcap


def encode_bcd(digits: str) -> bytes:
    """Encode a decimal string into 3GPP BCD nibble-swapped bytes."""
    if len(digits) % 2 != 0:
        digits += "f"
    encoded = bytearray()
    for i in range(0, len(digits), 2):
        low = int(digits[i], 16)
        high = int(digits[i + 1], 16)
        encoded.append((high << 4) | low)
    return bytes(encoded)


def encode_suci(imsi: str, mnc_len: int = 2, protection_scheme: int = 0) -> bytes:
    """
    Encode a 5GS Mobile Identity of type SUCI as laid out in TS 24.501 section 9.11.3.4:

      octet 1     : SUPI format (0 = IMSI) in bits 5-7 | identity type 1 (SUCI) in bits 1-3
      octets 2-4  : PLMN  (MCC digit 2|1, MNC digit 3|MCC digit 3, MNC digit 2|1)
      octets 5-6  : routing indicator
      octet 7     : protection scheme id (0 = null, 1 = Profile A, 2 = Profile B)
      octet 8     : home network public key identifier
      octets 9+   : scheme output (BCD MSIN for null scheme, ciphertext otherwise)
    """
    mcc, mnc, msin = imsi[:3], imsi[3 : 3 + mnc_len], imsi[3 + mnc_len :]
    mnc3 = mnc[2] if mnc_len == 3 else "f"
    plmn = bytes(
        [
            (int(mcc[1]) << 4) | int(mcc[0]),
            (int(mnc3, 16) << 4) | int(mcc[2]),
            (int(mnc[1]) << 4) | int(mnc[0]),
        ]
    )
    if protection_scheme == 0:
        output = encode_bcd(msin)
    else:
        # Opaque stand-in for ECIES output; the parser must never read this as digits.
        output = hashlib.sha256(msin.encode()).digest()
    return bytes([0x01]) + plmn + b"\x00\x00" + bytes([protection_scheme, 0x01 if protection_scheme else 0x00]) + output


def encode_imei_identity(digits: str) -> bytes:
    """Encode an IMEI (15 digits) or IMEISV (16 digits) 5GS Mobile Identity.

    The first digit lives in the HIGH nibble of octet 1 (with odd/even bit 4 and
    type 3 = IMEI / 5 = IMEISV in the low bits); the rest is TBCD, low nibble first.
    """
    id_type = 0x03 if len(digits) == 15 else 0x05
    odd = 0x08 if len(digits) % 2 else 0x00
    first = (int(digits[0]) << 4) | odd | id_type
    return bytes([first]) + encode_bcd(digits[1:])


def build_nas_registration_request(
    imsi: str, mnc_len: int = 2, protection_scheme: int = 0
) -> bytes:
    """
    Construct 5GS Registration Request NAS-PDU.
    EPD: 0x7E (5GS MM)
    Sec Header: 0x00 (Plain NAS)
    Msg Type: 0x41 (Registration Request)
    5GS Registration Type: 0x01 (Initial Registration)
    5GS Mobile Identity: SUCI (spec layout, see ``encode_suci``)
    """
    mobile_id = encode_suci(imsi, mnc_len=mnc_len, protection_scheme=protection_scheme)
    id_len = len(mobile_id).to_bytes(2, "big")
    nas_payload = bytearray([0x7E, 0x00, 0x41, 0x01]) + id_len + mobile_id
    return bytes(nas_payload)


def build_nas_identity_response(imsi: str | None = None, imei: str | None = None) -> bytes:
    """
    Construct 5GS Identity Response NAS-PDU (Msg Type 0x5C; 0x5B is Identity Request).
    """
    if imsi:
        mob_id = encode_suci(imsi)
    elif imei:
        mob_id = encode_imei_identity(imei)
    else:
        mob_id = b"\x01\x00"

    id_len = len(mob_id).to_bytes(2, "big")
    nas_payload = bytearray([0x7E, 0x00, 0x5C]) + id_len + mob_id
    return bytes(nas_payload)


def build_nas_security_mode_complete(imeisv: str) -> bytes:
    """
    Construct 5GS Security Mode Complete NAS-PDU (Msg Type 0x5E) carrying the optional
    IMEISV IE (IEI 0x77, TLV-E) whose value is a 5GS mobile identity of type IMEISV.
    """
    ident = encode_imei_identity(imeisv)
    return bytes([0x7E, 0x00, 0x5E, 0x77]) + len(ident).to_bytes(2, "big") + ident


def build_nas_pdu_session_establishment_request(sst: int, sd: str | None = None) -> bytes:
    """
    Construct a 5GMM UL NAS Transport (0x67) carrying a 5GSM PDU Session Establishment
    Request (0xC1) as its N1 SM payload container, plus the PDU session ID IE (0x12)
    and the S-NSSAI IE (0x22) that selects the slice.
    """
    # 5GSM: EPD 0x2E | PDU session ID | PTI | message type | integrity protection max data rate
    sm_message = bytes([0x2E, 0x01, 0x01, 0xC1, 0xFF, 0xFF])
    nas = bytearray([0x7E, 0x00, 0x67, 0x01]) + len(sm_message).to_bytes(2, "big") + sm_message
    nas += bytearray([0x12, 0x01])  # PDU session ID IE
    if sd:
        sd_bytes = bytes.fromhex(sd.replace("0x", "").zfill(6))
        nas += bytearray([0x22, 0x04, sst]) + sd_bytes
    else:
        nas += bytearray([0x22, 0x01, sst])
    return bytes(nas)


def build_mock_signaling_pcap(output_path: str = "data/pcaps/5g_signaling_demo.pcap") -> str:
    """
    Generates a full synthetic PCAP file containing both legitimate 5G signaling and 3 distinct attack vectors:
    - Packet 1-2: Legitimate device registration & session setup
    - Packet 3: Rogue eSIM / unauthorized IMSI
    - Packet 4: Identity Spoofing / SIM cloning (valid IMSI + spoofed IMEI)
    - Packet 5: Slice Intrusion (valid IMSI attempting unauthorized critical slice)
    - Packet 6: Suspended subscriber attempting registration
    """
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    packets = []

    # gNB IP: 192.168.56.10, AMF IP: 192.168.56.20
    gnb_ip = "192.168.56.10"
    amf_ip = "192.168.56.20"

    # 1. Legitimate Device Registration (IMSI: 999700000000001, IMEI: 860123456789012)
    nas1 = build_nas_registration_request("999700000000001")
    nas1_imei = build_nas_security_mode_complete("8601234567890120")
    pkt1 = IP(src=gnb_ip, dst=amf_ip) / SCTP(sport=38412, dport=38412) / Raw(load=nas1 + nas1_imei)
    packets.append(pkt1)

    # 2. Legitimate PDU Session Request (S-NSSAI SST=1, SD="000001" - eMBB)
    nas2 = build_nas_pdu_session_establishment_request(sst=1, sd="000001")
    # Include IMSI identity context in session
    nas2_id = build_nas_identity_response(imsi="999700000000001", imei="860123456789012")
    pkt2 = IP(src=gnb_ip, dst=amf_ip) / SCTP(sport=38412, dport=38412) / Raw(load=nas2_id + nas2)
    packets.append(pkt2)

    # 3. Rogue Device (IMSI: 999700000000999 - Not in inventory)
    nas3 = build_nas_registration_request("999700000000999")
    pkt3 = IP(src=gnb_ip, dst=amf_ip) / SCTP(sport=38412, dport=38412) / Raw(load=nas3)
    packets.append(pkt3)

    # 4. Identity Spoofing / SIM Cloning (IMSI: 999700000000001 with Cloned IMEI: 869999999999999)
    nas4 = build_nas_registration_request("999700000000001")
    nas4_fake_imei = build_nas_security_mode_complete("8699999999999990")
    pkt4 = IP(src=gnb_ip, dst=amf_ip) / SCTP(sport=38412, dport=38412) / Raw(load=nas4 + nas4_fake_imei)
    packets.append(pkt4)

    # 5. Slice Intrusion (IMSI: 999700000000002 authorized only for eMBB, requests URLLC SST=2, SD="000002")
    nas5_id = build_nas_identity_response(imsi="999700000000002", imei="860123456789022")
    nas5_slice = build_nas_pdu_session_establishment_request(sst=2, sd="000002")
    pkt5 = IP(src=gnb_ip, dst=amf_ip) / SCTP(sport=38412, dport=38412) / Raw(load=nas5_id + nas5_slice)
    packets.append(pkt5)

    # 6. Suspended Subscriber Access (IMSI: 999700000000003 - SUSPENDED)
    nas6 = build_nas_registration_request("999700000000003")
    pkt6 = IP(src=gnb_ip, dst=amf_ip) / SCTP(sport=38412, dport=38412) / Raw(load=nas6)
    packets.append(pkt6)

    wrpcap(str(output_path), packets)
    return str(output_path)


if __name__ == "__main__":
    out = build_mock_signaling_pcap()
    print(f"Generated synthetic 5G signaling PCAP with 6 packets at: {out}")
