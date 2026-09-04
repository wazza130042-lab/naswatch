"""
Synthetic 5G signaling PCAP generator for NASWatch.
Generates realistic SCTP / NGAP / NAS-5GS control-plane packets with Scapy:
1. Legit Subscribers (Allowed IMSI, matching IMEI, authorized S-NSSAI)
2. Rogue Devices (Unregistered IMSI attempting access)
3. Identity Spoofing / SIM Clones (Authorized IMSI with spoofed IMEI)
4. Slice Intrusions (Authorized IMSI accessing unprovisioned slice)
"""

from __future__ import annotations

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


def build_nas_registration_request(imsi: str) -> bytes:
    """
    Construct 5GS Registration Request NAS-PDU.
    EPD: 0x7E (5GS MM)
    Sec Header: 0x00 (Plain NAS)
    Msg Type: 0x41 (Registration Request)
    5GS Registration Type: 0x01 (Initial Registration)
    5GS Mobile Identity: SUCI / IMSI
    """
    bcd_imsi = encode_bcd(imsi)
    # Mobile identity format: [Type: 0x01 (SUPI/IMSI), Routing indicator (2 bytes), Protection scheme (1 byte), Home network PKI (1 byte), MSIN/BCD]
    mobile_id = b"\x01\x00\x00\x00\x00" + bcd_imsi
    id_len = len(mobile_id).to_bytes(2, "big")

    nas_payload = bytearray([0x7E, 0x00, 0x41, 0x01]) + id_len + mobile_id
    return bytes(nas_payload)


def build_nas_identity_response(imsi: str | None = None, imei: str | None = None) -> bytes:
    """
    Construct 5GS Identity Response NAS-PDU (Msg Type 0x5B).
    """
    if imsi:
        bcd = encode_bcd(imsi)
        mob_id = b"\x01\x00\x00\x00\x00" + bcd
    elif imei:
        bcd = encode_bcd(imei)
        mob_id = b"\x03" + bcd  # 0x03 = IMEI
    else:
        mob_id = b"\x01\x00"

    id_len = len(mob_id).to_bytes(2, "big")
    nas_payload = bytearray([0x7E, 0x00, 0x5B]) + id_len + mob_id
    return bytes(nas_payload)


def build_nas_security_mode_complete(imeisv: str) -> bytes:
    """
    Construct 5GS Security Mode Complete NAS-PDU (Msg Type 0x56) with embedded IMEISV.
    """
    bcd_imei = encode_bcd(imeisv)
    # IE 0x77 / 0x5c for IMEISV
    nas_payload = bytearray([0x7E, 0x00, 0x56, 0x77, len(bcd_imei)]) + bcd_imei
    return bytes(nas_payload)


def build_nas_pdu_session_establishment_request(sst: int, sd: str | None = None) -> bytes:
    """
    Construct 5GS PDU Session Establishment Request (Msg Type 0xC1) with S-NSSAI IE (0x22).
    """
    nas_payload = bytearray([0x2E, 0x00, 0xC1, 0x01])
    # S-NSSAI IE: IEI = 0x22
    if sd:
        sd_bytes = bytes.fromhex(sd.replace("0x", "").zfill(6))
        # Length 4: SST (1) + SD (3)
        nas_payload += bytearray([0x22, 0x04, sst]) + sd_bytes
    else:
        # Length 1: SST only
        nas_payload += bytearray([0x22, 0x01, sst])

    return bytes(nas_payload)


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
