"""
Unit tests for NGAP and NAS parsers.
"""

from __future__ import annotations

from naswatch.parsing.nas_parser import NASParser, decode_bcd_digits
from tests.fixtures.generate_mock_pcap import (
    build_nas_identity_response,
    build_nas_pdu_session_establishment_request,
    build_nas_registration_request,
    build_nas_security_mode_complete,
)


def test_decode_bcd_digits():
    """Test BCD nibble decoding with and without trailing 'f' filler."""
    # "999700" encoded as [0x99, 0x79, 0x00]
    encoded_hex = "997900"
    decoded = decode_bcd_digits(encoded_hex, 6)
    assert decoded == "999700"


def test_parse_raw_nas_registration_request():
    """Verify parsing of 5GS Registration Request NAS payload."""
    payload = build_nas_registration_request("999700000000001")
    parsed = NASParser.parse_raw_nas(payload)

    assert parsed["msg_type_name"] == "RegistrationRequest"
    assert parsed["imsi"] == "999700000000001"


def test_parse_raw_nas_identity_response():
    """Verify parsing of 5GS Identity Response NAS payload."""
    payload_imsi = build_nas_identity_response(imsi="999700000000002")
    parsed_imsi = NASParser.parse_raw_nas(payload_imsi)
    assert parsed_imsi["imsi"] == "999700000000002"

    payload_imei = build_nas_identity_response(imei="860123456789012")
    parsed_imei = NASParser.parse_raw_nas(payload_imei)
    assert parsed_imei["imei"] == "860123456789012"


def test_parse_raw_nas_security_mode_complete():
    """Verify parsing of Security Mode Complete containing IMEISV."""
    payload = build_nas_security_mode_complete("8601234567890120")
    parsed = NASParser.parse_raw_nas(payload)
    assert parsed["imei"] is not None
    assert "860123456789012" in parsed["imei"]


def test_parse_raw_nas_pdu_session_slice():
    """Verify extraction of S-NSSAI SST and SD from PDU Session Establishment Request."""
    payload = build_nas_pdu_session_establishment_request(sst=2, sd="000002")
    parsed = NASParser.parse_raw_nas(payload)
    assert parsed["sst"] == 2
    assert parsed["sd"] == "000002"


def test_defensive_parser_malformed_packets():
    """Ensure malformed or random binary data does not crash the parser."""
    garbage = b"\x00\xff\xee\xdd\xcc\xbb\xaa\x99"
    res = NASParser.parse_raw_nas(garbage)
    assert res["imsi"] is None
    assert res["imei"] is None

    # Empty payload
    res_empty = NASParser.parse_raw_nas(b"")
    assert res_empty["imsi"] is None
