"""
Regression tests for bugs found in the code review:

  * NAS parsing against TS 24.501 (SUCI layout, concealed SUCI, message-type table,
    secured NAS, 5GSM header, IMEISV, S-NSSAI in UL NAS Transport)
  * Flood rule measured in packet time (not wall-clock time)
  * Alert-storm suppression and bounded engine state
  * Scapy fallback no longer invents an authorized cell ID
  * Correlation updates one incident per subject and never mixes tenants

The NAS fixtures are additionally cross-checked against Wireshark's nas-5gs dissector when
tshark is installed (the test is skipped otherwise), so the parser is not only tested against
the author's own encoding.
"""

from __future__ import annotations

import shutil
import subprocess
from datetime import UTC, datetime, timedelta

import pytest
from scapy.all import IP, SCTP, Raw
from scapy.utils import PcapWriter

from naswatch.correlation.engine import CorrelationEngine
from naswatch.detection.engine import DetectionEngine
from naswatch.parsing.nas_parser import NAS_5GS_MSG_TYPES, NASParser
from naswatch.parsing.ngap_parser import NGAPParser
from naswatch.storage.models import (
    Alert,
    AlertRuleType,
    AlertSeverity,
    ParsedSignalingEvent,
)
from tests.fixtures.generate_mock_pcap import (
    build_nas_identity_response,
    build_nas_pdu_session_establishment_request,
    build_nas_registration_request,
    build_nas_security_mode_complete,
    encode_imei_identity,
)

T0 = datetime(2020, 1, 1, tzinfo=UTC)


class EmptyRepo:
    """Device repository with no provisioned subscribers."""

    def get_by_imsi(self, *args, **kwargs):
        return None

    def get_by_imei(self, *args, **kwargs):
        return None


def reg_event(imsi: str, when: datetime, procedure: str = "RegistrationRequest") -> ParsedSignalingEvent:
    return ParsedSignalingEvent(timestamp=when, procedure_name=procedure, imsi=imsi)


def alert(rule: AlertRuleType, *, imsi=None, cell=None, org="default", at=T0, sev=AlertSeverity.HIGH) -> Alert:
    return Alert(
        rule_type=rule, severity=sev, title="t", description="d",
        imsi=imsi, cell_id=cell, org_id=org, timestamp=at,
    )


# --------------------------------------------------------------------------- NAS parsing
def test_null_scheme_suci_yields_full_imsi_with_mcc_mnc():
    parsed = NASParser.parse_raw_nas(build_nas_registration_request("001010000000001"))
    assert parsed["imsi"] == "001010000000001"
    assert parsed["suci_concealed"] is False


def test_three_digit_mnc_is_decoded():
    parsed = NASParser.parse_raw_nas(build_nas_registration_request("310260123456789", mnc_len=3))
    assert parsed["imsi"] == "310260123456789"


@pytest.mark.parametrize("scheme", [1, 2])
def test_concealed_suci_is_never_read_as_an_imsi(scheme):
    parsed = NASParser.parse_raw_nas(
        build_nas_registration_request("001010000000001", protection_scheme=scheme)
    )
    assert parsed["imsi"] is None
    assert parsed["suci_concealed"] is True
    assert parsed["suci_scheme"] == scheme


def test_concealed_suci_does_not_raise_rogue_device_alert():
    """A protected SUCI is working-as-designed privacy, not an unknown subscriber."""
    payload = build_nas_registration_request("001010000000001", protection_scheme=1)
    event = ParsedSignalingEvent(timestamp=T0)
    NGAPParser._note_concealed_suci(event, NASParser.parse_raw_nas(payload))
    assert event.imsi is None
    assert event.metadata["suci_concealed"] is True
    assert DetectionEngine(EmptyRepo(), enable_flood_rule=False).process_event(event) == []


def test_imei_and_imeisv_mobile_identity_first_digit_in_octet_one():
    imei = "860123456789012"
    assert encode_imei_identity(imei)[0] >> 4 == 8  # first digit is the high nibble of octet 1
    assert NASParser.parse_raw_nas(build_nas_identity_response(imei=imei))["imei"] == imei
    sv = NASParser.parse_raw_nas(build_nas_security_mode_complete("8601234567890120"))
    assert sv["imei"] == "860123456789012"  # IMEISV truncated to the 15-digit IMEI base


@pytest.mark.parametrize(
    "code,name",
    [
        (0x4C, "ServiceRequest"),
        (0x56, "AuthenticationRequest"),
        (0x5B, "IdentityRequest"),
        (0x5C, "IdentityResponse"),
        (0x5D, "SecurityModeCommand"),
        (0x5E, "SecurityModeComplete"),
    ],
)
def test_message_type_table_matches_ts_24_501(code, name):
    assert NAS_5GS_MSG_TYPES[code] == name
    assert NASParser.parse_raw_nas(bytes([0x7E, 0x00, code, 0, 0, 0]))["msg_type_name"] == name


def test_identity_request_carries_no_identity():
    """0x5B is the network's Identity *Request*; it must not be parsed as a UE identity."""
    assert NASParser.parse_raw_nas(bytes([0x7E, 0x00, 0x5B, 0x01, 0x00]))["imsi"] is None


def test_5gsm_message_type_is_fourth_octet():
    # EPD | PDU session id | PTI | type
    parsed = NASParser.parse_raw_nas(bytes([0x2E, 0x01, 0x01, 0xC1, 0xFF, 0xFF]))
    assert parsed["msg_type_name"] == "PDUSessionEstablishmentRequest"


def test_security_protected_nas_is_unwrapped():
    inner = build_nas_registration_request("001010000000001")
    secured = bytes([0x7E, 0x01]) + b"\xde\xad\xbe\xef" + b"\x00" + inner  # integrity protected
    parsed = NASParser.parse_raw_nas(secured)
    assert parsed["msg_type_name"] == "RegistrationRequest"
    assert parsed["imsi"] == "001010000000001"


def test_slice_comes_from_ul_nas_transport_s_nssai_ie():
    with_sd = NASParser.parse_raw_nas(build_nas_pdu_session_establishment_request(2, "000002"))
    assert (with_sd["sst"], with_sd["sd"]) == (2, "000002")
    assert with_sd["requested_slices"] == [{"sst": 2, "sd": "000002"}]
    no_sd = NASParser.parse_raw_nas(build_nas_pdu_session_establishment_request(1))
    assert (no_sd["sst"], no_sd["sd"]) == (1, None)


def test_random_bytes_do_not_produce_identities():
    for blob in (b"\x00\xff\xee\xdd\xcc\xbb\xaa\x99", bytes(range(64)), b"\x77\x00\x09" * 8):
        parsed = NASParser.parse_raw_nas(blob)
        assert parsed["imsi"] is None and parsed["imei"] is None


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
def test_fixtures_agree_with_wiresharks_nas_5gs_dissector(tmp_path):
    cases = {
        "reg": build_nas_registration_request("999700000000001"),
        "reg3": build_nas_registration_request("310260123456789", mnc_len=3),
        "idresp": build_nas_identity_response(imei="860123456789012"),
        "smc": build_nas_security_mode_complete("8601234567890120"),
        "ul": build_nas_pdu_session_establishment_request(2, "000002"),
    }
    pcap = tmp_path / "nas.pcap"
    writer = PcapWriter(str(pcap), linktype=147)  # DLT_USER0, mapped to nas-5gs below
    for payload in cases.values():
        writer.write(Raw(load=payload))
    writer.close()

    out = subprocess.run(
        ["tshark", "-o", 'uat:user_dlts:"User 0 (DLT=147)","nas-5gs","0","","0",""',
         "-r", str(pcap), "-T", "fields", "-E", "separator=|", "-E", "occurrence=f",
         "-e", "nas-5gs.mm.message_type", "-e", "e212.mcc", "-e", "e212.mnc",
         "-e", "nas-5gs.mm.suci.msin", "-e", "nas-5gs.mm.imei", "-e", "nas-5gs.mm.imeisv",
         "-e", "nas-5gs.mm.sst", "-e", "nas-5gs.mm.mm_sd"],
        capture_output=True, text=True, check=True,
    ).stdout.strip().splitlines()
    rows = [line.split("|") for line in out if line.count("|") == 7]
    assert len(rows) == len(cases)

    by_name = dict(zip(cases, rows, strict=True))
    for name in ("reg", "reg3"):
        _, mcc, mnc, msin, *_ = by_name[name]
        assert NASParser.parse_raw_nas(cases[name])["imsi"] == mcc + mnc + msin
    assert NASParser.parse_raw_nas(cases["idresp"])["imei"] == by_name["idresp"][4]
    assert NASParser.parse_raw_nas(cases["smc"])["imei"] == by_name["smc"][5][:15]
    ul = NASParser.parse_raw_nas(cases["ul"])
    assert ul["sst"] == int(by_name["ul"][6], 0)
    assert int(ul["sd"], 16) == int(by_name["ul"][7], 0)


# --------------------------------------------------------------------------- flood rule
def test_flood_rule_uses_packet_time_not_wall_clock():
    engine = DetectionEngine(EmptyRepo(), enable_rogue_rule=False, flood_threshold=10, flood_window_seconds=60)
    fired = []
    for i in range(30):  # one registration per hour of *capture* time, replayed instantly
        fired += [a for a in engine.process_event(reg_event("001010000000009", T0 + timedelta(hours=i)))
                  if a.rule_type == AlertRuleType.SIGNALING_FLOOD]
    assert fired == []


def test_flood_rule_fires_for_a_real_storm_even_in_an_old_capture():
    engine = DetectionEngine(EmptyRepo(), enable_rogue_rule=False, flood_threshold=10, flood_window_seconds=60)
    fired = []
    for i in range(30):  # 30 registrations within 3 seconds of capture time
        fired += [a for a in engine.process_event(reg_event("001010000000009", T0 + timedelta(milliseconds=100 * i)))
                  if a.rule_type == AlertRuleType.SIGNALING_FLOOD]
    assert len(fired) == 1  # one alert for the storm, not one per packet past the threshold
    assert fired[0].raw_event["rate_count"] > 10


# --------------------------------------------------------------------------- alert storms
def test_repeated_identical_alerts_are_suppressed_then_counted():
    engine = DetectionEngine(EmptyRepo(), enable_flood_rule=False, alert_cooldown_seconds=60)
    first = []
    for i in range(50):
        first += engine.process_event(reg_event("001010000000777", T0 + timedelta(seconds=i * 0.5), "UplinkNASTransport"))
    assert len(first) == 1
    after = engine.process_event(reg_event("001010000000777", T0 + timedelta(seconds=90), "UplinkNASTransport"))
    assert len(after) == 1
    assert after[0].raw_event["suppressed_duplicates"] == 49


def test_suppression_is_per_subscriber_and_can_be_disabled():
    engine = DetectionEngine(EmptyRepo(), enable_flood_rule=False, alert_cooldown_seconds=60)
    a = engine.process_event(reg_event("001010000000001", T0, "UplinkNASTransport"))
    b = engine.process_event(reg_event("001010000000002", T0, "UplinkNASTransport"))
    assert len(a) == 1 and len(b) == 1

    off = DetectionEngine(EmptyRepo(), enable_flood_rule=False, alert_cooldown_seconds=0)
    assert sum(len(off.process_event(reg_event("001010000000001", T0, "UplinkNASTransport"))) for _ in range(5)) == 5


def test_engine_state_is_garbage_collected():
    engine = DetectionEngine(EmptyRepo(), flood_window_seconds=60, alert_cooldown_seconds=60)
    engine._GC_EVERY = 10
    for i in range(200):
        engine.process_event(reg_event(f"0010100000{i:05d}", T0))
    assert len(engine._rate_tracker) > 100
    for i in range(20):  # two hours later: old windows and suppression entries are irrelevant
        engine.process_event(reg_event("001010099999999", T0 + timedelta(hours=2, seconds=i)))
    assert len(engine._rate_tracker) <= 2
    assert len(engine._recent_alerts) <= 2


# --------------------------------------------------------------------------- scapy fallback
def test_scapy_fallback_does_not_invent_an_authorized_cell():
    pkt = IP(src="192.168.56.10", dst="192.168.56.20") / SCTP() / Raw(
        load=build_nas_registration_request("999700000000001")
    )
    pkt.time = 1_600_000_000.0
    event = NGAPParser.parse_scapy_packet(pkt)
    assert event.imsi == "999700000000001"
    assert event.cell_id is None and event.tac is None
    assert event.metadata["cell_unknown"] is True
    assert event.timestamp == datetime.fromtimestamp(1_600_000_000.0, tz=UTC)


def test_false_base_station_rule_still_fires_for_a_real_unknown_cell():
    engine = DetectionEngine(EmptyRepo(), enable_rogue_rule=False, authorized_cells=["0x000000010"])
    event = ParsedSignalingEvent(timestamp=T0, cell_id="0x0000000FF", imsi="001010000000001")
    assert [a.rule_type for a in engine.process_event(event)] == [AlertRuleType.FALSE_BASE_STATION]


# --------------------------------------------------------------------------- correlation
def test_same_subscriber_alerts_form_one_updating_incident():
    engine = CorrelationEngine(window_seconds=60)
    first = engine.ingest(alert(AlertRuleType.SIGNALING_FLOOD, imsi="001", at=T0))
    for i in range(1, 50):
        again = engine.ingest(alert(AlertRuleType.SIGNALING_FLOOD, imsi="001", at=T0 + timedelta(seconds=i)))
        assert again is first
    assert len(engine.get_incidents()) == 1
    assert len(first.alerts) == 50

    escalated = engine.ingest(alert(AlertRuleType.ROGUE_DEVICE, imsi="001", at=T0 + timedelta(seconds=51)))
    assert escalated is first and escalated.escalated and escalated.severity == AlertSeverity.CRITICAL


def test_different_subscribers_are_separate_incidents():
    engine = CorrelationEngine()
    a = engine.ingest(alert(AlertRuleType.ROGUE_DEVICE, imsi="001"))
    b = engine.ingest(alert(AlertRuleType.ROGUE_DEVICE, imsi="002"))
    assert a is not b and len(engine.get_incidents()) == 2


def test_incident_closes_after_the_window_using_alert_time():
    engine = CorrelationEngine(window_seconds=60)
    a = engine.ingest(alert(AlertRuleType.ROGUE_DEVICE, imsi="001", at=T0))
    b = engine.ingest(alert(AlertRuleType.ROGUE_DEVICE, imsi="001", at=T0 + timedelta(seconds=61)))
    assert a is not b


def test_alert_bridging_two_incidents_merges_them():
    engine = CorrelationEngine()
    a = engine.ingest(alert(AlertRuleType.CIPHER_DOWNGRADE, imsi="001", cell="0x1"))
    b = engine.ingest(alert(AlertRuleType.FALSE_BASE_STATION, imsi="002", cell="0x2"))
    assert a is not b
    merged = engine.ingest(alert(AlertRuleType.ROGUE_DEVICE, imsi="001", cell="0x2"))
    assert merged is a
    assert {r for r in merged.rule_types} >= {AlertRuleType.CIPHER_DOWNGRADE, AlertRuleType.FALSE_BASE_STATION}
    assert merged.escalated and len(engine.get_incidents()) == 1


def test_correlation_never_mixes_tenants():
    engine = CorrelationEngine()
    a = engine.ingest(alert(AlertRuleType.SIGNALING_FLOOD, imsi="001", org="org-A"))
    b = engine.ingest(alert(AlertRuleType.ROGUE_DEVICE, imsi="001", org="org-B"))
    assert a is not b
    assert not a.escalated and not b.escalated  # a flood in A must not escalate a rogue in B
    assert [i.incident_id for i in engine.get_incidents(org_id="org-A")] == [a.incident_id]
    assert [i.incident_id for i in engine.get_incidents(org_id="org-B")] == [b.incident_id]


def test_history_is_bounded_and_uncorrelatable_alerts_are_ignored():
    engine = CorrelationEngine(max_history=5)
    for i in range(20):
        engine.ingest(alert(AlertRuleType.ROGUE_DEVICE, imsi=f"{i:03d}"))
    assert len(engine.get_incidents(limit=100)) == 5
    assert engine.ingest(alert(AlertRuleType.ROGUE_DEVICE)) is None
