from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser
from fwmigrate.parsers.cisco_asa.extractor import extract_cisco_asa_config


def parse(text: str):
    return CiscoASAParser(text).parse_raw()


def test_unverified_top_level_connection_limits_are_preserved_not_invented():
    config = parse("""
conn-max 100
embryonic-conn-max 20
per-client-max 5
per-client-embryonic-max 2
""")
    assert [(item.control_type, item.source_order) for item in config.connection_controls] == [
        ("unverified_global_connection", 2),
        ("unverified_global_connection", 3),
        ("unverified_global_connection", 4),
        ("unverified_global_connection", 5),
    ]
    assert [item.migration_status for item in config.connection_controls] == ["UNSUPPORTED"] * 4
    assert [item.source_attributes["unmodeled_tokens"] for item in config.connection_controls] == [
        ["100"], ["20"], ["5"], ["2"],
    ]
    assert config.connection_controls[0].max_connections is None
    assert config.connection_controls[1].max_embryonic is None
    assert config.connection_controls[2].per_client_max is None
    assert config.connection_controls[3].per_client_embryonic is None


def test_timeout_domains_and_explicit_zero_remain_separate():
    config = parse("""
timeout conn 0:10:00
timeout half-closed 0:00:00
timeout udp 1:02:03
""")
    assert config.connection_controls[0].timeout_tcp == "0:10:00"
    assert config.connection_controls[1].timeout_half_closed == "0:00:00"
    assert config.connection_controls[2].timeout_udp == "1:02:03"


def test_malformed_timeout_is_a_parse_error_but_parser_continues():
    config = parse("""
timeout conn 1:60:00
timeout udp 0:00:30
""")
    assert config.connection_controls[0].migration_status == "PARSE_ERROR"
    assert config.connection_controls[1].timeout_udp == "0:00:30"
    assert config.parse_errors[0]["section"] == "timeout"


def test_threat_detection_rates_are_typed_and_unknown_variants_preserved():
    config = parse("""
threat-detection basic-threat
threat-detection rate average-rate 10 burst-rate 20 interval 60
threat-detection future-mode value
""")
    rate = config.connection_controls[1]
    assert (rate.threat_detection_type, rate.rate, rate.burst, rate.source_attributes["interval"]) == ("rate", 10, 20, 60)
    assert config.connection_controls[2].requires_manual_review
    assert config.connection_controls[2].source_attributes["raw_command"] == "threat-detection future-mode value"


def test_connection_control_coverage_reflects_verified_support():
    result = extract_cisco_asa_config("""
conn-max 100
timeout conn 0:10:00
threat-detection basic-threat
""")
    assert [section.status for section in result.source_sections] == [
        ExtractionStatus.UNSUPPORTED,
        ExtractionStatus.PARTIALLY_NORMALIZED,
        ExtractionStatus.PARTIALLY_NORMALIZED,
    ]


def test_threat_detection_disable_is_explicit_and_covered():
    config = parse("no threat-detection basic-threat")
    assert config.connection_controls[0].threat_detection_type == "basic-threat"
    assert config.connection_controls[0].enabled is False
    result = extract_cisco_asa_config("no threat-detection basic-threat")
    assert result.source_sections[0].status == ExtractionStatus.PARTIALLY_NORMALIZED
