from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.fortigate import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


CUSTOM_SERVICE_NEVER_CONFIG = """config firewall service custom
    edit "tcp_23"
        set protocol TCP/UDP/SCTP
        set tcp-portrange 23
        set session-ttl never
    next
end
"""


def test_custom_service_session_ttl_never_is_valid_source_semantics() -> None:
    fg = parse_fortigate_config(CUSTOM_SERVICE_NEVER_CONFIG)

    assert len(fg.services) == 1
    service = fg.services[0]
    assert service.session_ttl == "never"
    assert service.extra_settings["session_ttl"] == "never"
    assert "unparsed_session_ttl" not in service.extra_settings
    assert fg.model_dump()["services"][0]["session_ttl"] == "never"


def test_custom_service_session_ttl_never_remains_visible_to_coverage() -> None:
    result = extract_fortigate_config(CUSTOM_SERVICE_NEVER_CONFIG)
    section = next(
        item
        for item in result.source_sections
        if item.path == "firewall service custom"
    )

    assert section.status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert "session_ttl" in section.semantic_unknowns
