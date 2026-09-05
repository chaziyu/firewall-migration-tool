from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_non_root_system_commands_do_not_bleed_into_root():
    parser = JuniperSRXParser("""
    set system host-name root-fw
    set system time-zone UTC
    set tenants T1 system host-name tenant-fw
    set logical-systems LS1 system time-zone Asia/Kuala_Lumpur
    set logical-systems LS1 system syslog host 192.0.2.10 any emergency
    set tenants T1 system syslog host 192.0.2.11 any emergency
    """)
    parser.extract()
    config = parser.config
    assert config.hostname == "root-fw"
    assert config.time_zone == "UTC"
    assert config.contexts["LS1"].system_syslog.destinations
    assert config.contexts["T1"].source_attributes["unsupported_system"]


def test_context_system_commands_are_accounted_for_with_review():
    parser = JuniperSRXParser("set tenants T1 system host-name tenant-fw")
    result = parser.extract()
    context = parser.config.contexts["T1"]
    assert result.canonical_ir
    assert context.source_attributes["unsupported_system"]
