from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser
from fwmigrate.parsers.cisco_asa.section_scanner import scan_cisco_asa_sections
from fwmigrate.parsers.cisco_ftd.section_scanner import scan_cisco_ftd_sections
from fwmigrate.parsers.cisco_ftd.parser import CiscoFTDParser


def test_asa_negation_is_preserved_without_inverting_unrelated_state():
    config = CiscoASAParser("no access-list OLD extended permit ip any any").parse_raw()
    assert config.access_rules == []
    assert config.unsupported_commands[0]["raw_line"].startswith("no access-list")


def test_asa_scanner_keeps_repeated_children_in_parent_range():
    sections = scan_cisco_asa_sections("interface Gi0/1\n description one\n no shutdown\naaa-server RAD protocol radius\n host 192.0.2.10\ninterface Gi0/2\n shutdown\n")
    assert sections[0].path == "interface"
    assert sections[0].line_end == 3
    assert sections[1].path == "aaa-server"
    assert sections[1].line_end == 5
    assert sections[2].path == "interface"


def test_ftd_scanner_tracks_hierarchy_and_boundaries():
    sections = scan_cisco_ftd_sections("configure network\n  ipv4 manual 192.0.2.2\nmanagement gateway 192.0.2.1\n")
    assert sections[0].line_end == 2
    assert sections[1].path == "management"


def test_ftd_negation_is_preserved_as_source_state():
    config = CiscoFTDParser("no management gateway 192.0.2.1").parse_raw()
    assert config.management_settings[0].source_attributes["negated"] is True


def test_ftd_documented_cmi_negation_keeps_final_state():
    config = CiscoFTDParser("show management-interface convergence\nno management-interface convergence").parse_raw()
    assert config.cmi_enabled is False
