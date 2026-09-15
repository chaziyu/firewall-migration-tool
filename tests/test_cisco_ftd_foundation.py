from fwmigrate.core.registry import PluginRegistry
from fwmigrate.parsers.cisco_ftd import CiscoFTDParser
from fwmigrate.parsers.cisco_ftd.extractor import extract_cisco_ftd_config
from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser


def test_ftd_is_independent_and_preserves_management_source():
    text = "configure network ipv4 manual 192.0.2.2 255.255.255.0 192.0.2.1\nmanagement gateway 192.0.2.1\nmanagement dns 192.0.2.53\nconfigure ssh-access-list MGMT\nnameif diagnostic Diagnostic0"
    parser = CiscoFTDParser(text)
    config = parser.parse_raw()
    assert len(config.management_settings) == 4
    assert config.management_ipv4 == "192.0.2.2"
    assert config.management_netmask == "255.255.255.0"
    assert config.management_gateway == "192.0.2.1"
    assert config.management_gateway == "192.0.2.1"
    assert config.management_dns_servers == ["192.0.2.53"]
    assert config.ssh_access_list == ["MGMT"]
    assert config.diagnostic_interface == "Diagnostic0"
    assert not isinstance(parser, CiscoASAParser)
    assert config.management_settings[0].source_attributes["raw_command"].startswith("configure network")
    assert parser.parse().metadata.source_vendor == "cisco_ftd"
    assert PluginRegistry.get_parser("cisco_ftd").vendor_id == "cisco_ftd"
    result = extract_cisco_ftd_config(text)
    assert result.inventory_items[0].source_attributes["raw"].startswith("configure network")


def test_ftd_text_is_explicitly_limited_and_blocks_generation():
    result = extract_cisco_ftd_config("""
interface GigabitEthernet0/0
 nameif inside
 ip address 192.0.2.1 255.255.255.0
route inside 0.0.0.0 0.0.0.0 192.0.2.254
""")

    assert result.input_source_type == "ftd-text-evidence"
    assert result.policy_extraction_supported is False
    assert result.nat_extraction_supported is False
    assert result.object_extraction_supported is False
    assert result.migration_complete is False
    assert result.generation_safe is False
    assert "FTD text input does not contain an authoritative managed NAT/policy representation" in result.blocking_reasons


def test_ftd_text_nat_and_object_commands_remain_unsupported_evidence():
    result = extract_cisco_ftd_config("""
object network INSIDE
 host 10.0.0.10
nat (inside,outside) source dynamic INSIDE interface
""")

    assert result.generation_safe is False
    assert result.migration_complete is False
    raw = "\n".join(item.raw_capture or "" for item in result.unsupported_items)
    assert "object network INSIDE" in raw
    assert "nat (inside,outside) source dynamic INSIDE interface" in raw
