from fwmigrate.core.registry import PluginRegistry


def test_cisco_asa_and_ftd_are_advertised_as_separate_sources():
    parser = PluginRegistry.get_parser("cisco_asa")
    assert parser.display_name == "Cisco ASA"
    assert PluginRegistry.get_parser("cisco_ftd").display_name == "Cisco Firepower Threat Defense"
    assert parser.vendor_id != PluginRegistry.get_parser("cisco_ftd").vendor_id
