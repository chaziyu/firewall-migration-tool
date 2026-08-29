from fwmigrate.core.registry import PluginRegistry


def test_cisco_asa_is_advertised_without_ftd_alias():
    parser = PluginRegistry.get_parser("cisco_asa")
    assert parser.display_name == "Cisco ASA"
    assert "cisco_ftd" not in {
        item["vendor_id"] for item in PluginRegistry.list_source_vendors()
    }
