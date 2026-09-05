from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser
from fwmigrate.parsers.cisco_asa.section_scanner import scan_cisco_asa_sections


def test_phases_11_to_16_keep_source_values_and_boundaries():
    text = """dhcpd address 192.0.2.10-192.0.2.20 inside
dhcprelay server 192.0.2.53 inside
dns server-group corp
 name-server 192.0.2.53
 name-server 2001:db8::53
threat-detection basic-threat
failover
 context admin
  config-url disk0:/admin.cfg
  allocate-interface Gi0/1
"""
    cfg = CiscoASAParser(text).parse_raw()
    assert cfg.dhcp_servers[0].pool == "192.0.2.10-192.0.2.20"
    assert cfg.dhcp_relays[0].server == "192.0.2.53"
    assert cfg.dns_server_groups[0].name_servers == ["192.0.2.53", "2001:db8::53"]
    assert cfg.connection_controls[0].source_attributes["raw_command"] == "threat-detection basic-threat"
    assert cfg.failover_settings[0].source_attributes["raw_command"] == "failover"
    assert cfg.contexts[0].config_url == "disk0:/admin.cfg"
    assert cfg.contexts[0].allocated_interfaces == ["Gi0/1"]

    paths = [section.path for section in scan_cisco_asa_sections(text)]
    assert "dhcpd" in paths and "dhcprelay" in paths
    assert "dns" in paths and "threat-detection" in paths
