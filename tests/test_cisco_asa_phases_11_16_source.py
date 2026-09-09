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


def test_management_access_and_http_state_are_structured_separately():
    cfg = CiscoASAParser("""interface Gi0/1
 nameif inside
ssh 192.0.2.0 255.255.255.0 inside
http server enable
management-access inside
ntp server 192.0.2.10 source inside
""").parse_raw()
    assert cfg.management_access_rules[0].protocol == "ssh"
    assert cfg.management_access_rules[0].interface == "inside"
    assert next(item for item in cfg.management_settings if item.setting == "http server").enabled is True
    assert cfg.system_settings.management_access_interface == "inside"
    assert cfg.ntp_servers[0].interface == "inside"


def test_failover_ha_fields_and_interface_references_are_structured():
    cfg = CiscoASAParser("""interface GigabitEthernet0/0
 nameif inside
interface GigabitEthernet0/1
 nameif failover
failover
failover lan unit primary
failover lan interface FO GigabitEthernet0/1
failover link STATE GigabitEthernet0/1
failover state link GigabitEthernet0/1
failover interface ip inside 192.0.2.1 255.255.255.0 standby 192.0.2.2
failover polltime unit 1 holdtime 15
monitor-interface inside
no monitor-interface outside
failover group 1
 primary
 priority 100
""").parse_raw()
    ha = cfg.failover_config
    assert ha.enabled is True and ha.unit_role == "primary"
    assert ha.lan_interface == "GigabitEthernet0/1"
    assert ha.state_link_interface == "GigabitEthernet0/1"
    assert ha.interface_ips[0].address_family == "ipv4"
    assert ha.interface_monitoring == {"inside": True, "outside": False}
    assert ha.failover_groups[0].unit_role == "primary"
    assert ha.failover_groups[0].priority == 100
    assert all(issue["resolved"] for issue in cfg.reference_issues if issue["reference_name"] != "outside")


def test_disabled_failover_is_final_state_and_unresolved_monitor_is_reported():
    cfg = CiscoASAParser("""no failover
no monitor-interface missing
""").parse_raw()
    assert cfg.failover_config.enabled is False
    assert any(issue["reference_name"] == "missing" for issue in cfg.reference_issues)
