from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.cisco_asa.extractor import extract_cisco_asa_config
from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser
from fwmigrate.parsers.cisco_asa.section_scanner import scan_cisco_asa_sections


def test_typed_class_map_header_is_not_misnamed_or_malformed():
    config = CiscoASAParser("""
class-map type inspect http match-any HTTP_CLASS
 match request body length gt 1000
 match not request uri regex class URLS
""").parse_raw()
    class_map = config.class_maps[0]
    assert class_map.name == "HTTP_CLASS"
    assert class_map.class_map_type == "inspect"
    assert class_map.inspection_protocol == "http"
    assert class_map.match_type == "match-any"
    assert class_map.match_any is True
    assert class_map.migration_status != "PARSE_ERROR"
    assert [item.match_type for item in class_map.matches] == ["inspection", "inspection"]
    assert class_map.matches[1].negated is True


def test_typed_policy_map_keeps_inspection_hierarchy_separate_from_mpf_classes():
    config = CiscoASAParser("""
class-map type inspect http match-all HTTP_CLASS
 match request body length gt 1000
policy-map type inspect http HTTP_POLICY
 class HTTP_CLASS
  drop-connection log
 match request header length gt 1000
  reset log
 parameters
  protocol-violation action drop-connection log
""").parse_raw()
    policy = config.policy_maps[0]
    assert policy.name == "HTTP_POLICY"
    assert policy.policy_map_type == "inspect"
    assert policy.inspection_protocol == "http"
    assert policy.migration_status != "PARSE_ERROR"
    assert policy.classes == []
    assert [item.kind for item in policy.inspection_sections] == ["class", "match", "parameters"]
    assert policy.inspection_sections[0].class_name == "HTTP_CLASS"
    assert policy.inspection_sections[0].actions == ["drop-connection log"]
    assert policy.inspection_sections[1].actions == ["reset log"]
    assert policy.parameter_lines == ["protocol-violation action drop-connection log"]


def test_combined_set_connection_and_tcp_normalization_reference_are_preserved():
    config = CiscoASAParser("""
class-map CM
 match any
tcp-map TCPNORM
 checksum-verification
policy-map PM
 class CM
  set connection conn-max 600 embryonic-conn-max 50 per-client-max 10 per-client-embryonic-max 5 syn-cookie-mss 1360 random-sequence-number disable
  set connection timeout embryonic 0:00:30 advanced-options TCPNORM
""").parse_raw()
    section = config.policy_maps[0].classes[0]
    first, second = section.connection_actions
    assert first.max_connections == 600
    assert first.max_embryonic == 50
    assert first.per_client_max == 10
    assert first.per_client_embryonic == 5
    assert first.syn_cookie_mss == 1360
    assert first.random_sequence_number == "disable"
    assert second.timeout_embryonic == "0:00:30"
    assert second.advanced_options == "TCPNORM"
    assert section.tcp_map == "TCPNORM"


def test_inspection_action_coverage_keeps_legacy_engines_structured():
    config = CiscoASAParser("""
class-map CM
 match any
policy-map PM
 class CM
  inspect h323 h225 H323_POLICY
  inspect pptp
  inspect rtsp
  inspect sqlnet
  inspect sunrpc
  inspect tftp
""").parse_raw()
    actions = config.policy_maps[0].classes[0].inspect_actions
    assert [item.protocol for item in actions] == ["h323", "pptp", "rtsp", "sqlnet", "sunrpc", "tftp"]
    assert actions[0].parameters == ["h225"]
    assert actions[0].policy_name == "H323_POLICY"
    assert all(item.migration_status != "PARSE_ERROR" for item in actions)


def test_dhcp_explicit_interface_clause_is_removed_from_values_and_pools_do_not_merge():
    config = CiscoASAParser("""
interface GigabitEthernet0/0
 nameif inside
interface GigabitEthernet0/1
 nameif guest
dhcpd address 192.0.2.10-192.0.2.20 inside
dhcpd dns 192.0.2.53 interface inside
dhcpd domain inside.example interface inside
dhcpd address 198.51.100.10-198.51.100.20 guest
dhcpd dns 198.51.100.53 interface guest
dhcpd domain guest.example interface guest
""").parse_raw()
    servers = {item.interface: item for item in config.dhcp_servers}
    assert set(servers) == {"inside", "guest"}
    assert servers["inside"].pool == "192.0.2.10-192.0.2.20"
    assert servers["inside"].dns_servers == ["192.0.2.53"]
    assert servers["inside"].domain_name == "inside.example"
    assert servers["guest"].pool == "198.51.100.10-198.51.100.20"
    assert servers["guest"].dns_servers == ["198.51.100.53"]
    assert all("interface" not in value for item in servers.values() for value in item.dns_servers)


def test_interface_mode_dhcprelay_is_attached_to_owning_interface():
    config = CiscoASAParser("""
interface GigabitEthernet0/0
 nameif inside
 dhcprelay server 192.0.2.53
 dhcprelay information trusted
""").parse_raw()
    relay = config.dhcp_relays[0]
    assert relay.server_entries[0].server == "192.0.2.53"
    assert relay.server_entries[0].interface == "GigabitEthernet0/0"
    assert relay.options == ["GigabitEthernet0/0: information trusted"]
    assert "dhcprelay server 192.0.2.53" not in config.interfaces[0].source_attributes.get("unmodeled_lines", [])


def test_threat_detection_statistics_use_grammar_specific_fields_and_keep_no_state():
    config = CiscoASAParser("""
threat-detection statistics host number-of-rate 3
threat-detection statistics tcp-intercept rate-interval 1 burst-rate 200 average-rate 100
no threat-detection statistics access-list
""").parse_raw()
    first, second, third = config.connection_controls
    assert first.statistics_target == "host" and first.number_of_rate == 3
    assert second.statistics_target == "tcp-intercept"
    assert second.rate_interval == 1 and second.burst_rate == 200 and second.average_rate == 100
    assert third.statistics_target == "access-list"
    assert third.enabled is False and third.negated is True


def test_dns_server_group_options_and_default_group_are_structured_in_order():
    config = CiscoASAParser("""
dns server-group DefaultDNS
 name-server 192.0.2.53
 domain-name example.com
 retries 5
 timeout 7
 expire-entry-timer minutes 2
 poll-timer minutes 30
dns-group DefaultDNS
""").parse_raw()
    group = config.dns_server_groups[0]
    assert group.retries == 5
    assert group.timeout == 7
    assert group.expire_entry_timer == 2
    assert group.poll_timer == 30
    assert group.child_order[-2:] == ["expire-entry-timer minutes 2", "poll-timer minutes 30"]
    assert config.dns_settings.default_server_group == "DefaultDNS"
    assert any(issue["reference_type"] == "dns_server_group" and issue["resolved"] for issue in config.reference_issues)


def test_http_server_state_is_separate_from_ipv6_management_access_rules():
    config = CiscoASAParser("""
interface GigabitEthernet0/0
 nameif inside
http server enable 8443
http server idle-timeout 30
http server session-timeout 120
http 2001:db8::/64 inside
no http server enable
""").parse_raw()
    assert config.http_server.enabled is False
    assert config.http_server.port == 8443
    assert config.http_server.idle_timeout == 30
    assert config.http_server.session_timeout == 120
    rule = next(item for item in config.management_access_rules if item.protocol == "http")
    assert rule.address_family == "ipv6"
    assert rule.source == "2001:db8::/64"
    assert rule.interface == "inside"


def test_trustpoint_metadata_is_structured_without_secret_material():
    config = CiscoASAParser("""
crypto ca trustpoint VPN_TP
 enrollment terminal
 subject-name CN=vpn.example
 keypair VPN_KEY
 revocation-check crl ocsp
 password super-secret-value
""").parse_raw()
    record = config.trustpoint_records[0]
    assert record.name == "VPN_TP"
    assert record.enrollment == "terminal"
    assert record.subject_name == "CN=vpn.example"
    assert record.keypair_reference == "VPN_KEY"
    assert record.revocation_check == ["crl", "ocsp"]
    assert record.source_attributes["secret_present"] is True
    assert "super-secret-value" not in record.model_dump_json()


def test_admin_context_is_global_forward_reference_and_changeto_admin_uses_resolved_name():
    config = CiscoASAParser("""
interface GigabitEthernet0/1
interface GigabitEthernet0/2
admin-context tenant-b
context tenant-a
 allocate-interface GigabitEthernet0/1 mapped-a
 config-url disk0:/tenant-a.cfg
context tenant-b
 allocate-interface GigabitEthernet0/2 mapped-b
 config-url disk0:/tenant-b.cfg
changeto admin
object network OWNED_BY_ADMIN
 host 10.0.0.1
""").parse_raw()
    by_name = {item.name: item for item in config.contexts}
    assert config.multi_context_system.admin_context_name == "tenant-b"
    assert config.multi_context_system.admin_context_resolved is True
    assert by_name["tenant-a"].admin_context is None
    assert by_name["tenant-b"].admin_context is True
    assert by_name["tenant-a"].allocated_interface_entries[0].mapped_name == "mapped-a"
    assert by_name["tenant-b"].allocated_interface_entries[0].mapped_name == "mapped-b"
    assert next(item for item in config.network_objects if item.name == "OWNED_BY_ADMIN").source_context == "tenant-b"


def test_section_scanner_and_extractor_surface_typed_child_parse_error():
    text = """class-map type inspect http match-all WEB
 match
"""
    section = scan_cisco_asa_sections(text)[0]
    assert section.path == "class-map type inspect"
    result = extract_cisco_asa_config(text)
    assert result.source_sections[0].status == ExtractionStatus.PARSE_ERROR
    assert result.inventory_items[1].status == ExtractionStatus.PARSE_ERROR
