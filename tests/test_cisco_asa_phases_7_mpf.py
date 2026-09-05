from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.cisco_asa.extractor import extract_cisco_asa_config
from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser
from fwmigrate.parsers.cisco_asa.section_scanner import scan_cisco_asa_sections


def test_class_map_matches_are_typed_and_legacy_lines_remain():
    config = CiscoASAParser("""
class-map match-any CM
 description inspect web
 match access-list WEB_ACL
 match protocol tcp
 match port tcp eq 443
 match unsupported future-value
""").parse_raw()
    class_map = config.class_maps[0]
    assert class_map.match_type == "match-any"
    assert class_map.match_any is True
    assert class_map.match_all is False
    assert [item.match_type for item in class_map.matches] == ["access_list", "protocol", "port"]
    assert class_map.matches[0].acl_name == "WEB_ACL"
    assert class_map.match_lines[-1] == "match unsupported future-value"
    assert class_map.migration_status == "PARTIALLY_NORMALIZED"
    assert class_map.requires_manual_review


def test_policy_map_preserves_class_hierarchy_and_action_order():
    config = CiscoASAParser("""
policy-map PM
 class CLASS1
  inspect dns DNS_POLICY
  set connection conn-max 100
  set connection embryonic-conn-max 20
  set connection per-client-max 5
  set connection timeout embryonic 0:00:30
  police input 1000 2000 conform-action transmit exceed-action drop
  set connection tcp-map TCP_POLICY
 class CLASS2
  inspect ftp
 class class-default
  inspect icmp error
""").parse_raw()
    policy = config.policy_maps[0]
    assert policy.class_sections == ["class CLASS1", "class CLASS2", "class class-default"]
    assert [item.class_name for item in policy.classes] == ["CLASS1", "CLASS2", "class-default"]
    first = policy.classes[0]
    assert first.inspect_actions[0].policy_name == "DNS_POLICY"
    assert first.connection_actions[0].max_connections == 100
    assert first.connection_actions[1].max_embryonic == 20
    assert first.connection_actions[2].per_client_max == 5
    assert first.connection_actions[3].timeout_embryonic == "0:00:30"
    assert first.police_actions[0].rate == 1000
    assert first.police_actions[0].burst == 2000
    assert first.tcp_map == "TCP_POLICY"
    assert policy.classes[2].inspect_actions[0].parameters == ["error"]


def test_class_default_is_builtin_and_missing_references_are_partial():
    config = CiscoASAParser("""
class-map CM
 match access-list MISSING_ACL
policy-map PM
 class CM
  set connection tcp-map MISSING_TCP
 class class-default
  inspect dns
service-policy MISSING_POLICY interface missing_nameif
""").parse_raw()
    assert config.policy_maps[0].classes[1].class_name == "class-default"
    assert not any(item["reference_type"] == "class_map" and item["reference_name"] == "class-default" for item in config.reference_issues)
    missing = {(item["reference_type"], item["reference_name"]) for item in config.reference_issues if not item["resolved"]}
    assert {("acl", "MISSING_ACL"), ("tcp_map", "MISSING_TCP"), ("policy_map", "MISSING_POLICY"), ("interface", "missing_nameif")} <= missing
    assert config.class_maps[0].matches[0].resolved is False
    assert config.service_policies[0].requires_manual_review


def test_tcp_map_and_service_policy_attachments_are_structured_without_overwrite():
    config = CiscoASAParser("""
interface GigabitEthernet0/0
 nameif outside
tcp-map TM
 checksum-verification
 queue-limit 10
 reserved-bits clear
policy-map PM
 class CM
  tcp-map TM
service-policy PM global
service-policy PM interface outside
""").parse_raw()
    tcp_map = config.tcp_maps[0]
    assert tcp_map.settings == {"checksum-verification": True, "queue-limit": 10, "reserved-bits": "clear"}
    assert config.policy_maps[0].classes[0].tcp_map == "TM"
    assert [(item.scope, item.global_attachment, item.interface) for item in config.service_policies] == [
        ("global", True, None), ("interface", False, "outside")
    ]


def test_mpf_malformed_and_unsupported_actions_keep_diagnostics():
    config = CiscoASAParser("""
class-map CM
 match access-list
policy-map PM
 class CM
  inspect unknown-protocol
  set connection conn-max not-a-number
  police input invalid 10
tcp-map TM
 queue-limit invalid
""").parse_raw()
    assert config.parse_errors
    assert all(item["migration_effect"] == "PARSE_ERROR" for item in config.parse_errors)
    assert config.class_maps[0].migration_status == "PARSE_ERROR"
    assert config.policy_maps[0].classes[0].inspect_actions[0].migration_status == "PARTIALLY_NORMALIZED"
    assert config.policy_maps[0].classes[0].inspect_actions[0].requires_manual_review
    assert config.tcp_maps[0].migration_status == "PARSE_ERROR"


def test_mpf_coverage_is_partial_and_scanner_keeps_tcp_map_block():
    text = """
class-map CM
 match any
policy-map PM
 class CM
  inspect dns
service-policy PM global
tcp-map TM
 checksum-verification
"""
    result = extract_cisco_asa_config(text)
    statuses = [section.status for section in result.source_sections]
    assert statuses == [ExtractionStatus.PARTIALLY_NORMALIZED] * 4
    section = next(section for section in scan_cisco_asa_sections(text) if section.path == "tcp-map")
    assert section.object_count_source == 2
    assert section.line_end == 9
