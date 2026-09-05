import pytest

from fwmigrate.core.constants import IR_KEYWORD_ANY, IR_KEYWORD_ANY_IPV4, IR_KEYWORD_ANY_IPV6
from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser


def _bound(lines: str) -> CiscoASAParser:
    parser = CiscoASAParser(f"""
interface Gi0/0
 nameif inside
{lines}
access-group A in interface inside
""")
    parser.transform_to_ir()
    return parser


def test_any_any4_any6_remain_distinct_and_family_specific_rules_are_withheld():
    parser = _bound("""
access-list A extended permit ip any any
access-list A extended permit ip any4 any4
access-list A extended permit ip any6 any6
""")
    assert [rule.source[0] for rule in parser.transform_to_ir().policies] == [IR_KEYWORD_ANY, IR_KEYWORD_ANY_IPV4, IR_KEYWORD_ANY_IPV6]
    policies = parser.transform_to_ir().policies
    assert policies[0].migration_status == "NORMALIZED"
    assert all(rule.requires_manual_review for rule in policies[1:])


def test_standard_acl_keeps_type_action_and_source_without_extended_operands():
    parser = _bound("access-list A line 10 standard permit 10.0.0.0 255.255.255.0")
    rule = parser.config.access_rules[0]
    assert rule.acl_type == "standard"
    assert rule.action == "permit"
    assert rule.protocol is None
    assert rule.source_endpoint.value == "10.0.0.0/24"
    assert rule.destination_endpoint is None
    assert rule.source_attributes["acl_type"] == "standard"
    policy = parser.transform_to_ir().policies[0]
    assert policy.source
    assert policy.destination == []
    assert policy.service == []
    assert policy.migration_status == "PARTIALLY_NORMALIZED"


def test_ipv6_acl_operands_and_named_endpoints_are_preserved():
    parser = _bound("access-list A line 10 extended permit ip any6 object-group V6_NET")
    rule = parser.config.access_rules[0]
    assert rule.source_endpoint.value == "any6"
    assert rule.source_endpoint.address_family == "ipv6"
    assert rule.destination_endpoint.type == "object-group"
    assert rule.destination_endpoint.value == "V6_NET"


def test_protocol_object_group_and_object_endpoints_remain_references():
    parser = _bound("access-list A extended permit object-group PROTO_GROUP object SRC object-group DST")
    rule = parser.config.access_rules[0]
    assert (rule.protocol, rule.protocol_object) == ("object-group", "PROTO_GROUP")
    assert (rule.source_endpoint.type, rule.source_endpoint.value) == ("object", "SRC")
    assert (rule.destination_endpoint.type, rule.destination_endpoint.value) == ("object-group", "DST")
    assert parser.transform_to_ir().policies[0].service == ["PROTO_GROUP"]


def test_transport_acl_can_keep_object_group_as_destination_endpoint():
    parser = _bound("access-list A extended permit tcp any object-group WEB eq 443")
    rule = parser.config.access_rules[0]
    assert rule.source_port is None
    assert rule.destination_endpoint.type == "object-group"
    assert rule.destination_endpoint.value == "WEB"
    assert rule.destination_port.values == ["443"]


@pytest.mark.parametrize(
    ("logging", "enabled", "level", "interval"),
    [
        ("log", True, None, None),
        ("log 7", True, "7", None),
        ("log default", True, "default", None),
        ("log interval 60", True, None, 60),
        ("log disable", False, None, None),
    ],
)
def test_acl_logging_variants_are_kept_explicit(logging, enabled, level, interval):
    parser = _bound(f"access-list A extended permit ip any any {logging}")
    rule = parser.config.access_rules[0]
    assert rule.log_enabled is enabled
    assert rule.log_level == level
    assert rule.log_interval == interval
    assert rule.log_raw == logging


def test_acl_order_uses_sequence_then_source_order_and_flags_ambiguity():
    parser = _bound("""
access-list A line 20 extended deny ip any any
access-list A line 10 extended permit ip any any
access-list A line 10 extended deny ip any any
""")
    ir = parser.transform_to_ir()
    assert [policy.source_rule_id.split("_")[1] for policy in ir.policies] == ["10", "10", "20"]
    assert [rule.effective_source_order for rule in parser.config.access_rules] == [3, 1, 2]
    assert all(rule.migration_status == "PARTIALLY_NORMALIZED" for rule in parser.config.access_rules)
    assert all("Repeated ACL sequence" in " ".join(rule.review_reasons) or "sequence order" in " ".join(rule.review_reasons) for rule in parser.config.access_rules)


def test_remarks_attach_to_the_next_ace_and_preserve_rule_order():
    parser = _bound("""
access-list A line 10 remark allow web
access-list A line 20 extended permit tcp any any eq 443
access-list A line 30 extended deny ip any any
""")
    assert parser.config.access_rules[0].remark == "allow web"
    assert [rule.source_sequence for rule in parser.config.access_rules] == [20, 30]


def test_acl_optional_identity_time_range_and_inactive_fields_are_preserved():
    parser = _bound("access-list A extended permit ip user-group STAFF any any inactive time-range BUSINESS")
    rule = parser.config.access_rules[0]
    assert rule.user_group == "STAFF"
    assert rule.time_range == "BUSINESS"
    assert rule.inactive is True
    assert rule.source_attributes["raw_line"].endswith("time-range BUSINESS")


def test_malformed_acl_optional_syntax_is_parse_error_with_source_evidence():
    parser = _bound("access-list A extended permit tcp any any log interval")
    rule = parser.config.access_rules[0]
    assert rule.migration_status == "PARSE_ERROR"
    assert rule.requires_manual_review is True
    assert rule.source_attributes["malformed_optional_tokens"] == ["interval"]


def test_per_user_override_binding_is_preserved_and_requires_review():
    parser = CiscoASAParser("""
access-list A extended permit ip any any
access-group A in interface inside per-user-override
""")
    policy = parser.transform_to_ir().policies[0]
    assert policy.source_extra_settings["per_user_override"] is True
    assert policy.migration_status == "PARTIALLY_NORMALIZED"
    assert policy.requires_manual_review is True


@pytest.mark.parametrize(
    ("selector", "field", "value"),
    [
        (r"user DOMAIN\user", "user", r"DOMAIN\user"),
        ("user-group Staff", "user_group", "Staff"),
        ("object-group-user Staff", "user_group", "Staff"),
    ],
)
def test_identity_selectors_are_parsed_before_source_endpoint(selector, field, value):
    parser = _bound(f"access-list A extended permit ip {selector} any host 10.0.0.1")
    rule = parser.config.access_rules[0]
    assert getattr(rule, field) == value
    assert rule.source_endpoint.type == "any"
    assert rule.destination_endpoint.value == "10.0.0.1"
    assert parser.transform_to_ir().policies[0].identity_dependency_review


def test_source_and_destination_trustsec_selectors_stay_separate():
    parser = _bound("access-list A extended permit ip security-group name SRC any security-group tag 42 any")
    rule = parser.config.access_rules[0]
    assert (rule.source_security_group_type, rule.source_security_group_value) == ("name", "SRC")
    assert (rule.destination_security_group_type, rule.destination_security_group_value) == ("tag", "42")
    policy = parser.transform_to_ir().policies[0]
    assert policy.source_extra_settings["source_security_group_value"] == "SRC"
    assert policy.source_extra_settings["destination_security_group_value"] == "42"
    assert not policy.safe_for_target_generation


def test_interface_endpoint_is_preserved_without_fake_address():
    parser = _bound("access-list A extended permit ip interface outside any")
    rule = parser.config.access_rules[0]
    assert rule.source_endpoint.type == "interface"
    policy = parser.transform_to_ir().policies[0]
    assert policy.source == []
    assert policy.requires_manual_review
    assert all(item.name != "outside" for item in parser.transform_to_ir().addresses)


def test_unbound_and_crypto_acls_do_not_become_transit_policies():
    parser = CiscoASAParser("""
access-list UNBOUND extended permit ip any any
access-list CRYPTO extended permit ip host 10.0.0.1 host 10.0.1.1
crypto map VPN 10 match address CRYPTO
""")
    ir = parser.transform_to_ir()
    assert ir.policies == []
    assert parser.config.acl_consumers["CRYPTO"][0]["consumer_type"] == "crypto-map"
    assert len(parser.config.access_rules) == 2


def test_icmp_object_group_reference_resolves_without_becoming_literal_object_group():
    parser = _bound("""
object-group icmp-type ICMP_TYPES
 icmp-object echo
access-list A extended permit icmp any any object-group ICMP_TYPES
""")
    rule = parser.config.access_rules[0]
    assert rule.icmp_type is None
    assert rule.icmp_object_group == "ICMP_TYPES"
    policy = parser.transform_to_ir().policies[0]
    assert policy.service == ["ICMP_TYPES"]
    assert policy.requires_manual_review


@pytest.mark.parametrize(("operator", "expected"), [("lt 80", "1-79"), ("gt 1024", "1025-65535")])
def test_lt_and_gt_ports_normalize_to_safe_ranges(operator, expected):
    parser = _bound(f"access-list A extended permit tcp any any {operator}")
    policy = parser.transform_to_ir().policies[0]
    service = next(item for item in parser.transform_to_ir().services if item.name in policy.service)
    assert [port.port for port in service.ports] == [expected]


def test_neq_port_produces_two_disjoint_ranges_and_port_object_is_retained():
    parser = _bound("access-list A extended permit tcp any any neq 443")
    policy = parser.transform_to_ir().policies[0]
    service = next(item for item in parser.transform_to_ir().services if item.name in policy.service)
    assert [port.port for port in service.ports] == ["1-442", "444-65535"]

    referenced = _bound("""
object service WEB
 service tcp destination eq 443
access-list A extended permit tcp any any object WEB
""")
    assert referenced.transform_to_ir().policies[0].service == ["WEB"]


@pytest.mark.parametrize("protocol", ["47", "gre", "esp", "eigrp"])
def test_generic_ip_protocols_are_preserved_and_withheld(protocol):
    parser = _bound(f"access-list A extended permit {protocol} any any")
    policy = parser.transform_to_ir().policies[0]
    service = next(item for item in parser.transform_to_ir().services if item.name in policy.service)
    assert service.source_protocol == protocol
    assert service.source_protocol_number == (47 if protocol == "47" else None)
    assert policy.requires_manual_review
    assert not policy.safe_for_target_generation
