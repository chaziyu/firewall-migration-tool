from types import SimpleNamespace

from fwmigrate.vendors.cisco_asa.model import CiscoIPsecProfile, CiscoNATRule

from fwmigrate.vendors.cisco_asa.model.acl import CiscoACLEndpoint, CiscoAccessRule

from fwmigrate.vendors.cisco_asa.model.service import CiscoPortSpec

from fwmigrate.vendors.cisco_asa.relationships.acl import build_acl_relationships

from fwmigrate.vendors.cisco_asa.relationships.identity import build_identity_relationships

from fwmigrate.vendors.cisco_asa.relationships.mpf import build_mpf_relationships

from fwmigrate.vendors.cisco_asa.relationships.nat import build_nat_relationships

from fwmigrate.vendors.cisco_asa.relationships.references import ASAReferenceIndex, ASAReferenceKind

from fwmigrate.vendors.cisco_asa.relationships.routing import build_routing_relationships

from fwmigrate.vendors.cisco_asa.relationships.vpn import build_vpn_relationships

from fwmigrate.vendors.cisco_asa.parser import CiscoASAParser

def test_acl_global_binding_keeps_scope_separate_and_preserves_rule_order():
    first = SimpleNamespace(acl_name="OUT", source_order=2)
    second = SimpleNamespace(acl_name="OUT", source_order=3)
    binding = SimpleNamespace(acl_name="OUT", source_context=None, interface=None, direction="in")
    config = SimpleNamespace(access_rules=[first, second], acl_bindings=[binding])
    refs = ASAReferenceIndex(); refs.register(None, ASAReferenceKind.ACL, "OUT", "OUT")

    relation = build_acl_relationships(config, refs).bindings[0]

    assert relation.scope == "global" and relation.interface is None
    assert relation.rules == (first, second)
    assert not relation.issues

def test_acl_rule_relationships_resolve_endpoints_services_protocol_time_and_identity():
    rule = CiscoAccessRule(
        id="ACL:1", acl_name="ACL", source_context="ctx", protocol="object-group", protocol_object="PROTO",
        source_endpoint=CiscoACLEndpoint(type="object", value="SRC", raw="object SRC"),
        destination_endpoint=CiscoACLEndpoint(type="object-group", value="DST", raw="object-group DST"),
        source_port=CiscoPortSpec(operator="object", object_name="SRC-SVC"),
        destination_port=CiscoPortSpec(operator="object-group", object_name="DST-SVC"),
        time_range="HOURS", user="alice", user_group="REMOTE", source_security_group_type="object-group",
        source_security_group_value="SGT",
    )
    refs = ASAReferenceIndex()
    targets = {
        (ASAReferenceKind.PROTOCOL_GROUP, "PROTO"): object(),
        (ASAReferenceKind.NETWORK_OBJECT, "SRC"): object(),
        (ASAReferenceKind.NETWORK_GROUP, "DST"): object(),
        (ASAReferenceKind.SERVICE_OBJECT, "SRC-SVC"): object(),
        (ASAReferenceKind.SERVICE_GROUP, "DST-SVC"): object(),
        (ASAReferenceKind.TIME_RANGE, "HOURS"): object(),
        (ASAReferenceKind.LOCAL_USER, "alice"): object(),
        (ASAReferenceKind.USER_GROUP, "REMOTE"): object(),
        (ASAReferenceKind.SECURITY_GROUP, "SGT"): object(),
    }
    for (kind, name), target in targets.items():
        refs.register("ctx", kind, name, target)
    config = SimpleNamespace(access_rules=[rule], acl_bindings=[])

    relationship = build_acl_relationships(config, refs).rules[0]

    assert dict(relationship.references) == {
        "protocol": targets[(ASAReferenceKind.PROTOCOL_GROUP, "PROTO")],
        "source": targets[(ASAReferenceKind.NETWORK_OBJECT, "SRC")],
        "destination": targets[(ASAReferenceKind.NETWORK_GROUP, "DST")],
        "source-service": targets[(ASAReferenceKind.SERVICE_OBJECT, "SRC-SVC")],
        "destination-service": targets[(ASAReferenceKind.SERVICE_GROUP, "DST-SVC")],
        "time-range": targets[(ASAReferenceKind.TIME_RANGE, "HOURS")],
        "user": targets[(ASAReferenceKind.LOCAL_USER, "alice")],
        "user-group": targets[(ASAReferenceKind.USER_GROUP, "REMOTE")],
        "source-security-group": targets[(ASAReferenceKind.SECURITY_GROUP, "SGT")],
    }
    assert not relationship.issues

def test_acl_protocol_selector_types_resolve_service_protocol_and_icmp_namespaces():
    from fwmigrate.vendors.cisco_asa import extract_cisco_asa_source

    result = extract_cisco_asa_source(
        "object service WEB\n service tcp destination eq 80\n"
        "object-group service WEB-GROUP tcp\n port-object eq 443\n"
        "object-group protocol PROTOCOLS\n protocol-object icmp\n"
        "object-group icmp-type PINGS\n icmp-object echo\n"
        "access-list ACL1 extended permit object WEB any any\n"
        "access-list ACL2 extended permit object-group WEB-GROUP any any\n"
        "access-list ACL3 extended permit object-group PROTOCOLS any any\n"
        "access-list ACL4 extended permit icmp any any object-group PINGS\n"
    )
    rules = {rule.acl_name: rule for rule in result.config.access_rules}
    relationships = {row.rule.acl_name: row for row in result.derived.acl_relationships.rules}
    expected = {
        "ACL1": ("object", "WEB", "service_objects"),
        "ACL2": ("object-group", "WEB-GROUP", "service_groups"),
        "ACL3": ("object-group", "PROTOCOLS", "protocol_groups"),
    }
    for acl, (selector, name, kind) in expected.items():
        assert (rules[acl].protocol_reference_type, rules[acl].protocol_object) == (selector, name)
        target = dict(relationships[acl].references)["protocol"]
        assert target is next(item for item in getattr(result.config, kind) if item.name == name)
        assert not relationships[acl].issues
    assert "PINGS" == next(value for key, value in relationships["ACL4"].references
                             if key == "icmp-object-group").name
    assert not relationships["ACL4"].issues

def test_acl_protocol_object_group_namespace_ambiguity_is_reported():
    from fwmigrate.vendors.cisco_asa import extract_cisco_asa_source

    result = extract_cisco_asa_source(
        "object-group service SHARED tcp\n port-object eq 80\n"
        "object-group protocol SHARED\n protocol-object tcp\n"
        "access-list ACL extended permit object-group SHARED any any\n"
    )
    rule = result.derived.acl_relationships.rules[0]
    assert not any(key == "protocol" for key, _ in rule.references)
    issue = next(issue for issue in rule.issues if issue.reference_name == "SHARED")
    assert issue.status.value == "AMBIGUOUS"

def test_acl_remarks_keep_order_even_when_trailing_or_remark_only():
    config = CiscoASAParser(
        "access-list ACL line 10 remark before rule\n"
        "access-list ACL line 20 extended permit ip any any\n"
        "access-list ACL line 30 remark trailing\n"
        "access-list EMPTY remark only\n"
    ).parse_raw()
    assert [(row.acl_name, row.sequence, row.remark) for row in config.acl_remarks] == [
        ("ACL", 10, "before rule"), ("ACL", 30, "trailing"), ("EMPTY", None, "only")
    ]
    assert [row.source_order for row in config.acl_remarks] == sorted(row.source_order for row in config.acl_remarks)
    assert len(config.access_rules) == 1 and config.access_rules[0].remark is None
