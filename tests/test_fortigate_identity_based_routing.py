from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.ir.io import load_ir_payload
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import FortiGateParser
from fwmigrate.parsers.fortigate.tokenizer import FortiGateTokenizer


CONFIG = '''config system interface
    edit "wan1"
    next
end
config user group
    edit "Employees"
    next
    edit "Contractors"
    next
end
config firewall identity-based-route
    edit "AUTH_ROUTE"
        set comments "Employee routing"
        config rule
            edit 20
                set device "wan1"
                set gateway 192.0.2.1
                set groups "Employees" "Contractors"
                set future-setting enable
            next
            edit 5
                set device "missing-wan"
                set groups "MISSING_GROUP"
            next
        end
    next
end
config firewall auth-portal
    set groups "Employees" "MISSING_GROUP"
    set identity-based-route "AUTH_ROUTE"
    set portal-addr 192.0.2.10
    set proxy-auth enable
end
config firewall policy
    edit 100
        set name "AUTH_POLICY"
        set srcintf "wan1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set identity-based-route "AUTH_ROUTE"
    next
end
'''


def test_identity_routing_is_ordered_source_only_with_strict_dependencies() -> None:
    parsed = FortiGateParser(FortiGateTokenizer(CONFIG)).parse()
    route = next(item for item in parsed.structured_source_objects if item.source_path == "firewall identity-based-route")
    rules = route.root.children[0].children
    assert [rule.name for rule in rules] == ["20", "5"]
    assert rules[0].commands[2].values == ["Employees", "Contractors"]
    assert rules[0].commands[3].key == "future-setting"
    assert parsed.policies[0].identity_based_route == "AUTH_ROUTE"

    result = extract_fortigate_config(CONFIG)
    assert result.canonical_ir.routes == []
    assert result.canonical_ir.policies[0].source_identity_based_route == "AUTH_ROUTE"
    assert result.canonical_ir.policies[0].requires_manual_review is True
    assert result.canonical_ir.policies[0].safe_for_target_generation is False
    assert any("identity-based routing" in reason for reason in result.canonical_ir.policies[0].review_reasons)
    assert all(
        section.status == ExtractionStatus.EXTRACT_ONLY
        for section in result.source_sections
        if section.path in {"firewall identity-based-route", "firewall auth-portal"}
    )

    dependencies = [
        (item.source_path, item.source_field, item.reference, item.result, item.target_path)
        for item in result.dependencies
        if item.source_path.startswith("firewall identity-based-route")
        or item.source_path == "firewall auth-portal"
        or (item.source_path == "firewall policy" and item.source_field == "identity-based-route")
    ]
    assert dependencies == [
        ("firewall identity-based-route rule", "device", "wan1", "RESOLVED", "system interface"),
        ("firewall identity-based-route rule", "groups", "Employees", "RESOLVED", "user group"),
        ("firewall identity-based-route rule", "groups", "Contractors", "RESOLVED", "user group"),
        ("firewall identity-based-route rule", "device", "missing-wan", "UNRESOLVED", None),
        ("firewall identity-based-route rule", "groups", "MISSING_GROUP", "UNRESOLVED", None),
        ("firewall auth-portal", "groups", "Employees", "RESOLVED", "user group"),
        ("firewall auth-portal", "groups", "MISSING_GROUP", "UNRESOLVED", None),
        ("firewall auth-portal", "identity-based-route", "AUTH_ROUTE", "RESOLVED", "firewall identity-based-route"),
        ("firewall policy", "identity-based-route", "AUTH_ROUTE", "RESOLVED", "firewall identity-based-route"),
    ]
    assert not any(item.source_field in {"gateway", "portal-addr"} for item in result.dependencies)


def test_legacy_policy_migrates_without_inventing_identity_route() -> None:
    policy = load_ir_payload({
        "schema_version": "1.22",
        "metadata": {"source_vendor": "fortigate"},
        "policies": [{"name": "legacy"}],
    }).policies[0]
    assert policy.source_identity_based_route is None
