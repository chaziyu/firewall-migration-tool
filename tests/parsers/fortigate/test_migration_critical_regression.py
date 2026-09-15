from fwmigrate.extraction.models import SourceCommand, SourceInventoryItem
from fwmigrate.parsers.fortigate.dependencies import build_dependency_registry
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import FortiGateParser
from fwmigrate.parsers.fortigate.section_registry import get_section_parser_capability
from fwmigrate.parsers.fortigate.tokenizer import FortiGateTokenizer
from tests.fixture_paths import (
    FORTIGATE_P0_EDGE_CASES_FIXTURE,
    FORTIGATE_P0_MIGRATION_CRITICAL_FIXTURE,
)


def _fixture(path):
    return path.read_text(encoding="utf-8")


def test_p0_registry_and_source_models_cover_migration_critical_objects():
    config = FortiGateParser(
        FortiGateTokenizer(_fixture(FORTIGATE_P0_MIGRATION_CRITICAL_FIXTURE))
    ).parse()

    assert len(config.interfaces) == 3
    assert config.interfaces[-1].vlanid == 100
    assert config.interfaces[-1].interface == "port1"
    assert len(config.system_zones) == 1
    assert len(config.addresses) == 3
    assert len(config.address_groups) == 2
    assert len(config.services) == 2
    assert len(config.service_groups) == 1
    assert len(config.schedules) == 2
    assert len(config.schedule_groups) == 1
    assert len(config.ip_pools) == 1
    assert len(config.ip_pools6) == 1
    assert config.ip_pools[0].source_explicit_fields == {
        "comments", "endip", "startip", "type"
    }
    assert len(config.vips) == 1
    assert config.vips[0].extport == "8443"
    assert config.vips[0].mappedport == "443"
    assert len(config.vip_groups) == 1
    assert len(config.policies) == 2
    assert len(config.static_routes) == 1
    assert config.static_routes[0].distance == 10

    capability = get_section_parser_capability("firewall policy")
    assert {"application", "app_category"} <= set(capability["integer_list_fields"])
    assert {"poolname", "poolname6", "pcp_poolname"} <= set(capability["list_fields"])
    assert {"id", "protocol"} <= set(
        get_section_parser_capability("firewall central-snat-map")["integer_fields"]
    )


def test_p0_canonical_policy_nat_and_route_evidence_is_preserved():
    result = extract_fortigate_config(_fixture(FORTIGATE_P0_MIGRATION_CRITICAL_FIXTURE))
    ir = result.canonical_ir

    outbound = next(policy for policy in ir.policies if policy.name == "OUTBOUND_WEB")
    inbound = next(policy for policy in ir.policies if policy.name == "INBOUND_WEB")
    assert outbound.source == ["INTERNAL_NETS"]
    assert outbound.destination == ["<IR_ANY>"]
    assert outbound.service == ["WEB_SERVICES"]
    assert outbound.nat_pool_names == ["SNAT_POOL"]
    assert inbound.destination == ["VIP_SERVERS"]

    snat = next(rule for rule in ir.nat_rules if rule.name == "SNAT-P10")
    dnat = next(rule for rule in ir.nat_rules if rule.name == "DNAT-P20-VIP_WEB")
    assert snat.translated_sources == ["198.51.100.100-198.51.100.110"]
    assert dnat.translated_destinations == ["10.10.100.10"]
    assert snat.source_context == dnat.source_context == "root"
    assert ir.routes[0].destination == "0.0.0.0/0"


def test_p0_dependency_resolution_is_local_first_and_fail_closed():
    commands = [
        SourceCommand(operation="set", key="srcintf", values=["port1"]),
    ]
    items = [
        SourceInventoryItem(
            domain="system",
            source_path="system interface",
            source_context="tenant-a",
            name="port1",
        ),
        SourceInventoryItem(
            domain="firewall",
            source_path="firewall policy",
            source_context="tenant-b",
            name="1",
            commands=commands,
        ),
    ]
    dependency = build_dependency_registry(items)[0]
    assert dependency.result == "UNRESOLVED"
    assert dependency.target_path is None


def test_p0_pool_and_pool_group_collision_is_unresolved():
    source = """
config firewall ippool
    edit "COLLIDE"
        set startip 198.51.100.1
        set endip 198.51.100.2
    next
end
config firewall ippool_grp
    edit "COLLIDE"
        set member "POOL"
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set service "all"
        set poolname "COLLIDE"
    next
end
"""
    result = extract_fortigate_config(source)
    dependency = next(
        item for item in result.dependencies
        if item.source_path == "firewall policy" and item.source_field == "poolname"
    )
    assert dependency.result == "UNRESOLVED"
    assert dependency.reason == "ambiguous-reference"
    assert result.generation_safe is False


def test_p0_vip_src_vip_filter_is_preserved_and_blocks_unproven_nat():
    source = """
config system interface
    edit port1
    next
    edit port2
    next
end
config firewall vip
    edit VIP_WEB
        set extip 203.0.113.10
        set mappedip 10.0.0.10
        set src-vip-filter enable
    next
end
config firewall policy
    edit 1
        set srcintf port1
        set dstintf port2
        set srcaddr all
        set dstaddr VIP_WEB
        set service HTTPS
        set nat enable
    next
end
"""
    result = extract_fortigate_config(source)
    vip = result.canonical_ir.virtual_ips[0]
    nat_rule = next(rule for rule in result.canonical_ir.nat_rules if rule.source_vip_reference == "VIP_WEB")

    assert vip.extra_settings["src_vip_filter"] == "enable"
    assert vip.extra_settings["src_vip_filter_enabled"] is True
    assert vip.requires_manual_review is True
    assert "src-vip-filter" in vip.audit_note
    assert nat_rule.source_attributes["src_vip_filter_enabled"] is True
    assert any("src-vip-filter" in reason for reason in nat_rule.review_reasons)
    assert result.generation_safe is False


def test_p1_security_profile_relationships_are_explicit_and_secrets_are_redacted():
    profile_fields = {
        "application-list": "APP",
        "av-profile": "AV",
        "casb-profile": "CASB",
        "cifs-profile": "CIFS",
        "diameter-filter-profile": "DIAMETER",
        "dlp-profile": "DLP",
        "dnsfilter-profile": "DNS",
        "emailfilter-profile": "EMAIL",
        "file-filter-profile": "FILE",
        "icap-profile": "ICAP",
        "ips-sensor": "IPS",
        "ips-voip-filter": "VOIP",
        "profile-protocol-options": "PROTO",
        "profile-group": "GROUP",
        "sctp-filter-profile": "SCTP",
        "ssh-filter-profile": "SSH",
        "ssl-ssh-profile": "SSL",
        "videofilter-profile": "VIDEO",
        "virtual-patch-profile": "PATCH",
        "voip-profile": "VOIP_PROFILE",
        "waf-profile": "WAF",
        "webfilter-profile": "WEB",
    }
    profile_commands = "\n".join(
        f"        set {field} {value}"
        for field, value in profile_fields.items()
    )
    result = extract_fortigate_config(
        f"""\
config firewall policy
    edit 1
        set srcintf port1
        set dstintf port2
        set srcaddr all
        set dstaddr all
        set service ALL
        set action accept
{profile_commands}
    next
end
config user ldap
    edit LDAP1
        set server ldap.example
        set password supersecret
    next
end
config authentication scheme
    edit SCHEME
        set method local
        set user-database local
    next
end
"""
    )

    policy = result.canonical_ir.policies[0]
    assert set(policy.source_security_profile_references) == {
        field.replace("-", "_") for field in profile_fields
    }
    profile_dependencies = {
        dependency.source_field: dependency
        for dependency in result.dependencies
        if dependency.source_path == "firewall policy"
        and dependency.source_field in profile_fields
    }
    assert set(profile_dependencies) == set(profile_fields)
    assert all(item.result == "UNRESOLVED" for item in profile_dependencies.values())
    assert all(
        item.reference == profile_fields[item.source_field]
        for item in profile_dependencies.values()
    )
    auth_dependency = next(
        item
        for item in result.dependencies
        if item.source_path == "authentication scheme"
        and item.source_field == "user-database"
    )
    assert auth_dependency.result == "RESOLVED"
    assert "supersecret" not in str(result.model_dump())
    assert result.generation_safe is False
