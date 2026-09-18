from fwmigrate.extraction.models import ExtractionStatus, SourceCommand, SourceInventoryItem
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


def test_p0_vdom_source_context_is_preserved_for_services_and_source_sections():
    source = """
config vdom
    edit "tenant-a"
        config firewall service custom
            edit "svc1"
                set protocol TCP/UDP/SCTP
            next
        end
        config firewall service group
            edit "group1"
                set member "svc1"
            next
        end
    next
end
"""

    result = extract_fortigate_config(source)

    assert result.canonical_ir.services[0].source_context == "tenant-a"
    assert result.canonical_ir.service_groups[0].source_context == "tenant-a"
    sections = {
        section.path: section
        for section in result.source_sections
        if section.path in {"firewall service custom", "firewall service group"}
    }
    assert {
        path: section.source_context
        for path, section in sections.items()
    } == {
        "firewall service custom": "tenant-a",
        "firewall service group": "tenant-a",
    }


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


def test_dropped_fortigate_sections_are_dependency_isolated():
    dropped = [
        ("firewall local-in-policy", "srcaddr"),
        ("firewall multicast-policy", "srcaddr"),
        ("system dhcp server", "interface"),
        ("firewall access-proxy", "certificate"),
        ("authentication scheme", "user-database"),
        ("system global", "admin-server-cert"),
    ]
    items = [
        SourceInventoryItem(
            domain="firewall",
            source_path=path,
            source_context="root",
            name=str(index),
            commands=[SourceCommand(operation="set", key=field, values=["missing"])],
        )
        for index, (path, field) in enumerate(dropped, start=1)
    ]
    items.append(
        SourceInventoryItem(
            domain="firewall",
            source_path="firewall policy",
            source_context="root",
            name="supported",
            commands=[
                SourceCommand(operation="set", key="srcaddr", values=["missing"]),
            ],
        )
    )

    dependencies = build_dependency_registry(items)

    assert len(dependencies) == 1
    assert dependencies[0].source_path == "firewall policy"
    assert dependencies[0].result == "UNRESOLVED"


def test_p0_predefined_services_resolve_for_policies_and_groups():
    commands = [
        SourceCommand(
            operation="set",
            key="service",
            values=["HTTP", "HTTPS", "DNS", "PING"],
        ),
    ]
    group_commands = [
        SourceCommand(
            operation="set",
            key="member",
            values=["HTTP", "HTTPS", "DNS", "PING"],
        ),
    ]
    items = [
        SourceInventoryItem(
            domain="firewall",
            source_path="firewall policy",
            source_context="root",
            name="1",
            commands=commands,
        ),
        SourceInventoryItem(
            domain="firewall",
            source_path="firewall service group",
            source_context="root",
            name="WEB",
            commands=group_commands,
        ),
    ]

    dependencies = build_dependency_registry(items)

    assert {
        dependency.reference
        for dependency in dependencies
        if dependency.result == "RESOLVED"
        and dependency.target_path == "fortigate predefined service"
    } == {"HTTP", "HTTPS", "DNS", "PING"}
    assert all(
        "target semantic expansion is not modeled" in dependency.notes
        for dependency in dependencies
    )
    assert all(dependency.reason is None for dependency in dependencies)


def test_p0_custom_service_precedes_same_named_service_group():
    items = [
        SourceInventoryItem(
            domain="firewall",
            source_path="firewall policy",
            source_context="root",
            name="1",
            commands=[
                SourceCommand(operation="set", key="service", values=["WEB"]),
            ],
        ),
        SourceInventoryItem(
            domain="firewall",
            source_path="firewall service custom",
            source_context="root",
            name="WEB",
        ),
        SourceInventoryItem(
            domain="firewall",
            source_path="firewall service group",
            source_context="root",
            name="WEB",
        ),
    ]

    dependency = build_dependency_registry(items)[0]

    assert dependency.result == "RESOLVED"
    assert dependency.target_path == "firewall service custom"


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
    assert profile_dependencies["ips-sensor"].result == "EXTERNAL"
    assert all(
        item.result == "UNRESOLVED"
        for field, item in profile_dependencies.items()
        if field != "ips-sensor"
    )
    assert all(
        item.reference == profile_fields[item.source_field]
        for item in profile_dependencies.values()
    )
    auth_inventory = next(
        item for item in result.inventory_items
        if item.source_path == "authentication scheme"
    )
    assert auth_inventory.status == ExtractionStatus.IGNORED_BY_POLICY
    assert not any(
        item.source_path == "authentication scheme"
        for item in result.dependencies
    )
    assert result.canonical_ir.vendor_extensions.fortios.authentication_profiles == []
    assert result.canonical_ir.vendor_extensions.fortios.authentication_policies == []
    assert "supersecret" not in str(result.model_dump())
    assert result.generation_safe is False
