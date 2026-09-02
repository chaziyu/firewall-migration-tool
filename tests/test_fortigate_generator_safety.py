import pytest

from fwmigrate.ir.enums import MigrationConfidence
from fwmigrate.generators.fortigate.cli_generator import FortiGateCLIGenerator
from fwmigrate.generators.fortigate.terraform_generator import FortiGateTerraformGenerator
from fwmigrate.ir.core import (
    IRAddress,
    IRAddressGroup,
    IRConfig,
    IRInterface,
    IRIPPool,
    IRIPSSensor,
    IRMetadata,
    IRNATRule,
    IRPolicy,
    IRProxyAddress,
    IRRoute,
    IRSchedule,
    IRScheduleGroup,
    IRSecurityProfileGroup,
    IRService,
    IRServiceCategory,
    IRServiceGroup,
    IRServicePort,
    IRSystemSettings,
    IRTrafficShaper,
    IRVirtualIP,
    IRVirtualIPGroup,
    IRVPNPhase2,
    IRVPNTunnel,
    IRZone,
)
from fwmigrate.ir.enums import AddressType, NATType, PolicyAction, ServiceProtocol
from fwmigrate.parsers.fortigate.coverage import (
    ExtractionStatus,
    classify_section_coverage,
    fortigate_source_category,
)
from fwmigrate.extraction.models import SourceSectionResult
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.model import FGConfig, FGSystemGlobal
from fwmigrate.parsers.fortigate.parser import FortiGateParser
from fwmigrate.parsers.fortigate.tokenizer import FortiGateTokenizer
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def _build_minimal_ir(**kwargs) -> IRConfig:
    if "zones" not in kwargs and "interfaces" not in kwargs:
        kwargs["zones"] = [
            IRZone(name="trust"),
            IRZone(name="untrust"),
            IRZone(name="zone_trust"),
            IRZone(name="zone_untrust"),
        ]
    return IRConfig(
        metadata=IRMetadata(source_vendor="fortigate", hostname="test-fg"),
        **kwargs,
    )


def test_hard_generation_blocker():
    """Verify that when IR generation_safe is False, generators emit no deployable configuration."""
    ir = _build_minimal_ir(
        generation_safe=False,
        generation_blocking_reasons=["Central NAT mode enabled in root VDOM"],
        policies=[
            IRPolicy(
                name="allow_web",
                from_zone=["trust"],
                to_zone=["untrust"],
                source=["all"],
                destination=["all"],
                service=["ALL"],
                action=PolicyAction.ALLOW,
            )
        ],
    )
    cli_gen = FortiGateCLIGenerator()
    cli_artifacts = cli_gen.generate(ir)
    assert len(cli_artifacts) == 1
    assert "BLOCKED" in cli_artifacts[0].content
    assert "config firewall policy" not in cli_artifacts[0].content
    assert "Central NAT mode enabled" in cli_artifacts[0].content

    tf_gen = FortiGateTerraformGenerator()
    tf_artifacts = tf_gen.generate(ir)
    assert len(tf_artifacts) == 1
    assert "BLOCKED" in tf_artifacts[0].content
    assert 'resource "fortios_firewall_policy"' not in tf_artifacts[0].content


def test_schedule_exact_preservation_and_withholding():
    """Verify schedule preservation and withholding of unresolved / schedule-group schedules."""
    # Policy with valid emitted recurring schedule
    sched = IRSchedule(
        name="work_hours",
        start="08:00",
        end="17:00",
        days=["monday", "tuesday", "wednesday", "thursday", "friday"],
        schedule_type="recurring",
    )
    pol1 = IRPolicy(
        name="pol_work",
        from_zone=["trust"],
        to_zone=["untrust"],
        source=["all"],
        destination=["all"],
        service=["ALL"],
        action=PolicyAction.ALLOW,
        schedule="work_hours",
    )
    # Policy referencing un-emitted schedule
    pol2 = IRPolicy(
        name="pol_missing_sched",
        from_zone=["trust"],
        to_zone=["untrust"],
        source=["all"],
        destination=["all"],
        service=["ALL"],
        action=PolicyAction.ALLOW,
        schedule="nonexistent_schedule",
    )

    ir = _build_minimal_ir(
        schedules=[sched],
        policies=[pol1, pol2],
    )

    cli_artifacts = FortiGateCLIGenerator().generate(ir)
    cli_text = cli_artifacts[0].content
    assert 'edit "work_hours"' in cli_text
    assert 'set schedule "work_hours"' in cli_text
    assert 'set name "pol_work"' in cli_text
    assert "Policy pol_missing_sched withheld" in cli_text

    tf_artifacts = FortiGateTerraformGenerator().generate(ir)
    main_tf = [a for a in tf_artifacts if a.filename == "main.tf"][0].content
    assert 'resource "fortios_firewallschedule_recurring"' in main_tf
    assert 'schedule = "work_hours"' in main_tf
    assert "Policy pol_missing_sched withheld" in main_tf


def test_policy_omitted_schedule_is_none_and_withheld():
    """Verify omitted schedule in source config is None and policy is withheld in CLI/Terraform."""
    config_text = """
config firewall policy
    edit 1
        set name "pol_no_sched"
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
"""
    parser = FortiGateParser(FortiGateTokenizer(config_text))
    fg = parser.parse()
    # Check parser model: schedule is None (not "always")
    assert fg.policies[0].schedule is None

    transformer = FGToIRTransformer(fg)
    ir = transformer.transform()
    assert ir.policies[0].schedule is None
    assert ir.policies[0].source_schedule is None

    # CLI generator withholds policy
    cli_text = FortiGateCLIGenerator().generate(ir)[0].content
    assert "Policy pol_no_sched withheld: schedule is missing or empty" in cli_text

    # Terraform generator withholds policy
    tf_text = [a for a in FortiGateTerraformGenerator().generate(ir) if a.filename == "main.tf"][0].content
    assert "Policy pol_no_sched withheld: schedule is missing or empty" in tf_text


def test_address_withholding_and_ipv6():
    """Verify STUB_UNSUPPORTED / invalid addresses are withheld and IPv6 emits address6."""
    addr_stub = IRAddress(
        name="stub_addr",
        type=AddressType.STUB_UNSUPPORTED,
        stub_value="unsupported-type-val",
        requires_manual_review=True,
    )
    addr_v4 = IRAddress(
        name="web_srv",
        type=AddressType.HOST,
        subnet="192.168.1.50/32",
    )
    addr_v6 = IRAddress(
        name="web_srv6",
        type=AddressType.HOST,
        is_ipv6=True,
        subnet="2001:db8::50/128",
    )

    ir = _build_minimal_ir(addresses=[addr_stub, addr_v4, addr_v6])

    cli_text = FortiGateCLIGenerator().generate(ir)[0].content
    assert "# Address stub_addr withheld" in cli_text
    assert 'edit "web_srv"' in cli_text
    assert "set subnet 192.168.1.50 255.255.255.255" in cli_text
    assert "config firewall address6" in cli_text
    assert 'edit "web_srv6"' in cli_text
    assert "set ip6 2001:db8::50/128" in cli_text

    main_tf = [a for a in FortiGateTerraformGenerator().generate(ir) if a.filename == "main.tf"][0].content
    assert "# Address stub_addr withheld" in main_tf
    assert 'resource "fortios_firewall_address"' in main_tf
    assert 'resource "fortios_firewall_address6"' in main_tf
    assert 'ip6  = "2001:db8::50/128"' in main_tf


def test_wildcard_fqdn_dedicated_section():
    """Verify wildcard FQDN is emitted under config firewall wildcard-fqdn custom and withheld in Terraform."""
    addr_wf = IRAddress(
        name="wf_google",
        type=AddressType.WILDCARD_FQDN,
        value="*.google.com",
    )
    ir = _build_minimal_ir(addresses=[addr_wf])

    cli_text = FortiGateCLIGenerator().generate(ir)[0].content
    assert "config firewall wildcard-fqdn custom" in cli_text
    assert 'edit "wf_google"' in cli_text
    assert 'set wildcard-fqdn "*.google.com"' in cli_text
    assert "config firewall address\n" not in cli_text

    main_tf = [a for a in FortiGateTerraformGenerator().generate(ir) if a.filename == "main.tf"][0].content
    assert f"# Address wf_google withheld: unsupported IPv4 address type '{AddressType.WILDCARD_FQDN.value}' for Terraform" in main_tf


def test_positive_dependency_validation_interfaces_and_zones():
    """Verify positive interface/zone validation withholds unknown or wrong-VDOM references."""
    pol_unknown_zone = IRPolicy(
        name="pol_bad_zone",
        from_zone=["nonexistent_zone"],
        to_zone=["untrust"],
        source=["all"],
        destination=["all"],
        service=["ALL"],
        action=PolicyAction.ALLOW,
        schedule="always",
    )
    pol_cross_vdom_zone = IRPolicy(
        name="pol_cross_vdom",
        source_context="VDOM1",
        from_zone=["trust_vdom2"],
        to_zone=["untrust"],
        source=["all"],
        destination=["all"],
        service=["ALL"],
        action=PolicyAction.ALLOW,
        schedule="always",
    )
    ir = _build_minimal_ir(
        zones=[
            IRZone(name="trust", source_context=None),
            IRZone(name="untrust", source_context=None),
            IRZone(name="trust_vdom2", source_context="VDOM2"),
        ],
        policies=[pol_unknown_zone, pol_cross_vdom_zone],
    )

    cli_text = FortiGateCLIGenerator().generate(ir)[0].content
    assert "Policy pol_bad_zone withheld: from_zone or to_zone references unknown" in cli_text
    assert "Policy pol_cross_vdom withheld: from_zone or to_zone references unknown" in cli_text

    main_tf = [a for a in FortiGateTerraformGenerator().generate(ir) if a.filename == "main.tf"][0].content
    assert "Policy pol_bad_zone withheld: from_zone or to_zone references unknown" in main_tf
    assert "Policy pol_cross_vdom withheld: from_zone or to_zone references unknown" in main_tf


def test_nat_generation_from_ir_nat_rule():
    """Verify CLI generator emits NAT configuration derived from IRNATRule."""
    pol = IRPolicy(
        name="outbound_nat_policy",
        source_rule_id="10",
        from_zone=["trust"],
        to_zone=["untrust"],
        source=["all"],
        destination=["all"],
        service=["ALL"],
        action=PolicyAction.ALLOW,
        schedule="always",
        nat_enabled=True,
    )
    nat_rule = IRNATRule(
        name="nat_rule_10",
        source_policy_reference="10",
        type=NATType.SOURCE,
        source_policy_fixed_port="enable",
        source_pool_references=["corp_pool"],
    )
    pool = IRIPPool(
        name="corp_pool",
        start_ip="203.0.113.10",
        end_ip="203.0.113.20",
        pool_type="overload",
    )

    ir = _build_minimal_ir(
        ip_pools=[pool],
        policies=[pol],
        nat_rules=[nat_rule],
    )

    cli_text = FortiGateCLIGenerator().generate(ir)[0].content
    assert 'edit "corp_pool"' in cli_text
    assert "set startip 203.0.113.10" in cli_text
    assert "set nat enable" in cli_text
    assert "set ippool enable" in cli_text
    assert 'set poolname "corp_pool"' in cli_text
    assert "set fixedport enable" in cli_text

    # Basic canonical NAT is emitted by Terraform.
    main_tf = [a for a in FortiGateTerraformGenerator().generate(ir) if a.filename == "main.tf"][0].content
    assert 'resource "fortios_firewall_policy"' in main_tf
    assert 'nat      = "enable"' in main_tf


def test_terraform_hcl_serialization():
    """Verify Terraform generator emits valid HCL lists with double quotes, not Python single-quoted lists."""
    pol = IRPolicy(
        name="hcl_test_policy",
        from_zone=["zone_trust"],
        to_zone=["zone_untrust"],
        source=["all"],
        destination=["all"],
        service=["ALL"],
        action=PolicyAction.ALLOW,
        schedule="always",
    )
    ir = _build_minimal_ir(
        zones=[IRZone(name="zone_trust"), IRZone(name="zone_untrust")],
        policies=[pol],
    )

    main_tf = [a for a in FortiGateTerraformGenerator().generate(ir) if a.filename == "main.tf"][0].content
    assert 'for_each = ["zone_trust"]' in main_tf
    assert 'for_each = ["zone_untrust"]' in main_tf
    assert "['zone_trust']" not in main_tf
    assert "['zone_untrust']" not in main_tf


def test_static_routes_ipv4_and_ipv6_separation():
    """Verify static routes are separated by address family in CLI and Terraform."""
    rt_v4 = IRRoute(
        name="rt_v4_default",
        destination="0.0.0.0/0",
        next_hop="192.168.1.1",
        interface="port1",
        address_family="ipv4",
    )
    rt_v6 = IRRoute(
        name="rt_v6_default",
        destination="::/0",
        next_hop="2001:db8::1",
        interface="port2",
        address_family="ipv6",
    )
    rt_v6_no_intf = IRRoute(
        name="rt_v6_no_device",
        destination="2001:db8:abc::/64",
        next_hop="2001:db8::1",
        address_family="ipv6",
    )

    ir = _build_minimal_ir(routes=[rt_v4, rt_v6, rt_v6_no_intf])

    cli_text = FortiGateCLIGenerator().generate(ir)[0].content
    assert "config router static\n" in cli_text
    assert "set dst 0.0.0.0 0.0.0.0" in cli_text
    assert "config router static6\n" in cli_text
    assert "set dst ::/0" in cli_text
    assert "set dst 2001:db8:abc::/64" in cli_text

    main_tf = [a for a in FortiGateTerraformGenerator().generate(ir) if a.filename == "main.tf"][0].content
    assert 'resource "fortios_router_static"' in main_tf
    assert 'resource "fortios_router_static6"' in main_tf
    assert 'dst    = "::/0"' in main_tf
    assert "Route rt_v6_no_device withheld: Terraform IPv6 route requires device interface" in main_tf


def test_unset_handling_in_parser():
    """Verify that unsetting central-nat, ngfw-mode, session-ttl default restores default values."""
    config_text = """
config system settings
    set central-nat enable
    set ngfw-mode policy-based
    set opmode transparent
end
config system settings
    unset central-nat
    unset ngfw-mode
    unset opmode
end
config system session-ttl
    set default 3600
end
config system session-ttl
    unset default
end
"""
    parser = FortiGateParser(FortiGateTokenizer(config_text))
    fg = parser.parse()
    # Execution contexts
    ctx = fg.execution_contexts[0] if fg.execution_contexts else None
    assert ctx is not None
    assert ctx.central_nat is None
    assert ctx.ngfw_mode is None
    assert ctx.opmode is None
    assert fg.session_ttl_settings is None or fg.session_ttl_settings.default_timeout is None


def test_context_scoped_profile_resolution():
    """Verify that UTM profiles in different VDOMs do not cross-pollinate."""
    config_text = """
config vdom
edit VDOM1
config ips sensor
    edit "custom_sensor"
        set comment "Sensor in VDOM1"
    next
end
config firewall policy
    edit 1
        set name "pol_vdom1"
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set utm-status enable
        set ips-sensor "custom_sensor"
    next
end
next
edit VDOM2
config firewall policy
    edit 2
        set name "pol_vdom2"
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set utm-status enable
        set ips-sensor "custom_sensor"
    next
end
next
end
"""
    parser = FortiGateParser(FortiGateTokenizer(config_text))
    fg = parser.parse()
    transformer = FGToIRTransformer(fg)
    ir = transformer.transform()

    pol1 = next(p for p in ir.policies if p.name == "pol_vdom1")
    pol2 = next(p for p in ir.policies if p.name == "pol_vdom2")

    # pol1 in VDOM1 has matching ips-sensor custom_sensor in VDOM1
    assert "ips:custom_sensor" not in pol1.unresolved_security_profiles
    # pol2 in VDOM2 references custom_sensor which does NOT exist in VDOM2
    assert "ips:custom_sensor" in pol2.unresolved_security_profiles
    assert "unresolved security profile reference(s): ips:custom_sensor" in pol2.review_reasons


def test_direct_vdom_provenance_distinct_names():
    """Verify duplicate object names across VDOMs maintain direct source_context."""
    config_text = """
config vdom
edit VDOM_A
config firewall address
    edit "shared_host"
        set subnet 10.1.1.1 255.255.255.255
    next
end
next
edit VDOM_B
config firewall address
    edit "shared_host"
        set subnet 10.2.2.2 255.255.255.255
    next
end
next
end
"""
    parser = FortiGateParser(FortiGateTokenizer(config_text))
    fg = parser.parse()
    transformer = FGToIRTransformer(fg)
    ir = transformer.transform()

    vdom_a_addr = next(a for a in ir.addresses if a.source_context == "VDOM_A")
    vdom_b_addr = next(a for a in ir.addresses if a.source_context == "VDOM_B")

    assert vdom_a_addr.value == "10.1.1.1/32"
    assert vdom_b_addr.value == "10.2.2.2/32"


def test_vdom_provenance_survival_on_all_models():
    """Verify source_context survives model creation and model_dump for all VDOM-scoped IR models."""
    models = [
        IRTrafficShaper(name="shaper1", source_context="VDOM_X"),
        IRProxyAddress(name="proxy1", source_context="VDOM_X"),
        IRVirtualIPGroup(name="vipgrp1", source_context="VDOM_X"),
        IRIPSSensor(name="ips1", source_context="VDOM_X"),
        IRVPNTunnel(name="vpn1", local_interface="port1", source_context="VDOM_X"),
        IRVPNPhase2(name="p2_1", phase1_name="vpn1", source_context="VDOM_X"),
        IRRoute(name="rt1", source_context="VDOM_X"),
        IRSecurityProfileGroup(name="spg1", source_context="VDOM_X"),
        IRScheduleGroup(name="schg1", source_context="VDOM_X"),
    ]

    for model in models:
        assert model.source_context == "VDOM_X"
        dumped = model.model_dump()
        assert dumped["source_context"] == "VDOM_X"


def test_hostname_no_fabrication():
    """Verify absent or unset hostname is None across FGConfig, IRMetadata, and IRSystemSettings."""
    # Absent
    config_empty = "config system global\nend\n"
    parser = FortiGateParser(FortiGateTokenizer(config_empty))
    fg = parser.parse()
    assert (fg.system_global.hostname if fg.system_global else None) is None

    ir = FGToIRTransformer(fg).transform()
    assert ir.metadata.hostname is None
    assert (ir.system_settings.hostname if ir.system_settings else None) is None

    # Set then unset
    config_unset = """
config system global
    set hostname my-firewall
    unset hostname
end
"""
    parser2 = FortiGateParser(FortiGateTokenizer(config_unset))
    fg2 = parser2.parse()
    assert (fg2.system_global.hostname if fg2.system_global else None) is None

    ir2 = FGToIRTransformer(fg2).transform()
    assert ir2.metadata.hostname is None
    assert (ir2.system_settings.hostname if ir2.system_settings else None) is None


def test_system_settings_coverage_accounting():
    """Verify system settings is classified as EXTRACT_ONLY with apply_global_set and System Behaviour category."""
    fg_config = FGConfig()
    ir_config = IRConfig(metadata=IRMetadata(source_vendor="fortigate"))
    section = SourceSectionResult(path="system settings", status=ExtractionStatus.UNSUPPORTED, object_count_source=1)

    classify_section_coverage([section], fg_config, ir_config)
    assert section.status == ExtractionStatus.EXTRACT_ONLY
    assert section.parser_handler in ("source inventory", "FortiGateParser.apply_global_set")
    assert fortigate_source_category(section.path) == "System Behaviour"


def test_cli_nat_handling_twice_nat_and_dnat_vip_correlation():
    """Phase 1: Verify TWICE NAT policy withholding, DNAT VIP correlation, and IP pool safety."""
    vip = IRVirtualIP(name="VIP_Web", external_ip="203.0.113.10", mapped_ips=["10.0.0.10"])
    pool = IRIPPool(name="SNAT_Pool", start_ip="198.51.100.1", end_ip="198.51.100.10")

    # Policy 1: Safe SNAT with Pool
    # Policy 2: TWICE NAT -> Withheld
    # Policy 3: DNAT referencing un-emitted VIP -> Withheld
    # Policy 4: DNAT referencing emitted VIP -> Allowed
    ir = _build_minimal_ir(
        virtual_ips=[vip],
        ip_pools=[pool],
        addresses=[
            IRAddress(name="Host_Internal", type=AddressType.HOST, value="10.0.0.10"),
            IRAddress(name="VIP_Web", type=AddressType.HOST, value="203.0.113.10"),
        ],
        policies=[
            IRPolicy(
                name="Allow_SNAT",
                source_rule_id="101",
                from_zone=["trust"],
                to_zone=["untrust"],
                source=["Host_Internal"],
                destination=["all"],
                service=["ALL"],
                schedule="always",
                action=PolicyAction.ALLOW,
                nat_enabled=True,
                nat_pool_names=["SNAT_Pool"],
            ),
            IRPolicy(
                name="Deny_TWICE_NAT",
                source_rule_id="102",
                from_zone=["trust"],
                to_zone=["untrust"],
                source=["Host_Internal"],
                destination=["all"],
                service=["ALL"],
                schedule="always",
                action=PolicyAction.ALLOW,
            ),
            IRPolicy(
                name="Deny_Unemitted_DNAT",
                source_rule_id="103",
                from_zone=["untrust"],
                to_zone=["trust"],
                source=["all"],
                destination=["all"],
                service=["ALL"],
                schedule="always",
                action=PolicyAction.ALLOW,
            ),
            IRPolicy(
                name="Allow_Emitted_DNAT",
                source_rule_id="104",
                from_zone=["untrust"],
                to_zone=["trust"],
                source=["all"],
                destination=["VIP_Web"],
                service=["ALL"],
                schedule="always",
                action=PolicyAction.ALLOW,
            ),
        ],
        nat_rules=[
            IRNATRule(
                name="snat_101",
                type=NATType.SOURCE,
                source_policy_reference="101",
                source_translation_mode="pool",
                source_pool_references=["SNAT_Pool"],
            ),
            IRNATRule(
                name="twice_102",
                type=NATType.TWICE,
                source_policy_reference="102",
                source_translation_mode="pool",
                source_pool_references=["SNAT_Pool"],
                translated_source="198.51.100.1",
                destination_translation_mode="static",
                translated_destination="10.0.0.10",
            ),
            IRNATRule(
                name="dnat_103",
                type=NATType.DESTINATION,
                source_policy_reference="103",
                source_vip_reference="UNEMITTED_VIP",
                requires_manual_review=False,
                migration_status="NORMALIZED",
            ),
            IRNATRule(
                name="dnat_104",
                type=NATType.DESTINATION,
                source_policy_reference="104",
                source_vip_reference="VIP_Web",
                requires_manual_review=False,
                migration_status="NORMALIZED",
            ),
        ],
    )

    cli_gen = FortiGateCLIGenerator()
    artifacts = cli_gen.generate(ir)
    content = artifacts[0].content

    assert 'set name "Allow_SNAT"' in content
    assert "set poolname \"SNAT_Pool\"" in content
    assert "Policy Deny_TWICE_NAT withheld: TWICE NAT is not supported" in content
    assert "Policy Deny_Unemitted_DNAT withheld: associated DNAT rule references un-emitted VIP 'UNEMITTED_VIP'" in content
    assert 'set name "Allow_Emitted_DNAT"' in content


def test_terraform_no_fabricated_system_settings_placeholder():
    """Phase 2: Verify fortios_system_settings is never emitted in Terraform output."""
    ir = _build_minimal_ir(
        system_settings=IRSystemSettings(
            hostname="FW-CORE",
            timezone="04",
            admin_https_port=8443,
        )
    )
    tf_gen = FortiGateTerraformGenerator()
    artifacts = tf_gen.generate(ir)
    main_tf = next(a.content for a in artifacts if a.filename == "main.tf")

    assert 'resource "fortios_system_global" "migrated_global_settings"' in main_tf
    assert 'hostname = "FW-CORE"' in main_tf
    assert 'resource "fortios_system_settings"' not in main_tf
    assert "migrated_system_settings" not in main_tf


def test_strict_route_ip_and_range_validation_cli_and_terraform():
    """Phase 3, 4, 5, 12: Verify strict IP destination/next-hop/source-prefix parsing and numeric range guards."""
    ir = _build_minimal_ir(
        routes=[
            # Valid v4 route
            IRRoute(
                name="rt_valid",
                destination="192.0.2.0/24",
                next_hop="198.51.100.1",
                source_prefix="10.0.0.0/24",
                administrative_distance=10,
                priority=100,
                weight=5,
                vrf=1,
                route_tag=42,
                internet_service=1000,
                dynamic_gateway="enable",
                link_monitor_exempt="enable",
                bfd="enable",
            ),
            # Invalid v4 destination with host bits (192.0.2.1/24)
            IRRoute(name="rt_invalid_dst", destination="192.0.2.1/24"),
            # Cross-family next hop
            IRRoute(name="rt_cross_family", destination="192.0.2.0/24", next_hop="2001:db8::1"),
            # Out of range distance (0)
            IRRoute(name="rt_invalid_dist", destination="192.0.2.0/24", administrative_distance=0),
            # Out of range priority (70000)
            IRRoute(name="rt_invalid_prio", destination="192.0.2.0/24", priority=70000),
            # Out of range VRF (300)
            IRRoute(name="rt_invalid_vrf", destination="192.0.2.0/24", vrf=300),
            # Metric populated (withheld)
            IRRoute(name="rt_with_metric", destination="192.0.2.0/24", metric=10),
            # Invalid dynamic_gateway string
            IRRoute(name="rt_invalid_dg", destination="192.0.2.0/24", dynamic_gateway="yes"),
            # Valid v6 route
            IRRoute(
                name="rt6_valid",
                address_family="ipv6",
                destination="2001:db8:1::/64",
                next_hop="2001:db8:1::1",
                interface="port1",
            ),
            # Invalid v6 route without interface in Terraform (required for static6)
            IRRoute(
                name="rt6_no_intf",
                address_family="ipv6",
                destination="2001:db8:2::/64",
            ),
        ]
    )

    cli_content = FortiGateCLIGenerator().generate(ir)[0].content
    tf_content = next(a.content for a in FortiGateTerraformGenerator().generate(ir) if a.filename == "main.tf")

    # CLI Assertions
    assert "set dst 192.0.2.0 255.255.255.0" in cli_content
    assert "set src 10.0.0.0/24" in cli_content
    assert "set distance 10" in cli_content
    assert "set priority 100" in cli_content
    assert "set weight 5" in cli_content
    assert "set vrf 1" in cli_content
    assert "set tag 42" in cli_content
    assert "set internet-service 1000" in cli_content
    assert "set dynamic-gateway enable" in cli_content
    assert "set link-monitor-exempt enable" in cli_content
    assert "set bfd enable" in cli_content
    assert "Route rt_invalid_dst withheld: invalid or non-canonical IPv4 destination" in cli_content
    assert "Route rt_cross_family withheld: invalid or cross-family IPv4 gateway" in cli_content
    assert "Route rt_invalid_dist withheld: distance 0 outside range 1-255" in cli_content
    assert "Route rt_invalid_prio withheld: priority 70000 outside range 1-65535" in cli_content
    assert "Route rt_invalid_vrf withheld: vrf 300 outside range 0-251" in cli_content
    assert "Route rt_with_metric withheld: generic metric is not supported" in cli_content
    assert "Route rt_invalid_dg withheld: invalid dynamic_gateway setting 'yes'" in cli_content

    # Terraform Assertions
    assert 'dst = "192.0.2.0 255.255.255.0"' in tf_content
    assert 'src = "10.0.0.0/24"' in tf_content
    assert "distance = 10" in tf_content
    assert "priority = 100" in tf_content
    assert "weight   = 5" in tf_content
    assert "vrf = 1" in tf_content
    assert "tag = 42" in tf_content
    assert "internet_service = 1000" in tf_content
    assert 'dynamic_gateway = "enable"' in tf_content
    assert 'link_monitor_exempt = "enable"' in tf_content
    assert 'bfd = "enable"' in tf_content
    assert "Route rt_invalid_dst withheld: invalid or non-canonical IPv4 destination" in tf_content
    assert "Route rt_cross_family withheld: invalid or cross-family IPv4 gateway" in tf_content
    assert "Route rt_invalid_dist withheld: distance 0 outside range 1-255" in tf_content
    assert "Route rt_invalid_prio withheld: priority 70000 outside range 1-65535" in tf_content
    assert "Route rt_invalid_vrf withheld: vrf 300 outside range 0-251" in tf_content
    assert "Route rt_with_metric withheld: generic metric is not supported" in tf_content
    assert "Route rt6_no_intf withheld: Terraform IPv6 route requires device interface" in tf_content


def test_route_sdwan_and_custom_internet_service_withholding():
    """Phase 5: Verify routes with SD-WAN zones or custom Internet Service dependencies are withheld."""
    ir = _build_minimal_ir(
        routes=[
            IRRoute(name="rt_sdwan_zone", destination="192.0.2.0/24", sdwan_zone="zone1"),
            IRRoute(name="rt_sdwan_zones", destination="192.0.2.0/24", sdwan_zones=["zone1", "zone2"]),
            IRRoute(name="rt_inconsistent", destination="192.0.2.0/24", sdwan_zone="zone1", sdwan_zones=["zone2"]),
            IRRoute(name="rt_custom_isdb", destination="192.0.2.0/24", internet_service_custom="my-custom-isdb"),
        ]
    )

    cli_content = FortiGateCLIGenerator().generate(ir)[0].content
    tf_content = next(a.content for a in FortiGateTerraformGenerator().generate(ir) if a.filename == "main.tf")

    assert "Route rt_sdwan_zone withheld: referenced SD-WAN zone(s) are not generated" in cli_content
    assert "Route rt_sdwan_zones withheld: referenced SD-WAN zone(s) are not generated" in cli_content
    assert "Route rt_inconsistent withheld: inconsistent singular/list SD-WAN zone configuration" in cli_content
    assert "Route rt_custom_isdb withheld: custom Internet Service dependency is not generated" in cli_content

    assert "Route rt_sdwan_zone withheld: referenced SD-WAN zone(s) are not generated" in tf_content
    assert "Route rt_sdwan_zones withheld: referenced SD-WAN zone(s) are not generated" in tf_content
    assert "Route rt_inconsistent withheld: inconsistent singular/list SD-WAN zone configuration" in tf_content
    assert "Route rt_custom_isdb withheld: custom Internet Service dependency is not generated" in tf_content


def test_service_category_emission_and_dependency():
    """Phase 7: Verify service categories are emitted and required by referencing services in CLI and Terraform."""
    ir = _build_minimal_ir(
        service_categories=[
            IRServiceCategory(
                name="Web Services",
                description="Standard web traffic",
                source_fabric_object="enable",
                requires_manual_review=False,
                migration_status="NORMALIZED",
            ),
            IRServiceCategory(
                name="Invalid_Name_" + "x" * 60,
                requires_manual_review=False,
                migration_status="NORMALIZED",
            ),  # >63 chars -> withheld
        ],
        services=[
            IRService(
                name="HTTP_Custom",
                source_category="Web Services",
                ports=[IRServicePort(protocol=ServiceProtocol.TCP, port="8080")],
            ),
            IRService(
                name="Unemitted_Cat_Svc",
                source_category="NonExistent_Category",
                ports=[IRServicePort(protocol=ServiceProtocol.TCP, port="9090")],
            ),
        ],
    )

    cli_content = FortiGateCLIGenerator().generate(ir)[0].content
    tf_content = next(a.content for a in FortiGateTerraformGenerator().generate(ir) if a.filename == "main.tf")

    # CLI Assertions
    assert "config firewall service category" in cli_content
    assert 'edit "Web Services"' in cli_content
    assert 'set comment "Standard web traffic"' in cli_content
    assert "set fabric-object enable" in cli_content
    assert "Service category Invalid_Name_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx withheld: invalid name length" in cli_content
    assert 'edit "HTTP_Custom"' in cli_content
    assert 'set category "Web Services"' in cli_content
    assert "Service Unemitted_Cat_Svc withheld: references un-emitted service category 'NonExistent_Category'" in cli_content

    # Terraform Assertions
    assert 'resource "fortios_firewallservice_category" "Web_Services"' in tf_content
    assert 'name = "Web Services"' in tf_content
    assert 'category = fortios_firewallservice_category.Web_Services.name' in tf_content
    assert "Service Unemitted_Cat_Svc withheld: references un-emitted service category 'NonExistent_Category'" in tf_content


def test_service_icmp_integer_typing_and_range_validation():
    """Phase 6: Verify ICMP typing as integer in Terraform, port protocol validation, and conflicting ICMP withholding."""
    ir = _build_minimal_ir(
        services=[
            IRService(
                name="Custom_Ping",
                source_protocol_number=1,
                source_color=5,
                ports=[IRServicePort(protocol=ServiceProtocol.ICMP, port="0", icmptype=8, icmpcode=0)],
            ),
            IRService(
                name="Conflicting_ICMP",
                ports=[
                    IRServicePort(protocol=ServiceProtocol.ICMP, port="0", icmptype=8, icmpcode=0),
                    IRServicePort(protocol=ServiceProtocol.ICMP, port="0", icmptype=0, icmpcode=0),
                ],
            ),
            IRService(
                name="Invalid_Protocol_Num",
                source_protocol_number=300,  # outside 0-254
                ports=[IRServicePort(protocol=ServiceProtocol.IP, port="0")],
            ),
        ]
    )

    cli_content = FortiGateCLIGenerator().generate(ir)[0].content
    tf_content = next(a.content for a in FortiGateTerraformGenerator().generate(ir) if a.filename == "main.tf")

    # CLI Assertions
    assert 'edit "Custom_Ping"' in cli_content
    assert "set protocol-number 1" in cli_content
    assert "set color 5" in cli_content
    assert "set icmptype 8" in cli_content
    assert "set icmpcode 0" in cli_content
    assert "Service Conflicting_ICMP withheld: multiple conflicting ICMP types or codes" in cli_content
    assert "Service Invalid_Protocol_Num withheld: protocol-number 300 outside valid range 0-254" in cli_content

    # Terraform Assertions
    assert 'resource "fortios_firewallservice_custom" "Custom_Ping"' in tf_content
    assert "protocol_number = 1" in tf_content
    assert "icmptype = 8" in tf_content  # unquoted integer!
    assert "icmpcode = 0" in tf_content  # unquoted integer!
    assert "Service Conflicting_ICMP withheld: multiple conflicting ICMP types or codes" in tf_content
    assert "Service Invalid_Protocol_Num withheld: protocol-number 300 outside valid range 0-254" in tf_content


def test_security_profile_group_dependency_withholding():
    """Phase 8: Verify security profile groups with child references or unsupported profiles are withheld."""
    ir = _build_minimal_ir(
        security_profile_groups=[
            IRSecurityProfileGroup(name="Safe_Empty_Group", requires_manual_review=False, migration_status="NORMALIZED"),
            IRSecurityProfileGroup(name="With_Child_AV", antivirus="default-av", requires_manual_review=False, migration_status="NORMALIZED"),
            IRSecurityProfileGroup(name="With_Anti_Spyware", anti_spyware="default-spyware", requires_manual_review=False, migration_status="NORMALIZED"),
        ],
        policies=[
            IRPolicy(
                name="Allow_With_Safe_Group",
                from_zone=["trust"],
                to_zone=["untrust"],
                source=["all"],
                destination=["all"],
                service=["ALL"],
                schedule="always",
                action=PolicyAction.ALLOW,
                security_profile_group="Safe_Empty_Group",
            ),
            IRPolicy(
                name="Deny_With_Unemitted_Group",
                from_zone=["trust"],
                to_zone=["untrust"],
                source=["all"],
                destination=["all"],
                service=["ALL"],
                schedule="always",
                action=PolicyAction.ALLOW,
                security_profile_group="With_Child_AV",
            ),
        ],
    )

    cli_content = FortiGateCLIGenerator().generate(ir)[0].content

    assert 'edit "Safe_Empty_Group"' in cli_content
    assert "Security profile group With_Child_AV withheld: referenced child security profiles are not generated" in cli_content
    assert "Security profile group With_Anti_Spyware withheld: unsupported profile semantics" in cli_content
    assert 'set profile-group "Safe_Empty_Group"' in cli_content
    assert "Policy Deny_With_Unemitted_Group withheld: referenced security_profile_group 'With_Child_AV' is un-emitted" in cli_content


def test_parse_errors_in_common_target_safety():
    """Phase 10: Verify is_generation_safe_object checks parse_errors and callable safe_for_target_generation."""
    from fwmigrate.generators.target_helpers import is_generation_safe_object

    class CustomObject:
        def __init__(self, parse_errors=None, safe=True):
            self.parse_errors = parse_errors or []
            self.migration_status = "NORMALIZED"
            self.requires_manual_review = False
            self.review_reasons = []
            self._safe = safe

        def safe_for_target_generation(self):
            return self._safe

    # Safe object
    safe_obj = CustomObject()
    assert is_generation_safe_object(safe_obj) is True

    # Object with parse_errors
    error_obj = CustomObject(parse_errors=["Invalid IP mask"])
    assert is_generation_safe_object(error_obj) is False

    # Object returning False from callable safe_for_target_generation
    unsafe_callable_obj = CustomObject(safe=False)
    assert is_generation_safe_object(unsafe_callable_obj) is False


def test_schedule_complete_validation_cli_and_terraform():
    """Phase 11: Verify schedule exact field validation, recurring day rules, and onetime UTC timestamps."""
    ir = _build_minimal_ir(
        schedules=[
            # Valid recurring with weekdays
            IRSchedule(
                name="work_week",
                schedule_type="recurring",
                start="08:00",
                end="17:00",
                days=["monday", "tuesday", "wednesday", "thursday", "friday"],
                source_color=2,
                source_fabric_object="enable",
            ),
            # Valid recurring with days=[] (omit day in CLI/TF)
            IRSchedule(
                name="recurring_no_day",
                schedule_type="recurring",
                start="09:00",
                end="18:00",
                days=[],
            ),
            # Valid recurring with days=["none"] (emit explicit none)
            IRSchedule(
                name="recurring_explicit_none",
                schedule_type="recurring",
                start="00:00",
                end="23:59",
                days=["none"],
            ),
            # Invalid recurring: contradictory "none" + "monday" -> withheld
            IRSchedule(
                name="contradictory_days",
                schedule_type="recurring",
                start="08:00",
                end="17:00",
                days=["none", "monday"],
            ),
            # Invalid recurring: expiration_days on recurring -> withheld
            IRSchedule(
                name="recurring_with_expiry",
                schedule_type="recurring",
                start="08:00",
                end="17:00",
                days=["monday"],
                expiration_days=5,
            ),
            # Valid onetime with UTC epoch timestamps
            IRSchedule(
                name="maint_window",
                schedule_type="onetime",
                start="08:00 2026/08/30",
                end="12:00 2026/08/30",
                start_utc="1788076800",
                end_utc="1788091200",
                expiration_days=1,
                source_color=10,
                source_fabric_object="enable",
            ),
            # Invalid onetime: end before start -> withheld
            IRSchedule(
                name="invalid_onetime_dt",
                schedule_type="onetime",
                start="12:00 2026/08/30",
                end="08:00 2026/08/30",
            ),
            # Schedule with unmodeled cross-vendor attributes -> withheld
            IRSchedule(
                name="unmodeled_attr_sched",
                schedule_type="recurring",
                start="08:00",
                end="17:00",
                days=["monday"],
                source_attributes={"palo_alto_recurrence": "weekly"},
            ),
        ]
    )

    cli_content = FortiGateCLIGenerator().generate(ir)[0].content
    tf_content = next(a.content for a in FortiGateTerraformGenerator().generate(ir) if a.filename == "main.tf")

    # CLI Assertions
    assert 'edit "work_week"' in cli_content
    assert "set day monday tuesday wednesday thursday friday" in cli_content
    assert 'set start "08:00"' in cli_content
    assert 'set end "17:00"' in cli_content
    assert "set color 2" in cli_content
    assert "set fabric-object enable" in cli_content

    assert 'edit "recurring_no_day"' in cli_content
    assert "set day" not in cli_content.split('edit "recurring_no_day"')[1].split("next")[0]

    assert 'edit "recurring_explicit_none"' in cli_content
    assert "set day none" in cli_content

    assert "Schedule contradictory_days withheld: 'none' cannot be combined with weekday names" in cli_content
    assert "Schedule recurring_with_expiry withheld: expiration_days is not supported on recurring schedules" in cli_content

    assert 'edit "maint_window"' in cli_content
    assert 'set start "08:00 2026/08/30"' in cli_content
    assert 'set start-utc "1788076800"' in cli_content
    assert 'set end "12:00 2026/08/30"' in cli_content
    assert 'set end-utc "1788091200"' in cli_content
    assert "set expiration-days 1" in cli_content
    assert "set color 10" in cli_content
    assert "set fabric-object enable" in cli_content

    assert "Schedule invalid_onetime_dt withheld: end date/time must be after start date/time" in cli_content
    assert "Schedule unmodeled_attr_sched withheld: contains unmodeled source attributes" in cli_content

    # Terraform Assertions
    assert 'resource "fortios_firewallschedule_recurring" "work_week"' in tf_content
    assert 'day   = "monday tuesday wednesday thursday friday"' in tf_content
    assert 'resource "fortios_firewallschedule_recurring" "recurring_explicit_none"' in tf_content
    assert 'day   = "none"' in tf_content
    assert 'resource "fortios_firewallschedule_onetime" "maint_window"' in tf_content
    assert 'start_utc = "1788076800"' in tf_content
    assert 'end_utc = "1788091200"' in tf_content
    assert "expiration_days = 1" in tf_content
    assert "color = 10" in tf_content
    assert 'fabric_object = "enable"' in tf_content

    assert "Schedule contradictory_days withheld: 'none' cannot be combined with weekday names" in tf_content
    assert "Schedule recurring_with_expiry withheld: expiration_days is not supported on recurring schedules" in tf_content
    assert "Schedule invalid_onetime_dt withheld: end date/time must be after start date/time" in tf_content
    assert "Schedule unmodeled_attr_sched withheld: contains unmodeled source attributes" in tf_content
