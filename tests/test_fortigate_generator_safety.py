import pytest

from fwmigrate.ir.enums import MigrationConfidence
from fwmigrate.generators.fortigate.cli_generator import FortiGateCLIGenerator
from fwmigrate.generators.fortigate.terraform_generator import FortiGateTerraformGenerator
from fwmigrate.ir.core import (
    IRAddress,
    IRAddressGroup,
    IRConfig,
    IRIPPool,
    IRMetadata,
    IRNATRule,
    IRPolicy,
    IRSchedule,
    IRService,
    IRServicePort,
    IRVirtualIP,
)
from fwmigrate.ir.enums import AddressType, NATType, PolicyAction, ServiceProtocol
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import FortiGateParser
from fwmigrate.parsers.fortigate.tokenizer import FortiGateTokenizer
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def _build_minimal_ir(**kwargs) -> IRConfig:
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
    assert "resource \"fortios_firewall_policy\"" not in tf_artifacts[0].content


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
    assert 'Policy pol_missing_sched withheld' in cli_text

    tf_artifacts = FortiGateTerraformGenerator().generate(ir)
    main_tf = [a for a in tf_artifacts if a.filename == "main.tf"][0].content
    assert 'resource "fortios_firewallschedule_recurring"' in main_tf
    assert 'schedule = "work_hours"' in main_tf
    assert 'Policy pol_missing_sched withheld' in main_tf


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
    assert 'set startip 203.0.113.10' in cli_text
    assert 'set nat enable' in cli_text
    assert 'set ippool enable' in cli_text
    assert 'set poolname "corp_pool"' in cli_text
    assert 'set fixedport enable' in cli_text


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
    )
    ir = _build_minimal_ir(policies=[pol])

    main_tf = [a for a in FortiGateTerraformGenerator().generate(ir) if a.filename == "main.tf"][0].content
    assert 'for_each = ["zone_trust"]' in main_tf
    assert 'for_each = ["zone_untrust"]' in main_tf
    assert "['zone_trust']" not in main_tf
    assert "['zone_untrust']" not in main_tf


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

