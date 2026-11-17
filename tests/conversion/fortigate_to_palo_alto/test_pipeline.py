from types import SimpleNamespace
import pytest
from fwmigrate.conversion.fortigate_to_palo_alto import PANAutomationMode, PANMigrationOptions, run_migration_pipeline
from fwmigrate.vendors.fortigate.model.address import FGAddress, FGWildcardFQDN
from fwmigrate.vendors.fortigate.model.dhcp import FGDHCPIPRange, FGDHCPServer
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.route_static import FGStaticRoute
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.palo_alto.relationships.topology import PANInterfaceTopologyEntry
from fwmigrate.vendors.palo_alto.source_model import PANScope, pan_scope_identity
from fwmigrate.conversion.fortigate_to_palo_alto import FortiGateToPaloAltoPlanner
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import PANMigrationDecision, PANMigrationDecisionSet
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.model.zone import FGZone
from fwmigrate.vendors.fortigate.model.vip import FGVIP
from fwmigrate.vendors.fortigate.derived import build_derived_views
from fwmigrate.conversion.fortigate_to_palo_alto.planning.routing import _normalize_subnet
from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationPlan, PANMigrationStatus, PlannedAddress, PlannedAddressGroup, PlannedNATRule, PlannedSchedule, PlannedSecurityRule, PlannedService, PlannedServiceGroup, PlannedStaticRoute, PlannedZone
from fwmigrate.conversion.builtin import register_builtin_migration_planners
from fwmigrate.conversion.fortigate_to_palo_alto import InterfaceMapping, PlannedPANItem, VDOMMapping
from fwmigrate.conversion.registry import MigrationPlannerRegistry
from fwmigrate.vendors.fortigate.model.schedule import FGOneTimeSchedule, FGRecurringSchedule
from fwmigrate.vendors.fortigate.transform.services import NormalizedService, NormalizedServiceGroup, ServiceTransformResult
from fwmigrate.vendors.fortigate.transform.nat import NormalizedSourceNAT
from fwmigrate.conversion.fortigate_to_palo_alto.planning.nat import plan_nat
from fwmigrate.conversion.fortigate_to_palo_alto.planning.routing import plan_routes
from fwmigrate.vendors.fortigate.model.address import FGAddressGroup
from fwmigrate.conversion.fortigate_to_palo_alto import PANDecisionMode, PANRecommendationReadiness, build_recommendations
from fwmigrate.conversion.fortigate_to_palo_alto.recommendations import decision_value
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import decision_value as mapping_decision_value
from fwmigrate.conversion.fortigate_to_palo_alto.requirements import build_mapping_requirements
from fwmigrate.vendors.fortigate.model.sdwan import FGSDWAN, FGSDWANMember
from fwmigrate.vendors.fortigate.model.vpn import FGIPsecPhase1
from fwmigrate.vendors.fortigate.model.vpn_ssl import FGSSLVPNAuthenticationRule, FGSSLVPNSettings

# --- test_pipeline.py ---
def _empty_derived():
    return SimpleNamespace()


@pytest.mark.parametrize("failure", ["unsupported", "missing_reference", "disabled", "none"])
def test_policy_order_blocks_successors_but_preserves_scope_and_objects(failure):
    from dataclasses import replace
    from fwmigrate.conversion.fortigate_to_palo_alto.models import (
        PANMigrationPlan, PANMigrationStatus, PlannedAddress, PlannedSecurityRule,
    )
    from fwmigrate.conversion.fortigate_to_palo_alto.plan_dependencies import (
        build_plan_dependency_index, expand_plan_dependents, item_key,
    )
    from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
    from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan

    first = PlannedSecurityRule(source_vdom="root", source_kind="policy",
        source_object_type="security_rule", source_name="same", source_policy_id=20,
        target_vsys="vsys1", target_name="deny-first", status=PANMigrationStatus.SUPPORTED,
        from_zones=("any",), to_zones=("any",), sources=("any",), destinations=("any",),
        services=("any",), applications=("any",), action="deny")
    if failure in {"unsupported", "disabled"}:
        first = replace(first, status=PANMigrationStatus.PARTIAL, disabled=failure == "disabled")
    elif failure == "missing_reference":
        first = replace(first, sources=("missing",))
    later = replace(first, source_policy_id=1, target_name="allow-later",
        status=PANMigrationStatus.SUPPORTED, disabled=False, sources=("any",), action="allow")
    third = replace(later, source_policy_id=2, target_name="allow-third")
    disabled_middle = replace(later, source_policy_id=30, target_name="disabled-middle", disabled=True,
                              status=PANMigrationStatus.PARTIAL)
    other_vdom = replace(later, source_vdom="other", target_name="other-vdom")
    other_vsys = replace(later, target_vsys="vsys2", target_name="other-vsys")
    address = PlannedAddress(source_vdom="root", source_kind="address", source_object_type="address",
        source_name="independent", target_name="independent", target_vsys="vsys1",
        status=PANMigrationStatus.SUPPORTED, address_type="ip-netmask", value="192.0.2.1/32")
    plan = PANMigrationPlan(addresses=(address,),
        security_rules=(first, other_vdom, disabled_middle, later, other_vsys, third))
    validation = validate_plan(plan)
    rendered = PANSetRenderer().render(plan)
    blocked = failure in {"unsupported", "missing_reference"}
    for name in ("allow-later", "allow-third"):
        assert any(f"rules {name} " in command for command in rendered.commands) != blocked
    assert any("address independent " in command for command in rendered.commands)
    assert any("rules other-vdom " in command for command in rendered.commands)
    assert any("rules other-vsys " in command for command in rendered.commands)
    if blocked:
        assert any(issue.code == "policy_predecessor_not_renderable" and "ID 20" in issue.message
                   for issue in validation.issues)
    index = build_plan_dependency_index(plan, SimpleNamespace(decisions=()))
    descendants = expand_plan_dependents(index, [item_key(first)])
    assert (item_key(later) in descendants) == (failure != "disabled")
    assert item_key(other_vdom) not in descendants and item_key(other_vsys) not in descendants


def test_validation_exclusions_and_dependents_block_artifact_rendering():
    from fwmigrate.vendors.fortigate.model.address import FGAddressGroup

    source = FGConfig(addresses=[FGAddress(name="valid", subnet="192.0.2.1 255.255.255.255")],
                      address_groups=[FGAddressGroup(name="broken", members=["missing"]),
                                      FGAddressGroup(name="dependent", members=["broken"])])
    result = run_migration_pipeline(source, _empty_derived(), options=PANMigrationOptions(
        vdoms={"root": {"vsys": "vsys1"}},
    ))
    assert result.artifact_status == "PARTIAL"
    assert result.rendered.report["render_dispositions"] == {"CREATE": 1, "REUSE": 0, "BLOCK": 2}
    assert result.rendered.report["satisfied"] == 1
    assert all(item["render_disposition"] == "BLOCK" for item in result.rendered.report["items"]
               if item["source_name"] in {"broken", "dependent"})
    assert not any("address-group" in command for command in result.rendered.commands)


@pytest.mark.parametrize("setting,blocked", [
    ('set internet-service-src enable\nset internet-service-src-name "Google-Gmail"', True),
    ('set match-vip-only enable', True),
    ('set future-match-option enable', True),
    ('set internet-service disable\nset utm-status disable', False),
])
def test_explicit_policy_options_reach_fail_closed_rendering(setting, blocked):
    from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter

    source = f'''config system interface
edit "lan"
set type physical
set ip 192.0.2.1 255.255.255.0
next
edit "wan"
set type physical
set ip 198.51.100.1 255.255.255.0
next
end
config firewall policy
edit 1
set srcintf "trust"
set dstintf "untrust"
set srcaddr "all"
set dstaddr "all"
set service "ALL"
set schedule "always"
set action accept
{setting}
next
end
config system zone
edit "trust"
set interface "lan"
next
edit "untrust"
set interface "wan"
next
end
'''
    analysis = FortiGateSourceReporter().analyze_source(source)
    result = run_migration_pipeline(analysis.extracted.config, analysis.derived, options=PANMigrationOptions(
        vdoms={"root": {"vsys": "vsys1", "virtual_router": "default"}},
        interfaces={"root": {"lan": {"target_interface": "ethernet1/1", "target_zone": "trust"},
                             "wan": {"target_interface": "ethernet1/2", "target_zone": "untrust"}}},
        zones={"root": {"trust": {"target_zone": "trust"}, "untrust": {"target_zone": "untrust"}}},
    ))
    rule = next(item for item in result.rendered.report["items"] if item["source_object_type"] == "security_rule")
    assert (rule["render_disposition"] == "BLOCK") == blocked, rule
    assert bool([command for command in result.rendered.commands if "rules 1 " in command]) != blocked
    assert (result.artifact_status == "READY") != blocked


def _target_interface(name, ip, *, virtual_router="vr-main"):
    scope = PANScope(kind="device", name="dev", device_name="dev")
    interface = SimpleNamespace(
        name=name,
        scope=scope,
        interface_family="ethernet",
        ipv4_addresses=[ip],
        tag=None,
        parent=None,
        mode="layer3",
        raw_extra={},
        explicit_fields={"mode", "ipv4_addresses"},
    )
    topology = PANInterfaceTopologyEntry(
        name,
        pan_scope_identity(scope),
        imported_vsys=("vsys1",),
        virtual_routers=(virtual_router,),
    )
    config = SimpleNamespace(
        interfaces=[interface],
        interface_units=[],
        zones=[],
        virtual_routers=[],
        addresses=[],
        address_groups=[],
        services=[],
        service_groups=[],
        schedules=[],
        dhcp_servers=[],
        nat_rules=[],
        security_rules=[],
        scopes=[scope],
    )
    return SimpleNamespace(
        config=config,
        derived=SimpleNamespace(interface_topology=[topology]),
    )


def test_pipeline_renders_supported_objects_from_explicit_mapping():
    source = FGConfig(addresses=[
        FGAddress(name="host-a", subnet="192.0.2.10 255.255.255.255"),
    ])

    result = run_migration_pipeline(
        source,
        _empty_derived(),
        options=PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}),
    )

    assert result.artifact_status == "READY"
    assert result.unresolved_decisions == ()
    assert result.rendered.commands == (
        "set vsys vsys1 address host-a ip-netmask 192.0.2.10/32",
    )
    assert result.rendered.report["plan_status"] == "READY"


def test_pipeline_marks_unsupported_dhcp_plan_partial_without_coverage_gap():
    source = FGConfig(
        addresses=[FGAddress(name="host-a", subnet="192.0.2.10 255.255.255.255")],
        dhcp_servers=[FGDHCPServer(id=1)],
    )

    result = run_migration_pipeline(
        source,
        _empty_derived(),
        options=PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}),
    )

    assert result.artifact_status == "PARTIAL"
    assert result.coverage["complete"] is True
    assert result.coverage["unplanned_count"] == 0
    assert result.plan.dhcp_servers[0].status.value == "MANUAL_REVIEW"
    assert result.rendered.report["coverage"] == result.coverage
    assert any("set vsys vsys1 address host-a" in command for command in result.rendered.commands)
    assert not any("network dhcp" in command for command in result.rendered.commands)


def test_pipeline_renders_supported_dhcp_and_completes_coverage():
    source = FGConfig(
        interfaces=[FGInterface(name="lan", type="physical", mode="static", ip="10.0.0.1/24")],
        dhcp_servers=[FGDHCPServer(
            id=1,
            interface="lan",
            status="enable",
            server_type="regular",
            ip_mode="range",
            default_gateway="10.0.0.1",
            netmask="255.255.255.0",
            lease_time=3600,
            dns_service="specify",
            dns_server1="10.0.0.2",
            dns_server2="10.0.0.3",
            ip_ranges=[FGDHCPIPRange(start_ip="10.0.0.10", end_ip="10.0.0.50")],
        )],
    )

    result = run_migration_pipeline(
        source,
        _empty_derived(),
        options=PANMigrationOptions(
            vdoms={"root": {"vsys": "vsys1", "virtual_router": "vr-main"}},
            interfaces={"root": {"lan": {"target_interface": "ethernet1/3"}}},
        ),
    )

    assert result.artifact_status == "READY"
    assert result.coverage["complete"] is True
    assert result.plan.dhcp_servers[0].status.value == "SUPPORTED"
    assert "set network dhcp interface ethernet1/3 server mode enabled" in result.rendered.commands
    assert "set network dhcp interface ethernet1/3 server ip-pool [ 10.0.0.10-10.0.0.50 ]" in result.rendered.commands



def test_pipeline_marks_preserved_source_only_configuration_partial():
    source = FGConfig(
        addresses=[FGAddress(name="host-a", subnet="192.0.2.10 255.255.255.255")],
        wildcard_fqdns=[FGWildcardFQDN(name="wild", wildcard_fqdn="*.example.test")],
    )

    result = run_migration_pipeline(
        source,
        _empty_derived(),
        options=PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}),
    )

    assert result.artifact_status == "PARTIAL"
    assert result.coverage["counts"]["SOURCE_ONLY"] == 1
    entry = result.coverage["unplanned"][0]
    assert entry["source_kind"] == "wildcard_fqdn"
    assert entry["source_name"] == "wild"


def test_pipeline_uses_final_automated_decisions_before_planning():
    source = FGConfig(
        interfaces=[FGInterface(name="wan", ip="198.51.100.1/24")],
        static_routes=[
            FGStaticRoute(
                seq_num=1,
                dst="0.0.0.0/0",
                device="wan",
                gateway="198.51.100.254",
            )
        ],
    )
    target = _target_interface("ethernet1/1", "198.51.100.1/24")

    result = run_migration_pipeline(
        source,
        _empty_derived(),
        target=target,
        target_device="dev",
        target_evidence={"vendor": "palo_alto", "config_digest": "digest-a", "device": "dev"},
        automation_mode=PANAutomationMode.VERIFIED_AND_DERIVED,
    )

    assert result.artifact_status == "READY"
    assert result.unresolved_decisions == ()
    by_identity = {
        (item.source_kind, item.source_name, item.target_field): item
        for item in result.decisions.decisions
    }
    assert by_identity[("interface", "wan", "target_interface")].value == "ethernet1/1"
    assert by_identity[("vdom", "root", "virtual_router")].value == "vr-main"
    assert by_identity[("vdom", "root", "vsys")].value == "vsys1"
    assert all(item.evidence_source == "DERIVED" for item in by_identity.values())
    assert all(item.evidence_target_digest == "digest-a" and item.evidence_target_device == "dev"
               for item in by_identity.values())
    assert any("virtual-router vr-main" in command for command in result.rendered.commands)
    assert any("interface ethernet1/1" in command for command in result.rendered.commands)
    assert result.rendered.report["automation"]["applied"] == 3


def test_pipeline_invalidates_stale_target_backed_decisions_before_planning():
    source = FGConfig(
        interfaces=[FGInterface(name="wan", ip="198.51.100.1/24")],
        static_routes=[FGStaticRoute(
            seq_num=1, dst="0.0.0.0/0", device="wan", gateway="198.51.100.254",
        )],
    )
    target = _target_interface("ethernet1/1", "198.51.100.1/24")
    first = run_migration_pipeline(
        source,
        _empty_derived(),
        target=target,
        target_device="dev",
        target_evidence={"vendor": "palo_alto", "config_digest": "digest-a", "device": "dev"},
        automation_mode=PANAutomationMode.VERIFIED_AND_DERIVED,
    )
    assert first.artifact_status == "READY"

    second = run_migration_pipeline(
        source,
        _empty_derived(),
        decisions=first.decisions,
        target=target,
        target_device="dev",
        target_evidence={"vendor": "palo_alto", "config_digest": "digest-b", "device": "dev"},
        automation_mode=PANAutomationMode.REVIEW_ONLY,
    )

    assert second.artifact_status == "NEEDS_MAPPING"
    assert len(second.invalidated_target_decisions) == 3
    assert all(item.review_state.value == "PENDING" for item in second.decisions.decisions)
    assert second.rendered.report["invalidated_target_decisions"] == list(second.invalidated_target_decisions)


def test_dhcp_stops_rendering_when_target_backed_interface_evidence_is_invalidated():
    source = FGConfig(
        interfaces=[FGInterface(name="lan", ip="10.0.0.1/24")],
        dhcp_servers=[FGDHCPServer(
            id=1,
            interface="lan",
            status="enable",
            server_type="regular",
            ip_mode="range",
            lease_time=3600,
            ip_ranges=[FGDHCPIPRange(start_ip="10.0.0.10", end_ip="10.0.0.50")],
        )],
    )
    target = _target_interface("ethernet1/3", "10.0.0.1/24")
    first = run_migration_pipeline(
        source,
        _empty_derived(),
        target=target,
        target_device="dev",
        target_evidence={"vendor": "palo_alto", "config_digest": "digest-a", "device": "dev"},
        automation_mode=PANAutomationMode.VERIFIED_AND_DERIVED,
    )
    assert first.artifact_status == "READY"
    assert any("network dhcp interface ethernet1/3" in command for command in first.rendered.commands)

    second = run_migration_pipeline(
        source,
        _empty_derived(),
        decisions=first.decisions,
        target=target,
        target_device="dev",
        target_evidence={"vendor": "palo_alto", "config_digest": "digest-b", "device": "dev"},
        automation_mode=PANAutomationMode.REVIEW_ONLY,
    )
    assert second.artifact_status == "NEEDS_MAPPING"
    assert len(second.invalidated_target_decisions) == 3
    assert not any("network dhcp" in command for command in second.rendered.commands)



def test_pipeline_explicit_options_replace_invalidated_target_backed_decisions():
    source = FGConfig(
        interfaces=[FGInterface(name="wan", ip="198.51.100.1/24")],
        static_routes=[FGStaticRoute(
            seq_num=1, dst="0.0.0.0/0", device="wan", gateway="198.51.100.254",
        )],
    )
    target = _target_interface("ethernet1/1", "198.51.100.1/24")
    first = run_migration_pipeline(
        source,
        _empty_derived(),
        target=target,
        target_device="dev",
        target_evidence={"vendor": "palo_alto", "config_digest": "digest-a", "device": "dev"},
        automation_mode=PANAutomationMode.VERIFIED_AND_DERIVED,
    )

    second = run_migration_pipeline(
        source,
        _empty_derived(),
        decisions=first.decisions,
        options=PANMigrationOptions(
            vdoms={"root": {"vsys": "vsys1", "virtual_router": "vr-main"}},
            interfaces={"root": {"wan": {"target_interface": "ethernet1/1"}}},
        ),
        target=target,
        target_device="dev",
        target_evidence={"vendor": "palo_alto", "config_digest": "digest-b", "device": "dev"},
        automation_mode=PANAutomationMode.REVIEW_ONLY,
    )

    assert second.artifact_status == "READY"
    assert len(second.invalidated_target_decisions) == 3
    assert all(item.review_state.value == "CONFIRMED" for item in second.decisions.decisions)
    assert all(item.evidence_type == "EXPLICIT_MAPPING" for item in second.decisions.decisions)
    assert all(item.evidence_target_digest is None and item.evidence_target_device is None
               for item in second.decisions.decisions)


def test_pipeline_target_intent_remains_durable_after_target_evidence_changes():
    source = FGConfig(
        interfaces=[FGInterface(name="wan", ip="198.51.100.1/24")],
        static_routes=[FGStaticRoute(
            seq_num=1, dst="0.0.0.0/0", device="wan", gateway="198.51.100.254",
        )],
    )
    target = _target_interface("ethernet1/1", "198.51.100.1/24")
    first = run_migration_pipeline(
        source,
        _empty_derived(),
        target=target,
        target_device="dev",
        target_evidence={"vendor": "palo_alto", "config_digest": "digest-a", "device": "dev"},
        automation_mode=PANAutomationMode.VERIFIED_AND_DERIVED,
    )

    second = run_migration_pipeline(
        source,
        _empty_derived(),
        decisions=first.decisions,
        target=target,
        target_device="dev",
        target_evidence={"vendor": "palo_alto", "config_digest": "digest-b", "device": "dev"},
        target_intent={
            "vdoms": {"root": {"vsys": "vsys1", "virtual_router": "vr-main"}},
            "interfaces": {"wan": {"interface": "ethernet1/1"}},
        },
        automation_mode=PANAutomationMode.REVIEW_ONLY,
    )

    assert second.artifact_status == "READY"
    assert len(second.invalidated_target_decisions) == 3
    assert all(item.evidence_type == "TARGET_INTENT" for item in second.decisions.decisions)
    assert all(item.evidence_target_digest is None for item in second.decisions.decisions)


def test_populated_target_rulebase_blocks_new_security_rule_and_reports_placement():
    from fwmigrate.vendors.fortigate.model.policy import FGPolicy
    from fwmigrate.vendors.palo_alto.model.policy import PANSecurityRule

    source = FGConfig(policies=[FGPolicy(policy_id=7, name="new-rule", srcintf=["lan"], dstintf=["wan"],
        srcaddr=["all"], dstaddr=["all"], service=["ALL"], schedule="always", action="accept")])
    target = _target_interface("ethernet1/1", "192.0.2.1/24")
    target.config.security_rules = [PANSecurityRule(name="existing-rule", source_path="/rule",
        scope=PANScope(kind="vsys", name="vsys1", vsys="vsys1", device_name="dev"), source_order=1)]
    result = run_migration_pipeline(source, _empty_derived(), target=target, target_device="dev",
        target_evidence={"vendor": "palo_alto", "config_digest": "digest-a", "device": "dev"},
        options=PANMigrationOptions(vdoms={"root": {"vsys": "vsys1", "virtual_router": "vr-main"}},
            interfaces={"root": {"lan": {"target_zone": "trust"}, "wan": {"target_zone": "untrust"}}}))

    assert any(item.code == "TARGET_RULE_PLACEMENT_UNVERIFIED" for item in result.target_plan_findings)
    rule = next(item for item in result.rendered.report["items"] if item["source_object_type"] == "security_rule")
    assert rule["render_disposition"] == "BLOCK"
    assert "TARGET_RULE_PLACEMENT_UNVERIFIED" in rule["render_blockers"]
    assert not any("rulebase security rules new-rule" in command for command in result.rendered.commands)

# --- test_second_pass_pipeline.py ---
BASE = """config system interface
 edit "lan"
 next
 edit "wan"
 next
end
config system zone
 edit "trust"
  set interface "lan"
 next
 edit "untrust"
  set interface "wan"
 next
end
"""


OPTIONS = PANMigrationOptions(
    vdoms={"root": {"vsys": "vsys1", "virtual_router": "default"}},
    interfaces={"root": {"lan": {"target_interface": "ethernet1/1", "target_zone": "trust"},
                         "wan": {"target_interface": "ethernet1/2", "target_zone": "untrust"}}},
    zones={"root": {"trust": {"target_zone": "trust"}, "untrust": {"target_zone": "untrust"}}},
)


def _plan(source, options=OPTIONS):
    analysis = FortiGateSourceReporter().analyze_source(source)
    plan = FortiGateToPaloAltoPlanner().plan(analysis.extracted.config, analysis.derived, options)
    validation = validate_plan(plan)
    return analysis, plan, validation, PANSetRenderer().render(plan, validation)


def _static_vip_config():
    return FGConfig(
        interfaces=[FGInterface(name="lan", ip="10.0.0.1/24"), FGInterface(name="wan", ip="198.51.100.1/24")],
        zones=[FGZone(name="trust", interfaces=["lan"]), FGZone(name="untrust", interfaces=["wan"])],
        vips=[FGVIP(name="web-vip", type="static-nat", extip="198.51.100.10", mappedip=["10.0.0.10"], extintf="wan")],
        policies=[FGPolicy(policy_id=1, name="inbound", srcintf=["wan"], dstintf=["lan"],
            srcaddr=["all"], dstaddr=["web-vip"], service=["ALL"], action="accept", schedule="always")])


@pytest.mark.parametrize("updates", [
    {"type": None}, {"type": "unknown"}, {"portforward": "enable", "extport": "80", "mappedport": "8080"},
    {"extip": "0.0.0.0"}, {"extip": "198.51.100.10-198.51.100.20"}, {"mappedip": ["2001:db8::1"]},
    {"mapped_addr": "server"}, {"nat_source_vip": "enable"}, {"raw_extra": {"src-filter": ["192.0.2.1"]}},
    {"arp_reply": "disable"}, {"status": "disable"},
])
def test_uncertain_vip_blocks_dnat_and_dependent_security_without_mutating_source(updates):
    source = _static_vip_config()
    source.vips[0] = source.vips[0].model_copy(update=updates)
    before = source.model_dump()
    plan = FortiGateToPaloAltoPlanner().plan(source, build_derived_views(source), OPTIONS)
    rendered = PANSetRenderer().render(plan)
    assert not any("rulebase nat" in command or "rulebase security" in command for command in rendered.commands)
    assert source.model_dump() == before
    assert plan.nat_rules[0].warnings


def test_conflicting_vip_post_nat_zones_and_address_names_block_security():
    source = _static_vip_config()
    source.policies.append(source.policies[0].model_copy(update={"policy_id": 2, "name": "conflict", "dstintf": ["wan"]}))
    plan = FortiGateToPaloAltoPlanner().plan(source, build_derived_views(source), OPTIONS)
    assert any("post-NAT destination zones" in warning for warning in plan.nat_rules[0].warnings)
    assert not any("rulebase" in command for command in PANSetRenderer().render(plan).commands)

    source = _static_vip_config()
    source.addresses.append(FGAddress(name="web-vip", subnet="192.0.2.5/32"))
    plan = FortiGateToPaloAltoPlanner().plan(source, build_derived_views(source), OPTIONS)
    assert not any("rulebase security" in command for command in PANSetRenderer().render(plan).commands)
    assert any(issue.code == "duplicate_target_address_name" for issue in validate_plan(plan).issues)


def test_vip_requires_one_confirmed_post_nat_destination_zone():
    source = _static_vip_config()
    source.policies[0] = source.policies[0].model_copy(update={"dstintf": ["lan", "wan"]})
    plan = FortiGateToPaloAltoPlanner().plan(source, build_derived_views(source), OPTIONS)
    assert any("post-NAT destination zone" in warning for warning in plan.nat_rules[0].warnings)
    assert not any("rulebase" in command for command in PANSetRenderer().render(plan).commands)


def test_vip_service_group_expands_into_single_service_nat_rules():
    from fwmigrate.vendors.fortigate.model.service import FGServiceGroup
    source = _static_vip_config()
    source.zones = []
    source.service_groups.append(FGServiceGroup(name="web-services", members=["HTTP", "HTTPS"]))
    source.policies[0] = source.policies[0].model_copy(update={"service": ["web-services"]})
    plan = FortiGateToPaloAltoPlanner().plan(source, build_derived_views(source), OPTIONS, include_configuration=True)
    assert len(plan.nat_rules) == 2
    assert {rule.service for rule in plan.nat_rules} == {'HTTP', 'service-https'}
    commands = PANSetRenderer().render(plan).commands
    assert any(' service HTTP' in command and ' rulebase nat ' in command for command in commands)
    assert not any(' service web-services' in command and ' rulebase nat ' in command for command in commands)


def test_vip_nat_target_placement_block_propagates_through_existing_dependency_index():
    from fwmigrate.conversion.fortigate_to_palo_alto.pipeline import run_migration_pipeline
    from fwmigrate.conversion.fortigate_to_palo_alto.plan_dependencies import item_key
    from fwmigrate.conversion.fortigate_to_palo_alto.target.target_plan_validation import PANRenderDisposition
    source = _static_vip_config()

    def classifier(plan, target, device):
        nat = plan.nat_rules[0]
        return ({"status": "ORDER_UNVERIFIED", "family": "nat_rule", "source_name": nat.source_name,
                 "source_vdom": nat.source_vdom, "source_kind": nat.source_kind, "target_vsys": nat.target_vsys},)

    result = run_migration_pipeline(source, build_derived_views(source), options=OPTIONS,
                                   target_object_reuse_classifier=classifier)
    nat_key = item_key(result.plan.nat_rules[0])
    rule_key = item_key(result.plan.security_rules[0])
    assert rule_key in result.dependency_index.dependents_by_item[nat_key]
    assert result.dispositions[rule_key] is PANRenderDisposition.BLOCK
    assert not any("rulebase" in command for command in result.rendered.commands)
    assert result.artifact_status != "READY"


@pytest.mark.parametrize("configure", [False, True])
def test_pipeline_preserves_selected_classifier_conflicts_and_source(configure):
    from fwmigrate.conversion.fortigate_to_palo_alto.decisions import PANDecisionReviewState
    from fwmigrate.conversion.fortigate_to_palo_alto.pipeline import run_migration_pipeline
    from fwmigrate.conversion.fortigate_to_palo_alto.plan_dependencies import item_key
    from fwmigrate.conversion.fortigate_to_palo_alto.target.target_plan_validation import PANRenderDisposition

    source = _static_vip_config()
    before = source.model_dump()
    calls = []
    classified = []
    decisions = PANMigrationDecisionSet((PANMigrationDecision(
        "root", "interface", "wan", "target_zone", value="untrust",
        review_state=PANDecisionReviewState.CONFIRMED, approved_operation="CONFIGURE",
    ),)) if configure else None

    def classifier(plan, target, device):
        calls.append((plan, target, device))
        nat = plan.nat_rules[0]
        rows = ({"status": "NAME_CONFLICT", "family": "nat_rule", "source_name": nat.source_name,
                 "source_vdom": nat.source_vdom, "source_kind": nat.source_kind, "target_vsys": nat.target_vsys},)
        classified.append(rows)
        return rows

    def additive_classifier(plan, target, device, *, allow_additive):
        assert allow_additive is True
        return classifier(plan, target, device)

    result = run_migration_pipeline(
        source, build_derived_views(source), options=OPTIONS, decisions=decisions,
        target_object_reuse_classifier=additive_classifier if configure else classifier,
    )
    assert calls == [(result.plan, None, None)]
    assert result.target_object_reuse is classified[0]
    if configure:
        assert any(item.approved_operation == "CONFIGURE" for item in result.decisions.decisions)
    nat_key = item_key(result.plan.nat_rules[0])
    rule_key = item_key(result.plan.security_rules[0])
    assert rule_key in result.dependency_index.dependents_by_item[nat_key]
    assert result.dispositions[nat_key] is PANRenderDisposition.BLOCK
    assert result.dispositions[rule_key] is PANRenderDisposition.BLOCK
    assert "TARGET_NAME_CONFLICT" in result.render_blockers[nat_key]
    assert any(item.code == "TARGET_NAME_CONFLICT" for item in result.target_plan_findings)
    assert not any("rulebase" in command for command in result.rendered.commands)
    assert result.artifact_status != "READY"
    assert source.model_dump() == before


def test_pipeline_configure_requires_classifier_additive_support():
    from fwmigrate.conversion.fortigate_to_palo_alto.decisions import PANDecisionReviewState
    from fwmigrate.conversion.fortigate_to_palo_alto.pipeline import run_migration_pipeline

    source = _static_vip_config()
    before = source.model_dump()
    decisions = PANMigrationDecisionSet((PANMigrationDecision(
        "root", "interface", "wan", "target_zone", value="untrust",
        review_state=PANDecisionReviewState.CONFIRMED, approved_operation="CONFIGURE",
    ),))

    def classifier(plan, target, device):
        pytest.fail("three-argument classifier must not be invoked without additive classification")

    with pytest.raises(TypeError, match="allow_additive"):
        run_migration_pipeline(source, build_derived_views(source), options=OPTIONS, decisions=decisions,
                               target_object_reuse_classifier=classifier)
    assert source.model_dump() == before


def test_mixed_snat_dnat_and_overlapping_vips_require_precedence_review():
    source = _static_vip_config()
    source.policies.append(FGPolicy(policy_id=2, name="outbound", srcintf=["lan"], dstintf=["wan"],
        srcaddr=["all"], dstaddr=["all"], service=["ALL"], action="accept", schedule="always", nat="enable"))
    plan = FortiGateToPaloAltoPlanner().plan(source, build_derived_views(source), OPTIONS)
    assert len(plan.nat_rules) == 2
    assert all(any("precedence" in warning for warning in rule.warnings) for rule in plan.nat_rules)
    assert not any("rulebase nat" in command for command in PANSetRenderer().render(plan).commands)

    source = _static_vip_config()
    source.vips.append(source.vips[0].model_copy(update={"name": "second-vip"}))
    source.policies.append(source.policies[0].model_copy(update={"policy_id": 2, "name": "second", "dstaddr": ["second-vip"]}))
    plan = FortiGateToPaloAltoPlanner().plan(source, build_derived_views(source), OPTIONS)
    assert all(any("precedence" in warning for warning in rule.warnings) for rule in plan.nat_rules)
    assert not any("rulebase" in command for command in PANSetRenderer().render(plan).commands)


def test_predefined_services_and_subnets_reach_rendered_commands():
    policies = "".join(
        f''' edit {number}
  set name "rule-{name}"
  set srcintf "trust"
  set dstintf "untrust"
  set srcaddr "all"
  set dstaddr "all"
  set service {services}
  set schedule "always"
  set action accept
 next
'''
        for number, (name, services) in enumerate((
            ("all", '"ALL"'), ("http", '"HTTP"'), ("https", '"HTTPS"'),
            ("dns", '"DNS"'), ("ping", '"PING"'), ("mixed", '"CUSTOM" "HTTPS"'),
            ("group", '"web-group"'),
        ), start=1)
    )
    source = BASE + """config firewall address
 edit "net"
  set subnet 10.0.0.0 255.255.255.0
 next
end
config firewall service custom
 edit "CUSTOM"
  set tcp-portrange 8443
 next
end
config firewall service group
 edit "web-group"
  set member "HTTP" "HTTPS"
 next
end
config router static
 edit 1
  set dst 0.0.0.0 0.0.0.0
  set gateway 192.0.2.254
  set device "wan"
 next
end
config firewall policy
""" + policies + "end\n"
    analysis, plan, validation, rendered = _plan(source)
    assert analysis.extracted.config.addresses[0].subnet == "10.0.0.0 255.255.255.0"
    assert analysis.extracted.config.static_routes[0].dst == "0.0.0.0 0.0.0.0"
    assert plan.addresses[0].value == "10.0.0.0/24"
    assert plan.static_routes[0].destination == "0.0.0.0/0"
    assert all(("security_rule", "vsys1", f"rule-{name}") in validation.renderable_item_keys
               for name in ("all", "http", "https", "dns", "ping", "mixed", "group"))
    commands = rendered.commands
    assert "set vsys vsys1 service HTTP protocol tcp port 80" in commands
    assert "set vsys vsys1 service FG-DNS-TCP protocol tcp port 53" in commands
    assert "set vsys vsys1 service FG-DNS-UDP protocol udp port 53" in commands
    assert "set vsys vsys1 service-group web-group members [ HTTP service-https ]" in commands
    assert "set vsys vsys1 rulebase security rules rule-https service [ service-https ]" in commands
    assert "set vsys vsys1 rulebase security rules rule-all service [ any ]" in commands
    assert "set vsys vsys1 rulebase security rules rule-ping application [ ping ]" in commands


def test_vip_uses_original_packet_zone_and_conflicts_fail_closed():
    source = BASE + """config firewall vip
 edit "web-vip"
  set type static-nat
  set extip 198.51.100.10
  set mappedip 10.0.0.10
  set extintf "wan"
 next
end
config firewall policy
 edit 1
  set srcintf "wan"
  set dstintf "lan"
  set srcaddr "all"
  set dstaddr "web-vip"
  set service "ALL"
  set action accept
  set schedule always
 next
end
"""
    analysis, plan, validation, rendered = _plan(source)
    vip = plan.nat_rules[0]
    assert vip.from_zones == ("untrust",)
    assert vip.to_zones == ("untrust",)
    assert ("nat_rule", "vsys1", "web-vip") in validation.renderable_item_keys
    assert any("set vsys vsys1 rulebase nat rules web-vip" in command for command in rendered.commands)
    assert not analysis.extracted.config.addresses
    assert plan.addresses[0].source_kind == "vip"
    assert plan.addresses[0].value == "198.51.100.10/32"
    assert plan.security_rules[0].destinations == ("web-vip",)
    assert plan.security_rules[0].to_zones == ("trust",)
    assert ("security_rule", "vsys1", "1") in validation.renderable_item_keys
    assert "set vsys vsys1 address web-vip ip-netmask 198.51.100.10/32" in rendered.commands

    same_zone = source.replace(
        ' edit 1\n  set srcintf "wan"',
        ' edit 2\n  set srcintf "wan"\n  set dstintf "lan"\n  set srcaddr "all"\n  set service "ALL"\n  set action accept\n  set schedule always\n  set dstaddr "web-vip"\n next\n edit 1\n  set srcintf "wan"',
    )
    _, plan, validation, _ = _plan(same_zone)
    assert plan.nat_rules[0].from_zones == ("untrust",)
    assert ("nat_rule", "vsys1", "web-vip") in validation.renderable_item_keys

    conflicting = source.replace("end\n", "end\n", 1).replace(
        ' edit 1\n  set srcintf "wan"', ' edit 2\n  set srcintf "lan"\n  set dstaddr "web-vip"\n next\n edit 1\n  set srcintf "wan"'
    )
    _, plan, validation, rendered = _plan(conflicting)
    assert plan.nat_rules[0].from_zones == ()
    assert ("nat_rule", "vsys1", "web-vip") not in validation.renderable_item_keys
    assert not any("set vsys vsys1 rulebase nat rules web-vip" in command for command in rendered.commands)
    assert not any("rulebase security" in command for command in rendered.commands)

    unreferenced = source.replace('  set dstaddr "web-vip"\n', '')
    _, plan, validation, _ = _plan(unreferenced)
    assert plan.nat_rules[0].status.value == "MANUAL_REVIEW"
    assert ("nat_rule", "vsys1", "web-vip") not in validation.renderable_item_keys

    _, plan, validation, rendered = _plan(source.replace('  set extintf "wan"\n', ''))
    assert plan.nat_rules[0].to_zones == ()
    assert ("nat_rule", "vsys1", "web-vip") not in validation.renderable_item_keys
    assert not any("set vsys vsys1 rulebase nat rules web-vip" in command for command in rendered.commands)


def test_invalid_subnets_do_not_become_pan_values():
    assert _normalize_subnet("10.0.0.5 255.255.255.255") == "10.0.0.5/32"
    assert _normalize_subnet("10.0.0.0/24") == "10.0.0.0/24"
    assert _normalize_subnet("10.0.0.0 255.0.255.0") is None
    assert _normalize_subnet("10.0.0.0") is None
    source = FGConfig(addresses=[FGAddress(name="invalid", subnet="10.0.0.0 255.0.255.0")],
                      static_routes=[FGStaticRoute(seq_num=1, dst="10.0.0.0", gateway="192.0.2.1")])
    plan = FortiGateToPaloAltoPlanner().plan(source, build_derived_views(source), OPTIONS)
    assert plan.addresses[0].value is None
    assert plan.addresses[0].status.value == "UNSUPPORTED"
    assert plan.static_routes[0].destination is None
    assert plan.static_routes[0].status.value == "MANUAL_REVIEW"
    assert not PANSetRenderer().render(plan).commands


def test_interface_and_zone_decisions_with_same_name_remain_distinct():
    decisions = PANMigrationDecisionSet((
        PANMigrationDecision("root", "interface", "dmz", "target_zone").confirm("interface-zone"),
        PANMigrationDecision("root", "zone", "dmz", "target_zone").confirm("source-zone"),
    ))
    options = decisions.to_options()
    assert options.interfaces["root"]["dmz"].target_zone == "interface-zone"
    assert options.zones["root"]["dmz"].target_zone == "source-zone"
    config = FGConfig(interfaces=[FGInterface(name="dmz")], zones=[FGZone(name="dmz", members=["dmz"])],
                      policies=[FGPolicy(policy_id=1, name="rule", srcintf=["dmz"], dstintf=["dmz"],
                                         srcaddr=["all"], dstaddr=["all"], service=["ALL"], action="accept")],
                      static_routes=[FGStaticRoute(seq_num=1, dst="10.0.0.0 255.255.255.0",
                                                   gateway="192.0.2.1", device="dmz")])
    all_decisions = PANMigrationDecisionSet((*decisions.decisions,
        PANMigrationDecision("root", "vdom", "root", "vsys").confirm("vsys1"),
        PANMigrationDecision("root", "vdom", "root", "virtual_router").confirm("default"),
        PANMigrationDecision("root", "interface", "dmz", "target_interface").confirm("ethernet1/3")))
    plan = FortiGateToPaloAltoPlanner().plan(config, build_derived_views(config), all_decisions.to_options())
    assert plan.zones[0].target_name == "source-zone"
    assert plan.zones[0].interfaces == ("ethernet1/3",)
    assert plan.security_rules[0].from_zones == ("source-zone",)
    assert plan.static_routes[0].interface == "ethernet1/3"
    missing_zone = PANMigrationDecisionSet(tuple(item for item in all_decisions.decisions if item.source_kind != "zone"))
    unresolved = FortiGateToPaloAltoPlanner().plan(config, build_derived_views(config), missing_zone.to_options())
    assert unresolved.zones[0].status.value == "MANUAL_REVIEW"
    assert unresolved.security_rules[0].from_zones == ()

# --- test_mvp_hardening.py ---
def test_structured_plan_renders_scoped_policy_and_nat_commands_in_order():
    plan = PANMigrationPlan(
        addresses=(PlannedAddress(source_object_type="address", source_name="web", target_vsys="vsys1",
                                   target_name="web", status=PANMigrationStatus.SUPPORTED,
                                   address_type="ip-netmask", value="10.0.0.5/32"),
                   PlannedAddress(source_object_type="address", source_name="db", target_vsys="vsys2",
                                   target_name="db", status=PANMigrationStatus.SUPPORTED,
                                   address_type="ip-netmask", value="10.0.0.6/32")),
        services=(PlannedService(source_object_type="service", source_name="web-svc", target_vsys="vsys1",
                                  target_name="web-svc", status=PANMigrationStatus.SUPPORTED,
                                  protocol="tcp", destination_port="443", source_port="1024-65535"),
                   PlannedService(source_object_type="service", source_name="dns", target_vsys="vsys1",
                                  target_name="dns", status=PANMigrationStatus.SUPPORTED,
                                  protocol="udp", destination_port="53")),
        address_groups=(PlannedAddressGroup(source_object_type="address_group", source_name="web-group",
            target_vsys="vsys1", target_name="web-group", status=PANMigrationStatus.SUPPORTED,
            members=("web",)),),
        service_groups=(PlannedServiceGroup(source_object_type="service_group", source_name="web-services",
            target_vsys="vsys1", target_name="web-services", status=PANMigrationStatus.SUPPORTED,
            members=("web-svc",)),),
        schedules=(PlannedSchedule(source_object_type="schedule", source_name="business-hours",
            target_vsys="vsys1", target_name="business-hours", status=PANMigrationStatus.SUPPORTED,
            schedule_type="recurring", weekly=(("monday", "08:00", "17:00"),)),
                    PlannedSchedule(source_object_type="schedule", source_name="holiday",
            target_vsys="vsys1", target_name="holiday", status=PANMigrationStatus.SUPPORTED,
            schedule_type="one-time", non_recurring=(("2026/12/25@00:00", "2026/12/26@00:00"),))),
        zones=(PlannedZone(source_object_type="zone", source_name="trust", target_vsys="vsys1", target_name="trust",
                           status=PANMigrationStatus.SUPPORTED, interfaces=("ethernet1/1",)),
               PlannedZone(source_object_type="zone", source_name="untrust", target_vsys="vsys1", target_name="untrust",
                           status=PANMigrationStatus.SUPPORTED)),
        security_rules=(PlannedSecurityRule(applications=("any",), source_object_type="security_rule", source_name="allow-web",
            target_vsys="vsys1", target_name="allow-web", status=PANMigrationStatus.SUPPORTED,
            from_zones=("trust",), to_zones=("untrust",), sources=("web",), destinations=("any",),
            services=("web-svc",), schedule="business-hours", action="allow", negate_source=True,
            negate_destination=True, disabled=True, description="web access"),),
        nat_rules=(PlannedNATRule(source_object_type="nat_rule", source_name="snat", target_vsys="vsys1",
            target_name="snat", status=PANMigrationStatus.SUPPORTED, from_zones=("trust",),
            to_zones=("untrust",), source_addresses=("web",), destination_addresses=("any",),
            service="web-svc", to_interface="ethernet1/2",
            source_translation_type="dynamic-ip-and-port", translated_addresses=("203.0.113.5",)),
                   PlannedNATRule(source_object_type="nat_rule", source_name="dnat", target_vsys="vsys1",
            target_name="dnat", status=PANMigrationStatus.SUPPORTED, from_zones=("untrust",),
            to_zones=("trust",), source_addresses=("any",), destination_addresses=("203.0.113.20",),
            service="web-svc", to_interface="ethernet1/1", destination_translated_address="10.0.0.20",
            destination_translated_port="8443"),
                   PlannedNATRule(source_object_type="nat_rule", source_name="if-snat", target_vsys="vsys1",
            target_name="if-snat", status=PANMigrationStatus.SUPPORTED, from_zones=("trust",),
            to_zones=("untrust",), source_interface_address=True, to_interface="ethernet1/2",
            source_translation_type="dynamic-ip-and-port")),
        static_routes=(PlannedStaticRoute(source_object_type="static_route", source_name="default",
            target_vsys="vsys1", target_name="default", status=PANMigrationStatus.SUPPORTED,
            virtual_router="default", destination="0.0.0.0/0", interface="ethernet1/1",
            nexthop="192.0.2.1", admin_distance=10),
                       PlannedStaticRoute(source_object_type="static_route", source_name="blackhole",
            target_vsys="vsys1", target_name="blackhole", status=PANMigrationStatus.SUPPORTED,
            virtual_router="default", destination="198.51.100.0/24", nexthop_type="discard")),
    )
    validation = validate_plan(plan)
    commands = PANSetRenderer().render(plan, validation).commands
    assert commands[0] == "set vsys vsys1 address web ip-netmask 10.0.0.5/32"
    assert "set vsys vsys1 address web ip-netmask 10.0.0.5/32" in commands
    assert "set vsys vsys1 address-group web-group static [ web ]" in commands
    assert "set vsys vsys1 service web-svc protocol tcp port 443" in commands
    assert "set vsys vsys1 service web-svc protocol tcp source-port 1024-65535" in commands
    assert "set vsys vsys1 service dns protocol udp port 53" in commands
    assert "set vsys vsys1 service-group web-services members [ web-svc ]" in commands
    assert "set vsys vsys1 schedule business-hours schedule-type recurring" in commands
    assert "set vsys vsys1 schedule business-hours schedule-type recurring weekly monday [ 08:00-17:00 ]" in commands
    assert "set vsys vsys1 schedule holiday schedule-type non-recurring [ 2026/12/25@00:00-2026/12/26@00:00 ]" in commands
    assert "set vsys vsys1 zone trust network layer3 [ ethernet1/1 ]" in commands
    snat_match = ["set vsys vsys1 rulebase nat rules snat from [ trust ]", "set vsys vsys1 rulebase nat rules snat to [ untrust ]",
                  "set vsys vsys1 rulebase nat rules snat source [ web ]", "set vsys vsys1 rulebase nat rules snat destination [ any ]",
                  "set vsys vsys1 rulebase nat rules snat service web-svc", "set vsys vsys1 rulebase nat rules snat to-interface ethernet1/2",
                  "set vsys vsys1 rulebase nat rules snat source-translation dynamic-ip-and-port translated-address [ 203.0.113.5 ]"]
    assert [commands.index(command) for command in snat_match] == sorted(commands.index(command) for command in snat_match)
    assert "set vsys vsys1 rulebase nat rules dnat destination-translation translated-address 10.0.0.20" in commands
    assert "set vsys vsys1 rulebase nat rules dnat destination-translation translated-port 8443" in commands
    assert "set vsys vsys1 rulebase nat rules if-snat source-translation dynamic-ip-and-port interface-address interface ethernet1/2" in commands
    assert all("pool" not in command for command in commands)
    security_commands = ["set vsys vsys1 rulebase security rules allow-web from [ trust ]",
                         "set vsys vsys1 rulebase security rules allow-web to [ untrust ]",
                         "set vsys vsys1 rulebase security rules allow-web source [ web ]",
                         "set vsys vsys1 rulebase security rules allow-web destination [ any ]",
                         "set vsys vsys1 rulebase security rules allow-web service [ web-svc ]",
                         "set vsys vsys1 rulebase security rules allow-web schedule business-hours",
                         "set vsys vsys1 rulebase security rules allow-web negate-source yes",
                         "set vsys vsys1 rulebase security rules allow-web negate-destination yes",
                         "set vsys vsys1 rulebase security rules allow-web disabled yes",
                         "set vsys vsys1 rulebase security rules allow-web description \"web access\"",
                         "set vsys vsys1 rulebase security rules allow-web action allow"]
    assert [commands.index(command) for command in security_commands] == sorted(commands.index(command) for command in security_commands)
    nat_end = max(i for i, command in enumerate(commands) if "rulebase nat rules" in command)
    security_start = min(i for i, command in enumerate(commands) if "rulebase security rules" in command)
    assert nat_end < security_start
    assert "set vsys vsys2 address db ip-netmask 10.0.0.6/32" in commands
    reset = commands.index("set vsys vsys2 address db ip-netmask 10.0.0.6/32")
    assert commands[reset + 1] == "set network virtual-router default routing-table ip static-route default destination 0.0.0.0/0"
    assert commands[reset + 2] == "set network virtual-router default routing-table ip static-route default interface ethernet1/1"
    assert commands[reset + 3] == "set network virtual-router default routing-table ip static-route default nexthop ip-address 192.0.2.1"
    assert commands[reset + 4] == "set network virtual-router default routing-table ip static-route default admin-dist 10"
    assert commands[reset + 5] == "set network virtual-router default routing-table ip static-route blackhole destination 198.51.100.0/24"
    assert commands[reset + 6] == "set network virtual-router default routing-table ip static-route blackhole nexthop discard"


def test_validation_blocks_manual_review_from_rendered_artifact(tmp_path):
    plan = PANMigrationPlan(addresses=(PlannedAddress(source_name="review", status=PANMigrationStatus.MANUAL_REVIEW),))
    renderer = PANSetRenderer()
    rendered = renderer.render(plan, validate_plan(plan))
    renderer.write_files(rendered, tmp_path)
    assert rendered.commands == ()
    assert (tmp_path / "migration_report.json").exists()
    assert not (tmp_path / "conversion_report.json").exists()
    assert rendered.report["items"][0]["renderable"] is False
    assert rendered.report["items"][0]["render_blockers"]


def test_renderer_rejects_validation_for_another_plan():
    first = PANMigrationPlan()
    second = PANMigrationPlan(addresses=(PlannedAddress(source_name="different"),))
    with pytest.raises(ValueError, match="does not match"):
        PANSetRenderer().render(first, validate_plan(second))


def test_renderer_rejects_forged_validation_result():
    from fwmigrate.conversion.fortigate_to_palo_alto.validation import MigrationValidationResult

    plan = PANMigrationPlan()
    with pytest.raises(ValueError, match="does not match"):
        PANSetRenderer().render(plan, MigrationValidationResult())

# --- test_phase1.py ---
def test_phase1_package_exports_pair_boundary_types():
    item = PlannedPANItem(
        source_vdom="root",
        source_object_type="address",
        source_name="web",
        status=PANMigrationStatus.SUPPORTED,
    )
    plan = PANMigrationPlan(addresses=(item,))

    assert plan.addresses == (item,)
    assert PANMigrationOptions() == PANMigrationOptions()


def test_builtin_registration_exposes_the_directional_pair():
    registry = MigrationPlannerRegistry()
    planner = FortiGateToPaloAltoPlanner()
    registry.register(planner)

    assert registry.get("FORTIGATE", "PALO_ALTO") is planner


def test_planner_returns_pair_specific_empty_plan_until_mappings_exist():
    plan = FortiGateToPaloAltoPlanner().plan(object(), object())

    assert isinstance(plan, PANMigrationPlan)
    assert plan == PANMigrationPlan()


def test_builtin_registration_function_registers_the_pair_once():
    register_builtin_migration_planners()

    from fwmigrate.conversion.registry import migration_planners

    assert isinstance(
        migration_planners.get("fortigate", "palo_alto"),
        FortiGateToPaloAltoPlanner,
    )


def test_options_coerce_mapping_documents_to_explicit_mapping_models():
    options = PANMigrationOptions(
        vdoms={"root": {"vsys": "vsys1", "virtual_router": "default"}},
        interfaces={"root": {"port1": {"target_interface": "ethernet1/1", "target_zone": "trust"}}},
    )

    assert options.vdoms["root"] == VDOMMapping("vsys1", "default")
    assert options.interfaces["root"]["port1"] == InterfaceMapping("ethernet1/1", "trust")

# --- test_phases_6_10.py ---
def _options():
    return PANMigrationOptions(
        vdoms={"root": {"vsys": "vsys1", "virtual_router": "default"}},
        interfaces={"root": {
            "lan": {"target_interface": "ethernet1/1", "target_zone": "trust"},
            "wan": {"target_interface": "ethernet1/2", "target_zone": "untrust"},
        }},
    )


@pytest.mark.parametrize('fields', [{'session_ttl': 60}, {'proxy': 'enable'},
    {'raw_extra': {'iprange': '192.0.2.0/24'}}, {'raw_extra': {'future': 'enable'}}])
def test_service_semantics_block_expanded_children_and_group_in_own_vdom(fields):
    from fwmigrate.vendors.fortigate.model.service import FGService
    from fwmigrate.vendors.fortigate.transform.services import transform_services
    from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan

    source = FGConfig(services=[FGService(name='web', tcp_portrange='443 8443', **fields),
                               FGService(name='web', vdom='branch', tcp_portrange='443')])
    before = source.model_dump()
    plan = FortiGateToPaloAltoPlanner().plan(source, SimpleNamespace(services=transform_services(source)),
        options=PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}, 'branch': {'vsys': 'vsys2'}}))
    root = [item for item in (*plan.services, *plan.service_groups) if item.source_vdom == 'root']
    assert len(root) == 3
    assert all(item.status is PANMigrationStatus.UNSUPPORTED and item.warnings for item in root)
    assert next(item for item in plan.services if item.source_vdom == 'branch').status is PANMigrationStatus.SUPPORTED
    assert ('service_group', 'vsys1', 'web') not in validate_plan(plan).renderable_item_keys
    assert source.model_dump() == before


def test_services_use_derived_expansion_and_flag_non_tcp_udp():
    derived = SimpleNamespace(services=ServiceTransformResult(
        services=[
            NormalizedService(name="https", vdom="root", protocol="tcp", port="443"),
            NormalizedService(name="icmp", vdom="root", protocol="icmp"),
        ],
        groups=[NormalizedServiceGroup(name="web", vdom="root", members=("https",))],
    ))
    plan = FortiGateToPaloAltoPlanner().plan(FGConfig(), derived, options=_options())

    assert plan.services[0].destination_port == "443"
    assert plan.services[1].status is PANMigrationStatus.UNSUPPORTED
    assert plan.service_groups[0].members == ("https",)


def test_schedules_and_schedule_groups_preserve_source_semantics():
    source = FGConfig(
        recurring_schedules=[FGRecurringSchedule(name="work", days=["monday"], start="09:00", end="17:00")],
        one_time_schedules=[FGOneTimeSchedule(name="once", start="09:00 2026/01/01", end="17:00 2026/01/01")],
    )
    plan = FortiGateToPaloAltoPlanner().plan(source, SimpleNamespace(), options=_options())

    assert [item.schedule_type for item in plan.schedules] == ["recurring", "one-time"]
    assert plan.schedules[1].non_recurring == (("2026/01/01@09:00", "2026/01/01@17:00"),)


def test_topology_requires_every_zone_member_mapping():
    source = FGConfig(policies=[FGPolicy(srcintf=["lan-zone"])], zones=[FGZone(name="lan-zone", members=["lan", "missing"])])
    derived = SimpleNamespace(topology=SimpleNamespace(interfaces=()))
    plan = FortiGateToPaloAltoPlanner().plan(source, derived, options=_options())

    assert plan.zones[0].status is PANMigrationStatus.MANUAL_REVIEW
    assert plan.zones[0].interfaces == ("ethernet1/1",)


def test_routes_use_explicit_virtual_router_and_interface_mapping():
    source = FGConfig(static_routes=[FGStaticRoute(seq_num=10, dst="0.0.0.0/0", device="wan", gateway="192.0.2.1", distance=10)])
    plan = FortiGateToPaloAltoPlanner().plan(source, SimpleNamespace(), options=_options())

    route = plan.static_routes[0]
    assert route.virtual_router == "default"
    assert route.interface == "ethernet1/2"
    assert route.status is PANMigrationStatus.SUPPORTED


def test_policy_order_and_zone_action_mapping_are_preserved():
    source = FGConfig(policies=[
        FGPolicy(policy_id=20, name="second", srcintf=["lan"], dstintf=["wan"], action="deny"),
        FGPolicy(policy_id=30, name="third", srcintf=["lan"], dstintf=["wan"], action="accept"),
    ])
    plan = FortiGateToPaloAltoPlanner().plan(source, SimpleNamespace(), options=_options())

    assert [rule.source_policy_id for rule in plan.security_rules] == [20, 30]
    assert [rule.action for rule in plan.security_rules] == ["deny", "allow"]

# --- test_phases_11_18.py ---
def test_validation_reports_item_warnings_without_mutating_plan():
    item = PlannedAddress(source_name="bad", status=PANMigrationStatus.MANUAL_REVIEW, warnings=("needs mapping",))
    plan = PANMigrationPlan(addresses=(item,))

    result = validate_plan(plan)

    assert result.plan is plan
    assert result.issues[0].message == "needs mapping"
    assert plan.addresses[0] is item


def test_renderer_emits_only_supported_commands_and_complete_report():
    plan = PANMigrationPlan(addresses=(
        PlannedAddress(source_name="net", target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED, address_type="ip-netmask", value="10.0.0.0/24"),
        PlannedAddress(source_name="review", status=PANMigrationStatus.MANUAL_REVIEW),
    ))

    rendered = PANSetRenderer().render(plan)

    assert rendered.commands == ("set vsys vsys1 address net ip-netmask 10.0.0.0/24",)
    assert rendered.report["counts"]["SUPPORTED"] == 1
    assert rendered.report["counts"]["MANUAL_REVIEW"] == 1


def test_source_nat_item_with_transform_issue_is_not_renderable():
    source = FGConfig(policies=[FGPolicy(policy_id=1, name="nat", nat="enable", dstintf=["wan"])])
    derived = SimpleNamespace(nat=(NormalizedSourceNAT(
        vdom="root", policy_id=1, policy_name="nat", translation_type="ip_pool",
        pool_names=("missing",), translated_addresses=(), egress_interfaces=("wan",),
        issues=("IP pool 'missing' was not found.",),
    ),))
    options = PANMigrationOptions(interfaces={"root": {"wan": {"target_zone": "untrust"}}})

    from fwmigrate.conversion.fortigate_to_palo_alto.planning.nat import plan_nat
    item = plan_nat(source, derived, options)[0]

    assert item.status is PANMigrationStatus.MANUAL_REVIEW
    assert item.source_translation is None


def test_source_nat_to_interface_uses_confirmed_target_interface_mapping():
    source = FGConfig(policies=[FGPolicy(policy_id=1, name="nat", nat="enable", dstintf=["wan"])])
    derived = SimpleNamespace(nat=(NormalizedSourceNAT(
        vdom="root", policy_id=1, policy_name="nat", translation_type="interface_address",
        pool_names=(), translated_addresses=(), egress_interfaces=("wan",), issues=(),
    ),))
    options = PANMigrationOptions(interfaces={"root": {"wan": {
        "target_interface": "ethernet1/2", "target_zone": "untrust",
    }}})

    from fwmigrate.conversion.fortigate_to_palo_alto.planning.nat import plan_nat
    item = plan_nat(source, derived, options)[0]
    unmapped = plan_nat(source, derived, PANMigrationOptions())[0]

    assert item.to_interface == "ethernet1/2"
    assert unmapped.to_interface is None

# --- test_pr1_correctness.py ---
@pytest.mark.parametrize('src4,dst4,src6,dst6,supported', [
    (['all'], ['all'], None, None, True),
    (None, None, ['v6-source'], ['v6-destination'], False),
    (['all'], ['all'], ['v6-source'], ['v6-destination'], False),
    (['all'], ['all'], [], [], False),
    ([], [], ['v6-source'], ['v6-destination'], False),
    (None, None, None, None, False),
    ([], [], None, None, False),
])
def test_policy_address_families_never_fall_back_or_drop_ipv6(src4, dst4, src6, dst6, supported):
    from fwmigrate.vendors.fortigate.model.policy import FGPolicy
    from fwmigrate.conversion.fortigate_to_palo_alto.planning.policies import plan_policies
    from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
    policy = FGPolicy(vdom='root', policy_id=42, name='family-policy',
        srcintf=['lan'], dstintf=['wan'], srcaddr=src4, dstaddr=dst4, srcaddr6=src6, dstaddr6=dst6,
        service=['ALL'], schedule='always', action='accept')
    config = FGConfig(policies=[policy])
    options = PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}}, interfaces={'root': {
        'lan': {'target_zone': 'trust'}, 'wan': {'target_zone': 'untrust'}}})
    rules = plan_policies(config, options)
    plan = PANMigrationPlan(security_rules=rules, zones=(
        PlannedZone(source_vdom='root', source_kind='zone', source_name='trust',
            target_name='trust', target_vsys='vsys1', status=PANMigrationStatus.SUPPORTED),
        PlannedZone(source_vdom='root', source_kind='zone', source_name='untrust',
            target_name='untrust', target_vsys='vsys1', status=PANMigrationStatus.SUPPORTED)))
    validation = validate_plan(plan)
    artifact = PANSetRenderer().render(plan, validation)
    assert any('set vsys vsys1 rulebase security' in command for command in artifact.commands) == supported
    assert config.policies[0].srcaddr6 == src6
    rule = artifact.report['items'][-1]
    assert rule['source_policy_id'] == 42
    if src6 is not None or dst6 is not None:
        assert rules[0].status is PANMigrationStatus.UNSUPPORTED
        assert rules[0].sources == tuple('0.0.0.0/0' if name == 'all' else name for name in (src4 or ()))
        assert f'explicit source srcaddr6 = {src6!r}' in rule['warnings']
        assert f'explicit source dstaddr6 = {dst6!r}' in rule['warnings']
        assert rule['render_disposition'] == 'BLOCK'


def _objects(*, address_status=PANMigrationStatus.SUPPORTED, service_status=PANMigrationStatus.SUPPORTED,
             schedule_status=PANMigrationStatus.SUPPORTED, group_member="host", service_member="https"):
    return dict(
        addresses=(PlannedAddress(source_object_type="address", source_name="host", target_vsys="vsys1",
                                  status=address_status, address_type="ip-netmask", value="192.0.2.5/32"),),
        address_groups=(PlannedAddressGroup(source_object_type="address_group", source_name="hosts", target_vsys="vsys1",
                                            status=PANMigrationStatus.SUPPORTED, members=(group_member,)),),
        services=(PlannedService(source_object_type="service", source_name="https", target_vsys="vsys1",
                                 status=service_status, protocol="tcp", destination_port="443"),),
        service_groups=(PlannedServiceGroup(source_object_type="service_group", source_name="web", target_vsys="vsys1",
                                            status=PANMigrationStatus.SUPPORTED, members=(service_member,)),),
        schedules=(PlannedSchedule(source_object_type="schedule", source_name="work-hours", target_vsys="vsys1",
                                   status=schedule_status, schedule_type="weekly", weekly=(("monday", "08:00", "17:00"),)),),
        zones=(PlannedZone(source_object_type="zone", source_name="trust", target_vsys="vsys1",
                           status=PANMigrationStatus.SUPPORTED),),
    )


def _rule(**updates):
    values = dict(applications=("any",), source_object_type="security_rule", source_name="allow", target_vsys="vsys1",
                  status=PANMigrationStatus.SUPPORTED, from_zones=("trust",), to_zones=("trust",),
                  sources=("hosts",), destinations=("any",), services=("web",), action="allow")
    values.update(updates)
    return PlannedSecurityRule(**values)


def test_unsupported_address_blocks_group_and_security_rule_transitively():
    plan = PANMigrationPlan(**_objects(address_status=PANMigrationStatus.UNSUPPORTED), security_rules=(_rule(),))
    result = validate_plan(plan)
    assert not any(key[0] in {"address_group", "security_rule"} for key in result.renderable_item_keys)
    assert {issue.code for issue in result.issues} >= {"dependency_not_renderable"}


def test_unsupported_service_blocks_service_group_and_security_rule_transitively():
    plan = PANMigrationPlan(**_objects(service_status=PANMigrationStatus.UNSUPPORTED), security_rules=(_rule(),))
    result = validate_plan(plan)
    assert not any(key[0] in {"service_group", "security_rule"} for key in result.renderable_item_keys)
    assert sum(issue.code == "dependency_not_renderable" for issue in result.issues) >= 2


def test_manual_or_missing_schedule_blocks_security_rule():
    objects = _objects(schedule_status=PANMigrationStatus.MANUAL_REVIEW)
    plan = PANMigrationPlan(**objects, security_rules=(_rule(schedule="work-hours"),))
    result = validate_plan(plan)
    assert not any(key[0] == "security_rule" for key in result.renderable_item_keys)
    assert any(issue.code == "dependency_not_renderable" for issue in result.issues)

    missing = PANMigrationPlan(**_objects(), security_rules=(_rule(schedule="missing"),))
    missing_result = validate_plan(missing)
    assert not any(key[0] == "security_rule" for key in missing_result.renderable_item_keys)
    assert any(issue.code == "missing_schedule" for issue in missing_result.issues)


def test_renderable_address_and_service_groups_are_valid_rule_references():
    plan = PANMigrationPlan(**_objects(), security_rules=(_rule(),))
    result = validate_plan(plan)
    assert ("security_rule", "vsys1", "allow") in result.renderable_item_keys


def test_missing_group_member_blocks_group_and_dependent_rule():
    plan = PANMigrationPlan(**_objects(group_member="absent"), security_rules=(_rule(),))
    result = validate_plan(plan)
    assert not any(key[0] in {"address_group", "security_rule"} for key in result.renderable_item_keys)
    assert any(issue.code == "missing_group_member" for issue in result.issues)


def test_nat_planner_does_not_truncate_multiple_policy_services():
    policy = SimpleNamespace(vdom="root", policy_id=10, name="outbound", srcintf=["lan"],
                             srcaddr=["clients"], dstaddr=["any"], service=["http", "https"])
    nat = SimpleNamespace(vdom="root", policy_id=10, policy_name="outbound", egress_interfaces=["wan"],
                          translated_addresses=["203.0.113.8"], translation_type="ip_pool", pool_types=("overload",), issues=())
    options = PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}, interfaces={"root": {
        "lan": {"target_zone": "trust"}, "wan": {"target_zone": "untrust", "target_interface": "ethernet1/1"}}})
    planned = plan_nat(SimpleNamespace(policies=(policy,), vips=()), SimpleNamespace(nat=(nat,)), options)[0]
    assert planned.service is None
    assert planned.status is PANMigrationStatus.MANUAL_REVIEW
    assert any("multiple services" in warning for warning in planned.warnings)


def test_nat_planner_marks_missing_zone_mapping_for_review():
    policy = SimpleNamespace(vdom="root", policy_id=10, name="outbound", srcintf=["unmapped"],
                             srcaddr=["clients"], dstaddr=["any"], service=["https"])
    nat = SimpleNamespace(vdom="root", policy_id=10, policy_name="outbound", egress_interfaces=["wan"],
                          translated_addresses=["203.0.113.8"], translation_type="ip_pool", pool_types=("overload",), issues=())
    options = PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}, interfaces={"root": {
        "wan": {"target_zone": "untrust", "target_interface": "ethernet1/1"}}})
    planned = plan_nat(SimpleNamespace(policies=(policy,), vips=()), SimpleNamespace(nat=(nat,)), options)[0]
    assert planned.from_zones == ()
    assert planned.status is PANMigrationStatus.MANUAL_REVIEW
    assert any("zone mapping is incomplete" in warning for warning in planned.warnings)


def test_nat_validation_blocks_incomplete_source_nat_fields():
    nat = PlannedNATRule(source_object_type="nat_rule", source_kind="source_nat", source_name="outbound",
                         target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED,
                         source_translation_type="dynamic-ip-and-port", translated_addresses=("203.0.113.8",))
    result = validate_plan(PANMigrationPlan(nat_rules=(nat,)))
    assert not result.renderable_item_keys
    assert {issue.code for issue in result.issues} >= {"missing_nat_zone", "missing_nat_address", "missing_nat_service", "missing_nat_interface"}


def test_nat_validation_blocks_vip_without_required_zone_mappings():
    vip = PlannedNATRule(source_object_type="nat_rule", source_kind="vip", source_name="web-vip",
                         target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED,
                         destination_addresses=("198.51.100.10",), destination_translated_address="10.0.0.10")
    result = validate_plan(PANMigrationPlan(nat_rules=(vip,)))
    assert not result.renderable_item_keys
    assert any(issue.code == "missing_nat_zone" for issue in result.issues)


def test_route_dstaddr_resolves_only_direct_subnet_address():
    config = FGConfig(
        # A bare address does not carry an explicit mask and cannot define a route prefix.
        addresses=[FGAddress(name="servers", subnet="10.0.0.0 255.255.255.0"),
                   FGAddress(name="host-only", subnet="192.0.2.7")],
        address_groups=[FGAddressGroup(name="server-group", members=["servers"])],
        static_routes=[FGStaticRoute(seq_num=1, dstaddr="servers", gateway="192.0.2.1"),
                       FGStaticRoute(seq_num=2, dstaddr="server-group", gateway="192.0.2.1"),
                       FGStaticRoute(seq_num=3, dstaddr="missing", gateway="192.0.2.1"),
                       FGStaticRoute(seq_num=4, dstaddr="host-only", gateway="192.0.2.1")],
    )
    options = PANMigrationOptions(vdoms={"root": {"vsys": "vsys1", "virtual_router": "default"}})
    routes = plan_routes(config, options, build_derived_views(config))
    assert routes[0].destination == "10.0.0.0/24"
    assert routes[0].status is PANMigrationStatus.SUPPORTED
    assert routes[1].destination is None and routes[1].status is PANMigrationStatus.MANUAL_REVIEW
    assert routes[2].destination is None and routes[2].status is PANMigrationStatus.MANUAL_REVIEW
    assert routes[3].destination is None and routes[3].status is PANMigrationStatus.MANUAL_REVIEW


def test_static_route_disabled_and_any_explicit_priority_require_review():
    from fwmigrate.conversion.fortigate_to_palo_alto.options import VDOMMapping
    from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationStatus
    from fwmigrate.vendors.fortigate.model.route_static import FGStaticRoute

    options = PANMigrationOptions(vdoms={"root": VDOMMapping(virtual_router="vr1")})
    routes = plan_routes(FGConfig(static_routes=[
        FGStaticRoute(seq_num=1, dst="192.0.2.0/24", status="disable"),
        FGStaticRoute(seq_num=2, dst="198.51.100.0/24", priority=0, explicit_fields={"priority"}),
        FGStaticRoute(seq_num=3, dst="203.0.113.0/24", priority=10, explicit_fields={"priority"}),
        FGStaticRoute(seq_num=4, dst="10.0.0.0/24"),
    ]), options)
    assert [route.status for route in routes] == [PANMigrationStatus.MANUAL_REVIEW] * 3 + [PANMigrationStatus.SUPPORTED]
    assert routes[1].priority == 0
    assert any("priority" in warning for warning in routes[1].warnings)


def test_address_group_exclusion_uses_explicit_fortigate_values():
    from fwmigrate.conversion.fortigate_to_palo_alto.planning.addresses import _plan_group
    from fwmigrate.conversion.fortigate_to_palo_alto.options import VDOMMapping
    from fwmigrate.vendors.fortigate.model.address import FGAddressGroup

    options = PANMigrationOptions(vdoms={"root": VDOMMapping(vsys="vsys1")})
    disabled, _ = _plan_group(FGAddressGroup(name="g", members=["a"], exclude="disable"), options)
    enabled, _ = _plan_group(FGAddressGroup(name="g", members=["a"], exclude="enable"), options)
    missing, _ = _plan_group(FGAddressGroup(name="g", members=["a"], exclude_members=["b"]), options)
    assert disabled.status is PANMigrationStatus.SUPPORTED
    assert enabled.status is PANMigrationStatus.MANUAL_REVIEW
    assert missing.status is PANMigrationStatus.MANUAL_REVIEW


def test_fortigate_source_nat_transform_to_renderer_is_fail_closed():
    from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
    from fwmigrate.vendors.fortigate.model.interface import FGInterface
    from fwmigrate.vendors.fortigate.model.ippool import FGIPPool
    from fwmigrate.vendors.fortigate.model.policy import FGPolicy
    from fwmigrate.vendors.fortigate.transform.nat import transform_nat

    options = PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}, interfaces={"root": {
        "lan": {"target_zone": "trust"},
        "wan": {"target_zone": "untrust", "target_interface": "ethernet1/1"},
    }})
    base_policy = dict(policy_id=90, name="outbound", nat="enable", srcintf=["lan"], dstintf=["wan"],
                       srcaddr=["any"], dstaddr=["any"], service=["any"], status="enable", action="accept", schedule="always")
    interface_source = FGConfig(interfaces=[FGInterface(name="wan", ip="203.0.113.1/24")],
        policies=[FGPolicy(**base_policy)])
    interface_derived = SimpleNamespace(nat=tuple(transform_nat(interface_source)))
    interface_rule = plan_nat(interface_source, interface_derived, options)[0]
    zones = tuple(PlannedZone(source_object_type="zone", source_name=name, target_name=target,
                              target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED)
                  for name, target in (("lan", "trust"), ("wan", "untrust")))
    rendered = PANSetRenderer().render(PANMigrationPlan(zones=zones, nat_rules=(interface_rule,)))
    assert interface_rule.status is PANMigrationStatus.SUPPORTED
    assert "set vsys vsys1 rulebase nat rules outbound source-translation dynamic-ip-and-port interface-address interface ethernet1/1" in rendered.commands

    pool_source = FGConfig(interfaces=[FGInterface(name="wan", ip="203.0.113.1/24")],
        ip_pools=[FGIPPool(name="PAT", type="overload", startip="203.0.113.8", endip="203.0.113.8",
                           explicit_fields={"type"})],
        policies=[FGPolicy(**{**base_policy, "ippool": "enable", "poolname": ["PAT"]})])
    pool_derived = SimpleNamespace(nat=tuple(transform_nat(pool_source)))
    pool_rule = plan_nat(pool_source, pool_derived, options)[0]
    pool_rendered = PANSetRenderer().render(PANMigrationPlan(zones=zones, nat_rules=(pool_rule,)))
    assert pool_rule.status is PANMigrationStatus.SUPPORTED
    assert any("translated-address [ 203.0.113.8 ]" in command for command in pool_rendered.commands)

    unsupported_source = FGConfig(interfaces=[FGInterface(name="wan", ip="203.0.113.1/24")],
        ip_pools=[FGIPPool(name="ONE-TO-ONE", type="one-to-one", startip="203.0.113.8",
                           endip="203.0.113.8", explicit_fields={"type"})],
        policies=[FGPolicy(**{**base_policy, "ippool": "enable", "poolname": ["ONE-TO-ONE"]})])
    unsupported_rule = plan_nat(unsupported_source,
        SimpleNamespace(nat=tuple(transform_nat(unsupported_source))), options)[0]
    unsupported_rendered = PANSetRenderer().render(PANMigrationPlan(zones=zones, nat_rules=(unsupported_rule,)))
    assert unsupported_rule.status is PANMigrationStatus.MANUAL_REVIEW
    assert unsupported_rule.translated_addresses == ("203.0.113.8",)
    assert not unsupported_rendered.commands

    disabled_source = FGConfig(interfaces=[FGInterface(name="wan", ip="203.0.113.1/24")],
        policies=[FGPolicy(**{**base_policy, "status": "disable"})])
    disabled_rule = plan_nat(disabled_source, SimpleNamespace(nat=tuple(transform_nat(disabled_source))), options)[0]
    disabled_rendered = PANSetRenderer().render(PANMigrationPlan(zones=zones, nat_rules=(disabled_rule,)))
    assert disabled_rule.status is PANMigrationStatus.MANUAL_REVIEW
    assert not disabled_rendered.commands


def test_parsed_fortigate_cli_pool_nat_reaches_palo_alto_renderer():
    from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
    from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter

    analysis = FortiGateSourceReporter().analyze_source('''config system interface
    edit "lan"
        set ip 10.0.0.1 255.255.255.0
    next
    edit "wan"
        set ip 203.0.113.1 255.255.255.0
    next
end
config firewall ippool
    edit "PAT"
        set type overload
        set startip 203.0.113.8
        set endip 203.0.113.8
    next
end
config firewall policy
    edit 90
        set name "outbound"
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "any"
        set dstaddr "any"
        set service "any"
        set nat enable
        set action accept
        set schedule always
        set ippool enable
        set poolname "PAT"
    next
end
''')
    options = PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}, interfaces={"root": {
        "lan": {"target_zone": "trust"},
        "wan": {"target_zone": "untrust", "target_interface": "ethernet1/1"},
    }})
    rule = plan_nat(analysis.extracted.config, analysis.derived, options)[0]
    zones = tuple(PlannedZone(source_object_type="zone", source_name=name, target_name=target,
                              target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED)
                  for name, target in (("lan", "trust"), ("wan", "untrust")))
    rendered = PANSetRenderer().render(PANMigrationPlan(zones=zones, nat_rules=(rule,)))
    assert rule.status is PANMigrationStatus.SUPPORTED
    assert any("source-translation dynamic-ip-and-port translated-address [ 203.0.113.8 ]" in command
               for command in rendered.commands)


@pytest.mark.parametrize("updates", [
    {"srcaddr_negate": "enable"}, {"dstaddr_negate": "enable"}, {"service_negate": "enable"},
    {"internet_service": "enable"}, {"internet_service_src_name": ["example"]},
    {"users": ["alice"]}, {"groups": ["staff"]}, {"schedule": "work-hours"}, {"schedule": None},
    {"action": "deny"}, {"action": None}, {"raw_extra": {"match-vip": "enable"}},
])
def test_snat_unrepresented_policy_conditions_emit_no_commands(updates):
    from fwmigrate.vendors.fortigate.model.policy import FGPolicy
    from fwmigrate.vendors.fortigate.model.interface import FGInterface
    from fwmigrate.vendors.fortigate.transform.nat import transform_nat
    from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer

    values = dict(policy_id=1, name="unsafe", nat="enable", action="accept", schedule="always",
                  srcintf=["lan"], dstintf=["wan"], srcaddr=["all"], dstaddr=["all"], service=["ALL"])
    config = FGConfig(policies=[FGPolicy(**{**values, **updates})],
                      interfaces=[FGInterface(name="wan", ip="203.0.113.1/24")])
    options = PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}, interfaces={"root": {
        "lan": {"target_zone": "trust"}, "wan": {"target_zone": "untrust", "target_interface": "ethernet1/1"}}})
    rules = plan_nat(config, SimpleNamespace(nat=tuple(transform_nat(config))), options)
    assert rules[0].status is PANMigrationStatus.MANUAL_REVIEW
    rendered = PANSetRenderer().render(PANMigrationPlan(nat_rules=rules))
    assert rendered.commands == ()
    assert rendered.report["items"][0]["warnings"]
    for field, value in updates.items():
        assert getattr(config.policies[0], field) == value


@pytest.mark.parametrize("distance,supported", [(9, False), (10, True), (240, True), (241, False), (None, True)])
def test_route_distance_source_and_direct_plan_validation(distance, supported):
    from fwmigrate.conversion.fortigate_to_palo_alto.models import PlannedStaticRoute
    from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer

    options = PANMigrationOptions(vdoms={"root": {"vsys": "vsys1", "virtual_router": "default"}})
    source = FGConfig(static_routes=[FGStaticRoute(seq_num=1, dst="192.0.2.0/24", gateway="198.51.100.1", distance=distance)])
    route = plan_routes(source, options)[0]
    assert (route.status is PANMigrationStatus.SUPPORTED) == supported
    direct = PlannedStaticRoute(source_object_type="static_route", source_name="direct", status=PANMigrationStatus.SUPPORTED,
        destination="192.0.2.0/24", virtual_router="default", nexthop_type="ip-address", nexthop="198.51.100.1", admin_distance=distance)
    for item in (route, direct):
        rendered = PANSetRenderer().render(PANMigrationPlan(static_routes=(item,)))
        assert bool(rendered.commands) == supported
        if distance is None:
            assert not any("admin-dist" in command for command in rendered.commands)


@pytest.mark.parametrize("updates", [{"preferred_source": "192.0.2.1"}, {"raw_extra": {"link-monitor-exempt": "enable"}}])
def test_unrepresented_route_forwarding_settings_block_rendering(updates):
    from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
    route = FGStaticRoute(seq_num=1, dst="192.0.2.0/24", gateway="198.51.100.1", **updates)
    options = PANMigrationOptions(vdoms={"root": {"virtual_router": "default"}})
    planned = plan_routes(FGConfig(static_routes=[route]), options)
    assert planned[0].warnings
    assert PANSetRenderer().render(PANMigrationPlan(static_routes=planned)).commands == ()


def test_builtin_all_and_named_all_preserve_ipv4_match_identity():
    from fwmigrate.conversion.fortigate_to_palo_alto.planner import FortiGateToPaloAltoPlanner
    from fwmigrate.vendors.fortigate.model.policy import FGPolicy
    options = PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}, interfaces={"root": {
        "lan": {"target_zone": "trust"}, "wan": {"target_zone": "untrust"}}})
    policy = FGPolicy(policy_id=1, srcintf=["lan"], dstintf=["wan"], srcaddr=["all"], dstaddr=["all"],
                      service=["ALL"], action="accept", schedule="always")
    for addresses, expected in (([], "0.0.0.0/0"), ([FGAddress(name="all", subnet="192.0.2.0/24")], "all")):
        source = FGConfig(addresses=addresses, policies=[policy])
        plan = FortiGateToPaloAltoPlanner().plan(source, build_derived_views(source), options)
        assert plan.security_rules[0].sources == (expected,)
        assert plan.security_rules[0].destinations == (expected,)
        assert source.policies[0].srcaddr == ["all"]


@pytest.mark.parametrize("family", ["addresses", "address_groups", "vips", "vip_groups"])
@pytest.mark.parametrize("indexed", [False, True])
def test_address_references_preserve_explicit_all_in_each_scoped_family(family, indexed):
    from fwmigrate.conversion.fortigate_to_palo_alto.planning.addresses import address_references, explicit_all_vdoms
    source = SimpleNamespace(**{family: [SimpleNamespace(name="all", vdom="branch")]})
    kwargs = {"explicit_all": explicit_all_vdoms(source)} if indexed else {}
    assert address_references(source, "branch", ["host", "all", "all"], **kwargs) == ("host", "all", "all")
    assert address_references(source, "root", ["host", "all"], **kwargs) == ("host", "0.0.0.0/0")
    assert address_references(source, None, ["all"], **kwargs) == ("0.0.0.0/0",)


def test_address_references_skip_inventory_without_all_and_stop_at_explicit_all():
    from fwmigrate.conversion.fortigate_to_palo_alto.planning.addresses import address_references

    class UnreadableInventory:
        def __iter__(self):
            pytest.fail("Unneeded address inventory scan")

    source = SimpleNamespace(addresses=UnreadableInventory())
    assert address_references(source, "root", iter(["host", "host"])) == ("host", "host")
    assert address_references(source, "root", []) == ()
    assert address_references(source, "root", ["all"], explicit_all=set()) == ("0.0.0.0/0",)
    assert address_references(source, None, ["all"], explicit_all={"root"}) == ("all",)
    source.addresses = [SimpleNamespace(name="all", vdom=None)]
    source.address_groups = UnreadableInventory()
    assert address_references(source, "root", ["all"]) == ("all",)


def test_planner_shares_one_all_inventory_between_security_and_nat(monkeypatch):
    from importlib import import_module
    from unittest.mock import Mock
    from fwmigrate.conversion.fortigate_to_palo_alto.planning.addresses import explicit_all_vdoms
    from fwmigrate.vendors.fortigate.model.policy import FGPolicy

    planner = import_module('fwmigrate.conversion.fortigate_to_palo_alto.planner')
    inventory = Mock(wraps=explicit_all_vdoms)
    for module in ('planner', 'planning.policies', 'planning.nat'):
        monkeypatch.setattr(import_module('fwmigrate.conversion.fortigate_to_palo_alto.' + module),
                            'explicit_all_vdoms', inventory)
    source = FGConfig(policies=[FGPolicy(policy_id=1, name='nat', nat='enable',
        srcintf=['lan'], dstintf=['wan'], srcaddr=['all'], dstaddr=['all'],
        service=['ALL'], schedule='always', action='accept')])
    for addresses, expected in (([], '0.0.0.0/0'), ([FGAddress(name='all', subnet='192.0.2.0/24')], 'all')):
        source.addresses = addresses
        inventory.reset_mock()
        plan = planner.FortiGateToPaloAltoPlanner().plan(source, build_derived_views(source))
        inventory.assert_called_once_with(source)
        assert plan.security_rules[0].sources == plan.security_rules[0].destinations == (expected,)
        assert plan.nat_rules[0].source_addresses == plan.nat_rules[0].destination_addresses == (expected,)


def test_literal_ipv4_selectors_are_only_exempt_for_addresses_and_keep_named_dependencies():
    from dataclasses import replace
    address = PlannedAddress(source_object_type="address", source_name="192.0.2.1", target_vsys="vsys1",
                             status=PANMigrationStatus.UNSUPPORTED)
    rule = _rule(sources=("192.0.2.1",), destinations=("0.0.0.0/0",), services=("any",))
    objects = _objects()
    objects["addresses"] = (address,)
    assert ("security_rule", "vsys1", "allow") not in validate_plan(PANMigrationPlan(**objects, security_rules=(rule,))).renderable_item_keys
    objects["addresses"] = ()
    assert ("security_rule", "vsys1", "allow") in validate_plan(PANMigrationPlan(**objects, security_rules=(rule,))).renderable_item_keys
    invalid_zone = replace(rule, to_zones=("0.0.0.0/0",))
    assert ("security_rule", "vsys1", "allow") not in validate_plan(PANMigrationPlan(**objects, security_rules=(invalid_zone,))).renderable_item_keys


@pytest.mark.parametrize("named_all", [False, True])
def test_snat_builtin_all_and_named_all_share_policy_address_mapping(named_all):
    from fwmigrate.vendors.fortigate.model.policy import FGPolicy
    from fwmigrate.vendors.fortigate.model.interface import FGInterface
    from fwmigrate.conversion.fortigate_to_palo_alto.planner import FortiGateToPaloAltoPlanner
    source = FGConfig(interfaces=[FGInterface(name="wan", ip="203.0.113.1/24")],
        addresses=[FGAddress(name="all", subnet="192.0.2.0/24")] if named_all else [],
        policies=[FGPolicy(policy_id=1, nat="enable", action="accept", schedule="always", srcintf=["lan"],
                          dstintf=["wan"], srcaddr=["all"], dstaddr=["all"], service=["ALL"])])
    options = PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}, interfaces={"root": {
        "lan": {"target_zone": "trust"}, "wan": {"target_zone": "untrust", "target_interface": "ethernet1/1"}}})
    plan = FortiGateToPaloAltoPlanner().plan(source, build_derived_views(source), options)
    expected = ("all",) if named_all else ("0.0.0.0/0",)
    assert plan.nat_rules[0].source_addresses == plan.security_rules[0].sources == expected
    assert plan.nat_rules[0].destination_addresses == plan.security_rules[0].destinations == expected
    assert plan.nat_rules[0].status is PANMigrationStatus.SUPPORTED


def test_negated_ipv4_source_and_destination_do_not_expand_into_ipv6():
    from fwmigrate.vendors.fortigate.model.policy import FGPolicy
    from fwmigrate.conversion.fortigate_to_palo_alto.planning.policies import plan_policies
    source = FGConfig(policies=[FGPolicy(policy_id=1, action="accept", schedule="always", srcintf=["any"],
        dstintf=["any"], srcaddr=["all"], dstaddr=["all"], service=["ALL"], srcaddr_negate="enable", dstaddr_negate="enable")])
    options = PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}})
    rule = plan_policies(source, options)[0]
    assert rule.status is not PANMigrationStatus.SUPPORTED
    assert any("IPv6 matching" in warning for warning in rule.warnings)

# --- test_pr2_requirements_readiness.py ---
def _config():
    return FGConfig(
        dhcp_servers=[FGDHCPServer(id=1, interface="port1")],
        ipsec_phase1=[FGIPsecPhase1(name="vpn-a", interface="port1")],
        sdwans=[FGSDWAN(members=[FGSDWANMember(seq_num=1, interface="port1")])],
        ssl_vpn_settings=[FGSSLVPNSettings(
            source_interface=["port1"],
            authentication_rules=[FGSSLVPNAuthenticationRule(id=1, source_interface=["port2"])],
        )],
    )


def test_dhcp_mapping_is_required_while_remaining_recommendations_expose_readiness():
    source = _config()
    requirements = build_mapping_requirements(source, object())
    required = {(item["source_vdom"], item["source_name"], item["kind"]): item
                for item in requirements["interfaces"]}
    assert set(required) == {("root", "port1", "interface")}
    assert required[("root", "port1", "interface")]["requires"] == ["target_interface"]

    decisions = PANMigrationDecisionSet()
    recommendations = build_recommendations(source, object(), decisions)
    by_kind = {(item.source_kind, item.source_name): item for item in recommendations}
    assert ("dhcp_server", "1") not in by_kind

    vpn = by_kind[("ipsec_phase1", "vpn-a")]
    assert "Target interface mapping required" in vpn.blockers
    assert vpn.readiness is PANRecommendationReadiness.MANUAL_DESIGN

    sdwan = by_kind[("sdwan_member", "1")]
    assert "Target interface mapping required" in sdwan.blockers
    assert sdwan.readiness is PANRecommendationReadiness.REQUIRES_DECISION

    ssl_vpn = by_kind[("ssl_vpn_settings", "settings-root-0")]
    assert ssl_vpn.required_decision_keys == ()
    assert "Target interface mapping required for port1" in ssl_vpn.blockers
    assert "Target interface mapping required for port2" in ssl_vpn.blockers
    assert ssl_vpn.readiness is PANRecommendationReadiness.MANUAL_DESIGN
    assert ssl_vpn.to_dict()["readiness"] == "MANUAL_DESIGN"

def test_confirmed_interface_value_resolves_mapping_blockers():
    source = _config()
    assert build_mapping_requirements(source, object())["interfaces"]
    confirmed = PANMigrationDecisionSet((
        PANMigrationDecision("root", "interface", "port1", "target_interface").confirm("ethernet1/1"),
        PANMigrationDecision("root", "interface", "port2", "target_interface").confirm("ethernet1/2"),
    ))
    recommendations = build_recommendations(source, object(), confirmed)
    by_kind = {(item.source_kind, item.source_name): item for item in recommendations}

    assert ("dhcp_server", "1") not in by_kind
    assert "Target interface mapping required" not in by_kind[("ipsec_phase1", "vpn-a")].blockers
    assert "Target interface mapping required" not in by_kind[("sdwan_member", "1")].blockers
    assert not any("Target interface mapping required for" in blocker for blocker in by_kind[("ssl_vpn_settings", "settings-root-0")].blockers)
    assert by_kind[("ssl_vpn_settings", "settings-root-0")].readiness is PANRecommendationReadiness.MANUAL_DESIGN


def test_decision_value_requires_a_supported_nonempty_auto_or_confirmed_value():
    assert decision_value is mapping_decision_value
    pending = PANMigrationDecision("root", "interface", "port1", "target_interface")
    confirmed_empty = pending.confirm()
    unsupported_confirmed = PANMigrationDecision(
        "root", "interface", "port1", "target_interface", value="ethernet1/1",
        mode=PANDecisionMode.UNSUPPORTED,
    ).confirm()
    decisions = PANMigrationDecisionSet((pending,))
    assert decision_value(decisions, pending.key) is None
    assert decision_value(PANMigrationDecisionSet((confirmed_empty,)), pending.key) is None
    assert decision_value(PANMigrationDecisionSet((unsupported_confirmed,)), pending.key) is None
    auto = PANMigrationDecision(
        "root", "interface", "port1", "target_interface", value="ethernet1/1", mode=PANDecisionMode.AUTO,
    )
    assert decision_value(PANMigrationDecisionSet((auto,)), auto.key) == "ethernet1/1"
