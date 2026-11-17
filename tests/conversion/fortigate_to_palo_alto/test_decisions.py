import json
import pytest
from fwmigrate.conversion.fortigate_to_palo_alto import PANDecisionMode, PANDecisionReviewState, PANMigrationDecision, PANMigrationDecisionSet, build_decision_set, make_decision_key
from fwmigrate.conversion.fortigate_to_palo_alto.requirements import build_mapping_requirements
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.zone import FGZone
from types import SimpleNamespace
from fwmigrate.conversion.fortigate_to_palo_alto.auto_decisions import classify_auto_decisions
from fwmigrate.vendors.palo_alto.relationships.topology import PANInterfaceTopologyEntry
from fwmigrate.vendors.palo_alto.source_model import PANScope, pan_scope_identity
from fwmigrate.conversion.fortigate_to_palo_alto.decision_propagation import MigrationRuleType, apply_zone_to_members, dependent_decision_keys, apply_repeated_zone_action, repeated_zone_action_suggestions, rule_affected_decision_keys, zone_member_decision_keys
from fwmigrate.vendors.fortigate.model.address import FGAddress
from fwmigrate.vendors.fortigate.model.dhcp import FGDHCPServer
from fwmigrate.vendors.fortigate.model.route_static import FGStaticRoute
from fwmigrate.vendors.fortigate.model.sdwan import FGSDWAN, FGSDWANMember
from fwmigrate.vendors.fortigate.model.vpn import FGIPsecPhase1
from fwmigrate.vendors.fortigate.model.vpn_ssl import FGSSLVPNAuthenticationRule, FGSSLVPNClient, FGSSLVPNSettings

# --- test_decisions.py ---
def test_decision_key_is_stable_and_scope_sensitive():
    key = make_decision_key("root", "interface", "port/1", "target_zone")
    assert key == make_decision_key("root", "interface", "port/1", "target_zone")
    assert key != make_decision_key("blue", "interface", "port/1", "target_zone")


def test_confirmation_and_serialization_round_trip():
    decision = PANMigrationDecision(
        "root", "interface", "port1", "target_interface",
        mode=PANDecisionMode.REQUIRED, affected_by={"static_route": 1},
    ).confirm("ethernet1/1")
    restored = PANMigrationDecisionSet.from_dict(json.loads(json.dumps(PANMigrationDecisionSet((decision,)).to_dict())))
    assert restored.decisions == (decision,)
    assert restored.decisions[0].review_state == PANDecisionReviewState.CONFIRMED


def test_requirements_generate_scoped_suggestions_without_defaults():
    config = FGConfig(
        interfaces=[FGInterface(name="port1")],
        zones=[FGZone(name="trust", members=["port1"])],
        policies=[
            FGPolicy(policy_id=1, srcintf=["port1"]),
            FGPolicy(policy_id=2, srcintf=["trust"]),
        ],
    )
    requirements = build_mapping_requirements(config, object())
    decisions = build_decision_set(config, object(), requirements)
    by_identity = {(item.source_kind, item.source_name, item.target_field): item for item in decisions.decisions}

    assert by_identity[("zone", "trust", "target_zone")].suggested_value == "trust"
    assert by_identity[("zone", "trust", "target_zone")].mode == PANDecisionMode.SUGGESTED
    assert by_identity[("zone", "trust", "target_zone")].evidence_source == "SOURCE"
    assert by_identity[("zone", "trust", "target_zone")].evidence_type == "SOURCE_ZONE_NAME"
    assert by_identity[("interface", "port1", "target_zone")].suggested_value == "trust"
    assert by_identity[("interface", "port1", "target_zone")].evidence_source == "SOURCE"
    assert by_identity[("interface", "port1", "target_interface")].mode == PANDecisionMode.REQUIRED
    assert by_identity[("vdom", "root", "vsys")].suggested_value is None
    assert by_identity[("vdom", "root", "virtual_router")].suggested_value is None
    assert decisions.to_options().interfaces == {}
    assert decisions.to_options().vdoms == {}


def test_confirmed_decisions_override_suggestions_and_convert_to_options():
    config = FGConfig(
        interfaces=[FGInterface(name="port1")],
        zones=[FGZone(name="trust", members=["port1"])],
        policies=[
            FGPolicy(policy_id=1, srcintf=["port1"]),
            FGPolicy(policy_id=2, srcintf=["trust"]),
        ],
    )
    requirements = build_mapping_requirements(config, object())
    initial = build_decision_set(config, object(), requirements)
    confirmed = tuple(
        item.confirm("vsys-prod" if item.target_field == "vsys" else "vr-prod" if item.target_field == "virtual_router" else "corp-trust" if item.target_field == "target_zone" else "ethernet1/7")
        for item in initial.decisions
    )
    updated = build_decision_set(config, object(), requirements, PANMigrationDecisionSet(confirmed))
    options = updated.to_options()

    assert options.vdoms["root"].vsys == "vsys-prod"
    assert options.vdoms["root"].virtual_router == "vr-prod"
    assert options.zones["root"]["trust"].target_zone == "corp-trust"
    assert options.interfaces["root"]["port1"].target_interface == "ethernet1/7"


def test_target_evidence_provenance_round_trips_and_requires_a_complete_identity():
    decision = PANMigrationDecision(
        "root", "interface", "port1", "target_interface",
        value="ethernet1/1",
        review_state=PANDecisionReviewState.CONFIRMED,
        evidence_source="DERIVED",
        evidence_type="AUTOMATION_VERIFIED",
        evidence_target_digest="digest-a",
        evidence_target_device="fw-a",
        affected_by={},
    )
    restored = PANMigrationDecision.from_dict(json.loads(json.dumps(decision.to_dict())))
    assert restored == decision

    with pytest.raises(ValueError, match="digest and device"):
        PANMigrationDecision(
            "root", "interface", "port1", "target_interface",
            evidence_target_digest="digest-a",
        )
    with pytest.raises(ValueError, match="digest and device"):
        PANMigrationDecision(
            "root", "interface", "port1", "target_interface",
            evidence_target_device="fw-a",
        )


def test_build_decision_set_keeps_fresh_requirement_metadata_while_carrying_confirmation():
    config = FGConfig(
        interfaces=[FGInterface(name="port1")],
        zones=[FGZone(name="trust", members=["port1"])],
        policies=[FGPolicy(policy_id=1, srcintf=["port1"])],
    )
    requirements = build_mapping_requirements(config, object())
    fresh = build_decision_set(config, object(), requirements)
    original = next(
        item for item in fresh.decisions
        if item.source_kind == "interface"
        and item.source_name == "port1"
        and item.target_field == "target_zone"
    )
    previous = PANMigrationDecisionSet((
        PANMigrationDecision(
            original.source_vdom,
            original.source_kind,
            original.source_name,
            original.target_field,
            suggested_value="stale-zone",
            value="TRUST",
            mode=PANDecisionMode.REQUIRED,
            review_state=PANDecisionReviewState.CONFIRMED,
            reason="stale reason",
            evidence_source="ENGINEER",
            evidence_type="MANUAL",
            evidence_value="TRUST",
            target_object="TRUST",
        ),
    ))
    rebuilt = build_decision_set(config, object(), requirements, previous)
    carried = next(item for item in rebuilt.decisions if item.key == original.key)

    assert carried.value == "TRUST"
    assert carried.review_state is PANDecisionReviewState.CONFIRMED
    assert carried.suggested_value == "trust"
    assert carried.reason == original.reason
    assert carried.mode == original.mode

# --- test_auto_decisions.py ---
def _target(items):
    scope = PANScope(kind="device", name="dev", device_name="dev")
    for item in items:
        item.scope = scope
    topology = [PANInterfaceTopologyEntry(item.name, pan_scope_identity(scope),
        parent=getattr(item, "parent", None), imported_vsys=getattr(item, "imported_vsys", ()),
        zones=getattr(item, "zones", ()),
        virtual_routers=getattr(item, "virtual_routers", ())) for item in items]
    return SimpleNamespace(config=SimpleNamespace(interfaces=items, interface_units=[], zones=[]),
        derived=SimpleNamespace(interface_topology=topology)), scope


def test_exact_ip_verifies_and_confirmed_parent_derives_vlan_without_mutating_decisions():
    source = FGConfig(interfaces=[FGInterface(name="port1", ip="192.0.2.1/24"),
        FGInterface(name="vlan100", type="vlan", interface="port1", vlanid=100)])
    parent = SimpleNamespace(name="ethernet1/1", interface_family="ethernet", ipv4_addresses=["192.0.2.1/24"], tag=None, parent=None)
    child = SimpleNamespace(name="ethernet1/1.100", interface_family="vlan", ipv4_addresses=[], tag="100", parent="ethernet1/1")
    target, _ = _target([parent, child])
    decisions = PANMigrationDecisionSet((
        PANMigrationDecision("root", "interface", "port1", "target_interface", value="ethernet1/1", review_state=PANDecisionReviewState.CONFIRMED),
        PANMigrationDecision("root", "interface", "vlan100", "target_interface"),
    ))
    result = classify_auto_decisions(source, None, decisions, target, "dev")
    child_decision = decisions.decisions[1]
    assert result[child_decision.key]["status"] == "DERIVED"
    assert result[child_decision.key]["value"] == "ethernet1/1.100"
    assert result[child_decision.key]["uses_target_evidence"] is True
    assert child_decision.review_state == PANDecisionReviewState.PENDING


def test_exact_address_is_verified_and_multiple_exact_targets_remain_candidates():
    source = FGConfig(interfaces=[FGInterface(name="lan", ip="198.51.100.1/24")])
    targets = [SimpleNamespace(name=name, interface_family="ethernet", ipv4_addresses=["198.51.100.1/24"], tag=None, parent=None)
               for name in ("ethernet1/1", "ethernet1/2")]
    target, _ = _target(targets)
    decision = PANMigrationDecision("root", "interface", "lan", "target_interface")
    result = classify_auto_decisions(source, None, PANMigrationDecisionSet((decision,)), target, "dev")
    assert result[decision.key]["status"] == "CANDIDATE"

    one, _ = _target(targets[:1])
    result = classify_auto_decisions(source, None, PANMigrationDecisionSet((decision,)), one, "dev")
    assert result[decision.key]["status"] == "VERIFIED"
    assert result[decision.key]["uses_target_evidence"] is True


def test_vsys_and_virtual_router_derive_only_when_all_mapped_interfaces_agree():
    source = FGConfig(interfaces=[FGInterface(name="port1"), FGInterface(name="port2")])
    first = SimpleNamespace(name="ethernet1/1", interface_family="ethernet", ipv4_addresses=[], tag=None,
                            parent=None, imported_vsys=("vsys1",), virtual_routers=("vr-main",))
    second = SimpleNamespace(name="ethernet1/2", interface_family="ethernet", ipv4_addresses=[], tag=None,
                             parent=None, imported_vsys=("vsys1",), virtual_routers=("vr-main",))
    target, _ = _target([first, second])
    mapped = [PANMigrationDecision("root", "interface", name, "target_interface", value=target_name,
        review_state=PANDecisionReviewState.CONFIRMED)
        for name, target_name in (("port1", "ethernet1/1"), ("port2", "ethernet1/2"))]
    vdom = [PANMigrationDecision("root", "vdom", "root", field) for field in ("vsys", "virtual_router")]
    decisions = PANMigrationDecisionSet(tuple((*mapped, *vdom)))
    result = classify_auto_decisions(source, None, decisions, target, "dev")
    assert result[vdom[0].key]["status"] == "DERIVED"
    assert result[vdom[0].key]["value"] == "vsys1"
    assert result[vdom[0].key]["reason"] == "Consistent deterministic interface vsys evidence."
    assert result[vdom[0].key]["uses_target_evidence"] is True
    assert result[vdom[1].key]["status"] == "DERIVED"

    second.virtual_routers = ("vr-other",)
    target, _ = _target([first, second])
    result = classify_auto_decisions(source, None, decisions, target, "dev")
    assert result[vdom[0].key]["status"] == "DERIVED"
    assert result[vdom[1].key]["status"] == "MANUAL"


def test_zone_and_vsys_derive_from_unique_exact_interface_without_target_interface_requirement():
    source = FGConfig(interfaces=[FGInterface(name="lan", ip="192.0.2.1/24")])
    target_item = SimpleNamespace(
        name="ethernet1/1", interface_family="ethernet",
        ipv4_addresses=["192.0.2.1/24"], tag=None, parent=None,
        imported_vsys=("vsys1",), zones=("trust",), virtual_routers=("vr-main",),
    )
    target, _ = _target([target_item])
    zone = PANMigrationDecision("root", "interface", "lan", "target_zone")
    vsys = PANMigrationDecision("root", "vdom", "root", "vsys")
    decisions = PANMigrationDecisionSet((zone, vsys))

    result = classify_auto_decisions(source, None, decisions, target, "dev")

    assert result[zone.key]["status"] == "DERIVED"
    assert result[zone.key]["value"] == "trust"
    assert result[zone.key]["uses_target_evidence"] is True
    assert result[vsys.key]["status"] == "DERIVED"
    assert result[vsys.key]["value"] == "vsys1"


def test_zone_derivation_from_explicit_source_membership_is_not_target_backed():
    source = FGConfig(
        interfaces=[FGInterface(name="lan")],
        zones=[FGZone(name="USERS", members=["lan"], explicit_fields={"members"})],
    )
    zone_mapping = PANMigrationDecision(
        "root", "zone", "USERS", "target_zone",
        value="TRUST",
        review_state=PANDecisionReviewState.CONFIRMED,
        evidence_source="ENGINEER",
        evidence_type="TARGET_INTENT",
    )
    interface_zone = PANMigrationDecision("root", "interface", "lan", "target_zone")
    result = classify_auto_decisions(
        source,
        None,
        PANMigrationDecisionSet((zone_mapping, interface_zone)),
    )
    assert result[interface_zone.key]["status"] == "DERIVED"
    assert result[interface_zone.key]["value"] == "TRUST"
    assert result[interface_zone.key]["uses_target_evidence"] is False

# --- test_decision_propagation.py ---
def test_confirmed_parent_reports_direct_children_for_re_evaluation():
    config = FGConfig(interfaces=[FGInterface(name="agg1"), FGInterface(name="vlan120", interface="agg1", vlanid=120)])
    parent = PANMigrationDecision("root", "interface", "agg1", "target_interface", value="ae1",
                                  review_state=PANDecisionReviewState.CONFIRMED)
    child = PANMigrationDecision("root", "interface", "vlan120", "target_interface")
    assert dependent_decision_keys(config, PANMigrationDecisionSet((parent, child)))[parent.key] == [child.key]


def test_confirmed_vdom_and_interface_mapping_expose_only_same_vdom_dependents():
    config = FGConfig(interfaces=[FGInterface(name="agg1", type="aggregate"),
        FGInterface(name="vlan120", interface="agg1", vlanid=120, vdom="root"),
        FGInterface(name="vlan120", interface="agg1", vlanid=120, vdom="blue")])
    vdom = PANMigrationDecision("root", "vdom", "root", "vsys", value="vsys1",
                                review_state=PANDecisionReviewState.CONFIRMED)
    parent = PANMigrationDecision("root", "interface", "agg1", "target_interface", value="ae1",
                                  review_state=PANDecisionReviewState.CONFIRMED)
    child = PANMigrationDecision("root", "interface", "vlan120", "target_interface")
    other = PANMigrationDecision("blue", "interface", "vlan120", "target_interface")
    dependencies = dependent_decision_keys(config, PANMigrationDecisionSet((vdom, parent, child, other)))
    assert dependencies[vdom.key] == [child.key]
    assert other.key not in dependencies[parent.key]


def test_zone_apply_confirms_only_explicit_same_vdom_member_decisions():
    config = FGConfig(
        interfaces=[FGInterface(name="lan", vdom="root"), FGInterface(name="lan", vdom="blue")],
        zones=[FGZone(name="USERS", vdom="root", members=["lan"], explicit_fields={"members"}),
               FGZone(name="USERS", vdom="blue", members=["lan"], explicit_fields={"members"})],
    )
    zone = PANMigrationDecision("root", "zone", "USERS", "target_zone", value="TRUST",
                                review_state=PANDecisionReviewState.CONFIRMED)
    root_member = PANMigrationDecision("root", "interface", "lan", "target_zone")
    blue_member = PANMigrationDecision("blue", "interface", "lan", "target_zone")
    decisions = PANMigrationDecisionSet((zone, root_member, blue_member))
    assert zone_member_decision_keys(config, decisions, zone.key) == [root_member.key]
    updated = apply_zone_to_members(config, decisions, source_key=zone.key, value="TRUST", apply_to=[root_member.key])
    confirmed = next(item for item in updated.decisions if item.key == root_member.key)
    untouched = next(item for item in updated.decisions if item.key == blue_member.key)
    assert confirmed.review_state == PANDecisionReviewState.CONFIRMED and confirmed.value == "TRUST"
    assert confirmed.evidence_target_digest is None and confirmed.evidence_target_device is None
    assert untouched.review_state == PANDecisionReviewState.PENDING
    with pytest.raises(ValueError, match="not an unresolved explicit zone member"):
        apply_zone_to_members(config, decisions, source_key=zone.key, value="TRUST", apply_to=[blue_member.key])


def test_rule_impact_is_scoped_to_explicit_relationships_and_confirmed_sources():
    config = FGConfig(interfaces=[FGInterface(name="agg1", type="aggregate"),
        FGInterface(name="vlan120", type="vlan", interface="agg1", vlanid=120),
        FGInterface(name="other", type="ethernet")])
    parent = PANMigrationDecision("root", "interface", "agg1", "target_interface", value="ae1",
                                  review_state=PANDecisionReviewState.CONFIRMED)
    child = PANMigrationDecision("root", "interface", "vlan120", "target_interface")
    unrelated = PANMigrationDecision("root", "interface", "other", "target_interface", value="ethernet1/3",
                                     review_state=PANDecisionReviewState.CONFIRMED)
    decisions = PANMigrationDecisionSet((parent, child, unrelated))
    assert rule_affected_decision_keys(config, decisions, MigrationRuleType.PARENT_INTERFACE, parent.key) == [child.key]
    with pytest.raises(ValueError, match="explicit VLAN children"):
        rule_affected_decision_keys(config, decisions, MigrationRuleType.PARENT_INTERFACE, unrelated.key)


def test_repeated_engineer_pattern_is_only_a_suggestion_until_applied():
    names = ["lan1", "lan2", "lan3", "lan4", "lan5"]
    config = FGConfig(interfaces=[FGInterface(name=name) for name in names],
        zones=[FGZone(name="LAN", members=names, explicit_fields={"members"})])
    decisions = []
    for name in names[:3]:
        decisions.append(PANMigrationDecision("root", "interface", name, "target_zone", value="TRUST",
            review_state=PANDecisionReviewState.CONFIRMED, evidence_source="ENGINEER", evidence_type="MANUAL"))
    decisions.extend(PANMigrationDecision("root", "interface", name, "target_zone") for name in names[3:])
    decision_set = PANMigrationDecisionSet(tuple(decisions))
    suggestions = repeated_zone_action_suggestions(config, decision_set)
    assert len(suggestions) == 1 and suggestions[0]["affected"] == names[3:]
    assert all(item.review_state == PANDecisionReviewState.PENDING for item in decision_set.decisions[3:])
    updated = apply_repeated_zone_action(config, decision_set, source_vdom="root", source_zone="LAN",
        value="TRUST", apply_to=suggestions[0]["apply_to"])
    assert all(item.review_state == PANDecisionReviewState.CONFIRMED
               and item.evidence_type == "ENGINEER_REPEATED_ACTION_RULE"
               and item.evidence_target_digest is None
               and item.evidence_target_device is None
               for item in updated.decisions[3:])
    with pytest.raises(ValueError, match="explicit-member pattern"):
        apply_repeated_zone_action(config, decision_set, source_vdom="root", source_zone="LAN",
            value="TRUST", apply_to=['["root","interface","elsewhere","target_zone"]'])

# --- test_mapping_requirements.py ---
def test_requirements_are_scoped_to_consumers_and_mappings():
    config = FGConfig(
        interfaces=[FGInterface(name=name, vdom=vdom) for vdom in ("root", "blue") for name in ("wan", "spare")],
        policies=[FGPolicy(vdom="root", srcintf=["wan"], dstintf=["dmz"])],
        zones=[FGZone(vdom="root", name="dmz", members=["wan"]), FGZone(vdom="blue", name="unused", members=["spare"])],
        static_routes=[FGStaticRoute(vdom="blue", device="wan")],
    )
    result = build_mapping_requirements(config, object())
    required = {(item["source_vdom"], item["source_name"]): item for item in result["interfaces"]}

    assert set(required) == {("root", "wan"), ("root", "dmz"), ("blue", "wan")}
    assert required[("root", "dmz")]["kind"] == "zone"
    assert "target_interface" in required[("root", "wan")]["requires"]
    assert ("blue", "unused") not in required


def test_same_interface_name_keeps_separate_vdom_requirements():
    config = FGConfig(policies=[
        FGPolicy(vdom="root", srcintf=["port1"]),
        FGPolicy(vdom="blue", srcintf=["port1"]),
    ])
    result = build_mapping_requirements(config, object())
    assert {(item["source_vdom"], item["source_name"]) for item in result["interfaces"]} == {
        ("root", "port1"), ("blue", "port1")
    }


def test_policy_interface_references_count_unique_affected_policies():
    config = FGConfig(policies=[
        FGPolicy(policy_id=1, srcintf=["port1"], dstintf=["port1"]),
        FGPolicy(policy_id=2, srcintf=["port1"]),
    ])
    item = build_mapping_requirements(config, object())["interfaces"][0]
    assert item["affected_count"] == 2
    assert item["affected_by"] == {"security_policy": 2}
    assert item["reference_count"] == 2


def test_same_interface_name_impact_stays_scoped_to_each_vdom():
    config = FGConfig(policies=[
        FGPolicy(policy_id=1, vdom="root", srcintf=["port1"]),
        FGPolicy(policy_id=1, vdom="blue", srcintf=["port1"]),
    ])
    items = {(item["source_vdom"], item["source_name"]): item for item in build_mapping_requirements(config, object())["interfaces"]}
    assert items[("root", "port1")]["affected_by"] == {"security_policy": 1}
    assert items[("blue", "port1")]["affected_by"] == {"security_policy": 1}


def test_same_name_interface_and_zone_keep_compatible_decision_fields():
    config = FGConfig(
        policies=[FGPolicy(vdom="root", srcintf=["port1"])],
        zones=[FGZone(vdom="root", name="port1", members=["member1"])],
        static_routes=[FGStaticRoute(vdom="root", device="port1")],
    )
    requirements = build_mapping_requirements(config, object())
    items = requirements["interfaces"]
    same_name = {(item["kind"], tuple(item["requires"])) for item in items if item["source_name"] == "port1"}

    assert same_name == {
        ("zone", ("target_zone",)),
        ("interface", ("target_interface",)),
    }
    decisions = build_decision_set(config, object(), requirements)
    assert all(not (item.source_kind == "zone" and item.target_field == "target_interface") for item in decisions.decisions)


def test_dhcp_is_executable_consumer_while_other_guidance_remains_nonblocking():
    config = FGConfig(
        interfaces=[FGInterface(name=name, vdom="blue") for name in ("dhcp0", "wan0", "dmz0", "client0")],
        dhcp_servers=[FGDHCPServer(id=7, vdom="blue", interface="dhcp0")],
        ipsec_phase1=[FGIPsecPhase1(name="ike-a", vdom="blue", interface="wan0")],
        sdwans=[FGSDWAN(vdom="blue", members=[FGSDWANMember(seq_num=10, interface="wan0")])],
        ssl_vpn_settings=[FGSSLVPNSettings(vdom="blue", source_interface=["wan0"], authentication_rules=[
            FGSSLVPNAuthenticationRule(id=4, source_interface=["dmz0"]),
        ])],
        ssl_vpn_clients=[FGSSLVPNClient(name="client-a", vdom="blue", interface="client0")],
    )
    result = build_mapping_requirements(config, object())
    required = {(item["source_vdom"], item["source_name"], item["kind"]): item
                for item in result["interfaces"]}

    assert set(required) == {("blue", "dhcp0", "interface")}
    assert required[("blue", "dhcp0", "interface")]["requires"] == ["target_interface"]
    assert required[("blue", "dhcp0", "interface")]["affected_by"] == {"dhcp_server": 1}
    assert result["vdoms"] == [{"source_vdom": "blue", "requires": ["vsys", "virtual_router"]}]

def test_address_only_requires_vsys_but_not_virtual_router():
    config = FGConfig(addresses=[
        FGAddress(name="host", vdom="blue", subnet="10.0.0.1 255.255.255.255"),
    ])
    result = build_mapping_requirements(config, object())

    assert result["vdoms"] == [{"source_vdom": "blue", "requires": ["vsys"]}]


def test_static_route_requires_interface_ownership_and_mapping():
    config = FGConfig(
        interfaces=[FGInterface(name="wan", vdom="blue")],
        static_routes=[FGStaticRoute(vdom="blue", seq_num=1, device="wan")],
    )
    result = build_mapping_requirements(config, object())
    required = {(item["source_vdom"], item["source_name"], item["kind"]): item
                for item in result["interfaces"]}

    assert result["vdoms"] == [{"source_vdom": "blue", "requires": ["virtual_router", "vsys"]}]
    assert required[("blue", "wan", "interface")]["requires"] == ["target_interface"]


def test_direct_policy_interface_requires_zone_not_target_interface():
    config = FGConfig(
        interfaces=[FGInterface(name="lan", vdom="root")],
        policies=[FGPolicy(policy_id=1, vdom="root", srcintf=["lan"])],
    )
    result = build_mapping_requirements(config, object())
    item = next(entry for entry in result["interfaces"] if entry["source_name"] == "lan")

    assert item["requires"] == ["target_zone"]
    assert result["vdoms"] == [{"source_vdom": "root", "requires": ["vsys"]}]
