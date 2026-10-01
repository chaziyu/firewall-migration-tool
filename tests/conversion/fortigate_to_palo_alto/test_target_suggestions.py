from types import SimpleNamespace

from fwmigrate.conversion.fortigate_to_palo_alto import (
    PANDecisionReviewState, PANMigrationDecision, PANMigrationDecisionSet,
)
from fwmigrate.conversion.fortigate_to_palo_alto.target_suggestions import (
    discover_target_candidates, suggest_from_target, target_device_metadata, target_devices,
)
from fwmigrate.conversion.fortigate_to_palo_alto.interface_candidates import candidate_evidence
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.palo_alto.relationships.topology import PANInterfaceTopologyEntry
from fwmigrate.vendors.palo_alto.source_model import PANScope, pan_scope_identity
from fwmigrate.conversion.fortigate_to_palo_alto.target_suggestions import _compatible


def test_reservations_release_and_competing_strong_suggestions_stay_pending():
    scope = PANScope(kind="device", name="dev", device_name="dev")
    record = SimpleNamespace(name="ethernet1/1", interface_family="ethernet", ipv4_addresses=["192.0.2.1/24"],
                             scope=scope, tag=None, parent=None, comment=None)
    target = SimpleNamespace(config=SimpleNamespace(interfaces=[record], interface_units=[], zones=[]),
        derived=SimpleNamespace(interface_topology=[PANInterfaceTopologyEntry(record.name, pan_scope_identity(scope))]))
    source = FGConfig(interfaces=[FGInterface(name=name, type="physical", ip="192.0.2.1/24") for name in ("port1", "port2")])
    pending = PANMigrationDecisionSet(tuple(PANMigrationDecision("root", "interface", name, "target_interface") for name in ("port1", "port2")))
    reserved = PANMigrationDecisionSet((pending.decisions[0].confirm("ethernet1/1"), pending.decisions[1]))
    candidates = discover_target_candidates(source, reserved, target, "dev")
    assert candidates[pending.decisions[0].key][0]["available"]
    unavailable = candidates[pending.decisions[1].key][0]
    assert not unavailable["available"] and unavailable["assigned_to"] == [{"source_vdom": "root", "source_name": "port1"}]
    updated, _ = suggest_from_target(source, reserved, target, "dev")
    assert updated.decisions[1].suggested_value is None
    candidates = discover_target_candidates(source, pending, target, "dev")
    assert all(options[0]["available"] and options[0]["contested"] for options in candidates.values())
    updated, warnings = suggest_from_target(source, pending, target, "dev")
    assert len(warnings) == 2
    assert all(item.value is None and item.review_state == PANDecisionReviewState.PENDING for item in updated.decisions)
    from fwmigrate.conversion.fortigate_to_palo_alto.auto_decisions import classify_auto_decisions
    auto = classify_auto_decisions(source, None, pending, target, "dev")
    assert all(auto[item.key]["status"] == "CONFLICT" for item in pending.decisions)


def test_explicit_physical_interfaces_do_not_match_target_units():
    source = SimpleNamespace(type="physical", vlanid=None, ip=None, name="port1")
    target = SimpleNamespace(interface_family="ethernet", tag="201", parent="ethernet1/1", ipv4_addresses=[])
    assert not _compatible(source, target)
    assert candidate_evidence(source, target)[2]


def test_redundant_source_interface_is_not_assumed_to_be_aggregate():
    source = SimpleNamespace(type="redundant", vlanid=None)
    target = SimpleNamespace(interface_family="aggregate-ethernet", tag=None)
    assert _compatible(source, target) is False


def test_tunnel_source_only_receives_tunnel_candidates():
    assert _compatible(SimpleNamespace(type="tunnel", vlanid=None),
                       SimpleNamespace(interface_family="ethernet")) is False
    assert _compatible(SimpleNamespace(type="tunnel", vlanid=None),
                       SimpleNamespace(interface_family="tunnel")) is True


def test_tunnel_candidates_exclude_physical_and_remain_competing_without_topology_evidence():
    scope = PANScope(kind="device", name="dev", device_name="dev")
    identity = pan_scope_identity(scope)
    source = FGConfig(interfaces=[FGInterface(name="AWS-MYRegion", type="tunnel")])
    physical = SimpleNamespace(name="ethernet1/1", interface_family="ethernet", scope=scope, tag=None,
                               ipv4_addresses=[], parent=None, comment=None)
    tunnels = [SimpleNamespace(name=name, interface_family="tunnel", scope=scope, tag=None,
                               ipv4_addresses=[], parent=None, comment=None)
               for name in ("tunnel.11", "tunnel.12")]
    target = SimpleNamespace(config=SimpleNamespace(interfaces=[physical, *tunnels], interface_units=[], zones=[]),
        derived=SimpleNamespace(interface_topology=[PANInterfaceTopologyEntry(item.name, identity)
            for item in (physical, *tunnels)]))
    decision = PANMigrationDecision("root", "interface", "AWS-MYRegion", "target_interface")
    candidates = discover_target_candidates(source, PANMigrationDecisionSet((decision,)), target, "dev")[decision.key]
    assert {item["value"] for item in candidates} == {"tunnel.11", "tunnel.12"}


def test_same_subnet_vlan_and_mapped_parent_is_a_unique_candidate():
    scope = PANScope(kind="device", name="dev", device_name="dev")
    identity = pan_scope_identity(scope)
    source = FGConfig(interfaces=[
        FGInterface(name="port1", ip="192.0.2.1/24"),
        FGInterface(name="vlan100", type="vlan", interface="port1", vlanid=100, ip="10.0.0.1/24"),
    ])
    target_parent = SimpleNamespace(name="ethernet1/1", interface_family="ethernet", ipv4_addresses=["192.0.2.1/24"], scope=scope, tag=None, parent=None)
    target_child = SimpleNamespace(name="ethernet1/1.100", interface_family="vlan", ipv4_addresses=["10.0.0.2/24"], scope=scope, tag="100", parent="ethernet1/1")
    target = SimpleNamespace(
        config=SimpleNamespace(interfaces=[target_parent], interface_units=[target_child], zones=[]),
        derived=SimpleNamespace(interface_topology=[
            PANInterfaceTopologyEntry("ethernet1/1", identity),
            PANInterfaceTopologyEntry("ethernet1/1.100", identity, parent="ethernet1/1"),
        ]),
    )
    decisions = PANMigrationDecisionSet((
        PANMigrationDecision("root", "interface", "port1", "target_interface", value="ethernet1/1",
                             review_state=PANDecisionReviewState.CONFIRMED),
        PANMigrationDecision("root", "interface", "vlan100", "target_interface"),
    ))
    updated, _ = suggest_from_target(source, decisions, target, "dev")
    values = {item.source_name: item.value or item.suggested_value for item in updated.decisions}
    assert values["port1"] == "ethernet1/1"
    assert values["vlan100"] == "ethernet1/1.100"


def test_unconfirmed_parent_does_not_unlock_vlan_child_suggestion():
    scope = PANScope(kind="device", name="dev", device_name="dev")
    identity = pan_scope_identity(scope)
    source = FGConfig(interfaces=[
        FGInterface(name="port1", ip="192.0.2.1/24"),
        FGInterface(name="vlan100", type="vlan", interface="port1", vlanid=100, ip="10.0.0.1/24"),
    ])
    parent = SimpleNamespace(name="ethernet1/1", interface_family="ethernet", ipv4_addresses=["192.0.2.1/24"], scope=scope, tag=None, parent=None)
    child = SimpleNamespace(name="ethernet1/1.100", interface_family="vlan", ipv4_addresses=["10.0.0.2/24"], scope=scope, tag="100", parent="ethernet1/1")
    target = SimpleNamespace(config=SimpleNamespace(interfaces=[parent], interface_units=[child], zones=[]),
        derived=SimpleNamespace(interface_topology=[PANInterfaceTopologyEntry("ethernet1/1", identity),
                                                     PANInterfaceTopologyEntry("ethernet1/1.100", identity, parent="ethernet1/1")]))
    decisions = PANMigrationDecisionSet(tuple(PANMigrationDecision("root", "interface", name, "target_interface") for name in ("port1", "vlan100")))
    updated, _ = suggest_from_target(source, decisions, target, "dev")
    assert {item.source_name: item.suggested_value for item in updated.decisions}["vlan100"] is None


def test_same_vlan_under_multiple_unmapped_parents_stays_required():
    scope = PANScope(kind="device", name="dev", device_name="dev")
    identity = pan_scope_identity(scope)
    source = FGConfig(interfaces=[
        FGInterface(name="port1"),
        FGInterface(name="vlan100", type="vlan", interface="port1", vlanid=100),
    ])
    children = [SimpleNamespace(name=f"ae{index}.100", interface_family="vlan", ipv4_addresses=[],
                                scope=scope, tag="100", parent=f"ae{index}") for index in (1, 2)]
    target = SimpleNamespace(config=SimpleNamespace(interfaces=[], interface_units=children, zones=[]),
        derived=SimpleNamespace(interface_topology=[PANInterfaceTopologyEntry(
            item.name, identity, parent=item.parent) for item in children]))
    decisions = PANMigrationDecisionSet(tuple(PANMigrationDecision("root", "interface", name, "target_interface")
                                               for name in ("port1", "vlan100")))
    updated, _ = suggest_from_target(source, decisions, target, "dev")
    assert {item.source_name: item.suggested_value for item in updated.decisions}["vlan100"] is None


def test_candidate_discovery_returns_strong_and_possible_evidence_without_suggesting_possible():
    scope = PANScope(kind="device", name="dev", device_name="dev")
    identity = pan_scope_identity(scope)
    source = FGConfig(interfaces=[FGInterface(name="finance", alias="Finance LAN", role="lan")])
    strong = SimpleNamespace(name="ethernet1/1", interface_family="ethernet", ipv4_addresses=["10.0.0.1/24"], scope=scope, tag=None, parent=None, comment=None)
    possible = SimpleNamespace(name="ethernet1/2", interface_family="ethernet", ipv4_addresses=[], scope=scope, tag=None, parent=None, comment="Finance LAN")
    target = SimpleNamespace(config=SimpleNamespace(interfaces=[strong, possible], interface_units=[], zones=[]),
        derived=SimpleNamespace(interface_topology=[PANInterfaceTopologyEntry("ethernet1/1", identity), PANInterfaceTopologyEntry("ethernet1/2", identity)]))
    decision = PANMigrationDecision("root", "interface", "finance", "target_interface")
    candidates = discover_target_candidates(source, PANMigrationDecisionSet((decision,)), target, "dev")[decision.key]
    assert [item["class"] for item in candidates] == ["POSSIBLE", "POSSIBLE"]
    alias_candidate = next(item for item in candidates if item["value"] == "ethernet1/2")
    assert "source alias/comment matches target name/comment" in alias_candidate["supporting_evidence"]
    assert candidate_evidence(FGInterface(name="vlan100", type="vlan", vlanid=100),
                             SimpleNamespace(interface_family="vlan", tag="200"))[2] == ("VLAN mismatch",)


def test_confirmed_interface_unlocks_pending_zone_suggestion():
    scope = PANScope(kind="device", name="dev", device_name="dev")
    identity = pan_scope_identity(scope)
    source = SimpleNamespace(interfaces=[FGInterface(name="finance")], zones=[])
    target_interface = SimpleNamespace(name="ethernet1/7", interface_family="ethernet", ipv4_addresses=[],
                                        scope=scope, tag=None, parent=None)
    target = SimpleNamespace(config=SimpleNamespace(interfaces=[target_interface], interface_units=[], zones=[]),
        derived=SimpleNamespace(interface_topology=[PANInterfaceTopologyEntry(
            "ethernet1/7", identity, imported_vsys=("vsys1",), zones=("FINANCE",), virtual_routers=("vr-main",))]))
    pending = PANMigrationDecisionSet((
        PANMigrationDecision("root", "interface", "finance", "target_interface"),
        PANMigrationDecision("root", "interface", "finance", "target_zone"),
    ))
    first, _ = suggest_from_target(source, pending, target, "dev")
    assert all(item.suggested_value is None for item in first.decisions)
    confirmed = PANMigrationDecisionSet(tuple(
        item if item.target_field == "target_zone" else PANMigrationDecision(
            item.source_vdom, item.source_kind, item.source_name, item.target_field,
            value="ethernet1/7", review_state=PANDecisionReviewState.CONFIRMED)
        for item in first.decisions
    ))
    refreshed, _ = suggest_from_target(source, confirmed, target, "dev")
    zone = next(item for item in refreshed.decisions if item.target_field == "target_zone")
    assert zone.suggested_value == "FINANCE"
    assert zone.review_state == PANDecisionReviewState.PENDING


def test_equally_valid_target_candidates_stay_pending_with_warning():
    scope = PANScope(kind="device", name="dev", device_name="dev")
    identity = pan_scope_identity(scope)
    source = FGConfig(interfaces=[FGInterface(name="lan", ip="10.0.0.1/24")])
    target_items = [SimpleNamespace(name=name, interface_family="ethernet", ipv4_addresses=["10.0.0.1/24"], scope=scope, tag=None, parent=None) for name in ("ethernet1/1", "ethernet1/2")]
    target = SimpleNamespace(
        config=SimpleNamespace(interfaces=target_items, interface_units=[], zones=[]),
        derived=SimpleNamespace(interface_topology=[PANInterfaceTopologyEntry(item.name, identity) for item in target_items]),
    )
    decision = PANMigrationDecision("root", "interface", "lan", "target_interface")
    updated, warnings = suggest_from_target(source, PANMigrationDecisionSet((decision,)), target, "dev")
    assert updated.decisions[0].suggested_value is None
    assert decision.key in warnings


def test_confirmed_vsys_limits_interface_candidates_to_imported_vsys():
    scope = PANScope(kind="device", name="dev", device_name="dev")
    identity = pan_scope_identity(scope)
    source = FGConfig(interfaces=[FGInterface(name="lan", ip="10.0.0.1/24")])
    target_items = [
        SimpleNamespace(name=name, interface_family="ethernet", ipv4_addresses=["10.0.0.1/24"],
                        scope=scope, tag=None, parent=None)
        for name in ("ethernet1/1", "ethernet1/2")
    ]
    target = SimpleNamespace(
        config=SimpleNamespace(interfaces=target_items, interface_units=[], zones=[]),
        derived=SimpleNamespace(interface_topology=[
            PANInterfaceTopologyEntry("ethernet1/1", identity, imported_vsys=("vsys1",)),
            PANInterfaceTopologyEntry("ethernet1/2", identity, imported_vsys=("vsys2",)),
        ]),
    )
    vsys = PANMigrationDecision("root", "vdom", "root", "vsys", value="vsys2",
                                review_state=PANDecisionReviewState.CONFIRMED)
    interface = PANMigrationDecision("root", "interface", "lan", "target_interface")
    updated, _ = suggest_from_target(source, PANMigrationDecisionSet((vsys, interface)), target, "dev")
    assert updated.decisions[1].suggested_value == "ethernet1/2"


def test_target_device_metadata_keeps_multiple_devices_separate():
    first = PANScope(kind="device", name="first", device_name="branch-01", vsys="vsys1")
    second = PANScope(kind="device", name="second", device_name="branch-02", vsys="vsys1")
    target = SimpleNamespace(config=SimpleNamespace(
        interfaces=[
            SimpleNamespace(name="ethernet1/1", scope=first),
            SimpleNamespace(name="ethernet1/1", scope=second),
        ],
        interface_units=[],
        zones=[],
    ))
    assert target_devices(target) == ["branch-01", "branch-02"]
    metadata = target_device_metadata(target)
    assert [(item["id"], item["interfaces"], item["vsys"]) for item in metadata] == [
        ("branch-01", 1, 1), ("branch-02", 1, 1),
    ]


def test_target_devices_returns_empty_without_device_scoped_interfaces():
    target = SimpleNamespace(config=SimpleNamespace(interfaces=[], interface_units=[], zones=[]))
    assert target_devices(target) == []


def test_target_device_can_be_selected_from_explicit_scope_and_virtual_router():
    scope = PANScope(kind="vsys", name="vsys2", device_name="branch-02", vsys="vsys2")
    target = SimpleNamespace(config=SimpleNamespace(interfaces=[], interface_units=[], zones=[], scopes=[scope],
        virtual_routers=[SimpleNamespace(name="vr2", scope=scope)]))
    assert target_devices(target) == ["branch-02"]


def test_scope_and_zone_candidates_keep_target_scope_and_confirmed_vsys():
    from fwmigrate.conversion.fortigate_to_palo_alto.target_suggestions import discover_target_candidates

    scopes = [PANScope(kind="vsys", name=f"{name}-scope", device_name="dev", vsys=name)
              for name in ("vsys1", "vsys2")]
    source = FGConfig()
    decisions = PANMigrationDecisionSet((
        PANMigrationDecision("root", "vdom", "root", "vsys", value="vsys2",
                             review_state=PANDecisionReviewState.CONFIRMED),
        PANMigrationDecision("root", "vdom", "root", "virtual_router"),
        PANMigrationDecision("root", "zone", "inside", "target_zone"),
    ))
    routers = [SimpleNamespace(name=f"vr-{index + 1}", scope=scope) for index, scope in enumerate(scopes)]
    zones = [SimpleNamespace(name="inside", scope=scope) for scope in scopes]
    target = SimpleNamespace(config=SimpleNamespace(scopes=scopes, interfaces=[], interface_units=[],
        zones=zones, virtual_routers=routers), derived=SimpleNamespace(interface_topology=[]))
    candidates = discover_target_candidates(source, decisions, target, "dev")
    router_key = PANMigrationDecision("root", "vdom", "root", "virtual_router").key
    zone_key = PANMigrationDecision("root", "zone", "inside", "target_zone").key
    assert [item["value"] for item in candidates[router_key]] == ["vr-2"]
    assert [item["value"] for item in candidates[zone_key]] == ["inside"]
    assert candidates[zone_key][0]["target_scope"] == pan_scope_identity(scopes[1])
