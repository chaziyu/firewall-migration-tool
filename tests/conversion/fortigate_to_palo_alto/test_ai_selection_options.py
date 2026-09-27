from types import SimpleNamespace

from fwmigrate.conversion.fortigate_to_palo_alto.ai_selection_options import build_ai_selection_options
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import PANMigrationDecision, PANMigrationDecisionSet
from fwmigrate.vendors.palo_alto.source_model import PANScope, pan_scope_identity


def _target():
    vsys1 = PANScope(kind="vsys", name="vsys1", device_name="fw1", vsys="vsys1")
    vsys2 = PANScope(kind="vsys", name="vsys2", device_name="fw1", vsys="vsys2")
    return SimpleNamespace(config=SimpleNamespace(
        scopes=[vsys1, vsys2],
        virtual_routers=[SimpleNamespace(name="default", scope=vsys1)],
        zones=[SimpleNamespace(name="trust", scope=vsys1), SimpleNamespace(name="trust", scope=vsys2)],
        interfaces=[SimpleNamespace(name="tunnel.1", interface_family="tunnel", scope=vsys1),
                    SimpleNamespace(name="ethernet1/1", interface_family="ethernet", scope=vsys1)],
        interface_units=[]))


def _decisions(*items):
    return PANMigrationDecisionSet(tuple(PANMigrationDecision(*item) for item in items))


def test_selection_options_cover_explicit_pan_objects_and_source_compatible_interfaces():
    decisions = _decisions(
        ("root", "vdom", "root", "vsys"),
        ("root", "vdom", "root", "virtual_router"),
        ("root", "zone", "dmz", "target_zone"),
        ("root", "interface", "vpn1", "target_interface"),
        ("root", "interface", "lan1", "target_interface"),
    )
    options = build_ai_selection_options(None, None, decisions, _target(), "fw1", {
        ("root", "vpn1"): {"source_explicit": {"type": "tunnel"}},
        ("root", "lan1"): {"source_explicit": {"type": "physical"}},
    })
    assert [item["value"] for item in options[decisions.decisions[0].key]] == ["vsys1", "vsys2"]
    assert [item["value"] for item in options[decisions.decisions[1].key]] == ["default"]
    # Multiple explicit VSYSs leave zone/interface scope unresolved.
    assert decisions.decisions[2].key not in options
    assert decisions.decisions[3].key not in options


def test_selected_vsys_limits_options_and_duplicate_names_in_distinct_scopes_are_removed():
    decisions = _decisions(
        ("root", "vdom", "root", "vsys", None, "vsys1"),
        ("root", "zone", "dmz", "target_zone"),
        ("root", "interface", "vpn1", "target_interface"),
    )
    target = _target()
    duplicate = SimpleNamespace(name="ethernet1/1", interface_family="ethernet",
        scope=PANScope(kind="device", name="device1", device_name="fw1", vsys="vsys1"))
    target.config.interfaces.append(duplicate)
    options = build_ai_selection_options(None, None, decisions, target, "fw1", {
        ("root", "vpn1"): {"source_explicit": {"type": "tunnel"}},
    })
    assert [item["value"] for item in options[decisions.decisions[1].key]] == ["trust"]
    assert [item["value"] for item in options[decisions.decisions[2].key]] == ["tunnel.1"]


def test_missing_target_or_device_yields_no_ai_options():
    decisions = _decisions(("root", "zone", "dmz", "target_zone"))
    assert not build_ai_selection_options(None, None, decisions, None, None, {})


def test_device_scoped_interface_uses_derived_vsys_import_and_source_type():
    decisions = _decisions(
        ("root", "vdom", "root", "vsys", None, "vsys1"),
        ("root", "interface", "vpn1", "target_interface"),
    )
    target = _target()
    scope = PANScope(kind="device", name="dev", device_name="fw1")
    target.config.interfaces = [SimpleNamespace(name="tunnel.7", interface_family="tunnel", scope=scope)]
    target.derived = SimpleNamespace(interface_topology=[SimpleNamespace(
        scope=pan_scope_identity(scope), interface="tunnel.7", imported_vsys=("vsys1",))])
    options = build_ai_selection_options(None, None, decisions, target, "fw1", {
        ("root", "vpn1"): {"source_explicit": {"type": "tunnel"}}})
    assert [item["value"] for item in options[decisions.decisions[1].key]] == ["tunnel.7"]
    assert decisions.decisions[1].key not in build_ai_selection_options(None, None, decisions, target, "fw1", {
        ("root", "vpn1"): {"source_explicit": {}}})


def test_vlan_options_follow_proposed_parent_and_explicit_tag():
    decisions = _decisions(
        ("root", "vdom", "root", "vsys", None, "vsys1"),
        ("root", "interface", "agg1", "target_interface", None, "ae1"),
        ("root", "interface", "users20", "target_interface"),
    )
    target = _target()
    scope = PANScope(kind="device", name="dev", device_name="fw1")
    target.config.interfaces = []
    target.config.interface_units = [SimpleNamespace(name=name, interface_family="ethernet",
        scope=scope, tag="20", parent=parent) for name, parent in (
        ("ethernet1/1.20", "ae1"), ("ethernet1/2.20", "ae2"))]
    target.derived = SimpleNamespace(interface_topology=[SimpleNamespace(
        scope=pan_scope_identity(scope), interface=item.name, imported_vsys=("vsys1",))
        for item in target.config.interface_units])
    options = build_ai_selection_options(None, None, decisions, target, "fw1", {
        ("root", "users20"): {"source_explicit": {
            "type": "vlan", "vlanid": 20, "interface": "agg1"}}})
    assert [item["value"] for item in options[decisions.decisions[2].key]] == ["ethernet1/1.20"]

