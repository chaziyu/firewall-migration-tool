from types import SimpleNamespace

from fwmigrate.conversion.fortigate_to_palo_alto import (
    PANAutomationMode,
    PANMigrationOptions,
    run_migration_pipeline,
)
from fwmigrate.vendors.fortigate.model.address import FGAddress
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.route_static import FGStaticRoute
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.palo_alto.relationships.topology import PANInterfaceTopologyEntry
from fwmigrate.vendors.palo_alto.source_model import PANScope, pan_scope_identity


def _empty_derived():
    return SimpleNamespace()


def _target_interface(name, ip, *, virtual_router="vr-main"):
    scope = PANScope(kind="device", name="dev", device_name="dev")
    interface = SimpleNamespace(
        name=name,
        scope=scope,
        interface_family="ethernet",
        ipv4_addresses=[ip],
        tag=None,
        parent=None,
    )
    topology = PANInterfaceTopologyEntry(
        name,
        pan_scope_identity(scope),
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
        "set system setting target-vsys vsys1",
        "set address host-a ip-netmask 192.0.2.10/32",
    )
    assert result.rendered.report["plan_status"] == "READY"


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
    assert all(item.evidence_source == "DERIVED" for item in by_identity.values())
    assert any("virtual-router vr-main" in command for command in result.rendered.commands)
    assert any("interface ethernet1/1" in command for command in result.rendered.commands)
    assert result.rendered.report["automation"]["applied"] == 2
