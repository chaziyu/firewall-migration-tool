from types import SimpleNamespace

from fwmigrate.conversion.fortigate_to_palo_alto import (
    PANAutomationMode,
    PANMigrationOptions,
    run_migration_pipeline,
)
from fwmigrate.vendors.fortigate.model.address import FGAddress, FGWildcardFQDN
from fwmigrate.vendors.fortigate.model.dhcp import FGDHCPIPRange, FGDHCPServer
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
        "set system setting target-vsys vsys1",
        "set address host-a ip-netmask 192.0.2.10/32",
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
    assert any("set address host-a" in command for command in result.rendered.commands)
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
