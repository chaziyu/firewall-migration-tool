from copy import deepcopy
from types import SimpleNamespace

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto.dhcp import plan_dhcp
from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan,
    PANMigrationStatus,
    PlannedDHCPServer,
)
from fwmigrate.conversion.fortigate_to_palo_alto.options import PANMigrationOptions
from fwmigrate.conversion.fortigate_to_palo_alto.target_object_reuse import (
    _dhcp,
    classify_target_object_reuse,
)
from fwmigrate.vendors.fortigate.model.dhcp import (
    FGDHCPExcludeRange,
    FGDHCPIPRange,
    FGDHCPReservedAddress,
    FGDHCPServer,
)
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.palo_alto.model.dhcp import PANDHCPIPPool, PANDHCPReservation, PANDHCPServer
from fwmigrate.vendors.palo_alto.source_model import PANScope


def _options():
    return PANMigrationOptions(
        vdoms={"root": {"vsys": "vsys1", "virtual_router": "vr-main"}},
        interfaces={"root": {"lan": {"target_interface": "ethernet1/3"}}},
    )


def _server(**changes):
    values = dict(
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
    )
    values.update(changes)
    return FGDHCPServer(**values)


def test_supported_dhcp_plan_uses_only_explicit_source_and_keeps_source_immutable():
    source = FGConfig(dhcp_servers=[_server()])
    before = deepcopy(source.model_dump())

    planned, = plan_dhcp(source, _options())

    assert planned.status is PANMigrationStatus.SUPPORTED
    assert planned.source_name == "1"
    assert planned.target_vsys == "vsys1"
    assert planned.target_name == planned.interface == "ethernet1/3"
    assert planned.mode == "enabled"
    assert planned.lease_type == "timeout"
    assert planned.lease_timeout == 3600
    assert planned.gateway == "10.0.0.1"
    assert planned.subnet_mask == "255.255.255.0"
    assert planned.dns_primary == "10.0.0.2"
    assert planned.dns_secondary == "10.0.0.3"
    assert planned.ip_pools == ("10.0.0.10-10.0.0.50",)
    assert source.model_dump() == before


def test_explicit_zero_lease_becomes_unlimited_and_disabled_state_is_preserved():
    planned, = plan_dhcp(
        FGConfig(dhcp_servers=[_server(status="disable", lease_time=0)]),
        _options(),
    )
    assert planned.status is PANMigrationStatus.SUPPORTED
    assert planned.mode == "disabled"
    assert planned.lease_type == "unlimited"
    assert planned.lease_timeout is None


@pytest.mark.parametrize(
    ("changes", "warning"),
    (
        ({"status": None}, "status is not explicitly configured"),
        ({"server_type": None}, "server-type is not explicit"),
        ({"server_type": "ipsec"}, "requires manual target design"),
        ({"ip_mode": None}, "ip-mode is not explicit"),
        ({"ip_mode": "usrgrp"}, "is not rendered"),
        ({"lease_time": 1_000_001}, "outside the supported PAN-OS timeout range"),
        ({"dns_service": "local"}, "requires manual target design"),
        ({"dns_server3": "10.0.0.4"}, "at most two explicit DNS servers"),
        ({"ip_ranges": [FGDHCPIPRange(start_ip="10.0.0.50", end_ip="10.0.0.10")]}, "incomplete or invalid"),
        ({"exclude_ranges": [FGDHCPExcludeRange(start_ip="10.0.0.20", end_ip="10.0.0.25")]}, "exclude-range semantics"),
        ({"reserved_addresses": [FGDHCPReservedAddress(ip="10.0.0.11", mac="00:11:22:33:44:55")]}, "reservation semantics"),
        ({"relay_agent": "192.0.2.1"}, "relay-agent semantics"),
    ),
)
def test_unsupported_dhcp_semantics_fail_closed(changes, warning):
    planned, = plan_dhcp(FGConfig(dhcp_servers=[_server(**changes)]), _options())
    assert planned.status is PANMigrationStatus.MANUAL_REVIEW
    assert any(warning in item for item in planned.warnings)


def test_preserved_unknown_source_blocks_without_exposing_values():
    planned, = plan_dhcp(
        FGConfig(dhcp_servers=[_server(raw_extra={"ddns-key": "do-not-export"})]),
        _options(),
    )
    assert planned.status is PANMigrationStatus.MANUAL_REVIEW
    assert any("preserved unsupported source semantics" in item for item in planned.warnings)
    assert "do-not-export" not in " ".join(planned.warnings)


def _target_dhcp(*, gateway="10.0.0.1", reservations=None):
    scope = PANScope(kind="device", name="dev", device_name="dev")
    explicit = {
        "interface", "mode", "lease_type", "lease_timeout", "gateway",
        "subnet_mask", "dns_primary", "dns_secondary", "ip_pools",
    }
    if reservations is not None:
        explicit.add("reservations")
    return PANDHCPServer(
        name="ethernet1/3",
        interface="ethernet1/3",
        source_path="/network/dhcp/interface/ethernet1/3",
        scope=scope,
        mode="enabled",
        lease_type="timeout",
        lease_timeout="3600",
        gateway=gateway,
        subnet_mask="255.255.255.0",
        dns_primary="10.0.0.2",
        dns_secondary="10.0.0.3",
        ip_pools=[PANDHCPIPPool(value="10.0.0.10-10.0.0.50", explicit_fields={"value"})],
        reservations=reservations,
        explicit_fields=explicit,
    )


def _planned_dhcp():
    return PlannedDHCPServer(
        source_vdom="root",
        source_kind="dhcp_server",
        source_object_type="dhcp_server",
        source_name="1",
        target_vsys="vsys1",
        target_name="ethernet1/3",
        interface="ethernet1/3",
        status=PANMigrationStatus.SUPPORTED,
        mode="enabled",
        lease_type="timeout",
        lease_timeout=3600,
        gateway="10.0.0.1",
        subnet_mask="255.255.255.0",
        dns_primary="10.0.0.2",
        dns_secondary="10.0.0.3",
        ip_pools=("10.0.0.10-10.0.0.50",),
    )


def test_dhcp_target_reuse_requires_exact_explicit_semantics():
    planned = _planned_dhcp()
    target_server = _target_dhcp()
    strong, supporting, contradictions = _dhcp(planned, target_server)
    assert strong
    assert not supporting
    assert not contradictions

    target = SimpleNamespace(config=SimpleNamespace(dhcp_servers=[target_server]))
    result = classify_target_object_reuse(PANMigrationPlan(dhcp_servers=(planned,)), target, "dev")
    assert result[0]["status"] == "EXACT_MATCH"

    target_server.gateway = "10.0.0.254"
    conflict = classify_target_object_reuse(PANMigrationPlan(dhcp_servers=(planned,)), target, "dev")
    assert conflict[0]["status"] == "NAME_CONFLICT"


def test_dhcp_target_with_additional_explicit_semantics_is_not_auto_reused():
    reservation = PANDHCPReservation(
        name="printer", mac_address="00:11:22:33:44:55", explicit_fields={"mac_address"},
    )
    target = _target_dhcp(reservations=[reservation])
    strong, supporting, contradictions = _dhcp(_planned_dhcp(), target)
    assert strong
    assert supporting
    assert not contradictions


def test_dhcp_exact_reuse_does_not_collapse_explicit_empty_target_state():
    target = _target_dhcp()
    target.probe_ip = None
    target.explicit_fields.add("probe_ip")
    strong, supporting, contradictions = _dhcp(_planned_dhcp(), target)
    assert strong
    assert "target DHCP has additional explicit semantics: probe_ip" in supporting
    assert not contradictions
