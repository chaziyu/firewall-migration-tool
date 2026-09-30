"""Executable FortiGate to PAN-OS DHCP planning.

Only explicit source state with a deterministic PAN-OS representation is
rendered. Missing FortiGate fields are never replaced with vendor defaults.
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network
from typing import Any

from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationStatus, PlannedDHCPServer


def _source_value(item: Any, field: str):
    value = getattr(item, field, None)
    if value in (None, "", [], ()):
        return None
    explicit = getattr(item, "explicit_fields", ()) or ()
    if explicit and field not in explicit:
        return None
    return value


def _ipv4(value) -> str | None:
    if value is None:
        return None
    try:
        return str(IPv4Address(str(value)))
    except (ValueError, TypeError):
        return None


def _netmask(value) -> str | None:
    if value is None:
        return None
    try:
        IPv4Network(f"0.0.0.0/{value}")
        return str(value)
    except (ValueError, TypeError):
        return None


def _pool_value(pool) -> str | None:
    start = _ipv4(_source_value(pool, "start_ip"))
    end = _ipv4(_source_value(pool, "end_ip"))
    if start is None or end is None:
        return None
    if IPv4Address(start) > IPv4Address(end):
        return None
    return f"{start}-{end}"


def plan_dhcp(source: Any, options: Any) -> tuple[PlannedDHCPServer, ...]:
    """Plan the deterministic interface-scoped IPv4 DHCP subset."""
    result = []
    mappings_by_vdom = getattr(options, "interfaces", {}) or {}
    vdom_mappings = getattr(options, "vdoms", {}) or {}

    for index, server in enumerate(getattr(source, "dhcp_servers", ())):
        vdom = server.vdom or "root"
        name = str(server.id if server.id is not None else server.interface or index)
        blockers: list[str] = []
        notes: list[str] = []

        source_interface = _source_value(server, "interface")
        mapping = mappings_by_vdom.get(vdom, {}).get(source_interface) if source_interface else None
        target_interface = getattr(mapping, "target_interface", None) if mapping else None
        if not source_interface:
            blockers.append("DHCP server interface is not explicitly configured")
        elif not target_interface:
            blockers.append(f"missing target interface mapping for {source_interface!r}")

        ownership = vdom_mappings.get(vdom)
        target_vsys = getattr(ownership, "vsys", None) if ownership else None
        if not target_vsys:
            blockers.append(f"missing Palo Alto vsys mapping for VDOM {vdom!r}")

        source_status = str(_source_value(server, "status") or "").casefold()
        if source_status in {"enable", "enabled"}:
            mode = "enabled"
        elif source_status in {"disable", "disabled"}:
            mode = "disabled"
        else:
            mode = None
            blockers.append("DHCP server status is not explicitly configured with a supported value")

        server_type = str(_source_value(server, "server_type") or "").casefold()
        if not server_type:
            blockers.append("DHCP server-type is not explicit; FortiGate defaults are not assumed")
        elif server_type != "regular":
            blockers.append(f"DHCP server-type {server_type!r} requires manual target design")

        ip_mode = str(_source_value(server, "ip_mode") or "").casefold()
        if not ip_mode:
            blockers.append("DHCP ip-mode is not explicit; FortiGate defaults are not assumed")
        elif ip_mode != "range":
            blockers.append(f"DHCP ip-mode {ip_mode!r} is not rendered")

        lease_type = None
        lease_timeout = None
        lease = _source_value(server, "lease_time")
        if lease is not None:
            try:
                lease_value = int(lease)
            except (TypeError, ValueError):
                blockers.append("DHCP lease-time is not a valid integer")
            else:
                if lease_value == 0:
                    lease_type = "unlimited"
                elif 300 <= lease_value <= 1_000_000:
                    lease_type = "timeout"
                    lease_timeout = lease_value
                else:
                    blockers.append(
                        "DHCP lease-time is outside the supported PAN-OS timeout range"
                    )

        gateway = None
        gateway_value = _source_value(server, "default_gateway")
        if gateway_value is not None:
            gateway = _ipv4(gateway_value)
            if gateway is None:
                blockers.append("DHCP default gateway is not a valid IPv4 address")

        subnet_mask = None
        netmask_value = _source_value(server, "netmask")
        if netmask_value is not None:
            subnet_mask = _netmask(netmask_value)
            if subnet_mask is None:
                blockers.append("DHCP netmask is not a valid IPv4 netmask")

        dns_primary = None
        dns_secondary = None
        dns_service = str(_source_value(server, "dns_service") or "").casefold()
        dns_values = [
            _source_value(server, "dns_server1"),
            _source_value(server, "dns_server2"),
            _source_value(server, "dns_server3"),
            _source_value(server, "dns_server4"),
        ]
        if dns_service:
            if dns_service != "specify":
                blockers.append(f"DHCP dns-service {dns_service!r} requires manual target design")
            else:
                if dns_values[2] is not None or dns_values[3] is not None:
                    blockers.append("PAN-OS DHCP v1 planning supports at most two explicit DNS servers")
                if dns_values[0] is not None:
                    dns_primary = _ipv4(dns_values[0])
                    if dns_primary is None:
                        blockers.append("DHCP primary DNS server is not a valid IPv4 address")
                if dns_values[1] is not None:
                    dns_secondary = _ipv4(dns_values[1])
                    if dns_secondary is None:
                        blockers.append("DHCP secondary DNS server is not a valid IPv4 address")
        elif any(value is not None for value in dns_values):
            blockers.append("DHCP DNS servers are explicit but dns-service is not explicit")

        pools = []
        for pool in getattr(server, "ip_ranges", ()) or ():
            if getattr(pool, "raw_extra", None):
                blockers.append("DHCP IP range contains preserved unsupported source semantics")
            if _source_value(pool, "lease_time") is not None:
                blockers.append("per-range DHCP lease-time semantics are not rendered")
            value = _pool_value(pool)
            if value is None:
                blockers.append("DHCP IP range is incomplete or invalid")
            else:
                pools.append(value)
        if not pools:
            blockers.append("DHCP server has no supported explicit IP range")

        if getattr(server, "exclude_ranges", ()) or ():
            blockers.append("FortiGate DHCP exclude-range semantics are not rendered")
        if getattr(server, "reserved_addresses", ()) or ():
            blockers.append("FortiGate DHCP reservation semantics require manual target review")
        for field, label in (
            ("relay_agent", "relay-agent"),
            ("timezone_option", "timezone-option"),
            ("timezone", "timezone"),
        ):
            if _source_value(server, field) is not None:
                blockers.append(f"FortiGate DHCP {label} semantics are not rendered")
        if getattr(server, "raw_extra", None):
            blockers.append("DHCP server contains preserved unsupported source semantics")

        if mode == "disabled":
            notes.append("explicit disabled DHCP state is preserved as PAN-OS server mode disabled")

        result.append(PlannedDHCPServer(
            source_vdom=vdom,
            source_kind="dhcp_server",
            source_object_type="dhcp_server",
            source_name=name,
            target_vsys=target_vsys,
            target_name=target_interface,
            status=PANMigrationStatus.SUPPORTED if not blockers else PANMigrationStatus.MANUAL_REVIEW,
            warnings=tuple(dict.fromkeys((*blockers, *notes))),
            interface=target_interface,
            mode=mode,
            lease_type=lease_type,
            lease_timeout=lease_timeout,
            gateway=gateway,
            subnet_mask=subnet_mask,
            dns_primary=dns_primary,
            dns_secondary=dns_secondary,
            ip_pools=tuple(pools),
        ))

    return tuple(result)


__all__ = ["plan_dhcp"]
