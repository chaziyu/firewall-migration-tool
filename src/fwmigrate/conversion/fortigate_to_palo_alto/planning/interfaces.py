"""Executable FortiGate to PAN-OS interface planning.

This module plans only the deterministic subset that can be rendered without
guessing target ownership or source defaults. Target interface identity comes
from explicit pair-specific mappings/decisions.
"""

from __future__ import annotations

from ipaddress import IPv4Interface
import re
from typing import Any

from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationStatus, PlannedInterface


_ETHERNET = re.compile(r"^ethernet\d+/\d+$")


def _explicit_ipv4(value: str | None) -> str | None:
    if not value:
        return None
    parts = str(value).split()
    try:
        if len(parts) == 1:
            return str(IPv4Interface(parts[0]))
        if len(parts) == 2:
            return str(IPv4Interface(f"{parts[0]}/{parts[1]}"))
    except ValueError:
        return None
    return None


def plan_interfaces(source: Any, options: Any) -> tuple[PlannedInterface, ...]:
    """Plan mapped Layer 3 ethernet interfaces and ethernet subinterfaces.

    Absence in the FortiGate source never becomes a target default. Fields that
    are not explicitly represented by this vertical slice either remain
    source-only warnings or block rendering when omitting them could alter
    forwarding or management behavior.
    """
    result = []
    mappings_by_vdom = getattr(options, "interfaces", {}) or {}
    vdom_mappings = getattr(options, "vdoms", {}) or {}

    for item in getattr(source, "interfaces", ()):
        vdom = item.vdom or "root"
        mapping = mappings_by_vdom.get(vdom, {}).get(item.name)
        target = getattr(mapping, "target_interface", None) if mapping else None
        if not target:
            continue

        ownership = vdom_mappings.get(vdom)
        target_vsys = getattr(ownership, "vsys", None) if ownership else None
        virtual_router = getattr(ownership, "virtual_router", None) if ownership else None
        blockers: list[str] = []
        notes: list[str] = []

        if not target_vsys:
            blockers.append(f"missing Palo Alto vsys mapping for VDOM {vdom!r}")
        if not virtual_router:
            blockers.append(f"missing Palo Alto virtual-router mapping for VDOM {vdom!r}")

        kind = (item.type or "").casefold()
        is_vlan = item.vlanid is not None or kind == "vlan"
        parent_target = None
        interface_family = None
        tag = None

        if is_vlan:
            if not item.interface:
                blockers.append("VLAN interface has no explicit source parent")
            else:
                parent_mapping = mappings_by_vdom.get(vdom, {}).get(item.interface)
                parent_target = getattr(parent_mapping, "target_interface", None) if parent_mapping else None
                if not parent_target:
                    blockers.append(f"missing target interface mapping for parent {item.interface!r}")
                elif not _ETHERNET.fullmatch(parent_target):
                    blockers.append(
                        "automated VLAN rendering currently supports only ethernet parents"
                    )
            if item.vlanid is None:
                blockers.append("VLAN interface has no explicit VLAN ID")
            else:
                tag = item.vlanid
            if parent_target and not target.startswith(f"{parent_target}."):
                blockers.append(
                    f"target subinterface {target!r} is not under mapped parent {parent_target!r}"
                )
            interface_family = "ethernet"
        else:
            if item.interface:
                blockers.append("non-VLAN interface has an explicit parent relationship")
            if kind not in {"", "physical", "ethernet"}:
                blockers.append(f"unsupported FortiGate interface type {item.type!r}")
            if not _ETHERNET.fullmatch(target):
                blockers.append(
                    "automated physical interface rendering requires an ethernet target name"
                )
            interface_family = "ethernet"

        mode = (item.mode or "").casefold()
        if mode in {"dhcp", "pppoe"}:
            blockers.append(f"dynamic interface mode {mode!r} is not rendered")
        elif mode and mode != "static":
            blockers.append(f"unsupported explicit interface mode {item.mode!r}")

        ipv4_addresses: tuple[str, ...] = ()
        if item.ip:
            normalized = _explicit_ipv4(item.ip)
            if normalized is None:
                blockers.append("explicit source IPv4 address could not be parsed safely")
            else:
                ipv4_addresses = (normalized,)
        else:
            notes.append("source IPv4 address is not explicit; no target IP command is emitted")

        if item.secondary_ips:
            blockers.append("secondary interface IPv4 addresses are not rendered")
        if item.members:
            blockers.append("aggregate or redundant member semantics are not rendered")
        if item.allowaccess:
            blockers.append("FortiGate administrative access requires a PAN-OS management-profile decision")
        if item.vrf not in (None, 0):
            blockers.append("non-default FortiGate VRF requires explicit target routing design")
        if (item.status or "").casefold() in {"disable", "disabled", "down"}:
            blockers.append("disabled source interface state is not rendered")
        if item.raw_extra:
            blockers.append("interface contains preserved unsupported source semantics")

        for field, value in (
            ("alias", item.alias),
            ("description", item.description),
            ("role", item.role),
        ):
            if value:
                notes.append(f"source {field} is preserved as source-only evidence")

        result.append(PlannedInterface(
            source_vdom=vdom,
            source_kind="interface",
            source_object_type="interface",
            source_name=item.name,
            target_vsys=target_vsys,
            target_name=target,
            status=PANMigrationStatus.SUPPORTED if not blockers else PANMigrationStatus.MANUAL_REVIEW,
            warnings=tuple(dict.fromkeys((*blockers, *notes))),
            interface_family=interface_family,
            parent=parent_target,
            tag=tag,
            ipv4_addresses=ipv4_addresses,
            virtual_router=virtual_router,
        ))

    return tuple(result)


__all__ = ["plan_interfaces"]
