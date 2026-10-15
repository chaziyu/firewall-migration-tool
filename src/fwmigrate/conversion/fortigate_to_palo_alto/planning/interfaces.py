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
from ..target.profile import MODEL_PORTS, site_to_site_phase1


_ETHERNET = re.compile(r"^ethernet\d+/\d+$")
_AGGREGATE = re.compile(r"^ae(?:[1-9]|1[0-6])$")


def aggregate_member_owners(source):
    owners = {}
    for item in getattr(source, "interfaces", ()):
        if (getattr(item, "type", None) or "").casefold() in {"aggregate", "redundant"}:
            for member in item.members:
                owners.setdefault((item.vdom or "root", member), []).append(item)
    return owners


def _explicit_ipv4(value: str | None) -> str | None:
    if not value:
        return None
    parts = str(value).split()
    try:
        if len(parts) == 1 and "/" in parts[0]:
            return str(IPv4Interface(parts[0]))
        if len(parts) == 2:
            return str(IPv4Interface(f"{parts[0]}/{parts[1]}"))
    except ValueError:
        return None
    return None


def plan_interfaces(source: Any, options: Any) -> tuple[PlannedInterface, ...]:
    """Plan mapped Layer 3 ethernet interfaces, subinterfaces and loopbacks.

    Absence in the FortiGate source never becomes a target default. Fields that
    are not explicitly represented by this vertical slice either remain
    source-only warnings or block rendering when omitting them could alter
    forwarding or management behavior.
    """
    result = []
    mappings_by_vdom = getattr(options, "interfaces", {}) or {}
    vdom_mappings = getattr(options, "vdoms", {}) or {}
    source_interfaces = {(item.vdom or "root", item.name): item for item in getattr(source, "interfaces", ())}
    member_owners = aggregate_member_owners(source)
    vpns = site_to_site_phase1(source)

    for item in getattr(source, "interfaces", ()):
        vdom = item.vdom or "root"
        settings = getattr(options, 'conversion_settings', {})
        if f'{vdom}/{item.name}' in settings.get('excluded_interfaces', ()):
            result.append(PlannedInterface(source_vdom=vdom, source_kind='interface', source_object_type='interface',
                source_name=item.name, status=PANMigrationStatus.UNSUPPORTED,
                warnings=('Explicitly excluded from conversion; source evidence is retained',)))
            continue
        if (vdom, item.name) in member_owners:
            owners = member_owners[(vdom, item.name)]
            if not any(getattr(mappings_by_vdom.get(vdom, {}).get(owner.name), "target_interface", None) for owner in owners):
                member_mapping = mappings_by_vdom.get(vdom, {}).get(item.name)
                member_target = getattr(member_mapping, "target_interface", None)
                if member_target:
                    result.append(PlannedInterface(source_vdom=vdom, source_kind="interface", source_object_type="interface",
                        source_name=item.name, target_name=member_target,
                        target_vsys=getattr(vdom_mappings.get(vdom), "vsys", None),
                        virtual_router=getattr(vdom_mappings.get(vdom), "virtual_router", None), interface_family="ethernet",
                        warnings=("Aggregate or redundant member requires its parent mapping; standalone rendering is blocked",)))
            continue
        mapping = mappings_by_vdom.get(vdom, {}).get(item.name)
        target = getattr(mapping, "target_interface", None) if mapping else None
        if not target:
            continue

        ownership = vdom_mappings.get(vdom)
        target_vsys = getattr(ownership, "vsys", None) if ownership else None
        virtual_router = getattr(ownership, "virtual_router", None) if ownership else None
        blockers: list[str] = []
        notes: list[str] = []
        pool = MODEL_PORTS.get(settings.get('target_model'))
        if pool is not None and target.startswith('ethernet') and target.split('.', 1)[0] not in pool:
            blockers.append('Target interface is outside the selected hardware port pool')

        if not target_vsys:
            blockers.append(f"missing Palo Alto vsys mapping for VDOM {vdom!r}")
        if not virtual_router:
            blockers.append(f"missing Palo Alto virtual-router mapping for VDOM {vdom!r}")

        kind = (item.type or "").casefold()
        is_vlan = item.vlanid is not None or kind == "vlan"
        parent_target = None
        interface_family = None
        tag = None
        aggregate_members = []
        lacp_mode = None

        if is_vlan:
            if not item.interface:
                blockers.append("VLAN interface has no explicit source parent")
            else:
                parent_mapping = mappings_by_vdom.get(vdom, {}).get(item.interface)
                parent_target = getattr(parent_mapping, "target_interface", None) if parent_mapping else None
                if not parent_target:
                    blockers.append(f"missing target interface mapping for parent {item.interface!r}")
                elif not (_ETHERNET.fullmatch(parent_target) or _AGGREGATE.fullmatch(parent_target)):
                    blockers.append(
                        "automated VLAN rendering requires an ethernet or aggregate parent"
                    )
            if item.vlanid is None:
                blockers.append("VLAN interface has no explicit VLAN ID")
            else:
                tag = item.vlanid
                if not 1 <= tag <= 4094:
                    blockers.append("VLAN tag must be between 1 and 4094")
            if parent_target and not target.startswith(f"{parent_target}."):
                blockers.append(
                    f"target subinterface {target!r} is not under mapped parent {parent_target!r}"
                )
            elif parent_target:
                suffix = target[len(parent_target) + 1:]
                if not re.fullmatch(r"[0-9]+", suffix) or not 1 <= int(suffix) <= 9999:
                    blockers.append("target subinterface identifier must be between 1 and 9999")
            interface_family = "aggregate-ethernet" if parent_target and _AGGREGATE.fullmatch(parent_target) else "ethernet"
        elif kind == "aggregate":
            interface_family = "aggregate-ethernet"
            if not _AGGREGATE.fullmatch(target):
                blockers.append("target aggregate identifier must be ae1 through ae16")
            if item.interface:
                blockers.append("aggregate interface cannot have a source parent")
            lacp_mode = item.raw_extra.get("lacp-mode")
            if lacp_mode not in ("active", "passive", "static"):
                blockers.append("aggregate requires an explicit supported lacp-mode; absent mode is not a default")
                lacp_mode = None
            if not item.members:
                blockers.append("aggregate requires explicit physical members")
            for name in item.members:
                member = source_interfaces.get((vdom, name))
                member_mapping = mappings_by_vdom.get(vdom, {}).get(name)
                member_target = getattr(member_mapping, "target_interface", None)
                if not member_target or not _ETHERNET.fullmatch(member_target):
                    blockers.append(f"missing physical target interface mapping for aggregate member {name!r}")
                else:
                    aggregate_members.append(member_target)
                if len(member_owners.get((vdom, name), ())) != 1:
                    blockers.append(f"aggregate member {name!r} has conflicting source ownership")
                if member is None or (member.type or "").casefold() not in {"physical", "ethernet"}:
                    blockers.append(f"aggregate member {name!r} is not an explicit physical source interface")
                elif (member.ip or member.secondary_ips or member.allowaccess or member.interface or member.members
                        or member.vlanid is not None or member.raw_extra or member.vrf not in (None, 0)
                        or member.mode not in (None, "static") or member.status not in (None, "up", "enable")):
                    blockers.append(f"aggregate member {name!r} has unsupported standalone source settings")
                if getattr(member_mapping, "target_zone", None):
                    blockers.append(f"aggregate member {name!r} cannot have standalone zone ownership")
            if len(set(aggregate_members)) != len(aggregate_members):
                blockers.append("aggregate members must have distinct physical target allocations")
        elif kind == 'tunnel' and (vdom, item.name) in vpns:
            interface_family = 'tunnel'
            if not re.fullmatch(r'tunnel\.(?:[1-9][0-9]{0,3})', target):
                blockers.append('Target tunnel identifier must be between 1 and 9999')
            if item.interface != vpns[(vdom, item.name)].interface:
                blockers.append('Tunnel parent differs from the explicit Phase 1 egress interface')
            if f'{vdom}/{item.name}' not in settings.get('existing_vpns', ()):
                blockers.append('VPN gateway, credentials and selectors require an explicitly reviewed existing-target prerequisite')
        elif kind == "loopback":
            interface_family = "loopback"
            if item.interface:
                blockers.append("loopback interface cannot have a source parent")
            if not re.fullmatch(r"loopback\.(?:[1-9][0-9]{0,3})", target):
                blockers.append("target loopback identifier must be between 1 and 9999")
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
                if interface_family == "loopback" and IPv4Interface(normalized).network.prefixlen != 32:
                    blockers.append("PAN-OS loopback IPv4 addresses require an explicit /32 mask")
        else:
            notes.append("source IPv4 address is not explicit; no target IP command is emitted")

        if item.secondary_ips:
            if item.raw_extra.get('secondary-IP') != 'enable':
                blockers.append('Secondary IPv4 activation must be explicitly enabled')
            for secondary in item.secondary_ips:
                address = _explicit_ipv4(secondary.ip)
                if address is None or secondary.raw_extra or secondary.ha_priority is not None or secondary.allowaccess:
                    blockers.append('Secondary IPv4 contains unsupported addressing or administrative access semantics')
                elif address not in ipv4_addresses:
                    if interface_family == 'loopback' and IPv4Interface(address).network.prefixlen != 32:
                        blockers.append('PAN-OS loopback secondary IPv4 requires an explicit /32 mask')
                    ipv4_addresses += (address,)
        if item.members and kind != "aggregate":
            blockers.append("aggregate or redundant member semantics are not rendered")
        management_profile = settings.get('management_profiles', {}).get(f'{vdom}/{item.name}')
        identity = f'{vdom}/' + ','.join(sorted(set(item.allowaccess or ())))
        if not management_profile and identity in settings.get('generated_management_profiles', {}):
            from .management_profiles import management_profile_name
            management_profile = management_profile_name(identity)
        if item.allowaccess and not management_profile:
            blockers.append("FortiGate administrative access requires a PAN-OS management-profile decision")
        if item.allowaccess and set(item.allowaccess) - {'ping', 'https', 'ssh', 'snmp', 'http', 'telnet'}:
            blockers.append('Administrative access protocols have no verified target management-profile equivalent')
        if item.vrf not in (None, 0):
            blockers.append("non-default FortiGate VRF requires explicit target routing design")
        if (item.status or "").casefold() in {"disable", "disabled", "down"}:
            blockers.append("disabled source interface state is not rendered")
        known_metadata = {'snmp-index', 'monitor-bandwidth'}
        if 'monitor-bandwidth' in item.raw_extra:
            notes.append('Source bandwidth-monitoring display setting is retained as source-only evidence')
        if item.raw_extra.get('secondary-IP') == 'enable' and item.secondary_ips:
            known_metadata.add('secondary-IP')
        if set(item.raw_extra) - known_metadata - ({"lacp-mode"} if kind == "aggregate" else set()):
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
            aggregate_members=tuple(aggregate_members),
            lacp_mode=lacp_mode,
            management_profile=management_profile,
        ))

    return tuple(result)


__all__ = ["plan_interfaces"]
