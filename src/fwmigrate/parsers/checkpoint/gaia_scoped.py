"""VS-aware R81 Gaia parsing and ordered configuration reconciliation.

The established Gaia parser remains responsible for individual command
normalization. This layer adds virtual-system identity and replays ordered,
list-valued configuration where last-write-wins would lose source semantics.
"""

from __future__ import annotations

import ipaddress
import shlex
from collections import OrderedDict
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem, UnsupportedItem
from fwmigrate.extraction.sanitize import sanitize_raw_text, sanitize_source_attributes
from fwmigrate.ir.core import IRCheckpointInterfaceContext, IRInterface, IRMetadata, IRRoute, IRZone
from fwmigrate.parsers.checkpoint.gaia import parse_gaia_configuration as _parse_gaia_configuration_base


GaiaParseResult = Tuple[
    IRMetadata,
    List[IRInterface],
    List[IRZone],
    List[IRRoute],
    List[SourceInventoryItem],
    List[UnsupportedItem],
]


def _tokenize(line: str) -> List[str]:
    try:
        return shlex.split(line)
    except ValueError:
        return []


def _context_key(vsid: Optional[int]) -> str:
    return "global" if vsid is None else f"vsid={vsid}"


def _source_context(
    *, domain: Optional[str], gateway: Optional[str], source_response: Optional[str],
    cluster_member: Optional[str], vsid: Optional[int],
) -> str:
    base = (
        f"{domain or 'global'}:{gateway or cluster_member or 'unknown'}:{source_response}"
        if source_response else gateway or cluster_member or domain or "gaia"
    )
    if source_response and vsid is None:
        return base
    return f"{base}:{_context_key(vsid)}"


def split_virtual_system_contexts(
    gaia_text: str,
) -> Tuple["OrderedDict[Optional[int], List[str]]", List[Tuple[int, Optional[int], str]]]:
    """Partition commands according to explicit ``set virtual-system <VSID>`` state."""
    contexts: "OrderedDict[Optional[int], List[str]]" = OrderedDict()
    contexts[None] = []
    switches: List[Tuple[int, Optional[int], str]] = []
    current: Optional[int] = None

    for line_no, raw in enumerate(gaia_text.splitlines(), 1):
        line = raw.strip()
        tokens = _tokenize(line) if line and not line.startswith("#") else []
        lowered = [token.lower() for token in tokens]
        if len(tokens) == 3 and lowered[:2] == ["set", "virtual-system"]:
            try:
                candidate = int(tokens[2])
                if candidate < 0:
                    raise ValueError
            except ValueError:
                # A malformed switch never changes parser state. Keep it in the
                # current scope so it remains ordinary parse/source evidence.
                contexts.setdefault(current, []).append(raw)
                switches.append((line_no, None, line))
                continue
            current = candidate
            contexts.setdefault(current, [])
            switches.append((line_no, current, line))
            continue
        contexts.setdefault(current, []).append(raw)

    if None in contexts and not any(
        line.strip() and not line.strip().startswith("#") for line in contexts[None]
    ):
        contexts.pop(None)
    return contexts, switches


def _commands(lines: Iterable[str]) -> Iterable[Tuple[List[str], str]]:
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = _tokenize(line)
        if tokens:
            yield tokens, line


def _find_interface(interfaces: List[IRInterface], name: str) -> Optional[IRInterface]:
    return next((item for item in interfaces if item.name == name), None)


def _apply_setting_tokens(state: Dict[str, Any], tail: List[str], operation: str) -> None:
    """Apply ordered key/value logical-interface settings without flattening them."""
    if not tail:
        return
    low = [token.lower() for token in tail]
    if operation == "delete":
        state["settings"].pop(low[0], None)
        return

    index = 0
    while index < len(tail):
        key = low[index]
        if index + 1 >= len(tail):
            state["settings"][key] = True
            break
        state["settings"][key] = tail[index + 1]
        index += 2


def _logical_state(lines: Iterable[str], family: str) -> Dict[str, Dict[str, Any]]:
    """Replay bond/bridge add/set/delete operations into effective ordered state."""
    result: Dict[str, Dict[str, Any]] = {}
    prefix = "bond" if family == "bonding" else "br"
    phrase = [family, "group"]

    for tokens, line in _commands(lines):
        low = [token.lower() for token in tokens]
        if len(tokens) < 4 or low[0] not in {"add", "set", "delete"} or low[1:3] != phrase:
            continue
        group_id = tokens[3]
        if not group_id.isdigit():
            continue
        state = result.setdefault(group_id, {
            "name": f"{prefix}{group_id}", "members": [], "member_states": {},
            "settings": {}, "raw_commands": [], "deleted_members": [],
            "fail_open_members": [],
        })
        state["raw_commands"].append(sanitize_raw_text(line))
        operation = low[0]
        tail = tokens[4:]
        tail_low = low[4:]

        if operation == "delete" and not tail:
            state["members"].clear()
            state["member_states"].clear()
            state["settings"].clear()
            state["fail_open_members"].clear()
            state["deleted"] = True
            continue
        state.pop("deleted", None)

        if len(tail) >= 2 and tail_low[0] == "interface":
            member = tail[1]
            if operation == "delete":
                if member in state["members"]:
                    state["members"].remove(member)
                state["member_states"].pop(member, None)
                if member not in state["deleted_members"]:
                    state["deleted_members"].append(member)
            else:
                if member not in state["members"]:
                    state["members"].append(member)
                if member in state["deleted_members"]:
                    state["deleted_members"].remove(member)
                if len(tail) >= 4 and tail_low[2] == "state" and tail_low[3] in {"on", "off"}:
                    state["member_states"][member] = tail_low[3]
            continue

        if family == "bridging" and len(tail) >= 2 and tail_low[0] == "fail-open-interfaces":
            member = tail[1]
            if operation == "delete":
                if member in state["fail_open_members"]:
                    state["fail_open_members"].remove(member)
            elif member not in state["fail_open_members"]:
                state["fail_open_members"].append(member)
            continue

        _apply_setting_tokens(state, tail, operation)
    return result


def _reconcile_logical_interfaces(interfaces: List[IRInterface], lines: Iterable[str]) -> None:
    for family in ("bonding", "bridging"):
        states = _logical_state(lines, family)
        deleted_names = {state["name"] for state in states.values() if state.get("deleted")}
        if deleted_names:
            interfaces[:] = [item for item in interfaces if item.name not in deleted_names]

        for state in states.values():
            if state.get("deleted"):
                continue
            interface = _find_interface(interfaces, state["name"])
            if interface is None:
                continue
            interface.members = list(state["members"])
            attrs = interface.source_attributes
            stem = "bond" if family == "bonding" else "bridge"
            attrs[f"{stem}_members"] = list(state["members"])
            attrs[f"{stem}_member_states"] = dict(state["member_states"])
            attrs[f"{stem}_settings"] = dict(state["settings"])
            attrs[f"{stem}_raw_commands"] = list(state["raw_commands"])
            if state["deleted_members"]:
                attrs[f"{stem}_deleted_members"] = list(state["deleted_members"])
            if state["fail_open_members"]:
                attrs["bridge_fail_open_members"] = list(state["fail_open_members"])
            interface.requires_manual_review = True
            interface.migration_status = "PARTIALLY_NORMALIZED"
            reason = f"{stem}-behavior-not-portable"
            if reason not in interface.review_reasons:
                interface.review_reasons.append(reason)


def _reconcile_interface_properties(interfaces: List[IRInterface], lines: Iterable[str]) -> None:
    """Project portable fields and retain behavior-changing Gaia interface evidence."""
    for tokens, line in _commands(lines):
        low = [token.lower() for token in tokens]
        if len(tokens) < 4 or low[:2] != ["set", "interface"]:
            continue
        interface = _find_interface(interfaces, tokens[2])
        if interface is None:
            continue
        key = low[3]
        values = tokens[4:]
        if key in {"comment", "comments"}:
            interface.description = " ".join(values) if values else None
            continue
        if not values:
            continue
        value: Any = values[0] if len(values) == 1 else values
        if key == "mtu":
            try:
                mtu = int(values[0])
                if mtu <= 0:
                    raise ValueError
                interface.mtu = mtu
            except ValueError:
                interface.requires_manual_review = True
                interface.migration_status = "PARTIALLY_NORMALIZED"
                if "invalid-interface-mtu" not in interface.review_reasons:
                    interface.review_reasons.append("invalid-interface-mtu")
        elif key == "link-speed":
            interface.source_speed = str(values[0])
        elif key == "duplex":
            interface.source_duplex = str(values[0])
        elif key == "ipv6-autoconfig":
            interface.source_ipv6_autoconf = str(values[0])
        elif key in {"auto-negotiation", "mac-addr", "mac-address", "monitor-mode"}:
            normalized_key = "mac_address" if key in {"mac-addr", "mac-address"} else key.replace("-", "_")
            interface.source_attributes[normalized_key] = value
            interface.requires_manual_review = True
            interface.migration_status = "PARTIALLY_NORMALIZED"
            reason = f"unmodeled-interface-setting:{key}"
            if reason not in interface.review_reasons:
                interface.review_reasons.append(reason)
        interface.source_attributes.setdefault("ordered_interface_commands", []).append(sanitize_raw_text(line))


def _dns_effective(lines: Iterable[str]) -> Tuple[Dict[str, Any], List[str]]:
    result: Dict[str, Any] = {"servers": {}, "search_suffixes": [], "raw_commands": []}
    errors: List[str] = []
    for tokens, line in _commands(lines):
        low = [token.lower() for token in tokens]
        if len(tokens) >= 4 and low[:2] == ["set", "dns"]:
            setting = low[2]
            value = " ".join(tokens[3:])
            result["raw_commands"].append(sanitize_raw_text(line))
            if setting in {"primary", "secondary", "tertiary"}:
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    errors.append(f"invalid-dns-{setting}-address:{value}")
                result["servers"][setting] = value
            elif setting in {"domain", "domain-name"}:
                result["dns_domain"] = value
            elif setting in {"suffix", "search", "search-suffix"}:
                if value not in result["search_suffixes"]:
                    result["search_suffixes"].append(value)
            else:
                result.setdefault("unmodeled", []).append({"setting": setting, "value": value})
        elif len(tokens) >= 3 and low[0] == "set" and low[1] in {"domainname", "domain-name"}:
            result["system_domain_name"] = " ".join(tokens[2:])
            result["raw_commands"].append(sanitize_raw_text(line))
    return result, errors


def _system_effective(lines: Iterable[str]) -> Dict[str, Any]:
    result: Dict[str, Any] = {"ntp_servers": [], "raw_commands": []}
    for tokens, line in _commands(lines):
        low = [token.lower() for token in tokens]
        if len(tokens) >= 3 and low[:2] == ["set", "timezone"]:
            result["timezone"] = " ".join(tokens[2:])
            result["raw_commands"].append(sanitize_raw_text(line))
        elif len(tokens) >= 5 and low[:3] == ["set", "ntp", "server"]:
            entry: Dict[str, Any] = {"role": low[3], "address": tokens[4]}
            index = 5
            while index + 1 < len(tokens):
                entry[low[index].replace("-", "_")] = tokens[index + 1]
                index += 2
            result["ntp_servers"].append(entry)
            result["raw_commands"].append(sanitize_raw_text(line))
        elif len(tokens) >= 4 and low[:2] == ["set", "ntp"] and low[2] in {"active", "enable", "enabled"}:
            result["ntp_enabled"] = low[3] == "on"
            result["raw_commands"].append(sanitize_raw_text(line))
    return result


def _dhcp_effective(lines: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    """Replay known DHCP add/set/delete forms without confusing client mode."""
    servers: Dict[str, Dict[str, Any]] = {}
    process_enabled = True
    for tokens, line in _commands(lines):
        low = [token.lower() for token in tokens]
        if len(tokens) < 3 or low[0] not in {"add", "set", "delete"} or low[1:3] != ["dhcp", "server"]:
            continue
        operation = low[0]
        tail = tokens[3:]
        tail_low = low[3:]
        if tail_low and tail_low[0] in {"enable", "disable"}:
            process_enabled = tail_low[0] == "enable"
            continue
        if len(tail) < 2 or tail_low[0] != "subnet":
            continue
        subnet = tail[1]
        state = servers.setdefault(subnet, {
            "subnet": subnet, "enabled": True, "dns_servers": [], "pools": [],
            "reservations": [], "raw_commands": [],
        })
        state["raw_commands"].append(sanitize_raw_text(line))
        remainder = tail[2:]
        remainder_low = tail_low[2:]
        if operation == "delete" and not remainder:
            state["deleted"] = True
            state["enabled"] = False
            continue
        if operation != "delete":
            state.pop("deleted", None)
        index = 0
        while index < len(remainder):
            key = remainder_low[index]
            if key in {"enable", "disable"}:
                state["enabled"] = key == "enable" and operation != "delete"
                index += 1
            elif key in {"netmask", "interface", "default-gateway", "domain", "default-lease", "max-lease"} and index + 1 < len(remainder):
                normalized = key.replace("-", "_")
                if operation == "delete":
                    state.pop(normalized, None)
                else:
                    state[normalized] = remainder[index + 1]
                index += 2
            elif key == "dns" and index + 1 < len(remainder):
                values = [part.strip() for part in " ".join(remainder[index + 1:]).split(",") if part.strip()]
                if operation == "delete":
                    state["dns_servers"] = [item for item in state["dns_servers"] if item not in values]
                else:
                    for value in values:
                        if value not in state["dns_servers"]:
                            state["dns_servers"].append(value)
                break
            elif key in {"include-ip-pool", "exclude-ip-pool"} and index + 1 < len(remainder):
                value = remainder[index + 1]
                pool = {"type": "include" if key.startswith("include") else "exclude", "value": value}
                if operation == "delete":
                    state["pools"] = [item for item in state["pools"] if item != pool]
                elif pool not in state["pools"]:
                    state["pools"].append(pool)
                index += 2
            elif key == "reservation":
                reservation = {"tokens": remainder[index + 1:]}
                if operation == "delete":
                    state["reservations"] = [item for item in state["reservations"] if item != reservation]
                elif reservation not in state["reservations"]:
                    state["reservations"].append(reservation)
                break
            else:
                state.setdefault("unmodeled", []).append(remainder[index:])
                break
    for state in servers.values():
        state["process_enabled"] = process_enabled
        state["enabled"] = bool(state.get("enabled")) and process_enabled and not state.get("deleted", False)
    return servers


def _add_context_inventory(
    inventory: List[SourceInventoryItem], lines: List[str], *, context: str, vsid: Optional[int],
) -> None:
    dns, dns_errors = _dns_effective(lines)
    if dns["raw_commands"]:
        inventory.append(SourceInventoryItem(
            domain="gaia", source_path="gaia/show-configuration/dns-effective",
            name=f"dns-{_context_key(vsid)}", source_type="gaia-dns-effective",
            source_context=context,
            source_attributes=sanitize_source_attributes({**dns, "virtual_system_id": vsid}),
            status=ExtractionStatus.PARSE_ERROR if dns_errors else ExtractionStatus.PARTIALLY_NORMALIZED,
            requires_manual_review=True,
            notes=dns_errors or ["DNS semantics retained with explicit Gaia/VS scope"],
        ))

    system = _system_effective(lines)
    if system["raw_commands"]:
        inventory.append(SourceInventoryItem(
            domain="gaia", source_path="gaia/show-configuration/system-effective",
            name=f"system-{_context_key(vsid)}", source_type="gaia-system-effective",
            source_context=context,
            source_attributes=sanitize_source_attributes({**system, "virtual_system_id": vsid}),
            status=ExtractionStatus.PARTIALLY_NORMALIZED, requires_manual_review=True,
            notes=["Gaia system settings retained with explicit virtual-system scope"],
        ))

    for subnet, state in _dhcp_effective(lines).items():
        inventory.append(SourceInventoryItem(
            domain="gaia", source_path="gaia/show-configuration/dhcp-effective",
            name=f"{subnet}-{_context_key(vsid)}", source_type="gaia-dhcp-effective",
            source_context=context,
            source_attributes=sanitize_source_attributes({**state, "virtual_system_id": vsid}),
            status=ExtractionStatus.PARTIALLY_NORMALIZED,
            requires_manual_review=True,
            notes=["DHCP effective add/set/delete state retained as source-scoped evidence"],
        ))


def parse_gaia_configuration(
    gaia_text: str,
    *,
    domain: Optional[str] = None,
    gateway: Optional[str] = None,
    source_response: Optional[str] = None,
    cluster_member: Optional[str] = None,
) -> GaiaParseResult:
    """Parse Gaia configuration with authoritative VSID-aware source identity."""
    contexts, switches = split_virtual_system_contexts(gaia_text)
    all_interfaces: List[IRInterface] = []
    all_zones: List[IRZone] = []
    all_routes: List[IRRoute] = []
    all_inventory: List[SourceInventoryItem] = []
    all_unsupported: List[UnsupportedItem] = []
    selected_metadata: Optional[IRMetadata] = None

    for vsid, lines in contexts.items():
        context = _source_context(
            domain=domain, gateway=gateway, source_response=source_response,
            cluster_member=cluster_member, vsid=vsid,
        )
        metadata, interfaces, zones, routes, inventory, unsupported = _parse_gaia_configuration_base(
            "\n".join(lines), domain=domain, gateway=gateway,
            source_response=source_response, cluster_member=cluster_member,
        )
        if selected_metadata is None or vsid is None:
            selected_metadata = metadata

        _reconcile_logical_interfaces(interfaces, lines)
        _reconcile_interface_properties(interfaces, lines)
        _add_context_inventory(inventory, lines, context=context, vsid=vsid)

        provenance = {
            "domain": domain, "gateway": gateway, "source_response": source_response,
            "cluster_member": cluster_member, "virtual_system_id": vsid,
        }
        for item in interfaces:
            item.source_context = context
            item.source_attributes["virtual_system_id"] = vsid
            item.checkpoint_context = item.checkpoint_context or IRCheckpointInterfaceContext()
            item.checkpoint_context.virtual_system_id = vsid
            item.source_attributes.setdefault("provenance", {}).update(provenance)
        for item in zones:
            item.source_context = context
            item.source_attributes["virtual_system_id"] = vsid
            item.source_attributes.setdefault("provenance", {}).update(provenance)
        for item in routes:
            item.source_context = context
            item.source_attributes["virtual_system_id"] = vsid
            item.source_attributes.setdefault("provenance", {}).update(provenance)
        for item in inventory:
            item.source_context = context
            item.source_attributes["virtual_system_id"] = vsid
            item.source_attributes.setdefault("provenance", {}).update(provenance)

        all_interfaces.extend(interfaces)
        all_zones.extend(zones)
        all_routes.extend(routes)
        all_inventory.extend(inventory)
        all_unsupported.extend(unsupported)

    root_context = _source_context(
        domain=domain, gateway=gateway, source_response=source_response,
        cluster_member=cluster_member, vsid=None,
    )
    for line_no, vsid, command in switches:
        malformed = vsid is None
        all_inventory.append(SourceInventoryItem(
            domain=domain or "gaia", source_path="gaia/show-configuration/virtual-system",
            name=f"virtual-system-switch-{line_no}", source_type="gaia-virtual-system-context",
            source_context=root_context if malformed else _source_context(
                domain=domain, gateway=gateway, source_response=source_response,
                cluster_member=cluster_member, vsid=vsid,
            ),
            source_attributes={
                "virtual_system_id": vsid, "raw_command": sanitize_raw_text(command),
                "line_number": line_no,
            },
            status=ExtractionStatus.PARSE_ERROR if malformed else ExtractionStatus.NORMALIZED,
            requires_manual_review=malformed,
            notes=["malformed-virtual-system-context"] if malformed else [],
        ))

    if selected_metadata is None:
        selected_metadata = IRMetadata(
            hostname="checkpoint-gw", source_vendor="checkpoint", source_context=root_context,
        )
    selected_metadata.source_context = root_context
    return selected_metadata, all_interfaces, all_zones, all_routes, all_inventory, all_unsupported
