from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .nodes import GaiaCommandNode, GaiaConfigTree, GaiaUnknownCommandNode
from .section_registry import match_gaia_family


@dataclass
class GaiaEvaluation:
    kind: str
    identity: str | None = None
    values: dict[str, Any] = field(default_factory=dict)
    explicit_fields: set[str] = field(default_factory=set)
    source_line: int | None = None


def evaluate_gaia_commands(tree: GaiaConfigTree) -> list[GaiaEvaluation]:
    evaluations: list[GaiaEvaluation] = []
    state: dict[tuple[str, str | None], GaiaEvaluation] = {}
    for node in tree.commands:
        family, args = match_gaia_family(node.arguments)
        if family is None:
            evaluations.append(GaiaEvaluation("unsupported", values={"command": " ".join((node.operation, *node.arguments))}, source_line=node.line_number))
            continue
        if node.operation == "show":
            evaluations.append(GaiaEvaluation("unsupported", values={"command": " ".join((node.operation, *node.arguments))}, source_line=node.line_number))
            continue
        evaluation = _evaluate(family.name, node, args)
        if evaluation is None:
            continue
        key = (evaluation.kind, evaluation.identity)
        current = state.get(key)
        if current is None:
            state[key] = evaluation
            evaluations.append(evaluation)
        else:
            _merge(current, evaluation)
    for node in tree.unknown_commands:
        evaluations.append(GaiaEvaluation("unsupported", values={"command": " ".join((node.operation, *node.arguments))}, source_line=node.line_number))
    return evaluations


def _evaluate(kind: str, node: GaiaCommandNode, args: tuple[str, ...]) -> GaiaEvaluation | None:
    if kind == "interface":
        identity = args[0] if args else None
        values = _pairs(args[1:])
        if isinstance(values.get("state"), bool):
            values["state"] = "on" if values["state"] else "off"
        return GaiaEvaluation(kind, identity, values, set(values), node.line_number)
    if kind.startswith("static-route"):
        identity = args[0] if args else None
        values: dict[str, Any] = {"address_family": "ipv6" if kind.endswith("ipv6") else "ipv4", "next_hops": []}
        index = 1
        while index < len(args):
            key = args[index].lower().replace("-", "_")
            if key == "nexthop":
                index += 1
                hop: dict[str, Any] = {}
                if index < len(args) and args[index].lower() == "gateway":
                    hop["next_hop_type"] = "gateway"; index += 1
                    if index < len(args) and args[index].lower() == "address": index += 1
                    if index < len(args) and args[index].lower() not in {"on", "off", "priority", "rank", "ping", "ping6", "scopelocal", "blackhole", "reject"}:
                        hop["gateway"] = args[index]; index += 1
                elif index < len(args) and args[index].lower() in {"logical", "interface", "device"}:
                    hop["next_hop_type"] = "interface"; index += 1
                    if index < len(args) and args[index].lower() not in {"on", "off", "priority", "rank", "ping", "ping6", "scopelocal", "blackhole", "reject"}:
                        hop["interface"] = args[index]; index += 1
                while index < len(args) and args[index].lower() != "nexthop":
                    field = args[index].lower().replace("-", "_")
                    if field in {"blackhole", "reject", "scopelocal", "ping", "ping6"}:
                        hop[field] = True
                        if field in {"blackhole", "reject"}: hop["next_hop_type"] = field
                        index += 1
                    elif field in {"priority", "rank"} and index + 1 < len(args):
                        hop[field] = args[index + 1]; index += 2
                    elif field in {"on", "off"}:
                        index += 1
                    else:
                        break
                values["next_hops"].append(hop)
            elif key in {"blackhole", "reject"}:
                values["next_hops"].append({"next_hop_type": key, key: True}); index += 1
            elif key in {"scopelocal", "ping", "ping6"}:
                values[key] = True; index += 1
            elif key in {"comment", "rank"} and index + 1 < len(args):
                values[key] = args[index + 1]; index += 2
            elif key == "enabled" and index + 1 < len(args):
                values[key] = args[index + 1].lower() in {"on", "true", "enabled"}; index += 2
            else:
                index += 1
        if identity and identity.lower() == "default":
            values["default"] = True
        elif identity:
            values["ipv6_destination" if kind.endswith("ipv6") else "ipv4_destination"] = identity
        return GaiaEvaluation(kind, identity, values, set(values), node.line_number)
    if kind == "dhcp-server":
        return _evaluate_dhcp(args, node)
    if kind == "gaia-user":
        identity = args[0] if args else None
        values = _pairs(args[1:])
        for item in args:
            if item.lower() in {"password", "password-hash", "phash", "secret", "private-key"}:
                values["password_configured"] = True
        return GaiaEvaluation(kind, identity, values, set(values), node.line_number)
    if kind in {"gaia-rba-role", "gaia-rba-user-assignment"}:
        identity = args[0] if args else None
        values = _pairs(args[1:])
        if kind == "gaia-rba-user-assignment" and identity:
            values.setdefault("user", identity)
        return GaiaEvaluation(kind, identity, values, set(values), node.line_number)
    if kind == "vpn-tunnel-vti":
        identity = args[0] if args else None
        values = {"tunnel_id": identity}
        index = 1
        fields = {"type": "tunnel_type", "local": "local_address", "remote": "remote_address", "peer": "peer", "dev": "local_device", "device": "local_device", "state": "state"}
        while index < len(args):
            key = args[index].lower()
            if key in fields and index + 1 < len(args):
                value = args[index + 1]
                values[fields[key]] = ("on" if value.lower() in {"on", "enabled", "true"} else "off") if key == "state" else value
                index += 2
            else:
                index += 1
        return GaiaEvaluation(kind, identity, values, set(values), node.line_number)
    return None


def _pairs(args: tuple[str, ...]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    index = 0
    while index < len(args):
        key = args[index].lower().replace("-", "_")
        if index + 1 < len(args) and args[index + 1].lower() not in {"gateway", "address", "on", "off"}:
            value: Any = args[index + 1]
            if str(value).lower() in {"on", "off", "true", "false", "enabled", "disabled"}:
                value = str(value).lower() in {"on", "true", "enabled"}
            values[key] = value
            index += 2
        else:
            values[key] = True
            index += 1
    return values


def _evaluate_dhcp(args: tuple[str, ...], node: GaiaCommandNode) -> GaiaEvaluation:
    values: dict[str, Any] = {}
    subnet_index = next((i for i, token in enumerate(args) if token.lower() == "subnet"), None)
    if subnet_index is None:
        if len(args) >= 2 and args[0].lower() == "state":
            values["process_state"] = args[1]
        elif args and args[0].lower() in {"enable", "disable"}:
            values["enabled"] = args[0].lower() == "enable"
        return GaiaEvaluation("dhcp-server", "server", values, set(values), node.line_number)
    if subnet_index + 1 >= len(args):
        return GaiaEvaluation("dhcp-server", "server", values, set(values), node.line_number)
    subnet = {"subnet": args[subnet_index + 1]}
    index = subnet_index + 2
    while index < len(args):
        key = args[index].lower().replace("-", "_")
        if key == "netmask" and index + 1 < len(args):
            subnet["netmask"] = args[index + 1]; index += 2
        elif key in {"enable", "disable"}:
            subnet["enabled"] = key == "enable"; index += 1
        elif key in {"include_ip_pool", "exclude_ip_pool"}:
            pools_key = "included_pools" if key == "include_ip_pool" else "excluded_pools"
            index += 1
            if index < len(args) and args[index].lower() == "start" and index + 3 < len(args) and args[index + 2].lower() == "end":
                pool = {"start": args[index + 1], "end": args[index + 3]}; index += 4
            elif index < len(args) and "-" in args[index]:
                start, end = args[index].split("-", 1); pool = {"start": start, "end": end}; index += 1
            else:
                index += 1
                continue
            if index < len(args) and args[index].lower() in {"enable", "disable"}:
                pool["enabled"] = args[index].lower() == "enable"; index += 1
            subnet.setdefault(pools_key, []).append(pool)
        elif key in {"default_lease", "max_lease", "default_gateway", "domain", "dns"} and index + 1 < len(args):
            value = args[index + 1]; index += 2
            if key == "dns": subnet["dns_servers"] = [item for item in value.split(",") if item]
            elif key == "max_lease": subnet["maximum_lease"] = value
            elif key == "default_gateway": subnet["gateway"] = value
            else: subnet[key] = value
        else:
            index += 1
    return GaiaEvaluation("dhcp-server", "server", {"subnets": [subnet]}, {"subnets"}, node.line_number)


def _merge(target: GaiaEvaluation, source: GaiaEvaluation) -> None:
    for key, value in source.values.items():
        if key == "subnets" and isinstance(value, list):
            existing = {item.get("subnet"): item for item in target.values.setdefault(key, [])}
            for subnet in value:
                current = existing.get(subnet.get("subnet"))
                if current is None:
                    target.values[key].append(subnet)
                    continue
                for field, field_value in subnet.items():
                    if field in {"included_pools", "excluded_pools"}:
                        pools = current.setdefault(field, [])
                        for pool in field_value:
                            match = next((item for item in pools if item.get("start") == pool.get("start") and item.get("end") == pool.get("end")), None)
                            if match is None: pools.append(pool)
                            else: match.update(pool)
                    else:
                        current[field] = field_value
            continue
        if isinstance(value, list) and isinstance(target.values.get(key), list):
            target.values[key].extend(item for item in value if item not in target.values[key])
        else:
            target.values[key] = value
    target.explicit_fields.update(source.explicit_fields)
