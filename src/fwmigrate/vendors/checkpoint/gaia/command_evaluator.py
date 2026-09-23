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
        values: dict[str, Any] = {"address_family": "ipv6" if kind.endswith("ipv6") else "ipv4"}
        values.update(_pairs(args[1:]))
        for index, value in enumerate(args):
            lower = value.lower()
            if lower in {"blackhole", "reject", "scopelocal"}:
                values[lower] = True
            elif lower in {"gateway", "address", "interface", "device", "priority", "rank", "comment", "nexthop"} and index + 1 < len(args):
                if lower == "gateway" and args[index + 1].lower() == "address":
                    continue
                key = {"address": "next_hop", "interface": "outgoing_interface", "device": "outgoing_interface"}.get(lower, lower)
                values.setdefault(key, args[index + 1])
        if "address" in values:
            values["next_hop"] = values.pop("address")
        values.pop("gateway", None)
        values.pop("nexthop", None)
        if identity and identity.lower() == "default":
            values["default"] = True
        elif identity:
            values["ipv6_destination" if kind.endswith("ipv6") else "ipv4_destination"] = identity
        return GaiaEvaluation(kind, identity, values, set(values), node.line_number)
    if kind == "dhcp-server":
        subnet_index = next((i for i, value in enumerate(args) if value.lower() == "subnet"), None)
        identity = "server"
        state = next((x for x in args if x.lower() in {"on", "off", "enabled", "disabled"}), None)
        if subnet_index is not None and subnet_index + 1 < len(args):
            subnet = args[subnet_index + 1]
            subnet_values = _pairs(args[subnet_index + 2:])
            subnet_values["subnet"] = subnet
            if "netmask" in subnet_values:
                subnet_values["prefix"] = subnet_values.pop("netmask")
            values = {"subnets": [subnet_values]}
        else:
            values = {"process_state": state} if state else _pairs(args)
        values = {key: value for key, value in values.items() if value is not None}
        return GaiaEvaluation(kind, identity, values, set(values), node.line_number)
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
        values = _pairs(args[1:])
        if isinstance(values.get("state"), bool):
            values["state"] = "on" if values["state"] else "off"
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


def _merge(target: GaiaEvaluation, source: GaiaEvaluation) -> None:
    for key, value in source.values.items():
        if isinstance(value, list) and isinstance(target.values.get(key), list):
            target.values[key].extend(item for item in value if item not in target.values[key])
        else:
            target.values[key] = value
    target.explicit_fields.update(source.explicit_fields)
