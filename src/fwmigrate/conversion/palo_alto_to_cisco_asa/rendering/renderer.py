"""Native ASA commands from dependency-validated pair-owned settings."""

import hashlib
from ipaddress import IPv4Interface, IPv4Network

from ..models import ASARenderedMigration
from ..plan_dependencies import TRAFFIC, ordered_items, validate_plan


def _port(value):
    return "range " + value.replace("-", " ") if "-" in value else "eq " + value


def _commands(item, by_key):
    value, name = dict(item.settings), item.target_name
    if item.family == "address":
        if value["address_type"] == "prefix":
            network = IPv4Network(value["value"])
            command = f" host {network.network_address}" if network.prefixlen == 32 else f" subnet {network.network_address} {network.netmask}"
        else:
            command = f" range {value['range_start']} {value['range_end']}"
        return [f"object network {name}", command, "exit"]
    if item.family in {"address_group", "service_group"}:
        kind = "network" if item.family == "address_group" else "service"
        commands = [f"object-group {kind} {name}"]
        for dependency in item.dependencies:
            row = by_key[dependency]
            commands.append(f" group-object {row.target_name}" if row.family.endswith("group") or kind == "service" else
                            f" {'network-object' if kind == 'network' else 'service-object'} object {row.target_name}")
        return [*commands, "exit"]
    if item.family == "service":
        commands = [f"object-group service {name}"]
        for source_port in value.get("source_ports", (None,)):
            for destination_port in value["destination_ports"]:
                src = f" source {_port(source_port)}" if source_port else ""
                commands.append(f" service-object {value['protocol']}{src} destination {_port(destination_port)}")
        return [*commands, "exit"]
    if item.family == "interface":
        link = IPv4Interface(value["address"])
        return [f"interface {value['interface']}", " shutdown", f" nameif {value['nameif']}",
                f" security-level {value['security_level']}", f" ip address {link.ip} {link.netmask}", "exit"]
    if item.family == "static_route":
        network = IPv4Network(value["destination"])
        return [f"route {value['nameif']} {network.network_address} {network.netmask} {value['gateway']} {value['distance']}"]
    if item.family in TRAFFIC:
        return list(value.get("commands", ()))
    raise ValueError("Unsupported ASA render family")


class ASACLIRenderer:
    def render(self, plan):
        plan = validate_plan(plan)
        by_key = {row.key: row for row in plan.items}
        commands = []
        for item in ordered_items(plan):
            if item.target_disposition == "REUSE":
                continue
            commands.extend(_commands(item, by_key))
        text = "\n".join(commands) + ("\n" if commands else "")
        return ASARenderedMigration(tuple(commands), hashlib.sha256(text.encode()).hexdigest(),
                                    tuple((row.key, row.blockers) for row in plan.items if row.blockers))
