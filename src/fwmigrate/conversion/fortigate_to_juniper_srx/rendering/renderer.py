"""Deterministic Junos set rendering for validated SRX plan items."""

from collections import Counter
from dataclasses import dataclass, replace
import hashlib

from ..models import SRXMigrationPlan, SRXPlanItem
from ..plan_dependencies import assess_render_disposition, validate_plan


_FAMILY_ORDER = {
    "address": 0,
    "address_group": 1,
    "service": 2,
    "service_group": 3,
    "interface": 4,
    "zone": 5,
    "static_route": 6,
    "schedule": 7,
    "source_nat_pool": 8,
    "source_nat": 9,
    "policy": 8,
}


@dataclass(frozen=True, slots=True)
class SRXRenderedMigration:
    commands: tuple[str, ...]
    command_sha256: str
    family_counts: tuple[tuple[str, int], ...]
    blocked_items: tuple[tuple[str, tuple[str, ...]], ...]

    @property
    def command_count(self) -> int:
        return len(self.commands)

    @property
    def command_text(self) -> str:
        return "\n".join(self.commands) + ("\n" if self.commands else "")


def _settings(item):
    return dict(item.settings)


def _topological_order(items, satisfied=()):
    by_key = {item.key: item for item in items}
    ordered = []
    emitted = set()
    while len(ordered) < len(items):
        ready = [item for item in items if item.key not in emitted
                 and set(item.dependencies) <= emitted | set(satisfied)]
        if not ready:
            return ordered
        item = min(ready, key=lambda row: (_FAMILY_ORDER[row.family], row.source_order, row.key))
        ordered.append(item)
        emitted.add(item.key)
    return ordered


def _membership_command(item, member, by_target_name):
    member_item = by_target_name.get(member)
    if member_item is None:
        raise ValueError("SRX group member is missing from the validated plan")
    if item.family == "address_group":
        kind = "address-set" if member_item.family == "address_group" else "address"
    else:
        kind = "application-set" if member_item.family == "service_group" else "application"
    if item.family == "address_group":
        return f"set security address-book global address-set {item.target_name} {kind} {member}"
    return f"set applications application-set {item.target_name} {kind} {member}"


def _commands_for(item, by_target_name):
    values = _settings(item)
    name = item.target_name
    if item.family == "source_nat_pool" and values.get("translated_address"):
        prefix = f"set security nat source pool {name}"
        return [f"{prefix} address {values['translated_address']}/32", f"{prefix} port no-translation"]
    if item.family == "source_nat" and all(values.get(field) for field in ("source_prefix", "destination_prefix", "from_zone", "to_zone", "pool_name")):
        prefix = f"set security nat source rule-set {name}"
        rule = f"{prefix} rule {name}"
        return [f"{prefix} from zone {values['from_zone']}", f"{prefix} to zone {values['to_zone']}",
                f"{rule} match source-address {values['source_prefix']}",
                f"{rule} match destination-address {values['destination_prefix']}",
                f"{rule} then source-nat pool {values['pool_name']}"]
    if item.family == "address":
        if values.get("address_type") == "prefix" and values.get("value"):
            return [f"set security address-book global address {name} {values['value']}"]
        if values.get("address_type") == "range" and values.get("range_start") and values.get("range_end"):
            return [f"set security address-book global address {name} range-address {values['range_start']} to {values['range_end']}"]
    elif item.family == "address_group":
        members = values.get("members") or ()
        if members:
            return [_membership_command(item, member, by_target_name) for member in members]
    elif item.family == "service":
        protocol, destination = values.get("protocol"), values.get("destination_port")
        if protocol in {"tcp", "udp"} and destination:
            prefix = f"set applications application {name}"
            commands = [f"{prefix} protocol {protocol}"]
            if values.get("source_port"):
                commands.append(f"{prefix} source-port {values['source_port']}")
            commands.append(f"{prefix} destination-port {destination}")
            return commands
    elif item.family == "service_group":
        members = values.get("members") or ()
        if members:
            return [_membership_command(item, member, by_target_name) for member in members]
    elif item.family == "interface":
        address, unit = values.get("ipv4_address"), values.get("unit")
        physical = name.rsplit('.', 1)[0]
        if values.get("vlan_trunk"):
            return [f"set interfaces {physical} vlan-tagging"]
        if address and type(unit) is int:
            commands = [f"set interfaces {physical} unit {unit} family inet address {address}"]
            if values.get("vlan_id") is not None:
                commands.insert(0, f"set interfaces {physical} unit {unit} vlan-id {values['vlan_id']}")
            return commands
    elif item.family == "zone":
        interfaces = values.get("interfaces") or ()
        if interfaces:
            return [f"set security zones security-zone {name} interfaces {interface}"
                    for interface in interfaces]
    elif item.family == "static_route":
        destination, gateway = values.get("destination"), values.get("next_hop")
        if destination and gateway:
            prefix = f"set routing-options static route {destination}"
            commands = [f"{prefix} next-hop {gateway}"]
            if values.get("preference") is not None:
                commands.append(f"{prefix} preference {values['preference']}")
            return commands
    elif item.family == "schedule":
        if values.get("days") and values.get("start") and values.get("end"):
            return [f"set schedulers scheduler {name} {day} start-time {values['start']} stop-time {values['end']}"
                    for day in values["days"]]
        if values.get("start") and values.get("end"):
            return [f"set schedulers scheduler {name} start-date {values['start']}",
                    f"set schedulers scheduler {name} stop-date {values['end']}"]
    elif item.family == "policy":
        from_zone, to_zone = values.get("from_zone"), values.get("to_zone")
        sources, destinations = values.get("source_addresses"), values.get("destination_addresses")
        applications, action = values.get("applications"), values.get("action")
        if from_zone and to_zone and sources and destinations and applications and action in {"permit", "deny"}:
            prefix = f"set security policies from-zone {from_zone} to-zone {to_zone} policy {name}"
            commands = [f"{prefix} match source-address {address}" for address in sources]
            commands.extend(f"{prefix} match destination-address {address}" for address in destinations)
            commands.extend(f"{prefix} match application {application}" for application in applications)
            commands.append(f"{prefix} then {action}")
            if values.get("logging") == "all":
                commands.extend((f"{prefix} then log session-init", f"{prefix} then log session-close"))
            if values.get("schedule"):
                commands.append(f"{prefix} scheduler-name {values['schedule']}")
            if values.get("disabled"):
                commands.append(f"deactivate security policies from-zone {from_zone} to-zone {to_zone} policy {name}")
            return commands
    raise ValueError(f"Validated SRX {item.family} item has incomplete render settings")


class JunosSetRenderer:
    """Render only dependency-complete items in deterministic Junos set form."""

    def render(self, plan: SRXMigrationPlan) -> SRXRenderedMigration:
        plan = validate_plan(plan)
        unknown_families = {item.family for item in plan.items if item.family not in _FAMILY_ORDER}
        if unknown_families:
            plan = replace(plan, items=tuple(
                replace(item, blockers=tuple(dict.fromkeys((*item.blockers, "RENDER_FAMILY_UNSUPPORTED"))))
                if item.family in unknown_families else item
                for item in plan.items
            ))
        dispositions = assess_render_disposition(plan)
        allowed = [item for item in plan.items if dispositions[item.key] == "CREATE"]
        reused = {key for key, disposition in dispositions.items() if disposition == "REUSE"}
        ordered = _topological_order(allowed, reused)
        by_target_name = {item.target_name: item for item in plan.items}
        commands = []
        seen = set()
        rendered_families = Counter()
        for item in ordered:
            item_commands = _commands_for(item, by_target_name)
            unique = [command for command in item_commands if command not in seen]
            commands.extend(unique)
            seen.update(unique)
            rendered_families[item.family] += len(unique)
        commands = tuple(commands)
        digest = hashlib.sha256(("\n".join(commands) + ("\n" if commands else "")).encode("utf-8")).hexdigest()
        blocked = tuple((item.key, item.blockers or ("DEPENDENCY_BLOCKED",))
                        for item in plan.items if dispositions[item.key] == "BLOCK")
        return SRXRenderedMigration(
            commands=commands,
            command_sha256=digest,
            family_counts=tuple(sorted(rendered_families.items())),
            blocked_items=blocked,
        )
