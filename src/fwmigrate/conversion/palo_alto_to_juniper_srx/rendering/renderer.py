"""Deterministic Junos set rendering for supported PAN-OS plan items."""

from collections import defaultdict
import hashlib
import heapq

from ..models import SRXRenderedMigration


_ORDER = {"address": 0, "address_group": 1, "service": 2, "service_group": 3,
          "interface": 4, "zone": 5, "static_route": 6, "policy": 7}


def _settings(item):
    return dict(item.settings)


def _commands(item, by_key):
    value, name = _settings(item), item.target_name
    if item.family == "address":
        if value.get("address_type") == "prefix":
            return [f"set security address-book global address {name} {value['value']}"]
        if value.get("address_type") == "range":
            return [f"set security address-book global address {name} range-address {value['range_start']} to {value['range_end']}"]
    if item.family == "address_group":
        rows = []
        for member, dependency_key in zip(value["members"], item.dependencies):
            dependency = by_key.get(dependency_key)
            if dependency is None:
                raise ValueError("Address group member is absent from the validated plan")
            kind = "address-set" if dependency.family == "address_group" else "address"
            rows.append(f"set security address-book global address-set {name} {kind} {member}")
        return rows
    if item.family == "service":
        prefix = f"set applications application {name}"
        rows = [f"{prefix} protocol {value['protocol']}"]
        rows.extend(f"{prefix} destination-port {port}" for port in value["destination_ports"])
        rows.extend(f"{prefix} source-port {port}" for port in value.get("source_ports", ()))
        return rows
    if item.family == "service_group":
        rows = []
        for member, dependency_key in zip(value["members"], item.dependencies):
            dependency = by_key.get(dependency_key)
            if dependency is None:
                raise ValueError("Service group member is absent from the validated plan")
            kind = "application-set" if dependency.family == "service_group" else "application"
            rows.append(f"set applications application-set {name} {kind} {member}")
        return rows
    if item.family == "interface":
        physical, unit = value["physical_interface"], value["unit"]
        rows = []
        if value.get("vlan_trunk"):
            return [f"set interfaces {physical} vlan-tagging"]
        if value.get("tag") is not None:
            rows.append(f"set interfaces {physical} vlan-tagging")
            rows.append(f"set interfaces {physical} unit {unit} vlan-id {value['tag']}")
        if value.get("address"):
            rows.append(f"set interfaces {physical} unit {unit} family inet address {value['address']}")
        return rows
    if item.family == "zone":
        return [f"set security zones security-zone {name} interfaces {member}"
                for member in value["interfaces"]]
    if item.family == "static_route":
        prefix = f"set routing-options static route {value['destination']}"
        return [f"{prefix} next-hop {value['gateway']}", f"{prefix} metric {value['metric']}"]
    if item.family == "policy":
        prefix = f"set security policies from-zone {value['from_zone']} to-zone {value['to_zone']} policy {name}"
        rows = [f"{prefix} match source-address {entry}" for entry in value["source_addresses"]]
        rows.extend(f"{prefix} match destination-address {entry}" for entry in value["destination_addresses"])
        rows.extend(f"{prefix} match application {entry}" for entry in value["applications"])
        rows.append(f"{prefix} then {value['action']}")
        if value.get("log_start"):
            rows.append(f"{prefix} then log session-init")
        if value.get("log_end"):
            rows.append(f"{prefix} then log session-close")
        return rows
    raise ValueError(f"Unsupported PAN-OS to SRX family: {item.family}")


class JunosSetRenderer:
    def render(self, plan):
        by_key = {item.key: item for item in plan.items}
        blockers = {key: list(item.blockers) for key, item in by_key.items()}
        target_owners = defaultdict(list)
        for item in plan.items:
            if item.family in _ORDER:
                policy_scope = (_settings(item).get("from_zone"), _settings(item).get("to_zone")) if item.family == "policy" else ()
                target_owners[(item.family, item.target_name.casefold(), *policy_scope)].append(item.key)
        for owners in target_owners.values():
            if len(owners) > 1:
                for key in owners:
                    blockers[key].append("DUPLICATE_TARGET_OBJECT_NAME")
        for item in plan.items:
            if item.family not in _ORDER and item.family not in {"inactive_nat", "inactive_policy"}:
                blockers[item.key].append("RENDER_FAMILY_UNSUPPORTED")
            if any(dependency not in by_key for dependency in item.dependencies):
                blockers[item.key].append("PLAN_DEPENDENCY_UNRESOLVED")
        changed = True
        while changed:
            changed = False
            for item in plan.items:
                if not blockers[item.key] and any(blockers.get(dependency) for dependency in item.dependencies):
                    blockers[item.key].append("PLAN_DEPENDENCY_BLOCKED")
                    changed = True
        eligible = [item for item in plan.items if item.family in _ORDER and not blockers[item.key]
                    and item.target_disposition not in {"BLOCK", "REUSE"}]
        dependents = defaultdict(list)
        remaining = {item.key: set(item.dependencies) for item in eligible}
        ready = []
        for item in eligible:
            for dependency in tuple(remaining[item.key]):
                if dependency in remaining:
                    dependents[dependency].append(item.key)
                else:
                    remaining[item.key].discard(dependency)
            if not remaining[item.key]:
                heapq.heappush(ready, (_ORDER[item.family], item.source_order, item.key))
        ordered = []
        while ready:
            _, _, key = heapq.heappop(ready)
            ordered.append(by_key[key])
            for dependent in dependents[key]:
                remaining[dependent].discard(key)
                if not remaining[dependent]:
                    child = by_key[dependent]
                    heapq.heappush(ready, (_ORDER[child.family], child.source_order, child.key))
        if len(ordered) != len(eligible):
            for item in eligible:
                if item.key not in {row.key for row in ordered}:
                    blockers[item.key].append("PLAN_DEPENDENCY_CYCLE")
        commands = []
        for item in ordered:
            if not blockers[item.key]:
                commands.extend(_commands(item, by_key))
        command_tuple = tuple(commands)
        command_text = "\n".join(command_tuple) + ("\n" if command_tuple else "")
        digest = hashlib.sha256(command_text.encode("utf-8")).hexdigest()
        blocked = tuple((item.key, tuple(dict.fromkeys(blockers[item.key])))
                        for item in plan.items if blockers[item.key])
        return SRXRenderedMigration(command_tuple, digest, blocked)
