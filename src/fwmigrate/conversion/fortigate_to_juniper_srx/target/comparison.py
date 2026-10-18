"""Fail-closed Junos destination comparison for the SRX migration pair."""

from dataclasses import replace
import shlex

from ..models import SRXFinding
from ..plan_dependencies import validate_plan
from ..rendering.renderer import _commands_for
from .evidence import SRXTargetEvidence, _ITEM_FAMILY


_REQUIRED_FAMILIES = {"policy": ("policies", "nat")}


def _item_prefix(item):
    values = dict(item.settings)
    name = item.target_name
    if item.family in {"address", "address_group"}:
        kind = "address" if item.family == "address" else "address-set"
        return ("security", "address-book", "global", kind, name)
    if item.family in {"service", "service_group"}:
        kind = "application" if item.family == "service" else "application-set"
        return ("applications", kind, name)
    if item.family == "interface":
        if values.get("vlan_trunk"):
            return ("interfaces", name.rsplit(".", 1)[0])
        return ("interfaces", name.rsplit(".", 1)[0], "unit", str(values["unit"]))
    if item.family == "zone":
        return ("security", "zones", "security-zone", name)
    if item.family == "static_route":
        return ("routing-options", "static", "route", str(values["destination"]))
    if item.family == "schedule":
        return ("schedulers", "scheduler", name)
    if item.family == "policy":
        return ("security", "policies", "from-zone", str(values["from_zone"]),
                "to-zone", str(values["to_zone"]), "policy", name)
    if item.family in {"source_nat", "source_nat_pool"}:
        return ("security", "nat")
    raise ValueError(f"Unsupported SRX target comparison family: {item.family}")


def _is_prefix(prefix, path):
    return len(path) >= len(prefix) and tuple(token.casefold() for token in path[:len(prefix)]) == tuple(
        token.casefold() for token in prefix
    )


def _paths_for_commands(commands):
    active, inactive = set(), set()
    for command in commands:
        tokens = shlex.split(command)
        if tokens and tokens[0] == "set":
            active.add(tuple(tokens[1:]))
        elif tokens and tokens[0] == "deactivate":
            inactive.add(tuple(tokens[1:]))
    return active, inactive


def _item_entries(item, prefix, evidence):
    return [statement for statement in evidence.statements
            if statement.get("context", "root") == "root"
            and _is_prefix(prefix, tuple(statement.get("target_path") or ()))
            and statement.get("status") in {"EFFECTIVE", "INACTIVE"}]


def _inactive_at(prefix, entries, evidence):
    if any(item.get("context", "root") == "root"
           and (_is_prefix(prefix, tuple(item.get("path") or ()))
                or _is_prefix(tuple(item.get("path") or ()), prefix))
           for item in evidence.inactive_hierarchies):
        return True
    return any(item.get("status") == "INACTIVE" for item in entries)


def _policy_names_by_pair(evidence):
    rows = {}
    for statement in evidence.statements:
        path = tuple(statement.get("target_path") or ())
        if (statement.get("context", "root") != "root"
                or statement.get("status") not in {"EFFECTIVE", "INACTIVE"}
                or len(path) < 8 or path[:2] != ("security", "policies")
                or path[2] != "from-zone" or path[4] != "to-zone" or path[6] != "policy"):
            continue
        key = (path[3], path[5])
        rows.setdefault(key, []).append((statement.get("source_order", 0), path[7]))
    result = {}
    for pair, entries in rows.items():
        result[pair] = tuple(dict.fromkeys(name for _, name in sorted(entries, key=lambda row: row[0])))
    return result


def _policy_table_is_safe(item, plan, evidence):
    values = dict(item.settings)
    pair = (values.get("from_zone"), values.get("to_zone"))
    planned_names = tuple(
        candidate.target_name for candidate in sorted(
            (candidate for candidate in plan.items
             if candidate.family == "policy" and not candidate.blockers
             and dict(candidate.settings).get("from_zone") == pair[0]
             and dict(candidate.settings).get("to_zone") == pair[1]),
            key=lambda candidate: (candidate.source_order, candidate.key),
        )
    )
    return _policy_names_by_pair(evidence).get(pair, ()) == planned_names


def _address_book_collision(item, evidence):
    values = dict(item.settings)
    policy_names = set(values.get("source_addresses", ())) | set(values.get("destination_addresses", ()))
    if not policy_names:
        return False
    attachments = {}
    objects = set()
    for statement in evidence.statements:
        if statement.get("context", "root") != "root" or statement.get("status") != "EFFECTIVE":
            continue
        path = tuple(statement.get("target_path") or ())
        if (len(path) == 6 and path[:2] == ("security", "address-book")
                and path[3:5] == ("attach", "zone")):
            attachments.setdefault(path[5], set()).add(path[2])
        if (len(path) >= 5 and path[:2] == ("security", "address-book")
                and path[2] != "global" and path[3] in {"address", "address-set"}):
            objects.add((path[2], path[4]))
    for zone in (values.get("from_zone"), values.get("to_zone")):
        local_books = attachments.get(zone, set()) - {"global"}
        if any((book, name) in objects for book in local_books for name in policy_names):
            return True
    return False


def _routing_instance_conflict(item, plan, evidence):
    values = dict(item.settings)
    zone_names = {values.get("from_zone"), values.get("to_zone")}
    interfaces = {
        interface
        for zone in plan.items if zone.family == "zone" and zone.target_name in zone_names
        for interface in dict(zone.settings).get("interfaces", ())
    }
    return any(statement.get("context", "root") == "root"
               and statement.get("status") == "EFFECTIVE"
               and (path := tuple(statement.get("target_path") or ()))
               and len(path) >= 4 and path[0] == "routing-instances" and path[2] == "interface"
               and path[3] in interfaces for statement in evidence.statements)


def compare_target_plan(plan, evidence: SRXTargetEvidence):
    """Classify exact reuse, proven absence, and target conflicts without overwrites."""
    if not isinstance(evidence, SRXTargetEvidence):
        raise TypeError("SRX target comparison requires validated Junos evidence")
    plan = validate_plan(plan)
    by_target_name = {item.target_name: item for item in plan.items}
    findings = list(plan.findings)
    items = []
    for code in evidence.global_blockers:
        findings.append(SRXFinding(code, code.replace("_", " ").capitalize(),
                                   plan.source_vdom, "target", "Juniper SRX"))

    policy_group_inheritance = any(
        statement.get("origin") == "inherited-group"
        and tuple(statement.get("target_path") or ())[:2] == ("security", "policies")
        for statement in evidence.statements
    )
    for item in plan.items:
        if item.blockers:
            items.append(replace(item, target_disposition="BLOCK"))
            continue
        blockers = list(item.blockers)
        family = _ITEM_FAMILY.get(item.family)
        if item.family == "policy" and policy_group_inheritance:
            blockers.append("TARGET_POLICY_ORDER_INHERITANCE_UNVERIFIED")
        for required_family in _REQUIRED_FAMILIES.get(item.family, (family,)):
            blockers.extend(evidence.blockers_for(required_family or ""))
        blockers.extend(evidence.global_blockers)
        prefix = _item_prefix(item)
        entries = _item_entries(item, prefix, evidence)
        if _inactive_at(prefix, entries, evidence):
            blockers.append("TARGET_INACTIVE_CONFIGURATION_CONFLICT")

        try:
            commands = _commands_for(item, by_target_name)
            expected, expected_inactive = _paths_for_commands(commands)
        except (KeyError, TypeError, ValueError):
            expected, expected_inactive = set(), set()
            blockers.append("TARGET_COMPARISON_RENDER_UNAVAILABLE")

        present = {tuple(statement.get("target_path") or ()) for statement in entries}
        inactive_expected = bool(expected_inactive)
        actual_disabled = _inactive_at(prefix, entries, evidence)
        exact = (bool(expected) and present == expected
                 and (actual_disabled if inactive_expected else not actual_disabled)
                 and (not inactive_expected or expected_inactive))

        if item.family == "policy" and not blockers:
            if any(tuple(statement.get("target_path") or ())[:2] == ("security", "nat")
                   for statement in evidence.statements):
                blockers.append("TARGET_NAT_POLICY_INTERACTION_UNVERIFIED")
            if not _policy_table_is_safe(item, plan, evidence):
                blockers.append("TARGET_POLICY_ORDER_UNVERIFIED")
            if _address_book_collision(item, evidence):
                blockers.append("TARGET_ZONE_ADDRESS_BOOK_RESOLUTION_UNVERIFIED")
            if _routing_instance_conflict(item, plan, evidence):
                blockers.append("TARGET_POLICY_ROUTING_INSTANCE_UNVERIFIED")

        if item.family == "policy" and not exact:
            blockers.append("TARGET_POLICY_INSERTION_ANCHOR_UNVERIFIED")
        elif not exact and (present or entries or _inactive_at(prefix, entries, evidence)):
            blockers.append("TARGET_CONFIGURATION_CONFLICT")

        if blockers:
            items.append(replace(item, blockers=tuple(dict.fromkeys(blockers)), target_disposition="BLOCK"))
        else:
            items.append(replace(item, target_disposition="REUSE" if exact else "CREATE"))

    return validate_plan(replace(plan, items=tuple(items), findings=tuple(findings)))


__all__ = ["compare_target_plan"]
