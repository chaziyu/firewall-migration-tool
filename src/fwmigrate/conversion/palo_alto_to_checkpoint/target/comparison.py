"""Exact native object UID reuse; existing policy placement remains blocked."""

from collections import defaultdict
from dataclasses import replace

from ..models import CPFinding
from ..plan_dependencies import ordered_items


def _matches(obj, operation):
    body = operation["request_body_template"]
    if obj.raw_extra:
        return False
    path = operation["path"]
    if path == "/web_api/add-host":
        return (obj.object_type == "host" and obj.ipv4_address == body.get("ipv4-address")
                and not obj.ipv6_address and obj.nat_settings == {"auto-rule": False})
    if path == "/web_api/add-network":
        return (obj.object_type == "network" and obj.subnet4 == body.get("subnet4")
                and obj.mask_length4 == body.get("mask-length4") and not obj.subnet6
                and obj.nat_settings == {"auto-rule": False})
    if path == "/web_api/add-address-range":
        return (obj.object_type == "address-range" and obj.ipv4_address_first == body.get("ipv4-address-first")
                and obj.ipv4_address_last == body.get("ipv4-address-last")
                and obj.nat_settings == {"auto-rule": False})
    # shortcut: service reuse lacks complete protocol/inspection evidence; extend with explicit native fixtures.
    return False


def classify_target_reuse(plan, evidence):
    names = defaultdict(list)
    for obj in evidence["objects"]:
        if obj.name:
            names[obj.name.casefold()].append(obj)
    families = evidence["complete_families"]
    completed = {}
    for row in ordered_items(plan):
        blockers, settings, disposition = list(row.blockers), dict(row.settings), None
        if row.family in {"address", "address_group", "service", "service_group"}:
            required = "services" if row.family.startswith("service") else "objects"
            if required not in families or "nat" not in families:
                blockers.append("TARGET_OBJECT_OR_NAT_FAMILY_INCOMPLETE")
            else:
                existing = names[row.target_name.casefold()]
                if existing:
                    obj = existing[0]
                    compatible = False
                    if len(existing) == 1 and obj.uid and not obj.raw_extra:
                        if row.family in {"address_group", "service_group"}:
                            expected = [dict(completed[key].settings).get("target_uid") for key in row.dependencies]
                            actual = [ref if isinstance(ref, str) else ref.uid for ref in obj.members or ()] if hasattr(obj, "members") else []
                            compatible = (obj.object_type == ("group" if row.family == "address_group" else "service-group")
                                and bool(expected) and all(expected) and len(actual) == len(set(actual))
                                and set(actual) == set(expected))
                        elif settings.get("management_operation"):
                            compatible = _matches(obj, settings["management_operation"])
                    if compatible:
                        settings["target_uid"], disposition = obj.uid, "REUSE"
                    else:
                        blockers.append("TARGET_OBJECT_COLLISION_OR_EQUIVALENCE_UNKNOWN")
        elif row.family in {"policy", "package", "layer", "cleanup"}:
            blockers.append("EXISTING_TARGET_POLICY_INSERTION_NOT_PROVEN")
        completed[row.key] = replace(row, settings=tuple(settings.items()),
            blockers=tuple(dict.fromkeys(blockers)), target_disposition=disposition)
    findings = (*plan.findings, CPFinding("DESTINATION_SNAPSHOT_COMPARED",
        "Scoped Management object evidence compared; existing policy, Gaia and live acceptance remain unverified.", blocking=False))
    return replace(plan, items=tuple(completed[row.key] for row in plan.items), findings=findings)
