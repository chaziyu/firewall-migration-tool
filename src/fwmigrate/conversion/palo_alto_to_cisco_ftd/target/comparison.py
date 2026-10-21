"""Exact native object reuse and target comparison for Cisco FMC."""

from collections import defaultdict
from dataclasses import replace

from ..models import FTDFinding
from ..plan_dependencies import ordered_items


def _get_id(obj):
    return (
        getattr(obj, "source_id", None)
        or getattr(obj, "id", None)
        or (getattr(obj, "raw_extra", {}) or {}).get("id")
    )


def _match_address(obj, operation):
    body = operation.get("request_body_template", {})
    raw = getattr(obj, "raw_extra", {}) or {}
    obj_type = getattr(obj, "address_type", None) or getattr(obj, "type", None) or raw.get("type")
    obj_val = getattr(obj, "value", None) or raw.get("value")
    expected_type = body.get("type")
    expected_val = body.get("value")
    return obj_type == expected_type and obj_val == expected_val


def _match_service(obj, operation):
    body = operation.get("request_body_template", {})
    raw = getattr(obj, "raw_extra", {}) or {}
    obj_proto = getattr(obj, "protocol", "") or raw.get("protocol", "")
    obj_port = getattr(obj, "port", "") or raw.get("port", "")
    expected_proto = body.get("protocol", "")
    expected_port = body.get("port", "")
    return str(obj_proto).upper() == str(expected_proto).upper() and str(obj_port) == str(expected_port)


def classify_target_reuse(plan, evidence):
    names = defaultdict(list)
    for obj in evidence["network_addresses"]:
        if getattr(obj, "name", None):
            names[("address", obj.name.casefold())].append(obj)
    for obj in evidence["protocol_port_objects"]:
        if getattr(obj, "name", None):
            names[("service", obj.name.casefold())].append(obj)
    for obj in evidence["security_zones"]:
        if getattr(obj, "name", None):
            names[("zone", obj.name.casefold())].append(obj)
    for obj in evidence["network_groups"]:
        if getattr(obj, "name", None):
            names[("address_group", obj.name.casefold())].append(obj)
    for obj in evidence["port_object_groups"]:
        if getattr(obj, "name", None):
            names[("service_group", obj.name.casefold())].append(obj)

    families = evidence["complete_families"]
    completed = {}

    for row in ordered_items(plan):
        blockers, settings, disposition = list(row.blockers), dict(row.settings), None
        op = settings.get("fmc_operation")

        if row.family in {"address", "address_group", "service", "service_group", "zone"}:
            req_family = (
                "services" if row.family.startswith("service")
                else "zones" if row.family == "zone"
                else "objects"
            )
            if req_family not in families:
                blockers.append("TARGET_OBJECT_OR_FAMILY_INCOMPLETE")
            else:
                lookup_key = (
                    "service" if row.family == "service"
                    else "service_group" if row.family == "service_group"
                    else "address_group" if row.family == "address_group"
                    else "zone" if row.family == "zone"
                    else "address"
                )
                existing = names.get((lookup_key, row.target_name.casefold()), ())
                if existing:
                    obj = existing[0]
                    obj_id = _get_id(obj)
                    compatible = False
                    if len(existing) == 1 and obj_id:
                        if row.family in {"address_group", "service_group"}:
                            expected_deps = [dict(completed[k].settings).get("target_id") for k in row.dependencies]
                            raw_members = getattr(obj, "objects", ()) or getattr(obj, "members", ())
                            actual_ids = [
                                _get_id(m) if (hasattr(m, "id") or hasattr(m, "source_id") or hasattr(m, "raw_extra")) else str(m)
                                for m in raw_members
                            ]
                            compatible = (
                                bool(expected_deps)
                                and all(expected_deps)
                                and len(actual_ids) == len(set(actual_ids))
                                and set(actual_ids) == set(expected_deps)
                            )
                        elif row.family == "zone":
                            raw = getattr(obj, "raw_extra", {}) or {}
                            mode = getattr(obj, "interface_mode", None) or getattr(obj, "interfaceMode", None) or raw.get("interfaceMode")
                            compatible = (mode == "ROUTED")
                        elif row.family == "address" and op:
                            compatible = _match_address(obj, op)
                        elif row.family == "service" and op:
                            compatible = _match_service(obj, op)

                    if compatible:
                        settings["target_id"] = obj_id
                        disposition = "REUSE"
                    else:
                        blockers.append("TARGET_OBJECT_COLLISION_OR_EQUIVALENCE_UNKNOWN")

        elif row.family in {"policy", "acp"}:
            blockers.append("EXISTING_TARGET_POLICY_INSERTION_NOT_PROVEN")

        completed[row.key] = replace(
            row,
            settings=tuple(settings.items()),
            blockers=tuple(dict.fromkeys(blockers)),
            target_disposition=disposition,
        )

    findings = [
        *plan.findings,
        FTDFinding(
            "DESTINATION_SNAPSHOT_COMPARED",
            "Scoped FMC object evidence compared; existing policy and device deployment remain unverified.",
            blocking=False,
        ),
    ]

    # Check device interface assignment
    devices = evidence.get("devices", ())
    if not devices:
        findings.append(
            FTDFinding(
                "UNRESOLVED_INTERFACE_ASSIGNMENT_PREREQUISITE",
                "Security zones must be assigned to FTD device interfaces before traffic can be enforced. Interface assignment remains manual.",
                blocking=False,
            )
        )

    return replace(plan, items=tuple(completed[row.key] for row in plan.items), findings=tuple(findings))
