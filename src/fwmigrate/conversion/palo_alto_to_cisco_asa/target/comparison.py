"""Exact object reuse without replacing target ACLs or changing existing traffic."""

from dataclasses import replace

from ..plan_dependencies import TRAFFIC
from ..rendering.renderer import _commands


def classify_target_reuse(plan, evidence):
    actual = dict(evidence.blocks)
    by_key = {row.key: row for row in plan.items}
    result = []
    for item in plan.items:
        reasons = list(evidence.global_blockers)
        family = "addresses" if item.family in {"address", "address_group"} else "services"
        if item.family in TRAFFIC:
            reasons.append("EXISTING_TARGET_TRAFFIC_PLACEMENT_UNSUPPORTED")
        elif item.family in {"address", "address_group", "service", "service_group"}:
            reasons.extend(evidence.blockers_for(family))
            if not item.blockers and not reasons:
                commands = _commands(item, by_key)
                header, body = commands[0], tuple(line.strip() for line in commands[1:-1])
                if header in actual:
                    if actual[header] == body:
                        result.append(replace(item, target_disposition="REUSE"))
                        continue
                    reasons.append("TARGET_OBJECT_CONFLICT")
                # ASA group names share a namespace even across network/service types.
                if any(key.split()[-1].casefold() == item.target_name.casefold() and key != header for key in actual):
                    reasons.append("TARGET_OBJECT_NAMESPACE_CONFLICT")
        result.append(replace(item, blockers=tuple(dict.fromkeys((*item.blockers, *reasons)))))
    return tuple(result)
