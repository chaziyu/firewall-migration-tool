"""Conservative L3/L4 policies; unsupported earlier matches block successors."""
from dataclasses import replace

from .context import unsupported_fields
from .source_scope import identity, in_scope
from .naming import allocate_plan_names


def policy_choice(ctx, obj, field):
    explicit = getattr(obj, field)
    proposal = ctx.options.policy_settings.get(identity(obj, "policy"), {}).get(field)
    if explicit is not None and proposal is not None:
        raise ValueError("Target policy choices cannot override explicit source values")
    return explicit if explicit is not None else proposal


def plan_policies(ctx):
    rules = [r for r in ctx.source.security_rules if in_scope(r, ctx.scope)]
    rules.sort(key=lambda r: (r.source_order if r.source_order is not None else -1, r.source_path))
    names = allocate_plan_names(rules, "policy", limit=35)
    result = []
    predecessors = []
    for number, obj in enumerate(rules, 1):
        reasons = unsupported_fields(obj, {"from_zones", "to_zones", "source", "destination", "application", "service", "action", "source_user", "category",
             "negate_source", "negate_destination", "schedule", "rule_type", "log_start", "log_end", "disabled"})
        if obj.rulebase_position not in {None, "local"} or obj.source_order is None:
            reasons.append("Only verified standalone local rule ordering is supported.")
        if obj.action not in {"allow", "drop"}:
            reasons.append("Only explicit allow/drop actions are verified; application-dependent deny and reset actions remain manual.")
        if obj.application != ["any"]:
            reasons.append("App-ID and application-default conversion require manual implementation.")
        for field in ("source_user", "category"):
            if policy_choice(ctx, obj, field) not in (["any"], "any"):
                reasons.append(f"Explicit unrestricted {field} or a reviewed target choice is required.")
        if policy_choice(ctx, obj, "rule_type") != "universal":
            reasons.append("Choose universal target policy behavior; specialized rule types remain manual.")
        settings = {"name": names[identity(obj, "policy")], "action": "accept" if obj.action == "allow" else "deny", "nat": "disable", "utm-status": "disable"}
        dependencies = list(predecessors)
        for field, output, families in (("from_zones", "srcintf", ("zone",)), ("to_zones", "dstintf", ("zone",)),
                ("source", "srcaddr", ("address", "address_group")), ("destination", "dstaddr", ("address", "address_group")),
                ("service", "service", ("service", "service_group"))):
            values, deps, errors = ctx.resolve(obj, field, getattr(obj, field), families)
            settings[output] = values
            dependencies.extend(deps)
            reasons.extend(errors)
        if "application-default" in (obj.service or ()):
            reasons.append("application-default cannot become an unrestricted target service.")
        for field, output in (("negate_source", "srcaddr-negate"), ("negate_destination", "dstaddr-negate"), ("disabled", "status"), ("log_start", "logtraffic-start")):
            value = policy_choice(ctx, obj, field)
            if value not in {"yes", "no"}:
                reasons.append(f"Choose explicit target {field} behavior for the omitted source field.")
            else:
                enabled = (value == "no") if field == "disabled" else (value == "yes")
                settings[output] = "enable" if enabled else "disable"
        logging = policy_choice(ctx, obj, "log_end")
        if logging not in {"yes", "no"}:
            reasons.append("Choose explicit target log_end behavior.")
        settings["logtraffic"] = "all" if logging == "yes" else "disable"
        if policy_choice(ctx, obj, "log_start") == "yes" and logging == "no":
            reasons.append("Start-only logging has no verified equivalent and requires manual implementation.")
        if obj.action == "drop":
            settings["send-deny-packet"] = "disable"
        schedule = policy_choice(ctx, obj, "schedule")
        if obj.schedule is None and schedule == "always":
            settings["schedule"] = "always"
        else:
            values, deps, errors = ctx.resolve(obj, "schedule", [schedule] if schedule else None, ("schedule",))
            settings["schedule"] = values
            dependencies.extend(deps)
            reasons.extend(errors)
        if obj.description is not None:
            settings["comments"] = obj.description
        item = ctx.item(obj, "policy", "firewall policy", settings, dependencies, reasons, target_name=str(number))
        result.append(item)
        # All predecessors are dependencies: omitting even a supported deny from partial approval must not expose later allows.
        predecessors[:] = [item.key]
    if any(in_scope(r, ctx.scope) for r in ctx.source.default_security_rules):
        result = [replace(item, reasons=(*item.reasons, "Explicit default security-rule behavior requires separate manual design.")) for item in result]
    return result
