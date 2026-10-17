"""Explicit placement requirements presented before review."""
from .planning.source_scope import identity, in_scope, select_source_scope, source_scopes


def build_mapping_requirements(source, derived, options):
    scope, findings = select_source_scope(source, options)
    rows = [{"key": "source_scope", "label": "Source device / VSYS", "choices": source_scopes(source), "value": options.source_scope},
            {"key": "vdom", "label": "Target VDOM", "value": options.vdom}]
    if scope is not None:
        for family, items, values in (("zones", source.zones, options.zones), ("routers", source.virtual_routers, options.routers)):
            for item in items:
                if in_scope(item, scope) or (family == "routers" and item.scope and item.scope.device_name == scope.device_name):
                    rows.append({"key": f"{family}:{item.name}", "label": f"{family}: {item.name}", "value": values.get(item.name)})
        names = set()
        for zone in source.zones:
            if in_scope(zone, scope):
                names.update(zone.members or ())
        for imported in source.interface_imports:
            if in_scope(imported, scope):
                names.update(imported.interfaces or ())
        for item in (*source.interfaces, *source.interface_units):
            if item.name in names:
                names.add(getattr(item, "parent", None))
        for name in sorted(n for n in names if n):
            rows.append({"key": f"interfaces:{name}", "label": f"Interface: {name}", "value": options.interfaces.get(name)})
        choices = {"schedule": ["always"], "disabled": ["yes", "no"], "log_start": ["yes", "no"], "log_end": ["yes", "no"],
                   "negate_source": ["yes", "no"], "negate_destination": ["yes", "no"], "rule_type": ["universal"], "source_user": ["any"], "category": ["any"]}
        for rule in source.security_rules:
            if not in_scope(rule, scope):
                continue
            key = identity(rule, "policy")
            for field, values in choices.items():
                if getattr(rule, field) is None:
                    rows.append({"key": f"policy:{key}:{field}", "label": f"{rule.name}: omitted {field} — explicit target choice",
                                 "policy_key": key, "field": field, "choices": values,
                                 "value": options.policy_settings.get(key, {}).get(field)})
    def visible(items):
        return scope is not None and any(in_scope(item, scope) for item in items)
    return {"decisions": rows, "findings": list(findings), "source_scopes": source_scopes(source),
            "has_schedules": visible(source.schedules),
            "has_dnat": visible([r for r in source.nat_rules if r.destination_translation is not None]),
            "has_pool_snat": visible([r for r in source.nat_rules if r.source_translation is not None and getattr(r.source_translation, "translated_addresses", None)])}
