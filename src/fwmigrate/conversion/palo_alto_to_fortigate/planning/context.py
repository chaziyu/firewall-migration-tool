"""Pair-local source resolution and FortiOS item construction."""
from ..models import FGPlannedItem
from .naming import allocate_plan_names
from .source_scope import identity, in_scope
from fwmigrate.vendors.palo_alto.source_model import pan_scope_identity


class PlanningContext:
    def __init__(self, source, derived, options, scope):
        self.source, self.derived, self.options, self.scope = source, derived, options, scope
        families = {"address": "addresses", "address_group": "address_groups", "service": "services",
                    "service_group": "service_groups", "schedule": "schedules", "zone": "zones"}
        self.objects = {(family, identity(obj, family)): obj for family, field in families.items()
                        for obj in getattr(source, field) if in_scope(obj, scope)}
        self.names = allocate_plan_names(self.objects.values(), "name")
        self.references = {}
        for reference in derived.reference_resolutions:
            scope_key = pan_scope_identity(reference.source_scope) if reference.source_scope else "unscoped"
            key = (reference.owner_source_path, reference.owner_name, scope_key, reference.owner_field, reference.reference_name)
            self.references.setdefault(key, []).append(reference)
        self.targets = {}
        for (family, _), obj in self.objects.items():
            self.targets.setdefault((family, obj.source_path, obj.name, pan_scope_identity(obj.scope)), []).append(obj)

    def name(self, obj):
        return self.names.get(identity(obj, "name"), obj.name or "unnamed")

    def item(self, obj, family, section, settings=None, dependencies=(), reasons=(), **kwargs):
        return FGPlannedItem(identity(obj, family), family, pan_scope_identity(obj.scope), obj.name or "unnamed",
            obj.source_path, kwargs.pop("target_name", self.name(obj)), self.options.vdom, section,
            tuple((key, tuple(str(v) for v in (value if isinstance(value, (list, tuple)) else (value,))))
                  for key, value in (settings or {}).items()), tuple(dict.fromkeys(dependencies)), tuple(dict.fromkeys(reasons)), **kwargs)

    def resolve(self, owner, field, names, families):
        if not names:
            return (), (), (f"Missing explicit {field}.",)
        if list(names) == ["any"] and families in (("address", "address_group"), ("service", "service_group")):
            return (("all" if families[0] == "address" else "ALL"),), (), ()
        values, dependencies, reasons = [], [], []
        for name in names:
            matches = self.references.get((owner.source_path, owner.name, pan_scope_identity(owner.scope), field, name), ())
            targets = {(r.target_source_path, pan_scope_identity(r.resolved_target_scope)) for r in matches
                       if r.status == "RESOLVED" and r.resolved_target_scope is not None}
            candidates = [(family, obj) for path, scope in targets for family in families
                          for obj in self.targets.get((family, path, name, scope), ())]
            if len(candidates) != 1 or any(r.status != "RESOLVED" for r in matches):
                reasons.append(f"Unresolved or unsupported {field} reference: {name}.")
            else:
                family, obj = candidates[0]
                values.append(self.options.zones.get(obj.name, "") if family == "zone" else self.name(obj))
                dependencies.append(identity(obj, family))
        return tuple(values), tuple(dependencies), tuple(reasons)


def unsupported_fields(obj, allowed):
    reasons = []
    if obj.raw_extra:
        reasons.append("Unsupported source settings require manual implementation.")
    extra = set(obj.explicit_fields) - set(allowed) - {"description", "tags", "name"}
    if extra:
        reasons.append("Unsupported explicit fields: " + ", ".join(sorted(extra)) + ".")
    return reasons
