"""Consume version-verified FortiGate derivations without changing source state."""

from dataclasses import asdict

from fwmigrate.vendors.fortigate.relationships.references import ResolvedReference


def effective_fields(derived, vdom, kind):
    result = {}
    for row in getattr(derived, "effective_values", ()):
        if row.vdom == vdom and row.kind == kind:
            result.setdefault(row.name, {})[row.field] = row
    return result


def source_value(item, field, defaults):
    explicit = getattr(item, field)
    if explicit is not None:
        return explicit
    row = defaults.get(field)
    return row.value if row else None


def default_evidence(defaults):
    return tuple(asdict(row) for row in defaults.values())


def resolve_reference(derived, vdom, name, kinds):
    # Explicit source definitions take precedence over built-in-name aliases.
    matches = [(kind, derived.references.get(kind, vdom=vdom, name=name)) for kind in kinds]
    matches = [(kind, target) for kind, target in matches if target is not None]
    if len(matches) > 1 or any(row.vdom == vdom and row.name == name and row.kind in kinds
                               for row in derived.references.duplicates):
        return None
    if matches:
        kind, target = matches[0]
        return ResolvedReference(kind=kind, vdom=vdom, name=name, target=target)
    return derived.references.resolve_any(vdom=vdom, name=name, kinds=kinds)
