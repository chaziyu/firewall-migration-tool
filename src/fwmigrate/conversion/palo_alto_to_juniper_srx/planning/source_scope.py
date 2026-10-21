"""Select one standalone PAN-OS VSYS without collapsing ownership."""

from fwmigrate.vendors.palo_alto.source_model import pan_scope_identity


def source_scopes(source):
    return tuple(sorted({pan_scope_identity(scope) for scope in source.scopes if scope.kind == "vsys"}))


def select_source_scope(source, requested):
    matches = [scope for scope in source.scopes if scope.kind == "vsys" and pan_scope_identity(scope) == requested]
    if len(matches) != 1:
        return None, "Choose one unambiguous PAN-OS device/VSYS scope."
    selected = matches[0]
    if selected.device_group or selected.device_serial or any(
        scope.kind in {"device-group", "template", "template-stack"} for scope in source.scopes
    ):
        return None, "Managed Panorama inheritance is unsupported and remains manual."
    return selected, None


def in_scope(item, selected):
    return item.scope is not None and (
        item.scope.kind == "shared" or pan_scope_identity(item.scope) == pan_scope_identity(selected)
    )


def identity(item, family):
    scope = pan_scope_identity(item.scope) if item.scope else "unscoped"
    return f"{family}:{scope}:{item.source_path}:{item.name or ''}:{item.source_order}"
