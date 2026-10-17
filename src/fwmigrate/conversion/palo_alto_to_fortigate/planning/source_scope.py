"""Select source ownership without collapsing managed/inherited configuration."""
from fwmigrate.vendors.palo_alto.source_model import pan_scope_identity


def source_scopes(source):
    return sorted({pan_scope_identity(scope) for scope in source.scopes if scope.kind == "vsys"})


def select_source_scope(source, options):
    scopes = [scope for scope in source.scopes if scope.kind == "vsys" and pan_scope_identity(scope) == options.source_scope]
    if len(scopes) != 1:
        return None, ("Choose one unambiguous source device/VSYS scope.",)
    scope = scopes[0]
    # shortcut: managed effective configuration remains manual until template and rule inheritance are fully verified.
    if scope.device_group or scope.device_serial or any(s.kind in {"device-group", "template", "template-stack"} for s in source.scopes):
        return None, ("Managed/Panorama source requires verified effective inheritance; conversion is manual.",)
    return scope, ()


def in_scope(item, scope):
    return item.scope is not None and (item.scope.kind == "shared" or pan_scope_identity(item.scope) == pan_scope_identity(scope))


def identity(item, family):
    scope = pan_scope_identity(item.scope) if item.scope else "unscoped"
    return f"{family}:{scope}:{item.source_path}:{item.name or ''}:{item.source_order}"
