"""Source inventory coverage without exporting raw source values."""
from ..models import FGPlannedItem, digest
from fwmigrate.vendors.palo_alto.source_model import pan_scope_identity


def manual_inventory(source, items):
    represented = {(item.source_path, item.source_name, item.source_scope) for item in items}
    result = []
    for record in source.source_inventory:
        scope = pan_scope_identity(record.scope) if record.scope else "unscoped"
        if (record.source_path, record.name, scope) in represented:
            continue
        # Do not duplicate typed children already represented by a parent object.
        if any(record.source_path.startswith(path + "/") and record.name == name and scope == owner_scope for path, name, owner_scope in represented):
            continue
        result.append(FGPlannedItem("manual:" + digest((scope, record.source_path, record.name, record.source_order)), "manual", scope,
            record.name or record.kind, record.source_path, "manual_" + digest(record.source_path)[:12], "", "",
            reasons=("Source inventory item has no verified executable conversion in this selected scope.",), disposition="BLOCK"))
    return result
