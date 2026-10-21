"""Keep PAN-OS NAT visible and block policies when NAT may be active."""

from .source_scope import identity, in_scope
from ..models import ASAPlanItem
from fwmigrate.vendors.palo_alto.source_model import pan_scope_identity


def plan_nat(source, selected):
    items, active = [], False
    for order, rule in enumerate(row for row in source.nat_rules if in_scope(row, selected)):
        disabled = rule.disabled == "yes"
        if not disabled:
            active = True
        items.append(ASAPlanItem(
            key=identity(rule, "inactive_nat" if disabled else "nat"),
            family="inactive_nat" if disabled else "nat",
            source_scope=pan_scope_identity(rule.scope), source_kind="nat",
            source_name=rule.name or "(unnamed)", source_path=rule.source_path,
            target_name=rule.name or "(unnamed)",
            blockers=(("SOURCE_ITEM_EXPLICITLY_DISABLED_NOT_RENDERED",) if disabled
                      else ("ACTIVE_OR_UNKNOWN_NAT_UNSUPPORTED",)),
            source_order=rule.source_order or order,
        ))
    return items, active
