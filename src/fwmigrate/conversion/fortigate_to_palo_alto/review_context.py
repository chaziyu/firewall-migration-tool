"""Source facts shown beside pair-specific migration decisions."""


def build_review_context(config, decisions, *, candidates=None, target_available=False, target_selected=False,
                         target_device_count=0):
    interfaces = {(item.vdom or "root", item.name): item for item in getattr(config, "interfaces", ())}
    zones = {(item.vdom or "root", item.name): item for item in getattr(config, "zones", ())}
    context = {}
    fields = {
        "source_type": "type", "source_role": "role", "source_ip": "ip",
        "source_parent": "interface", "source_vlan": "vlanid", "source_members": "members",
        "source_vrf": "vrf", "source_alias": "alias", "source_description": "description",
    }
    for decision in decisions.decisions:
        identity = (decision.source_vdom, decision.source_name)
        item = interfaces.get(identity) if decision.source_kind == "interface" else zones.get(identity)
        values = {"affected_count": decision.affected_count, "affected_by": dict(decision.affected_by or {})}
        if item is not None and decision.source_kind == "interface":
            explicit = getattr(item, "explicit_fields", None)
            for output, name in fields.items():
                value = getattr(item, name, None)
                if value is not None and (explicit is None or name in explicit):
                    values[output] = list(value) if isinstance(value, (list, tuple, set)) else value
            if decision.target_field == "target_interface":
                matches = (candidates or {}).get(decision.key, ())
                strong = [candidate for candidate in matches if candidate["class"] == "STRONG"]
                if not target_available:
                    values["next_action"] = "Upload PAN-OS target XML or enter the intended target interface manually."
                elif not target_device_count:
                    values["next_action"] = "Target XML has no device-scoped interfaces; enter the intended interface manually."
                elif not target_selected:
                    values["next_action"] = "Select the PAN-OS target device to discover compatible interfaces."
                elif len(strong) > 1:
                    values["next_action"] = "Several target interfaces match strong evidence; select one."
                elif len(strong) == 1:
                    values["next_action"] = "Review the strong target candidate, then confirm the mapping."
                elif matches:
                    values["next_action"] = "Review possible candidates; none has enough evidence for an automatic suggestion."
                else:
                    values["next_action"] = "No compatible target candidate was found; enter the intended interface manually."
        elif item is not None and decision.source_kind == "zone":
            explicit = getattr(item, "explicit_fields", None)
            if explicit is None or "members" in explicit:
                values["source_members"] = list(item.members or ())
        if decision.target_field == "target_zone" and not decision.suggested_value:
            values["next_action"] = "Choose the intended PAN-OS zone; no unique zone relationship is available."
        context[decision.key] = values
    return context
