"""Check Point rulebase tree traversal and section title extraction."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


def parse_required_bool(
    value: Any,
    field_name: str,
) -> Tuple[Optional[bool], Optional[str]]:
    """Accept only actual JSON booleans for required Check Point fields."""
    if isinstance(value, bool):
        return value, None
    if value is None:
        return None, f"missing-{field_name}"
    return None, f"invalid-{field_name}-value"


def flatten_rulebase(
    rulebase_entries: List[Any],
    current_section: str = "",
    inline_layer_context: Optional[Dict[str, Any]] = None,
) -> List[Tuple[Dict[str, Any], str]]:
    """
    Recursively traverse a Check Point rulebase structure, flattening section titles,
    sub-layers, and returning a list of (rule_dict, section_title) preserving native rule order.
    """
    flattened: List[Tuple[Dict[str, Any], str]] = []

    for entry in rulebase_entries:
        if not isinstance(entry, dict):
            flattened.append(({"_malformed_rule": entry}, current_section))
            continue

        entry_type = str(entry.get("type", "")).strip().lower()

        # Check for section title / header container
        if entry_type in ("access-section", "nat-section", "section") or entry_type.endswith("-section"):
            section_name = entry.get("name") or current_section
            sub_rules = entry.get("rulebase", [])
            if isinstance(sub_rules, list):
                flattened.extend(flatten_rulebase(
                    sub_rules,
                    current_section=section_name,
                    inline_layer_context=inline_layer_context,
                ))
        elif "rulebase" in entry and entry_type != "access-rule":
            # A nested rulebase is a distinct layer, not an ordinary section. Keep
            # its children in source inventory, but mark them so callers can
            # prevent flattening into deployable parent-layer policy order.
            nested_context = {
                "uid": entry.get("uid"),
                "name": entry.get("name"),
                "type": entry.get("type"),
            }
            sub_rules = entry.get("rulebase", [])
            if isinstance(sub_rules, list):
                flattened.extend(flatten_rulebase(
                    sub_rules,
                    current_section=current_section,
                    inline_layer_context=nested_context,
                ))
        else:
            rule = dict(entry)
            if inline_layer_context:
                rule["_checkpoint_inline_layer_context"] = inline_layer_context
            flattened.append((rule, current_section))

    return flattened
