"""Check Point rulebase tree traversal and section title extraction."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple


def flatten_rulebase(
    rulebase_entries: List[Any],
    current_section: str = "",
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
        if entry_type in ("access-section", "section") or "rulebase" in entry and entry_type != "access-rule":
            section_name = entry.get("name") or current_section
            sub_rules = entry.get("rulebase", [])
            if isinstance(sub_rules, list):
                flattened.extend(flatten_rulebase(sub_rules, current_section=section_name))
        else:
            flattened.append((entry, current_section))

    return flattened
