import json
import re
from typing import Any, Iterable, Optional, Set, Tuple


def allocate_target_helper_name(
    preferred_name: str,
    existing_objects: dict[str, str],
    expected_value: str,
) -> Tuple[str, bool]:
    """
    Allocates a collision-safe name for a target generator helper object.

    Args:
        preferred_name: The ideal name for the object (e.g., "__fwmigrate_any_ipv4")
        existing_objects: A dictionary mapping existing object names to their values.
                          For example, if mapping addresses, the value would be the IP/subnet.
        expected_value: The value the helper object must have.

    Returns:
        A tuple of (name_to_use, was_reused_from_existing).
        - If preferred_name not in existing: return (preferred_name, False)
        - If preferred_name exists with matching value: return (preferred_name, True)
        - If collision, returns a deterministic fallback name and False.
    """
    if preferred_name not in existing_objects:
        return preferred_name, False
        
    if existing_objects[preferred_name] == expected_value:
        return preferred_name, True
        
    # Collision occurred (same name, different value)
    # Generate fallbacks: name_2, name_3, etc.
    counter = 2
    while True:
        fallback_name = f"{preferred_name}_{counter}"
        if fallback_name not in existing_objects:
            return fallback_name, False
        if existing_objects[fallback_name] == expected_value:
            return fallback_name, True
        counter += 1


def is_generation_safe_object(obj: Any) -> bool:
    """Verify an IR object is normalized, free of manual review flags, and parse errors."""
    if obj is None:
        return False
    if getattr(obj, "migration_status", "NORMALIZED") != "NORMALIZED":
        return False
    if getattr(obj, "requires_manual_review", False):
        return False
    if getattr(obj, "review_reasons", []):
        return False
    if getattr(obj, "parse_error", None) is not None:
        return False
    if hasattr(obj, "safe_for_target_generation"):
        if not getattr(obj, "safe_for_target_generation"):
            return False
    return True


def ir_generation_blocked(ir: Any) -> bool:
    """Check if IR-level generation is blocked."""
    if ir is None:
        return True
    return not getattr(ir, "generation_safe", True)


def hcl_string(value: str) -> str:
    """Format a string safely as an HCL double-quoted literal."""
    return json.dumps(str(value))


def hcl_list(values: Iterable[str]) -> str:
    """Format an iterable of strings as a valid HCL list expression."""
    return json.dumps([str(v) for v in values])


def terraform_resource_label(name: str, used_labels: Optional[Set[str]] = None) -> str:
    """
    Produce a valid, deterministic Terraform resource label from an arbitrary object name.

    Replaces non-alphanumeric characters with underscores, ensures valid leading character,
    and resolves collisions if used_labels set is provided.
    """
    sanitized = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    if not sanitized or not (sanitized[0].isalpha() or sanitized[0] == "_"):
        sanitized = f"r_{sanitized}"

    if used_labels is None:
        return sanitized

    if sanitized not in used_labels:
        used_labels.add(sanitized)
        return sanitized

    counter = 2
    while True:
        candidate = f"{sanitized}_{counter}"
        if candidate not in used_labels:
            used_labels.add(candidate)
            return candidate
        counter += 1
