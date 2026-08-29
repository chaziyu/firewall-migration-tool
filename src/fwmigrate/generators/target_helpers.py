from typing import Tuple

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
