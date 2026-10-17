"""Bounded FortiOS names allocated from stable source identities."""
import hashlib
import re

from .source_scope import identity


def allocate_plan_names(items, family, reserved=(), limit=63):
    used = set(reserved) | {"all", "ALL", "always"}
    result = {}
    for item in sorted(items, key=lambda value: identity(value, family)):
        key = identity(item, family)
        base = re.sub(r"[^A-Za-z0-9_.-]", "_", item.name or family)[:limit]
        name = base
        if not name or name in used:
            suffix = hashlib.sha256(key.encode()).hexdigest()[:10]
            name = f"{base[:limit - 11]}_{suffix}"
        while name in used:
            name = hashlib.sha256((key + name).encode()).hexdigest()[:limit]
        used.add(name)
        result[key] = name
    return result
