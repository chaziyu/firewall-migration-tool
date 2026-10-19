"""PAN source-record ownership, including nested routing and rulebase context."""

import json

from .source_model import pan_scope_identity


def source_identity(item) -> tuple:
    if item is None:
        return ()
    existing = getattr(item, "source_identity", ()) or getattr(item, "owner_identity", ())
    if existing:
        return existing
    scope = getattr(item, "scope", None) or getattr(item, "source_scope", None)
    return (
        pan_scope_identity(scope) if scope else None,
        getattr(item, "source_path", None),
        getattr(item, "name", getattr(item, "source_name", None)),
        getattr(item, "source_order", None),
        getattr(item, "router_type", None), getattr(item, "router_name", None),
        getattr(item, "vrf_name", None), getattr(item, "rulebase_position", None),
    )


def source_identity_text(item) -> str:
    # The source order links nested typed objects back to the inventory record.
    return json.dumps(source_identity(item)[:4], ensure_ascii=False, separators=(",", ":"))
