from __future__ import annotations

from typing import Any, Dict

from fwmigrate.parsers.fortigate.extraction import sanitize_source_attributes
from fwmigrate.parsers.fortigate.model import FGSystemFSSOPolling
from fwmigrate.parsers.fortigate.source_tree import FGSourceNode


def parse_system_fsso_polling_node(
    node: FGSourceNode,
    source_context: str,
) -> FGSystemFSSOPolling:
    """Build typed FSSO polling settings without retaining credential values.

    The recursive source tree remains authoritative for command operations.
    Unknown future fields are sanitized into ``extra_settings``.
    """

    attributes: Dict[str, Any] = {
        "source_context": source_context or "root",
        "source_explicit_fields": set(),
        "has_auth_password": False,
    }
    unknown: Dict[str, Any] = {}

    for command in node.commands:
        key = command.key.replace("-", "_")
        operation = getattr(command, "operation", "set")
        values = list(command.values)

        if operation == "unset":
            attributes["source_explicit_fields"].discard(key)
            if key == "auth_password":
                attributes["has_auth_password"] = False
            elif key in {"status", "listening_port", "authentication"}:
                attributes.pop(key, None)
            else:
                unknown.pop(key, None)
            continue

        attributes["source_explicit_fields"].add(key)

        if key == "auth_password":
            # Never retain the actual password, including in source fallback.
            attributes["has_auth_password"] = bool(values)
            continue

        # ``append`` has no documented meaning for these scalar settings.
        # Keep that operation in the recursive source tree, but do not invent
        # typed semantics for it.
        if operation != "set":
            continue

        value: Any = (
            values[0]
            if len(values) == 1
            else (" ".join(values) if values else True)
        )
        if key in {"status", "listening_port", "authentication"}:
            attributes[key] = value
        else:
            unknown[key] = value

    raw_port = attributes.get("listening_port")
    if raw_port is not None:
        try:
            attributes["listening_port"] = int(raw_port)
        except (TypeError, ValueError):
            attributes.pop("listening_port", None)
            unknown["unparsed_listening_port"] = raw_port

    attributes["extra_settings"] = sanitize_source_attributes(unknown)
    return FGSystemFSSOPolling(**attributes)
