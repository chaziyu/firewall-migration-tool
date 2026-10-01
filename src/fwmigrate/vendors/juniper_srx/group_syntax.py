"""Syntax-only classification for Junos configuration-group commands."""

from __future__ import annotations

from collections.abc import Sequence

APPLY_GROUP_KEYWORDS = frozenset({"apply-groups", "apply-groups-except"})
_CONTEXT_ROOTS = frozenset({"logical-systems", "tenants"})

# Tokens whose following value is an identifier, not a hierarchy keyword.
# This prevents objects literally named "groups" or "apply-groups" from
# being intercepted as configuration-group syntax.
_IDENTIFIER_DECLARATORS = frozenset({
    "address", "address-set", "application", "application-set", "client",
    "client-config", "filter", "from-zone", "gateway", "group", "host",
    "interface", "logical-systems", "policy", "pool", "profile", "proposal",
    "routing-instances", "rule", "rule-set", "scheduler", "security-zone",
    "term", "to-zone", "unit", "user", "vpn",
})


def group_definition_index(tokens: Sequence[str]) -> int | None:
    """Return the valid groups hierarchy index, excluding identifier values."""
    lowered = [token.lower() for token in tokens]
    if lowered[:1] == ["groups"]:
        return 0
    if len(lowered) >= 3 and lowered[0] in _CONTEXT_ROOTS and lowered[2] == "groups":
        return 2
    return None


def apply_group_index(tokens: Sequence[str]) -> int | None:
    """Return an apply-groups marker without mistaking object names."""
    lowered = [token.lower() for token in tokens]
    for index, token in enumerate(lowered):
        if token not in APPLY_GROUP_KEYWORDS:
            continue
        if index > 0 and lowered[index - 1] in _IDENTIFIER_DECLARATORS:
            continue
        return index
    return None


def is_group_command(tokens: Sequence[str]) -> bool:
    return group_definition_index(tokens) is not None or apply_group_index(tokens) is not None
