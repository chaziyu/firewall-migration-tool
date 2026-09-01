"""Context-aware FortiGate dependency accounting."""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Tuple

from fwmigrate.extraction.models import DependencyRecord, SourceInventoryItem


# Values are source section families, not canonical IR types.  Keeping this
# table vendor-local prevents FortiGate-only relationships leaking into the
# generic IR while still making missing references auditable.
REFERENCE_RULES: Dict[Tuple[str, str], str] = {
    ("firewall policy", "network-service-dynamic"): "firewall network-service-dynamic",
    ("firewall network-service-dynamic", "sdn"): "system sdn-connector",
    ("firewall policy", "ips-sensor"): "ips sensor",
    ("firewall policy", "profile-group"): "firewall profile-group",
    ("firewall policy", "av-profile"): "antivirus profile",
    ("firewall policy", "webfilter-profile"): "webfilter profile",
    ("firewall policy", "ssl-ssh-profile"): "firewall ssl-ssh-profile",
    ("firewall policy", "application-list"): "application list",
    ("firewall policy", "srcintf"): "system interface",
    ("firewall policy", "dstintf"): "system interface",
    ("firewall policy", "srcaddr"): "firewall address",
    ("firewall policy", "dstaddr"): "firewall address",
    ("firewall policy", "srcaddr6"): "firewall address6",
    ("firewall policy", "dstaddr6"): "firewall address6",
    ("firewall policy", "service"): "firewall service custom",
    ("firewall policy", "schedule"): "firewall schedule recurring",
    ("firewall policy", "groups"): "user group",
    ("firewall policy", "users"): "user",
    ("system interface", "member"): "system interface",
    ("firewall profile-group", "ssh-filter-profile"): "ssh-filter profile",
    ("firewall profile-group", "diameter-filter-profile"): "diameter-filter profile",
    ("firewall profile-group", "sctp-filter-profile"): "sctp-filter profile",
    ("firewall profile-group", "videofilter-profile"): "videofilter profile",
    ("system link-monitor", "srcintf"): "system interface",
    ("router static", "device"): "system interface",
    ("router static", "sdwan-zone"): "system sdwan zone",
    ("router static6", "sdwan-zone"): "system sdwan zone",
    ("router static", "dstaddr"): "firewall address",
    ("router static6", "dstaddr"): "firewall address6",
    ("firewall vip", "extintf"): "system interface",
    ("firewall vip", "extip"): "firewall address",
    ("firewall vip", "mappedip"): "firewall address",
    ("user group", "member"): "user",
    ("vpn certificate setting", "crl"): "vpn certificate crl",
    ("vpn certificate setting", "ocsp-server"): "vpn certificate ocsp-server",
    ("system sdwan members", "interface"): "system interface",
    ("system sdwan members", "zone"): "system sdwan zone",
    ("system sdwan health-check", "members"): "system sdwan members",
    ("system sdwan service", "health-check"): "system sdwan health-check",
    ("system sdwan service", "priority-members"): "system sdwan members",
    ("system sdwan service", "priority-zone"): "system sdwan zone",
    ("system sdwan service", "src"): "firewall address",
    ("system sdwan service", "dst"): "firewall address",
}

# These are deliberately rule-specific.  ``REFERENCE_RULES`` retains the
# display/general expected type on DependencyRecord, while this map describes
# the source sections that are safe matches for a particular relationship.
# In particular, SD-WAN zones are valid policy interface selectors and VIPs
# are valid policy destinations, but neither is a global alias for an
# interface or address.
REFERENCE_TARGET_SECTIONS: Dict[Tuple[str, str], set[str]] = {
    ("firewall policy", "srcintf"): {
        "system interface",
        "system zone",
        "system sdwan zone",
    },
    ("firewall policy", "dstintf"): {
        "system interface",
        "system zone",
        "system sdwan zone",
    },
    ("firewall policy", "srcaddr"): {
        "firewall address",
        "firewall addrgrp",
    },
    ("firewall policy", "dstaddr"): {
        "firewall address",
        "firewall addrgrp",
        "firewall vip",
        "firewall vipgrp",
    },
    ("firewall policy", "srcaddr6"): {
        "firewall address6",
        "firewall addrgrp6",
    },
    ("firewall policy", "dstaddr6"): {
        "firewall address6",
        "firewall addrgrp6",
    },
    ("system interface", "member"): {
        "system interface",
    },
    ("router static", "dstaddr"): {
        "firewall address",
        "firewall addrgrp",
    },
    ("router static6", "dstaddr"): {
        "firewall address6",
        "firewall addrgrp6",
    },
    ("router static", "sdwan-zone"): {
        "system sdwan zone",
    },
    ("router static6", "sdwan-zone"): {
        "system sdwan zone",
    },
    ("system sdwan members", "interface"): {
        "system interface",
    },
    ("system sdwan members", "zone"): {
        "system sdwan zone",
    },
    ("system sdwan health-check", "members"): {
        "system sdwan members",
    },
    ("system sdwan service", "health-check"): {
        "system sdwan health-check",
    },
    ("system sdwan service", "priority-members"): {
        "system sdwan members",
    },
    ("system sdwan service", "priority-zone"): {
        "system sdwan zone",
    },
    ("system sdwan service", "src"): {
        "firewall address",
        "firewall addrgrp",
    },
    ("system sdwan service", "dst"): {
        "firewall address",
        "firewall addrgrp",
    },
}

BUILTIN_REFERENCES = {
    "all", "any", "always", "none", "default", "enable", "disable",
}


def _norm(value: str) -> str:
    return " ".join(value.lower().replace("_", "-").split())


def _legacy_expected_sections(expected: str) -> set[str]:
    expected = _norm(expected)
    aliases = {
        "firewall address": {"firewall address", "firewall address6", "firewall addrgrp", "firewall addrgrp6"},
        "firewall service custom": {"firewall service custom", "firewall service group"},
        "system interface": {"system interface", "system zone"},
        "ssh-filter profile": {"ssh-filter profile", "firewall profile-group ssh-filter"},
        "diameter-filter profile": {"diameter-filter profile", "firewall profile-group diameter-filter"},
        "sctp-filter profile": {"sctp-filter profile", "firewall profile-group sctp-filter"},
        "videofilter profile": {"videofilter profile", "firewall profile-group videofilter"},
    }
    return aliases.get(expected, {expected})


def _allowed_target_sections(
    source_path: str,
    field: str,
    expected: str,
) -> set[str]:
    explicit = REFERENCE_TARGET_SECTIONS.get((_norm(source_path), _norm(field)))
    if explicit is not None:
        return {_norm(value) for value in explicit}
    return _legacy_expected_sections(expected)


def _section_matches(actual: str, expected: str) -> bool:
    """Match a legacy expected type, including the user-section prefix rule."""

    actual = _norm(actual)
    expected = _norm(expected)
    if expected == "user":
        return actual.startswith("user ")
    return actual in _legacy_expected_sections(expected)


def _allowed_section_matches(actual: str, allowed_sections: set[str]) -> bool:
    """Match explicit sections while preserving legacy ``user`` prefix matching."""

    actual = _norm(actual)
    return actual in allowed_sections or (
        "user" in allowed_sections and actual.startswith("user ")
    )


def _flatten(items: Iterable[SourceInventoryItem]) -> List[SourceInventoryItem]:
    result: List[SourceInventoryItem] = []
    for item in items:
        result.append(item)
        result.extend(_flatten(item.children))
    return result


def _reference_values(values: list[str]) -> list[str]:
    return [
        value for value in values
        if value and value.lower() not in BUILTIN_REFERENCES
        and value not in {"[REDACTED]", "<redacted>"}
    ]


def build_dependency_registry(items: Iterable[SourceInventoryItem]) -> List[DependencyRecord]:
    """Build deterministic context-scoped dependency records."""

    all_items = _flatten(items)
    index: Dict[Tuple[Optional[str], str], List[SourceInventoryItem]] = {}
    for item in all_items:
        source_context = item.source_context or "root"
        names = [name for name in (item.name, item.source_id) if name]
        for name in names:
            index.setdefault((source_context, name), []).append(item)

    dependencies: List[DependencyRecord] = []
    for item in all_items:
        source_context = item.source_context or "root"
        source_path = _norm(item.source_path)
        for command in item.commands:
            field = _norm(command.key)
            expected = REFERENCE_RULES.get((source_path, field))
            if expected is None:
                continue
            allowed_sections = _allowed_target_sections(
                source_path,
                field,
                expected,
            )
            for reference in _reference_values(command.values):
                self_reference = (
                    source_path == "system interface"
                    and field == "member"
                    and item.name == reference
                )
                if self_reference:
                    target = None
                    note = "Interface member cannot reference its own interface."
                else:
                    candidates = index.get((source_context, reference), [])
                    target = next(
                        (
                            candidate
                            for candidate in candidates
                            if _allowed_section_matches(
                                candidate.source_path,
                                allowed_sections,
                            )
                        ),
                        None,
                    )
                    note = (
                        None
                        if target
                        else "Reference was not found in the same VDOM/context."
                    )
                dependencies.append(DependencyRecord(
                    source_context=source_context,
                    source_path=source_path,
                    source_object=item.name or item.source_id,
                    source_field=command.key,
                    reference=reference,
                    expected_type=expected,
                    result="RESOLVED" if target else "UNRESOLVED",
                    target_path=_norm(target.source_path) if target else None,
                    notes=note,
                ))
    return dependencies
