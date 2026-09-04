"""Context-aware FortiGate dependency accounting."""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Tuple

from fwmigrate.extraction.models import DependencyRecord, SourceInventoryItem
from fwmigrate.parsers.fortigate.predefined_services import is_predefined_service


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
    ("firewall policy", "identity-based-route"): "firewall identity-based-route",
    ("firewall identity-based-route rule", "device"): "system interface",
    ("firewall identity-based-route rule", "groups"): "user group",
    ("firewall auth-portal", "groups"): "user group",
    ("firewall auth-portal", "identity-based-route"): "firewall identity-based-route",
    ("router policy", "input-device"): "system interface",
    ("router policy", "output-device"): "system interface",
    ("router policy", "srcaddr"): "firewall address",
    ("router policy", "dstaddr"): "firewall address",
    ("router policy", "internet-service-custom"): "firewall internet-service-custom",
    ("router policy", "internet-service-id"): "FortiGuard Internet Service ID",
    ("router policy6", "input-device"): "system interface",
    ("router policy6", "output-device"): "system interface",
    ("router policy6", "srcaddr"): "firewall address6",
    ("router policy6", "dstaddr"): "firewall address6",
    ("router policy6", "internet-service-custom"): "firewall internet-service-custom",
    ("router policy6", "internet-service-id"): "FortiGuard Internet Service ID",
    ("firewall local-in-policy", "intf"): "system interface",
    ("firewall local-in-policy", "srcaddr"): "firewall address",
    ("firewall local-in-policy", "dstaddr"): "firewall address",
    ("firewall local-in-policy", "service"): "firewall service custom",
    ("firewall local-in-policy", "schedule"): "firewall schedule recurring",
    ("firewall local-in-policy", "internet-service-src-custom"): "firewall internet-service-custom",
    ("firewall local-in-policy", "internet-service-src-custom-group"): "firewall internet-service-custom-group",
    ("firewall local-in-policy", "internet-service-src-group"): "firewall internet-service-group",
    ("firewall local-in-policy", "internet-service-src-name"): "firewall internet-service-name",
    ("firewall local-in-policy6", "intf"): "system interface",
    ("firewall local-in-policy6", "srcaddr"): "firewall address6",
    ("firewall local-in-policy6", "dstaddr"): "firewall address6",
    ("firewall local-in-policy6", "service"): "firewall service custom",
    ("firewall local-in-policy6", "schedule"): "firewall schedule recurring",
    ("firewall local-in-policy6", "internet-service6-src-custom"): "firewall internet-service-custom",
    ("firewall local-in-policy6", "internet-service6-src-custom-group"): "firewall internet-service-custom-group",
    ("firewall local-in-policy6", "internet-service6-src-group"): "firewall internet-service-group",
    ("firewall local-in-policy6", "internet-service6-src-name"): "firewall internet-service-name",
    ("system interface", "member"): "system interface",
    ("firewall internet-service-custom-group", "member"): "firewall internet-service-custom",
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
    ("firewall vip", "extaddr"): "firewall address",
    ("firewall vip", "mapped-addr"): "firewall address",
    ("firewall vip", "service"): "firewall service custom",
    ("firewall vip", "monitor"): "firewall ldb-monitor",
    ("firewall vip realservers", "address"): "firewall address",
    ("firewall vip realservers", "monitor"): "firewall ldb-monitor",
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
    ("system sdwan service", "src6"): "firewall address6",
    ("system sdwan service", "dst6"): "firewall address6",
    ("system sdwan service", "input-device"): "system interface",
    ("system sdwan service", "input-zone"): "system zone",
    ("system sdwan service", "groups"): "user group",
    ("system sdwan service", "users"): "user",
    ("system sdwan service", "internet-service-custom"): "firewall internet-service-custom",
    ("system sdwan service", "internet-service-custom-group"): "firewall internet-service-custom-group",
    ("system sdwan service", "internet-service-name"): "firewall internet-service-name",
    ("system sdwan service", "internet-service-app-ctrl"): "FortiGuard Internet Service ID",
    ("system sdwan service", "internet-service-app-ctrl-category"): "FortiGuard Internet Service category",
    ("system sdwan service", "internet-service-app-ctrl-group"): "FortiGuard Internet Service group",
    ("system sdwan service", "internet-service-group"): "FortiGuard Internet Service group",
    ("system sdwan service sla", "edit"): "system sdwan health-check",
}

# These are deliberately rule-specific.  ``REFERENCE_RULES`` retains the
# display/general expected type on DependencyRecord, while this map describes
# the source sections that are safe matches for a particular relationship.
# In particular, SD-WAN zones are valid policy interface selectors and VIPs
# are valid policy destinations, but neither is a global alias for an
# interface or address. Configured custom Internet Service/group references
# match only their exact indexed source sections; numeric ISDB IDs and
# database-only names use explicit external resolution modes below.
REFERENCE_TARGET_SECTIONS: Dict[Tuple[str, str], set[str]] = {
    ("firewall vip", "extaddr"): {
        "firewall address",
    },
    ("firewall vip", "mapped-addr"): {
        "firewall address",
    },
    ("firewall vip", "service"): {
        "firewall service custom",
        "firewall service group",
    },
    ("firewall vip", "monitor"): {
        "firewall ldb-monitor",
    },
    ("firewall vip realservers", "address"): {
        "firewall address",
    },
    ("firewall vip realservers", "monitor"): {
        "firewall ldb-monitor",
    },
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
    ("firewall policy", "identity-based-route"): {
        "firewall identity-based-route",
    },
    ("firewall identity-based-route rule", "device"): {
        "system interface",
    },
    ("firewall identity-based-route rule", "groups"): {
        "user group",
    },
    ("firewall auth-portal", "groups"): {
        "user group",
    },
    ("firewall auth-portal", "identity-based-route"): {
        "firewall identity-based-route",
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
    ("router policy", "input-device"): {
        "system interface",
    },
    ("router policy", "output-device"): {
        "system interface",
    },
    ("router policy", "srcaddr"): {
        "firewall address",
        "firewall addrgrp",
    },
    ("router policy", "dstaddr"): {
        "firewall address",
        "firewall addrgrp",
    },
    ("router policy", "internet-service-custom"): {
        "firewall internet-service-custom",
    },
    ("router policy6", "input-device"): {
        "system interface",
    },
    ("router policy6", "output-device"): {
        "system interface",
    },
    ("router policy6", "srcaddr"): {
        "firewall address6",
        "firewall addrgrp6",
    },
    ("router policy6", "dstaddr"): {
        "firewall address6",
        "firewall addrgrp6",
    },
    ("router policy6", "internet-service-custom"): {
        "firewall internet-service-custom",
    },
    ("firewall local-in-policy", "intf"): {
        "system interface",
    },
    ("firewall local-in-policy", "srcaddr"): {
        "firewall address",
        "firewall addrgrp",
    },
    ("firewall local-in-policy", "dstaddr"): {
        "firewall address",
        "firewall addrgrp",
    },
    ("firewall local-in-policy", "service"): {
        "firewall service custom",
        "firewall service group",
    },
    ("firewall local-in-policy", "schedule"): {
        "firewall schedule recurring",
        "firewall schedule onetime",
        "firewall schedule group",
    },
    ("firewall local-in-policy", "internet-service-src-custom"): {
        "firewall internet-service-custom",
    },
    ("firewall local-in-policy", "internet-service-src-custom-group"): {
        "firewall internet-service-custom-group",
    },
    ("firewall local-in-policy", "internet-service-src-group"): {
        "firewall internet-service-group",
    },
    ("firewall local-in-policy", "internet-service-src-name"): {
        "firewall internet-service-name",
    },
    ("firewall local-in-policy6", "intf"): {
        "system interface",
    },
    ("firewall local-in-policy6", "srcaddr"): {
        "firewall address6",
        "firewall addrgrp6",
    },
    ("firewall local-in-policy6", "dstaddr"): {
        "firewall address6",
        "firewall addrgrp6",
    },
    ("firewall local-in-policy6", "service"): {
        "firewall service custom",
        "firewall service group",
    },
    ("firewall local-in-policy6", "schedule"): {
        "firewall schedule recurring",
        "firewall schedule onetime",
        "firewall schedule group",
    },
    ("firewall local-in-policy6", "internet-service6-src-custom"): {
        "firewall internet-service-custom",
    },
    ("firewall local-in-policy6", "internet-service6-src-custom-group"): {
        "firewall internet-service-custom-group",
    },
    ("firewall local-in-policy6", "internet-service6-src-group"): {
        "firewall internet-service-group",
    },
    ("firewall local-in-policy6", "internet-service6-src-name"): {
        "firewall internet-service-name",
    },
    ("firewall internet-service-custom-group", "member"): {
        "firewall internet-service-custom",
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
        "vpn ipsec phase1-interface",
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
    ("system sdwan service", "src6"): {"firewall address6", "firewall addrgrp6"},
    ("system sdwan service", "dst6"): {"firewall address6", "firewall addrgrp6"},
    ("system sdwan service", "input-device"): {"system interface", "vpn ipsec phase1-interface"},
    ("system sdwan service", "input-zone"): {"system zone"},
    ("system sdwan service", "groups"): {"user group"},
    ("system sdwan service", "users"): {"user local"},
    ("system sdwan service", "internet-service-custom"): {"firewall internet-service-custom"},
    ("system sdwan service", "internet-service-custom-group"): {"firewall internet-service-custom-group"},
    ("system sdwan service", "internet-service-name"): {"firewall internet-service-name"},
    ("system sdwan service sla", "edit"): {"system sdwan health-check"},
}

BUILTIN_REFERENCES = {
    "all", "any", "always", "none", "default", "enable", "disable",
}

SDWAN_BUILTIN_REFERENCES = {
    ("system sdwan members", "zone", "virtual-wan-link"),
    ("system sdwan service", "priority-zone", "virtual-wan-link"),
}

REFERENCE_RESOLUTION_MODES: Dict[Tuple[str, str], str] = {
    ("router policy", "internet-service-id"): "external",
    ("router policy6", "internet-service-id"): "external",
    ("firewall local-in-policy", "internet-service-src-name"): "local-or-external",
    ("firewall local-in-policy6", "internet-service6-src-name"): "local-or-external",
    ("system sdwan service", "internet-service-name"): "local-or-external",
    ("system sdwan service", "internet-service-app-ctrl"): "external",
    ("system sdwan service", "internet-service-app-ctrl-category"): "external",
    ("system sdwan service", "internet-service-app-ctrl-group"): "external",
    ("system sdwan service", "internet-service-group"): "external",
}

EXTERNAL_REFERENCE_NOTE = (
    "Reference requires FortiGuard/Internet Service Database or "
    "appliance-generated Internet Service data and cannot be conclusively "
    "validated from the supplied configuration."
)


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


def _reference_resolution_mode(source_path: str, field: str) -> str:
    return REFERENCE_RESOLUTION_MODES.get(
        (_norm(source_path), _norm(field)),
        "local",
    )


def _reference_is_active(item: SourceInventoryItem, field: str) -> bool:
    """Return whether a conditional FortiGate reference has object semantics."""

    if _norm(item.source_path) != "firewall vip realservers" or field != "address":
        return True
    return any(
        _norm(command.key) == "type" and any(_norm(value) == "address" for value in command.values)
        for command in item.commands
    )


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
        if source_path == "system sdwan service sla" and item.name:
            health_check = index.get((source_context, item.name), [])
            resolved = any(_norm(candidate.source_path) == "system sdwan health-check" for candidate in health_check)
            dependencies.append(DependencyRecord(
                source_context=source_context,
                source_path=source_path,
                source_object=item.name,
                source_field="edit",
                reference=item.name,
                expected_type="system sdwan health-check",
                result="RESOLVED" if resolved else "UNRESOLVED",
                target_path="system sdwan health-check" if resolved else None,
                notes="Nested SD-WAN service SLA references its health-check by edit name.",
            ))
        for command in item.commands:
            field = _norm(command.key)
            expected = REFERENCE_RULES.get((source_path, field))
            if expected is None or not _reference_is_active(item, field):
                continue
            resolution_mode = _reference_resolution_mode(source_path, field)
            allowed_sections = _allowed_target_sections(
                source_path,
                field,
                expected,
            )
            for reference in _reference_values(command.values):
                if (source_path, field, _norm(reference)) in SDWAN_BUILTIN_REFERENCES:
                    dependencies.append(DependencyRecord(
                        source_context=source_context,
                        source_path=source_path,
                        source_object=item.name or item.source_id,
                        source_field=command.key,
                        reference=reference,
                        expected_type=expected,
                        result="RESOLVED",
                        target_path="fortigate built-in sdwan zone",
                        notes="FortiOS built-in virtual-wan-link zone.",
                    ))
                    continue
                predefined_service = False
                if resolution_mode == "external":
                    target = None
                    result = "EXTERNAL"
                    note = EXTERNAL_REFERENCE_NOTE
                else:
                    self_reference = (
                        source_path == "system interface"
                        and field == "member"
                        and item.name == reference
                    )
                    if self_reference:
                        target = None
                        result = "UNRESOLVED"
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
                        predefined_service = (
                            target is None
                            and expected == "firewall service custom"
                            and is_predefined_service(reference)
                        )
                        result = "RESOLVED" if target or predefined_service else (
                            "EXTERNAL"
                            if resolution_mode == "local-or-external"
                            else "UNRESOLVED"
                        )
                        note = (
                            None
                            if target
                            else (
                                "FortiOS 7.4.x predefined service."
                                if predefined_service
                                else (
                                    EXTERNAL_REFERENCE_NOTE
                                    if result == "EXTERNAL"
                                    else "Reference was not found in the same VDOM/context."
                                )
                            )
                        )
                dependencies.append(DependencyRecord(
                    source_context=source_context,
                    source_path=source_path,
                    source_object=item.name or item.source_id,
                    source_field=command.key,
                    reference=reference,
                    expected_type=expected,
                    result=result,
                    target_path=(
                        _norm(target.source_path) if target
                        else "fortigate predefined service" if predefined_service
                        else None
                    ),
                    notes=note,
                ))
    return dependencies
