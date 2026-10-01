"""Shared FortiGate Excel presentation constants and value helpers.

This module is presentation-only. It does not mutate or infer source configuration.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, is_dataclass
from enum import Enum
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Iterable, Iterator, Mapping, Sequence

from ..security.extraction import sanitize_source_attributes, sanitize_source_value
from .excel_schema import SHEET_HEADERS

if TYPE_CHECKING:
    from .excel import _ExcelContext


_POLICY_ACTION_NOTE = "Missing or empty Action values display the FortiOS default (deny)."


_SOURCE_PATHS_BY_SHEET: dict[str, tuple[str, ...]] = {
    "DNS Settings": ("system dns",),
}

_SOURCE_HEADER_ALIASES: dict[str, tuple[str, ...]] = {
    "Alias": ("alias",),
    "IP / Prefix": ("ip",),
    "Interface Type": ("type",),
    "Role": ("role",),
    "Addressing Mode": ("mode",),
    "Management Access": ("allowaccess",),
    "VLAN ID": ("vlanid",),
    "Members": ("member", "members"),
    "Description": ("description", "comment", "comments"),
    "Protocol": ("protocol",),
    "Source Port": ("src-port", "source-port"),
    "Destination Port": ("dst-port", "destination-port"),
    "Auto Negotiate": ("auto-negotiate", "auto_negotiate"),
}


def _normalize_key(value: Any) -> str:
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")


_NORMALIZED_SOURCE_HEADER_CANDIDATES = {
    header: tuple(dict.fromkeys(
        _normalize_key(candidate)
        for candidate in (*_SOURCE_HEADER_ALIASES.get(header, ()), header)
    ))
    for header in {
        *_SOURCE_HEADER_ALIASES,
        *(header for headers in SHEET_HEADERS.values() for header in headers),
    }
}


_VISIBLE_MODEL_FIELDS_BY_SHEET: dict[str, frozenset[str]] = {
    "Interface Secondary IPs": frozenset({"id", "ip", "allowaccess", "ha_priority"}),
    "Zones": frozenset({"name", "members", "description", "intrazone", "vdom"}),
    "Policies": frozenset({
        "policy_id", "name", "srcintf", "dstintf", "srcaddr", "dstaddr",
        "srcaddr6", "dstaddr6", "srcaddr_negate", "dstaddr_negate",
        "srcaddr6_negate", "dstaddr6_negate", "service", "service_negate",
        "schedule", "groups", "users", "action", "vpntunnel", "nat",
        "utm_status", "profile_group", "profile_protocol_options",
        "per_ip_shaper", "av_profile", "ips_sensor", "application_list",
        "webfilter_profile", "dnsfilter_profile", "ssl_ssh_profile",
        "logtraffic", "comments", "status", "vdom",
    }),
    "VIP Real Servers": frozenset({"id", "ip", "address", "port", "status", "weight", "monitor"}),
    "VPN Tunnels": frozenset({
        "name", "interface", "remote_gw", "remotegw_ddns", "type", "ike_version", "mode",
        "authmethod", "authmethod_remote", "proposal", "dhgrp", "keylife", "nattraversal",
        "dpd", "dpd_retrycount", "dpd_retryinterval", "local_gw", "localid", "localid_type",
        "peerid", "certificate", "comments", "vdom",
    }),
    "VPN Phase 2": frozenset({
        "name", "phase1name", "proposal", "pfs", "dhgrp", "keylifeseconds", "keylifekbs",
        "src_subnet", "dst_subnet", "src_start_ip", "src_end_ip", "dst_start_ip", "dst_end_ip",
        "src_subnet6", "dst_subnet6", "src_start_ip6", "src_end_ip6", "dst_start_ip6",
        "dst_end_ip6", "protocol", "src_port", "dst_port", "auto_negotiate", "comments", "vdom",
    }),
    "Policy IPsec Phase 2": frozenset({
        "name", "phase1name", "proposal", "pfs", "dhgrp", "keylifeseconds", "keylifekbs",
        "src_subnet", "dst_subnet", "src_start_ip", "src_end_ip", "dst_start_ip", "dst_end_ip",
        "src_subnet6", "dst_subnet6", "src_start_ip6", "src_end_ip6", "dst_start_ip6",
        "dst_end_ip6", "protocol", "src_port", "dst_port", "auto_negotiate", "comments", "vdom",
    }),
    "DHCP Reservations": frozenset({"id", "ip", "mac", "description", "action", "type"}),
    "DHCP IP Ranges": frozenset({"id", "start_ip", "end_ip", "lease_time"}),
    "DHCP Exclude Ranges": frozenset({"id", "start_ip", "end_ip", "lease_time"}),
    "SD-WAN": frozenset({"status", "load_balance_mode", "vdom"}),
    "SD-WAN Zones": frozenset({"name", "vdom"}),
    "SD-WAN Members": frozenset({
        "seq_num", "interface", "zone", "gateway", "source", "cost", "weight", "priority", "status",
    }),
    "SD-WAN Health Checks": frozenset({
        "name", "server", "members", "protocol", "interval", "failtime", "recoverytime",
    }),
    "SD-WAN Rules": frozenset({
        "id", "name", "status", "mode", "src", "dst", "priority_members", "health_check", "priority_zone",
    }),
    "SSL VPN Authentication Rules": frozenset({
        "id", "auth", "cipher", "client_cert", "realm", "source_interface", "source_address",
        "source_address_negate", "users", "user_peer", "groups", "portal",
    }),
    "User Group Matches": frozenset({"id", "server_name", "group_name"}),
    "IPS Sensor Entries": frozenset({
        "id", "rule", "cve", "application", "os", "protocol", "severity", "location",
        "default_action", "default_status", "action", "status", "log", "log_packet",
        "log_attack_context", "rate_count", "rate_duration", "rate_mode", "rate_track",
        "quarantine", "quarantine_expiry", "quarantine_log", "vuln_type", "last_modified",
    }),
    "IPS Exempt IPs": frozenset({"id", "src_ip", "dst_ip"}),
}

def _model_rows(
    context: _ExcelContext,
    objects: Iterable[Any],
    headers: Sequence[str],
    mapping: Mapping[str, str | None | Any],
    *,
    domains: Iterable[str] | None = None,
    issue_vdom: str | None = None,
) -> Iterator[dict[str, Any]]:
    header_set = frozenset(headers)
    active_mapping = tuple(
        (header, attribute)
        for header, attribute in mapping.items()
        if header in header_set
    )
    represented_fields = frozenset(
        attribute
        for _, attribute in active_mapping
        if isinstance(attribute, str) and attribute
    )
    include_explicit_fields = "Source Explicit Fields" in header_set
    include_additional_settings = "Additional Settings" in header_set

    for item in objects:
        row: dict[str, Any] = {}

        for header, attribute in active_mapping:
            if callable(attribute):
                row[header] = attribute(item)
            elif attribute:
                row[header] = _serialize_nested_value(
                    getattr(item, attribute, None)
                )

        raw_extra = _additional_settings(item, represented_fields=represented_fields)

        _overlay_safe_raw(
            row,
            raw_extra,
            headers,
        )

        if include_explicit_fields:
            row["Source Explicit Fields"] = sorted(
                getattr(item, "explicit_fields", ())
            )

        if include_additional_settings:
            row["Additional Settings"] = raw_extra

        vdom = issue_vdom if issue_vdom is not None else str(getattr(item, "vdom", "") or "")

        name = (
            getattr(item, "name", None)
            or getattr(item, "policy_id", None)
            or getattr(item, "seq_num", None)
            or getattr(item, "id", None)
        )

        _add_analysis_status(
            row,
            context,
            vdom=vdom,
            names=(name,),
            domains=domains,
        )

        yield row


def _additional_settings(
    item: Any,
    *,
    represented_fields: Iterable[str] = (),
    sheet_name: str | None = None,
) -> dict[str, Any]:
    if sheet_name is not None:
        represented_fields = _VISIBLE_MODEL_FIELDS_BY_SHEET.get(sheet_name, represented_fields)
    settings = _build_additional_settings(item, represented_fields=represented_fields)
    return sanitize_source_attributes(settings) if settings else {}


@lru_cache(maxsize=None)
def _model_field_order(model_type: type[Any]) -> Mapping[str, int]:
    return {
        field: position
        for position, field in enumerate(model_type.model_fields)
    }


def _build_additional_settings(
    item: Any,
    *,
    represented_fields: Iterable[str] = (),
) -> dict[str, Any]:
    settings = dict(getattr(item, "raw_extra", {}) or {})

    explicit_fields = set(getattr(item, "explicit_fields", ()) or ())
    represented = frozenset(represented_fields)
    remaining_fields = explicit_fields.difference(
        {"name", "vdom", "raw_extra", "explicit_fields"},
        represented,
    )
    if not remaining_fields:
        return settings

    field_order = _model_field_order(type(item))
    for field in sorted(
        (field for field in remaining_fields if field in field_order),
        key=field_order.__getitem__,
    ):
        value = _serialize_nested_value(getattr(item, field, None))
        if value in (None, "", [], {}):
            continue
        settings[field] = value

    return settings


def _serialize_nested_value(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="python")
    if isinstance(value, Mapping):
        return {
            key: _serialize_nested_value(child)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_serialize_nested_value(child) for child in value]
    if isinstance(value, tuple):
        return tuple(_serialize_nested_value(child) for child in value)
    if isinstance(value, set):
        return {_serialize_nested_value(child) for child in value}
    return value


def _add_analysis_status(
    row: dict[str, Any],
    context: _ExcelContext,
    *,
    vdom: str,
    names: Iterable[Any],
    domains: Iterable[str] | None = None,
    extra_reasons: Iterable[str] = (),
) -> None:
    names = tuple(name for name in names if name not in (None, ""))
    issues = context.issues_for(vdom=vdom, names=names, domains=domains) if names else []
    reasons = [issue.message for issue in issues]
    reasons.extend(str(reason) for reason in extra_reasons if reason)
    reasons = list(dict.fromkeys(reasons))

    row["Analysis Status"] = "REVIEW_REQUIRED" if reasons else "EXTRACTED"
    row["Review Reasons"] = reasons
    row["__review__"] = bool(reasons)
    row["__error__"] = any(
        issue.severity.value == "error"
        for issue in issues
    )


def _overlay_raw(
    row: dict[str, Any],
    raw: Mapping[str, Any],
    headers: Sequence[str],
) -> None:
    safe = sanitize_source_attributes(raw)
    _overlay_safe_raw(row, safe, headers)


def _overlay_safe_raw(
    row: dict[str, Any],
    safe_raw: Mapping[str, Any],
    headers: Sequence[str],
) -> None:
    """Overlay an already-sanitized raw source mapping without sanitizing again."""
    if not safe_raw:
        return

    safe = safe_raw
    normalized_values = _normalized_source_values(safe)

    for header in headers:
        if row.get(header) not in (None, "", [], {}):
            continue

        value, _ = _lookup_source_header(header, safe, normalized_values)
        if value not in (None, "", [], {}):
            row[header] = value


def _lookup_source_header(
    header: str,
    values: Mapping[str, Any],
    normalized_values: Mapping[str, tuple[str, Any]] | None = None,
) -> tuple[Any, str | None]:
    normalized_values = (
        _normalized_source_values(values)
        if normalized_values is None
        else normalized_values
    )

    candidates = _NORMALIZED_SOURCE_HEADER_CANDIDATES.get(
        header,
        (_normalize_key(header),),
    )
    for normalized in candidates:
        if normalized not in normalized_values:
            continue

        source_key, value = normalized_values[
            normalized
        ]

        return value, source_key

    return None, None


def _normalized_source_values(
    values: Mapping[str, Any],
) -> dict[str, tuple[str, Any]]:
    return {
        _normalize_key(key): (key, value)
        for key, value in values.items()
    }


def _enabled_text(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if normalized in {"enable", "enabled", "up", "yes", "true", "1"}:
        return "Yes"
    if normalized in {"disable", "disabled", "down", "no", "false", "0"}:
        return "No"
    return str(value)


def _nat_type(value: str | None) -> str | None:
    return {
        "ip_pool": "IP Pool",
        "nat64_ip_pool": "NAT64 IP Pool",
        "interface_address": "Interface Address",
    }.get(value, value)


def _disabled_text(value: Any) -> str | None:
    enabled = _enabled_text(value)
    if enabled == "Yes":
        return "No"
    if enabled == "No":
        return "Yes"
    return None


def _interface_source_values(
    context: _ExcelContext,
    *,
    vdom: str,
    name: str,
) -> dict[str, Any]:
    """
    Return safe explicit source values for one interface, including nested
    interface configuration.

    Nested values are exposed both by their raw key when unambiguous and by a
    namespaced key such as ipv6.ip6-address. This is report presentation only;
    FGInterface remains the typed source model.
    """

    cache_key = (vdom, name)
    cached = context._interface_safe_source_cache.get(cache_key)
    if cached is not None:
        return deepcopy(cached)

    values: dict[str, Any] = {}
    records = [
        *context.source_by_identity.get((vdom, "system interface", name), ()),
        *context.nested_source_by_parent.get((vdom, "system interface", name), ()),
    ]

    for record in records:
        nested = record.source_path != "system interface"
        suffix = (
            record.source_path.removeprefix("system interface ").strip()
            if nested
            else ""
        )

        for key, value in record.values.items():
            if key not in values:
                values[key] = value

            if suffix:
                values[f"{suffix}.{key}"] = value

    safe_values = sanitize_source_attributes(values)
    context._interface_safe_source_cache[cache_key] = deepcopy(safe_values)
    context._interface_source_key_cache[cache_key] = frozenset(
        _normalize_key(key) for key in safe_values
    )
    return deepcopy(safe_values)


def _source_secret_configured(
    context: _ExcelContext,
    *,
    vdom: str,
    name: str,
    keys: Iterable[str],
) -> str | None:
    wanted = {
        _normalize_key(key)
        for key in keys
    }

    _interface_source_values(context, vdom=vdom, name=name)
    present = context._interface_source_key_cache.get((vdom, name), frozenset())
    return "Yes" if present & wanted else None


def _additional_source_settings(
    source_values: Mapping[str, Any],
    row: Mapping[str, Any],
    headers: Sequence[str],
) -> dict[str, Any]:
    consumed: set[str] = set()
    normalized_values = _normalized_source_values(source_values)

    for header in headers:
        if row.get(header) in (None, "", [], {}):
            continue

        _, source_key = _lookup_source_header(
            header,
            source_values,
            normalized_values,
        )

        if source_key is not None:
            consumed.add(source_key)

    return {
        key: value
        for key, value in source_values.items()
        if key not in consumed
    }


def _source_category(path: str) -> str:
    parts = path.split()
    return " ".join(parts[:2]) if len(parts) >= 2 else path


def _sheet_for_domain(domain: str) -> str:
    return {
        "interface": "Interfaces",
        "interface_topology": "Interfaces",
        "zone": "Zones",
        "address": "Addresses",
        "address6": "Addresses",
        "address_group": "Address Groups",
        "address_group6": "Address Groups",
        "service": "Services",
        "service_group": "Service Groups",
        "policy": "Policies",
        "nat": "NAT Rules",
        "vip": "Virtual IPs",
        "vip_group": "VIP Groups",
        "ip_pool": "IP Pools",
        "ipsec_phase1": "VPN Tunnels",
        "vpn_topology": "VPN Tunnels",
        "vpn_phase2": "VPN Phase 2",
        "static_route": "Routes",
        "user_group": "User Groups",
        "ips_sensor": "IPS Sensors",
    }.get(domain, "FortiGate Source Inventory")


def _safe_command_value(
    key: str,
    values: Iterable[Any],
) -> Any:
    """
    Sanitize one raw CLI command before it reaches Excel.

    Source-command appendix sheets must never bypass the same secret-redaction
    rules used for raw_extra/source inventory.
    """

    raw_values = list(values)
    raw_value: Any

    if not raw_values:
        raw_value = True
    elif len(raw_values) == 1:
        raw_value = raw_values[0]
    else:
        raw_value = raw_values

    return sanitize_source_value(key, raw_value)


def _excel_safe(value: Any) -> Any:
    if value is None:
        return None
    if type(value) is str:
        if value.startswith(("=", "+", "-", "@")):
            return "'" + value
        return value
    if type(value) is bool:
        return "Yes" if value else "No"
    if type(value) is int or type(value) is float:
        return value

    value = _plain_value(value)

    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return "'" + value

    return value


def _plain_value(value: Any) -> Any:
    if value is None:
        return None

    if isinstance(value, Enum):
        return value.value

    if is_dataclass(value):
        return _plain_value(asdict(value))

    if isinstance(value, Mapping):
        return "\n".join(
            f"{key} = {_plain_value(item)}"
            for key, item in value.items()
        )

    if isinstance(value, (list, tuple, set, frozenset)):
        return "\n".join(
            str(_plain_value(item))
            for item in value
            if item not in (None, "", [], {})
        )

    if isinstance(value, bool):
        return "Yes" if value else "No"

    if isinstance(value, (str, int, float)):
        return value

    return str(value)
