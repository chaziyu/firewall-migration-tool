"""FortiOS 7.4.6 firewall IP resource contract and validation."""

from ipaddress import AddressValueError, IPv4Address, IPv6Address
from typing import Any

FORTIOS_746_IPPOOL_TYPES = frozenset({
    "overload",
    "one-to-one",
    "fixed-port-range",
    "port-block-allocation",
    "cgn-resource-allocation",
})

FORTIOS_746_IPPOOL_FIELDS = frozenset({
    "add_nat64_route",
    "arp_intf",
    "arp_reply",
    "associated_interface",
    "block_size",
    "cgn_block_size",
    "cgn_client_endip",
    "cgn_client_ipv6shift",
    "cgn_client_startip",
    "cgn_fixedalloc",
    "cgn_overload",
    "cgn_port_end",
    "cgn_port_start",
    "cgn_spa",
    "comments",
    "endip",
    "endport",
    "exclude_ip",
    "nat64",
    "num_blocks_per_user",
    "pba_interim_log",
    "pba_timeout",
    "permit_any_host",
    "port_per_user",
    "source_endip",
    "source_startip",
    "startip",
    "startport",
    "subnet_broadcast_in_ippool",
    "type",
    "utilization_alarm_clear",
    "utilization_alarm_raise",
})

FORTIOS_746_IPPOOL_COSMETIC_EXTRA_SETTINGS = frozenset()
FORTIOS_746_IPPOOL_BOOKKEEPING_EXTRA_SETTINGS = frozenset({
    "unparsed_fields",
    "invalid_fields",
})

FORTIOS_746_IPPOOL_INT_RANGES = {
    "block_size": (64, 4096),
    "cgn_block_size": (64, 4096),
    "cgn_client_ipv6shift": (0, 127),
    "cgn_port_start": (1024, 65535),
    "cgn_port_end": (1024, 65535),
    "endport": (5117, 65533),
    "num_blocks_per_user": (1, 128),
    "pba_timeout": (3, 86400),
    "startport": (5117, 65533),
    "utilization_alarm_clear": (40, 100),
    "utilization_alarm_raise": (50, 100),
}

FORTIOS_746_IPPOOL_ZERO_OR_RANGES = {
    "pba_interim_log": (600, 86400),
    "port_per_user": (32, 60417),
}

FORTIOS_746_IPPOOL_DEFAULTS = {
    "add_nat64_route": "enable",
    "arp_reply": "enable",
    "block_size": 128,
    "cgn_block_size": 128,
    "cgn_client_ipv6shift": 0,
    "cgn_fixedalloc": "disable",
    "cgn_overload": "disable",
    "cgn_port_start": 5117,
    "cgn_port_end": 65530,
    "cgn_spa": "disable",
    "endip": "0.0.0.0",
    "endport": 65533,
    "nat64": "disable",
    "num_blocks_per_user": 8,
    "pba_interim_log": 0,
    "pba_timeout": 30,
    "permit_any_host": "disable",
    "port_per_user": 0,
    "source_startip": "0.0.0.0",
    "source_endip": "0.0.0.0",
    "startip": "0.0.0.0",
    "startport": 5117,
    "subnet_broadcast_in_ippool": "enable",
    "type": "overload",
    "utilization_alarm_clear": 80,
    "utilization_alarm_raise": 100,
}

FORTIOS_746_IPPOOL6_FIELDS = frozenset({
    "add_nat46_route",
    "comments",
    "endip",
    "nat46",
    "startip",
})

FORTIOS_746_IPPOOL6_DEFAULTS = {
    "add_nat46_route": "enable",
    "endip": "::",
    "nat46": "disable",
    "startip": "::",
}

FORTIOS_746_IPV6_EH_DEFAULTS = {
    "auth": "disable",
    "dest_opt": "disable",
    "fragment": "disable",
    "hop_opt": "disable",
    "no_next": "disable",
    "routing": "enable",
    "routing_type": 0,
}


def _validate_range(
    reasons: list[str],
    field_name: str,
    value: Any,
    minimum: int,
    maximum: int,
) -> None:
    if value is not None and not minimum <= value <= maximum:
        reasons.append(
            f"{field_name.replace('_', '-')} value {value} is outside "
            f"FortiOS 7.4.6 range {minimum}-{maximum}."
        )


def _validate_zero_or_range(
    reasons: list[str],
    field_name: str,
    value: Any,
    minimum: int,
    maximum: int,
) -> None:
    if value is None or value == 0:
        return
    if not minimum <= value <= maximum:
        reasons.append(
            f"{field_name.replace('_', '-')} value {value} must be 0 or "
            f"within {minimum}-{maximum}."
        )


def _is_valid_ipv4(value: Any) -> bool:
    if value is None:
        return True
    try:
        IPv4Address(value)
        return True
    except AddressValueError:
        return False


def _is_valid_ipv6(value: Any) -> bool:
    if value is None:
        return True
    try:
        IPv6Address(value)
        return True
    except ValueError:
        return False


def validate_ippool_746(pool: Any, source_version: str | None = None) -> list[str]:
    reasons: list[str] = []

    if pool.type not in FORTIOS_746_IPPOOL_TYPES:
        reasons.append(f"Unknown FortiOS IP pool type '{pool.type}'.")
    if pool.type == "cgn-resource-allocation":
        reasons.append(
            "cgn-resource-allocation is hyperscale-specific and requires "
            "target-specific review."
        )

    for field, (minimum, maximum) in FORTIOS_746_IPPOOL_INT_RANGES.items():
        _validate_range(reasons, field, getattr(pool, field, None), minimum, maximum)
    for field, (minimum, maximum) in FORTIOS_746_IPPOOL_ZERO_OR_RANGES.items():
        _validate_zero_or_range(
            reasons, field, getattr(pool, field, None), minimum, maximum
        )

    for key in sorted(pool.extra_settings):
        if key.startswith("unparsed_"):
            reasons.append(
                "IP pool contains invalid source value for "
                f"{key.removeprefix('unparsed_').replace('_', '-')}."
            )
        elif (
            key not in FORTIOS_746_IPPOOL_BOOKKEEPING_EXTRA_SETTINGS
            and key not in FORTIOS_746_IPPOOL_COSMETIC_EXTRA_SETTINGS
        ):
            reasons.append(
                f"IP pool contains unmodeled source setting '{key}' and "
                "requires target-specific review."
            )

    ip_fields = (
        "startip",
        "endip",
        "source_startip",
        "source_endip",
        "cgn_client_startip",
        "cgn_client_endip",
    )
    for field in ip_fields:
        value = getattr(pool, field, None)
        if value and not _is_valid_ipv4(value):
            reasons.append(
                f"{field.replace('_', '-')} contains invalid IPv4 address '{value}'."
            )
    for address in pool.exclude_ip:
        if not _is_valid_ipv4(address):
            reasons.append(
                f"exclude-ip contains invalid IPv4 address '{address}'."
            )

    for start_field, end_field, reason in (
        ("startip", "endip", "IP pool startip is greater than endip."),
        (
            "source_startip",
            "source_endip",
            "IP pool source-startip is greater than source-endip.",
        ),
    ):
        start = getattr(pool, start_field, None)
        end = getattr(pool, end_field, None)
        if start and end and _is_valid_ipv4(start) and _is_valid_ipv4(end):
            if IPv4Address(start) > IPv4Address(end):
                reasons.append(reason)
    for start_field, end_field, reason in (
        ("startport", "endport", "IP pool startport is greater than endport."),
        (
            "cgn_port_start",
            "cgn_port_end",
            "IP pool cgn-port-start is greater than cgn-port-end.",
        ),
    ):
        start = getattr(pool, start_field, None)
        end = getattr(pool, end_field, None)
        if start is not None and end is not None and start > end:
            reasons.append(reason)

    for field, maximum in (
        ("name", 79),
        ("comments", 255),
        ("associated_interface", 15),
        ("arp_intf", 15),
    ):
        value = getattr(pool, field, None)
        if value is not None and len(value) > maximum:
            reasons.append(
                f"{field.replace('_', '-')} exceeds FortiOS 7.4.6 maximum "
                f"length of {maximum}."
            )

    valid_flags = {
        "arp_reply",
        "permit_any_host",
        "nat64",
        "add_nat64_route",
        "subnet_broadcast_in_ippool",
        "privileged_port_use_pba",
        "cgn_fixedalloc",
        "cgn_overload",
        "cgn_spa",
    }
    for field in valid_flags:
        value = getattr(pool, field, None)
        if value is not None and value not in {"enable", "disable"}:
            reasons.append(
                f"{field.replace('_', '-')} has invalid FortiOS value '{value}'."
            )

    if source_version == "7.4.6":
        for field in sorted(pool.source_explicit_fields - FORTIOS_746_IPPOOL_FIELDS):
            reasons.append(
                f"Configured IP-pool field '{field}' is not part of the FortiOS "
                "7.4.6 reference baseline and is retained as version/model-specific "
                "semantics."
            )

    return list(dict.fromkeys(reasons))


def validate_ippool6_746(pool: Any) -> list[str]:
    reasons: list[str] = []
    for field in ("startip", "endip"):
        value = getattr(pool, field, None)
        if value and not _is_valid_ipv6(value):
            reasons.append(
                f"{field} contains invalid IPv6 address '{value}'."
            )
    for field in ("nat46", "add_nat46_route"):
        value = getattr(pool, field, None)
        if value is not None and value not in {"enable", "disable"}:
            reasons.append(f"{field.replace('_', '-')} has invalid FortiOS value '{value}'.")
    for field, maximum in (("name", 79), ("comments", 255)):
        value = getattr(pool, field, None)
        if value is not None and len(value) > maximum:
            reasons.append(
                f"{field} exceeds FortiOS 7.4.6 maximum length of {maximum}."
            )
    if (
        pool.startip
        and pool.endip
        and _is_valid_ipv6(pool.startip)
        and _is_valid_ipv6(pool.endip)
        and IPv6Address(pool.startip) > IPv6Address(pool.endip)
    ):
        reasons.append("IP pool6 startip is greater than endip.")
    return list(dict.fromkeys(reasons))


def _effective_settings(pool: Any, defaults: dict[str, Any]) -> dict[str, Any]:
    result = {
        field: getattr(pool, field) if field in pool.source_explicit_fields else default
        for field, default in defaults.items()
    }
    for field in sorted(pool.source_explicit_fields - defaults.keys()):
        if hasattr(pool, field):
            result[field] = getattr(pool, field)
    return result


def effective_ippool_settings(pool: Any) -> dict[str, Any]:
    return _effective_settings(pool, FORTIOS_746_IPPOOL_DEFAULTS)


def effective_ippool6_settings(pool: Any) -> dict[str, Any]:
    return _effective_settings(pool, FORTIOS_746_IPPOOL6_DEFAULTS)


def validate_ipv6_eh_filter_746(item: Any) -> list[str]:
    reasons: list[str] = []
    for field in (
        "auth", "dest_opt", "fragment", "hop_opt", "no_next", "routing",
    ):
        value = getattr(item, field, None)
        if value is not None and value not in {"enable", "disable"}:
            reasons.append(
                f"{field.replace('_', '-')} has invalid FortiOS value '{value}'."
            )
    if len(item.hdopt_type) > 7:
        reasons.append("hdopt-type supports at most seven values.")
    for value in item.hdopt_type:
        if not 0 <= value <= 255:
            reasons.append(f"hdopt-type value {value} is outside range 0-255.")
    if item.routing_type is not None and not 0 <= item.routing_type <= 255:
        reasons.append(
            f"routing-type value {item.routing_type} is outside range 0-255."
        )
    for key in sorted(item.extra_settings):
        if key.startswith("unparsed_"):
            reasons.append(
                "IPv6 EH filter contains invalid source value for "
                f"{key.removeprefix('unparsed_').replace('_', '-')}."
            )
    return list(dict.fromkeys(reasons))


def effective_ipv6_eh_filter_settings(item: Any) -> dict[str, Any]:
    return _effective_settings(item, FORTIOS_746_IPV6_EH_DEFAULTS)
