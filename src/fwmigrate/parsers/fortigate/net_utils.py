from __future__ import annotations

from ipaddress import ip_interface, ip_network


def normalize_ipv4_prefix(value: str) -> str:
    value = value.strip()

    if not value:
        raise ValueError("IPv4 prefix value is empty.")

    parts = value.split()
    if len(parts) == 2:
        ip_value, mask = parts
        candidate = f"{ip_value}/{mask}"
        error_message = f"Invalid IPv4 address/netmask: {value!r}"
    elif len(parts) == 1 and "/" in parts[0]:
        candidate = parts[0]
        error_message = f"Invalid IPv4 CIDR: {value!r}"
    else:
        raise ValueError(f"Unsupported IPv4 prefix syntax: {value!r}")

    try:
        parsed = ip_interface(candidate)
        if parsed.version != 4:
            raise ValueError("not IPv4")
    except ValueError as exc:
        raise ValueError(error_message) from exc

    return f"{parsed.ip}/{parsed.network.prefixlen}"


def normalize_ipv4_network(value: str) -> str:
    value = value.strip()
    parts = value.split()

    if len(parts) == 2:
        ip_value, mask = parts
        candidate = f"{ip_value}/{mask}"
    elif len(parts) == 1 and "/" in parts[0]:
        candidate = parts[0]
    else:
        raise ValueError(f"Unsupported IPv4 network syntax: {value!r}")

    try:
        parsed = ip_network(candidate, strict=False)
        if parsed.version != 4:
            raise ValueError("not IPv4")
    except ValueError as exc:
        raise ValueError(f"Invalid IPv4 network: {value!r}") from exc

    return str(parsed)
