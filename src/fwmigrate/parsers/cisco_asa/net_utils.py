from __future__ import annotations

import ipaddress
from typing import Optional


def parse_ipv4_netmask(mask: str) -> Optional[int]:
    """Return a prefix length only for a valid contiguous dotted IPv4 mask."""
    try:
        network = ipaddress.IPv4Network(f"0.0.0.0/{mask}")
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return None
    return network.prefixlen


def normalize_ipv4_network(address: str, mask: str) -> Optional[str]:
    prefix = parse_ipv4_netmask(mask)
    if prefix is None:
        return None
    try:
        ipaddress.IPv4Address(address)
    except ipaddress.AddressValueError:
        return None
    return f"{address}/{prefix}"
