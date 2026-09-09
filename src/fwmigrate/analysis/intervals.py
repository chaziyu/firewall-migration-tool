"""Inclusive interval set operations without enumerating individual addresses."""

from ipaddress import IPv4Address, IPv4Network


def merge(spans):
    result = []
    for lo, hi in sorted(spans):
        if lo > hi:
            raise ValueError("Reversed interval")
        if result and lo <= result[-1][1] + 1:
            result[-1] = (result[-1][0], max(hi, result[-1][1]))
        else:
            result.append((lo, hi))
    return result


def intersect(left, right):
    return merge((max(a, c), min(b, d)) for a, b in left for c, d in right if max(a, c) <= min(b, d))


def subtract(left, right):
    result = merge(left)
    for lo, hi in merge(right):
        updated = []
        for start, end in result:
            if end < lo or start > hi:
                updated.append((start, end))
            else:
                if start < lo:
                    updated.append((start, lo - 1))
                if end > hi:
                    updated.append((hi + 1, end))
        result = updated
    return result


def size(spans):
    return sum(hi - lo + 1 for lo, hi in merge(spans))


def ipv4(value):
    value = str(value).strip()
    if "-" in value:
        lo, hi = value.split("-", 1)
        return merge([(int(IPv4Address(lo.strip())), int(IPv4Address(hi.strip())))])
    parts = value.split()
    network = IPv4Network("/".join(parts) if len(parts) == 2 else value, strict=False)
    return [(int(network.network_address), int(network.broadcast_address))]


def display(spans):
    return [str(IPv4Address(lo)) if lo == hi else f"{IPv4Address(lo)}-{IPv4Address(hi)}" for lo, hi in spans]


RFC1918 = merge(ipv4("10.0.0.0/8") + ipv4("172.16.0.0/12") + ipv4("192.168.0.0/16"))
