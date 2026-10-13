"""Verified static IPv4 VIP translation shared by address and NAT planning."""

from ipaddress import IPv4Address


def vip_translation(vip):
    warnings = []
    ext = vip.extip
    mapped = vip.mappedip[0] if len(vip.mappedip) == 1 else None
    try:
        IPv4Address(ext)
        IPv4Address(mapped)
        if ext == "0.0.0.0" or mapped == "0.0.0.0":
            raise ValueError("interface-dependent VIP address")
    except (ValueError, TypeError):
        warnings.append("VIP requires one explicit external and mapped IPv4 host address")
    if vip.extaddr or vip.mapped_addr:
        warnings.append("VIP address-object translation requires manual resolution")
    if vip.realservers or vip.ldb_method or vip.service or vip.type != "static-nat":
        warnings.append("VIP type or load-balancing/service semantics are unsupported")
    if vip.status not in {None, "enable"}:
        warnings.append("VIP state is unsupported")
    for field in ("arp_reply", "server_type"):
        if getattr(vip, field, None) is not None:
            warnings.append(f"VIP {field} requires manual target semantics")
    for field in ("nat_source_vip", "monitor"):
        if getattr(vip, field, None) not in (None, [], "disable"):
            warnings.append(f"VIP {field} requires manual target semantics")
    for key in vip.raw_extra:
        warnings.append(f"unclassified VIP setting {key!r} requires manual review")
    if vip.portforward not in {None, "disable", "no", "0"} or any(
        getattr(vip, field, None) for field in ("protocol", "extport", "mappedport")
    ):
        warnings.append("VIP port-forwarding semantics are unsupported")
    return ext, mapped, warnings
