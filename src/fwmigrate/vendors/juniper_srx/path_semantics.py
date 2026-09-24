"""Small, shared path classification for supported Junos group semantics."""

_DAYS_OF_WEEK = {"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}
SCALAR_LEAVES = {
    "description", "hostname", "host-name", "mtu", "scheduler-name", "action", "class", "routing-instance", "instance-type",
    "authentication-method", "dh-group", "authentication-algorithm", "encryption-algorithm",
    "digital-signature-scheme", "prf-algorithm", "signature-hash-algorithm", "lifetime-seconds",
    "mode", "proposal-set", "ike-policy", "address", "external-interface", "version",
    "local-address", "local-identity", "remote-identity", "protocol", "lifetime-kilobytes",
    "pfs", "bind-interface", "type", "start-date", "stop-date", "interval",
}
MEMBER_LEAVES = {"members", "applications", "application", "interfaces", "proposals", "source-address",
                 "destination-address", "from-zone", "to-zone", "source-identity", "address", "address-set", "daily"}


def candidate_field_value(path: tuple[str, ...]) -> tuple[str, object]:
    low = [part.lower() for part in path]
    if "security-zone" in low:
        if "interfaces" in low:
            i = low.index("interfaces")
            if i + 1 < len(path) and "host-inbound-traffic" not in low[i + 1:]:
                return "interfaces", path[i + 1]
            if "host-inbound-traffic" in low[i + 1:]:
                h = low.index("host-inbound-traffic", i + 1)
                interface = path[i + 1] if i + 1 < h and low[i + 1] != "host-inbound-traffic" else None
                kind = low[h + 1] if h + 1 < len(path) else ""
                field = f"interface:{interface}:{'system_services' if kind == 'system-services' else 'protocols'}" if interface else (
                    "host_inbound_system_services" if kind == "system-services" else "host_inbound_protocols"
                )
                return field, path[h + 2] if h + 2 < len(path) else None
        if "description" in low:
            i = low.index("description")
            return "description", " ".join(path[i + 1:])
        if "screen" in low:
            return "screen", path[low.index("screen") + 1]
        if "tcp-rst" in low:
            return "tcp_rst", True
    if low[:2] == ["schedulers", "scheduler"]:
        key = low[2] if len(low) > 2 else ""
        value = path[3] if len(path) > 3 else None
        if key in {"description", "start-date", "stop-date"}:
            return key.replace("-", "_"), value
        if key == "daily":
            return "daily", " ".join(path[3:])
        if key in _DAYS_OF_WEEK:
            return f"weekday:{key}", " ".join(path[3:])
    if low[:2] == ["security", "policies"]:
        if "scheduler-name" in low:
            i = low.index("scheduler-name")
            return "scheduler_name", path[i + 1]
        if "match" in low:
            i = low.index("match")
            key = low[i + 1] if i + 1 < len(low) else ""
            names = {"source-address": "source_addresses", "destination-address": "destination_addresses",
                     "application": "applications", "dynamic-application": "dynamic_applications",
                     "source-identity": "source_identities"}
            return names.get(key, key), path[i + 2] if i + 2 < len(path) else None
        if "then" in low:
            i = low.index("then")
            return "action", path[i + 1] if i + 1 < len(path) else None
    if low[:3] == ["security", "address-book", low[2] if len(low) > 2 else ""] and "address-set" in low:
        i = low.index("address-set")
        if i + 2 < len(path) and low[i + 2] in {"address", "address-set"}:
            return low[i + 2], path[i + 3] if i + 3 < len(path) else None
    if "routing-options" in low and "route" in low:
        key = low[-2] if len(low) > 1 else ""
        return {"next-hop": "next_hops", "qualified-next-hop": "next_hops"}.get(key, key.replace("-", "_")), path[-1] if path else None
    return (low[-2] if len(low) > 1 else low[-1] if low else "unknown"), path[-1] if path else None


def scalar_identity(path: tuple[str, ...]):
    low = tuple(part.lower() for part in path)
    if (len(low) == 7 and low[:3] == ("security", "ipsec", "vpn")
            and low[4] == "ike" and low[5] in {"gateway", "ipsec-policy"}):
        return path[:5], low[5]
    if (len(low) == 7 and low[:3] == ("security", "ike", "policy")
            and low[4:6] == ("certificate", "local-certificate")):
        return path[:6], "local-certificate"
    if (len(low) == 6 and low[:3] == ("security", "ipsec", "vpn")
            and low[4] in {"bind-interface", "establish-tunnels"}):
        return path[:4], low[4]
    if "then" in low:
        index = low.index("then")
        if index + 2 == len(low) and low[index + 1] in {"permit", "deny", "reject", "discard", "next-term"}:
            return path[:index], "action"
    index = next((i for i in range(len(low) - 1, -1, -1) if low[i] in SCALAR_LEAVES), None)
    if index is None or (low[index] in MEMBER_LEAVES and
                         not (low[index] == "address" and low[:2] == ("security", "ike"))):
        return None
    return path[:index], low[index]
