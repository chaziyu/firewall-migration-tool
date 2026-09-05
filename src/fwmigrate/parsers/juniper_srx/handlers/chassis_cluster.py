"""Handler for Junos chassis-cluster source inventory."""

import ipaddress

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.parsers.juniper_srx.model import (
    JuniperClusterIPMonitorTarget,
    JuniperClusterIPMonitoring,
    JuniperClusterPreempt,
    JuniperContextConfig,
    JuniperRedundancyGroup,
)
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand


def _parse_uint_range(cmd: JunosCommand, value: str, label: str, minimum: int, maximum: int) -> int | None:
    try:
        parsed = int(value)
    except ValueError:
        parsed = None
    if parsed is None or not minimum <= parsed <= maximum:
        cmd.extraction_status = ExtractionStatus.PARSE_ERROR
        cmd.parse_error = f"Invalid {label}: {value}"
        return None
    return parsed


def _parse_ipv4(cmd: JunosCommand, value: str, label: str) -> str | None:
    try:
        ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        cmd.extraction_status = ExtractionStatus.PARSE_ERROR
        cmd.parse_error = f"Invalid {label}: {value}"
        return None
    return value


def _parse_ip_monitoring(group: JuniperRedundancyGroup, cmd: JunosCommand, path: list[str]) -> None:
    monitoring = group.ip_monitoring or JuniperClusterIPMonitoring()
    group.ip_monitoring = monitoring
    monitoring.source_attributes.setdefault("raw", cmd.raw_sanitized)

    if not path:
        cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
        cmd.requires_manual_review = True
        return

    option = path[0].lower()
    if option in {"global-threshold", "global-weight", "retry-count", "retry-interval"}:
        ranges = {
            "global-threshold": (0, 255),
            "global-weight": (0, 255),
            "retry-count": (5, 15),
            "retry-interval": (1, 30),
        }
        if len(path) != 2:
            cmd.extraction_status = ExtractionStatus.PARSE_ERROR
            cmd.parse_error = f"Missing {option} value"
            return
        value = _parse_uint_range(cmd, path[1], option, *ranges[option])
        if value is not None:
            setattr(monitoring, option.replace("-", "_"), value)
        return

    if option == "family" and len(path) >= 3 and path[1].lower() == "inet":
        address = _parse_ipv4(cmd, path[2], "monitored IPv4 address")
        if address is None:
            return
        target = next((item for item in monitoring.targets if item.address == address), None)
        if target is None:
            target = JuniperClusterIPMonitorTarget(address=address)
            monitoring.targets.append(target)
        target.source_attributes.setdefault("raw", cmd.raw_sanitized)
        rest = path[3:]
        if not rest:
            return
        if rest[0].lower() == "weight" and len(rest) >= 2:
            value = _parse_uint_range(cmd, rest[1], "IP-monitoring weight", 0, 255)
            if value is not None:
                target.weight = value
            rest = rest[2:]
        elif rest[0].lower() == "interface" and len(rest) >= 2:
            target.interface = rest[1]
            rest = rest[2:]
        if rest and rest[0].lower() == "secondary-ip-address" and len(rest) >= 2:
            value = _parse_ipv4(cmd, rest[1], "secondary IPv4 address")
            if value is not None:
                target.secondary_ip_address = value
            rest = rest[2:]
        if rest:
            cmd.remaining_tokens = rest
            cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
            cmd.requires_manual_review = True
        return

    monitoring.source_attributes.setdefault("unknown", []).append(
        sanitize_source_attributes({"tokens": path, "raw": cmd.raw_sanitized})
    )
    cmd.remaining_tokens = path
    cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
    cmd.requires_manual_review = True


def _invalid_redundancy_setting(group: JuniperRedundancyGroup, cmd: JunosCommand, path: list[str]) -> None:
    group.source_attributes.setdefault("invalid", []).append(
        sanitize_source_attributes({"tokens": path, "raw": cmd.raw_sanitized})
    )


def _parse_preempt(group: JuniperRedundancyGroup, cmd: JunosCommand, path: list[str]) -> None:
    if group.group_id == "0":
        _invalid_redundancy_setting(group, cmd, ["preempt", *path])
        cmd.extraction_status = ExtractionStatus.PARSE_ERROR
        cmd.parse_error = "Preemption is not permitted for redundancy group 0"
        return

    preempt = group.preempt or JuniperClusterPreempt()
    group.preempt = preempt
    preempt.enabled = True
    preempt.source_attributes.setdefault("raw", cmd.raw_sanitized)
    if not path:
        return

    ranges = {"delay": (1, 21600), "limit": (1, 50), "period": (1, 1400)}
    option = path[0].lower()
    if option in ranges:
        if len(path) != 2:
            cmd.extraction_status = ExtractionStatus.PARSE_ERROR
            cmd.parse_error = f"Missing preempt {option} value"
            return
        value = _parse_uint_range(cmd, path[1], f"preempt {option}", *ranges[option])
        if value is not None:
            setattr(preempt, option, value)
        return

    preempt.source_attributes.setdefault("unknown", []).append(
        sanitize_source_attributes({"tokens": path, "raw": cmd.raw_sanitized})
    )
    cmd.remaining_tokens = path
    cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
    cmd.requires_manual_review = True


def _parse_redundancy_group_setting(group: JuniperRedundancyGroup, cmd: JunosCommand, option: str, path: list[str]) -> None:
    ranges = {
        "hold-down-interval": (300, 1800) if group.group_id == "0" else (0, 1800),
        "gratuitous-arp-count": (1, 16),
    }
    if option not in ranges:
        group.settings["_".join(sanitize_tokens([option, *path]))] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
        return
    if len(path) != 1:
        cmd.extraction_status = ExtractionStatus.PARSE_ERROR
        cmd.parse_error = f"Missing {option} value"
        return
    value = _parse_uint_range(cmd, path[0], option, *ranges[option])
    if value is not None:
        setattr(group, "hold_down_interval" if option == "hold-down-interval" else "gratuitous_arp_count", value)


def handle_chassis_cluster_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    toks = cmd.tokens
    if len(toks) < 3 or toks[1].lower() != "chassis" or toks[2].lower() != "cluster":
        return False
    path = toks[3:]
    cluster = context.chassis_cluster
    key = "_".join(sanitize_tokens(path)) or "cluster"
    if len(path) >= 2 and path[0].lower() == "cluster-id":
        cluster.cluster_id = path[1]
    elif len(path) >= 3 and path[0].lower() == "redundancy-group":
        group = cluster.redundancy_groups.setdefault(path[1], JuniperRedundancyGroup(group_id=path[1]))
        if path[2].lower() == "node":
            node = group.nodes.setdefault(path[3], {})
            node["settings"] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
            if len(path) >= 6 and path[4].lower() == "priority":
                try: node["priority"] = int(path[5])
                except ValueError: node["priority"] = path[5]
        elif path[2].lower() == "ip-monitoring":
            _parse_ip_monitoring(group, cmd, path[3:])
        elif path[2].lower() == "preempt":
            _parse_preempt(group, cmd, path[3:])
        elif path[2].lower() in {"hold-down-interval", "gratuitous-arp-count"}:
            _parse_redundancy_group_setting(group, cmd, path[2].lower(), path[3:])
        elif path[2].lower() == "interface-monitor" and len(path) >= 4:
            interface = path[3]
            monitor = group.interface_monitors.setdefault(interface, {"interface": interface})
            if len(path) >= 5 and path[4].lower() == "weight":
                if len(path) < 6:
                    cmd.extraction_status = ExtractionStatus.PARSE_ERROR
                    cmd.parse_error = "Missing interface-monitor weight"
                else:
                    try:
                        monitor["weight"] = int(path[5])
                    except ValueError:
                        cmd.extraction_status = ExtractionStatus.PARSE_ERROR
                        cmd.parse_error = f"Invalid interface-monitor weight: {path[5]}"
                    else:
                        if not 0 <= monitor["weight"] <= 255:
                            del monitor["weight"]
                            cmd.extraction_status = ExtractionStatus.PARSE_ERROR
                            cmd.parse_error = f"Invalid interface-monitor weight: {path[5]}"
                        elif len(path) > 6:
                            cmd.remaining_tokens = path[6:]
                            cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
                            cmd.requires_manual_review = True
            elif len(path) > 4:
                cmd.remaining_tokens = path[4:]
                cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
                cmd.requires_manual_review = True
            monitor["source_attributes"] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
        else:
            group.settings["_".join(sanitize_tokens(path[2:]))] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
    elif len(path) >= 2 and path[0].lower() == "node":
        cluster.nodes.setdefault(path[1], {})["_".join(sanitize_tokens(path[2:])) or "configured"] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
    elif path and path[0].lower() == "fabric":
        cluster.fabric_interfaces.append(sanitize_source_attributes({"path": path[1:], "raw": cmd.raw_sanitized}))
    elif path and path[0].lower() == "control-link":
        cluster.control_links.append(sanitize_source_attributes({"path": path[1:], "raw": cmd.raw_sanitized}))
    else:
        cluster.settings[key] = sanitize_source_attributes({"raw": cmd.raw_sanitized, "tokens": path})
    context.source_attributes.setdefault("chassis_cluster", {}).setdefault(key, []).append(
        sanitize_source_attributes({"raw": cmd.raw_sanitized, "tokens": path})
    )
    cmd.consumed = True
    cmd.handler = "chassis_cluster"
    if cmd.extraction_status is None:
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
