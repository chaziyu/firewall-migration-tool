"""Handler for Junos chassis-cluster source inventory."""

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.parsers.juniper_srx.model import JuniperContextConfig, JuniperRedundancyGroup
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand


def handle_chassis_cluster_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    toks = cmd.tokens
    if len(toks) < 3 or toks[1].lower() != "chassis" or toks[2].lower() != "cluster":
        return False
    path = toks[3:]
    cluster = context.chassis_cluster
    key = "_".join(sanitize_tokens(path)) or "cluster"
    if len(path) >= 2 and path[0].lower() == "cluster-id":
        cluster.cluster_id = path[1]
    elif len(path) >= 4 and path[0].lower() == "redundancy-group":
        group = cluster.redundancy_groups.setdefault(path[1], JuniperRedundancyGroup(group_id=path[1]))
        if path[2].lower() == "node":
            node = group.nodes.setdefault(path[3], {})
            node["settings"] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
            if len(path) >= 6 and path[4].lower() == "priority":
                try: node["priority"] = int(path[5])
                except ValueError: node["priority"] = path[5]
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
