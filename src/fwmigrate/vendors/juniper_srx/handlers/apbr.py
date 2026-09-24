"""Extract selected APBR/AppQoE configuration as separate source objects."""

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.vendors.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.vendors.juniper_srx.model import (
    JuniperAPBRActiveProbeParams, JuniperAPBRDestinationPathGroup, JuniperAPBRMetricsProfile,
    JuniperAPBRMultipathRule, JuniperAPBROverlayPath, JuniperAPBRPassiveProbeParams,
    JuniperAPBRSLARule, JuniperContextConfig,
)
from fwmigrate.vendors.juniper_srx.tokenizer import JunosCommand, extract_value_list


def handle_apbr_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    t = cmd.tokens
    if len(t) < 3 or [x.lower() for x in t[1:3]] != ["security", "advance-policy-based-routing"]:
        return False
    tail = t[3:]
    low = [x.lower() for x in tail]
    if not tail:
        return _source_only(cmd, context.apbr.source_attributes)
    kind = low[0]
    if kind not in {"metrics-profile", "active-probe-params", "passive-probe-params", "overlay-path", "destination-path-group", "multipath-rule", "sla-rule"}:
        return _source_only(cmd, context.apbr.source_attributes)
    if len(tail) < 2:
        return _source_only(cmd, context.apbr.source_attributes)
    name, props = tail[1], tail[2:]
    plow = [x.lower() for x in props]
    apbr = context.apbr
    status = ExtractionStatus.EXTRACTED
    if kind == "metrics-profile":
        obj = apbr.metrics_profiles.setdefault(name, JuniperAPBRMetricsProfile(name=name))
        fields = {"jitter": "jitter", "packet-loss": "packet_loss", "delay-round-trip": "round_trip_delay", "rtt": "round_trip_delay"}
        if props:
            key = plow[0]
            if key in fields and len(props) > 1:
                setattr(obj, fields[key], " ".join(props[1:]))
            else:
                obj.source_attributes["_".join(sanitize_tokens(props))] = cmd.raw_sanitized
                status = ExtractionStatus.PARTIAL
    elif kind in {"active-probe-params", "passive-probe-params"}:
        collection = apbr.active_probe_params if kind == "active-probe-params" else apbr.passive_probe_params
        model = JuniperAPBRActiveProbeParams if kind == "active-probe-params" else JuniperAPBRPassiveProbeParams
        obj = collection.setdefault(name, model(name=name))
        if props:
            obj.settings[props[0]] = sanitize_tokens(props[1:])
            status = ExtractionStatus.PARTIAL
    elif kind == "overlay-path":
        obj = apbr.overlay_paths.setdefault(name, JuniperAPBROverlayPath(name=name))
        if props:
            obj.settings[props[0]] = sanitize_tokens(props[1:])
            status = ExtractionStatus.PARTIAL
    elif kind == "destination-path-group":
        obj = apbr.destination_path_groups.setdefault(name, JuniperAPBRDestinationPathGroup(name=name))
        if "probe-routing-instance" in plow and plow.index("probe-routing-instance") + 1 < len(props):
            obj.probe_routing_instance = props[plow.index("probe-routing-instance") + 1]
        elif "overlay-path" in plow and plow.index("overlay-path") + 1 < len(props):
            for value in extract_value_list(props[plow.index("overlay-path") + 1:]):
                if value not in obj.overlay_paths:
                    obj.overlay_paths.append(value)
        else:
            obj.source_attributes["_".join(sanitize_tokens(props))] = cmd.raw_sanitized
            status = ExtractionStatus.PARTIAL
    elif kind == "multipath-rule":
        obj = apbr.multipath_rules.setdefault(name, JuniperAPBRMultipathRule(name=name))
        if props and plow[0] == "bandwidth-limit" and len(props) > 1:
            obj.bandwidth_limit = props[1]
        elif props and plow[0] in {"application", "application-group"}:
            field = obj.applications if plow[0] == "application" else obj.application_groups
            for value in extract_value_list(props[1:]):
                if value not in field:
                    field.append(value)
        elif props:
            obj.settings[props[0]] = sanitize_tokens(props[1:])
            status = ExtractionStatus.PARTIAL
    else:
        obj = apbr.sla_rules.setdefault(name, JuniperAPBRSLARule(name=name))
        refs = {"metrics-profile": "metrics_profile", "active-probe-params": "active_probe_params", "passive-probe-params": "passive_probe_params", "multipath-rule": "multipath_rule", "switch-idle-time": "switch_idle_time"}
        if props and plow[0] in refs and len(props) > 1:
            setattr(obj, refs[plow[0]], props[1])
        elif props:
            obj.source_attributes["_".join(sanitize_tokens(props))] = cmd.raw_sanitized
            status = ExtractionStatus.PARTIAL
    obj.source_attributes.setdefault("commands", []).append(cmd.raw_sanitized)
    cmd.consumed, cmd.handler, cmd.extraction_status = True, "apbr", status
    return True


def _source_only(cmd: JunosCommand, target: dict) -> bool:
    target.setdefault("commands", []).append(sanitize_source_attributes({"raw": cmd.raw_sanitized}))
    cmd.consumed, cmd.handler, cmd.extraction_status = True, "apbr", ExtractionStatus.SOURCE_ONLY
    return True
