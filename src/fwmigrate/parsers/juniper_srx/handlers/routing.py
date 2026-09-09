"""Handler for Junos static routes and routing instances configuration hierarchy."""

from __future__ import annotations

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import (
    sanitize_source_attributes,
    sanitize_tokens,
)
from fwmigrate.parsers.juniper_srx.model import (
    JuniperContextConfig,
    JuniperRoute,
    JuniperRouteNextHop,
    JuniperRoutingInstance,
)
from fwmigrate.parsers.juniper_srx.provenance import record_member_candidate, record_scalar_candidate
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand


def handle_routing_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    """
    Handle 'set routing-options ...' and 'set routing-instances ...' commands.
    """
    toks = cmd.tokens
    if len(toks) < 2:
        return False

    first = toks[1].lower()

    if first == "routing-options" and len(toks) >= 3:
        cmd.consumed = True
        cmd.handler = "routing"

        if len(toks) >= 7 and toks[2].lower() == "rib" and toks[4].lower() == "static" and toks[5].lower() == "route":
            route = _get_or_create_route(context, toks[6], routing_instance=None)
            route.rib = toks[3]
            return _parse_route_settings(cmd, toks[7:], route) if len(toks) > 7 else _normalized(cmd)
        if len(toks) >= 5 and toks[2].lower() == "static" and toks[3].lower() == "route":
            dst = toks[4]
            route = _get_or_create_route(context, dst, routing_instance=None)
            if len(toks) == 5:
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            return _parse_route_settings(cmd, toks[5:], route)

        # Other routing-options
        safe_toks = sanitize_tokens(toks)
        context.source_attributes["_".join(safe_toks[1:])] = sanitize_source_attributes(
            {"raw": cmd.raw_sanitized}
        )
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    if first == "routing-instances" and len(toks) >= 3:
        inst_name = toks[2]
        instance = _get_or_create_routing_instance(context, inst_name)
        cmd.consumed = True
        cmd.handler = "routing"

        if (
            len(toks) >= 7
            and toks[3].lower() == "routing-options"
            and toks[4].lower() == "rib"
            and len(toks) >= 9
            and toks[6].lower() == "static"
            and toks[7].lower() == "route"
        ):
            dst = toks[8]
            route = _get_or_create_route(context, dst, routing_instance=inst_name)
            route.rib = toks[5]
            if len(toks) == 9:
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            return _parse_route_settings(cmd, toks[9:], route)

        if (
            len(toks) >= 7
            and toks[3].lower() == "routing-options"
            and toks[4].lower() == "static"
            and toks[5].lower() == "route"
        ):
            dst = toks[6]
            route = _get_or_create_route(context, dst, routing_instance=inst_name)
            if len(toks) == 7:
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            return _parse_route_settings(cmd, toks[7:], route)

        if len(toks) > 3:
            path = toks[3:]
            if path[0].lower() in {"instance-type", "route-distinguisher"} and len(path) > 1:
                if path[0].lower() == "instance-type":
                    instance.instance_type = path[1]
                    record_scalar_candidate(instance.field_provenance, instance.field_candidate_history, "instance_type", instance.instance_type, cmd)
                else:
                    instance.route_distinguisher = path[1]
                    record_scalar_candidate(instance.field_provenance, instance.field_candidate_history, "route_distinguisher", instance.route_distinguisher, cmd)
            elif path[0].lower() == "interface" and len(path) > 1:
                record_member_candidate(instance.member_candidate_history, "interfaces", path[1], cmd)
                if path[1] not in instance.interfaces:
                    instance.interfaces.append(path[1])
            else:
                instance.source_attributes.setdefault("unsupported_children", []).append(
                    sanitize_source_attributes({"path": path, "raw": cmd.raw_sanitized})
                )

        # Other routing-instance attributes
        safe_toks = sanitize_tokens(toks)
        context.source_attributes[f"routing_instance_{inst_name}_{'_'.join(safe_toks[3:])}"] = (
            sanitize_source_attributes({"raw": cmd.raw_sanitized})
        )
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    return False


def _get_or_create_routing_instance(
    context: JuniperContextConfig, instance_name: str
) -> JuniperRoutingInstance:
    """Look up a routing instance only within its owning context."""
    return context.routing_instances.setdefault(
        instance_name, JuniperRoutingInstance(name=instance_name)
    )


def _get_or_create_route(
    context: JuniperContextConfig, dst: str, routing_instance: str | None
) -> JuniperRoute:
    for r in context.routes:
        if r.destination == dst and r.routing_instance == routing_instance:
            return r
    new_r = JuniperRoute(destination=dst, routing_instance=routing_instance)
    context.routes.append(new_r)
    return new_r


def _normalized(cmd: JunosCommand) -> bool:
    cmd.extraction_status = ExtractionStatus.NORMALIZED
    return True


def _parse_route_settings(cmd: JunosCommand, toks: list[str], route: JuniperRoute) -> bool:
    if not toks:
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    key = toks[0].lower()

    if key == "next-hop" and len(toks) >= 2:
        nh_val = toks[1]
        nh = JuniperRouteNextHop(value=nh_val, qualified=False)
        record_member_candidate(route.member_candidate_history, "next_hops", nh_val, cmd)
        if len(toks) > 2:
            i = 2
            while i < len(toks):
                sub = toks[i].lower()
                if sub == "metric" and i + 1 < len(toks):
                    try:
                        nh.metric = int(toks[i + 1])
                        record_scalar_candidate(nh.field_provenance, nh.field_candidate_history, "metric", nh.metric, cmd)
                    except ValueError:
                        pass
                    i += 2
                elif sub == "preference" and i + 1 < len(toks):
                    try:
                        nh.preference = int(toks[i + 1])
                        record_scalar_candidate(nh.field_provenance, nh.field_candidate_history, "preference", nh.preference, cmd)
                    except ValueError:
                        pass
                    i += 2
                elif sub == "tag" and i + 1 < len(toks):
                    try:
                        nh.tag = int(toks[i + 1])
                        record_scalar_candidate(nh.field_provenance, nh.field_candidate_history, "tag", nh.tag, cmd)
                    except ValueError:
                        pass
                    i += 2
                else:
                    i += 1
        _append_next_hop(route, nh)
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif key == "qualified-next-hop" and len(toks) >= 2:
        nh_val = toks[1]
        nh = JuniperRouteNextHop(value=nh_val, qualified=True)
        record_member_candidate(route.member_candidate_history, "next_hops", nh_val, cmd)
        if len(toks) > 2:
            i = 2
            while i < len(toks):
                sub = toks[i].lower()
                if sub == "metric" and i + 1 < len(toks):
                    try:
                        nh.metric = int(toks[i + 1])
                        record_scalar_candidate(nh.field_provenance, nh.field_candidate_history, "metric", nh.metric, cmd)
                    except ValueError:
                        pass
                    i += 2
                elif sub == "preference" and i + 1 < len(toks):
                    try:
                        nh.preference = int(toks[i + 1])
                        record_scalar_candidate(nh.field_provenance, nh.field_candidate_history, "preference", nh.preference, cmd)
                    except ValueError:
                        pass
                    i += 2
                elif sub == "tag" and i + 1 < len(toks):
                    try:
                        nh.tag = int(toks[i + 1])
                        record_scalar_candidate(nh.field_provenance, nh.field_candidate_history, "tag", nh.tag, cmd)
                    except ValueError:
                        pass
                    i += 2
                else:
                    i += 1
        _append_next_hop(route, nh)
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif key == "discard":
        _record_action(route, "discard", cmd)
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif key == "reject":
        _record_action(route, "reject", cmd)
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif key == "receive":
        _record_action(route, "receive", cmd)
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif key == "next-table" and len(toks) >= 2:
        route.next_table = toks[1]
        record_scalar_candidate(route.field_provenance, route.field_candidate_history, "next_table", route.next_table, cmd)
        _record_action(route, "next-table", cmd)
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif key == "metric" and len(toks) >= 2:
        try:
            route.metric = int(toks[1])
            record_scalar_candidate(route.field_provenance, route.field_candidate_history, "metric", route.metric, cmd)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
        except ValueError:
            cmd.extraction_status = ExtractionStatus.PARSE_ERROR
            cmd.parse_error = f"Invalid route metric: {toks[1]}"
        return True
    elif key == "preference" and len(toks) >= 2:
        try:
            route.preference = int(toks[1])
            record_scalar_candidate(route.field_provenance, route.field_candidate_history, "preference", route.preference, cmd)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
        except ValueError:
            cmd.extraction_status = ExtractionStatus.PARSE_ERROR
            cmd.parse_error = f"Invalid route preference: {toks[1]}"
        return True
    elif key == "tag" and len(toks) >= 2:
        try:
            route.tag = int(toks[1])
            record_scalar_candidate(route.field_provenance, route.field_candidate_history, "tag", route.tag, cmd)
            cmd.extraction_status = ExtractionStatus.NORMALIZED
        except ValueError:
            cmd.extraction_status = ExtractionStatus.PARSE_ERROR
            cmd.parse_error = f"Invalid route tag: {toks[1]}"
        return True
    elif key == "disable":
        route.disabled = True
        record_scalar_candidate(route.field_provenance, route.field_candidate_history, "disabled", True, cmd)
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif key == "retain":
        route.retain = True
        _record_action(route, "retain", cmd)
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    safe_toks = sanitize_tokens(toks)
    route.source_attributes["_".join(safe_toks)] = sanitize_source_attributes(
        {"raw": cmd.raw_sanitized}
    )
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True


def _record_action(route: JuniperRoute, action: str, cmd: JunosCommand) -> None:
    record_scalar_candidate(route.field_provenance, route.field_candidate_history, "action", action, cmd)
    route.action = action
    route.discard = action == "discard"
    route.reject = action == "reject"
    route.receive = action == "receive"


def _append_next_hop(route: JuniperRoute, nh: JuniperRouteNextHop) -> None:
    for existing in route.next_hops:
        if existing.value == nh.value and existing.qualified == nh.qualified:
            existing.metric = nh.metric if nh.metric is not None else existing.metric
            existing.preference = nh.preference if nh.preference is not None else existing.preference
            existing.tag = nh.tag if nh.tag is not None else existing.tag
            return
    route.next_hops.append(nh)
