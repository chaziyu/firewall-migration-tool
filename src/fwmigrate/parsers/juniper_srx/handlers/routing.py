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

        instance = context.routing_instances.setdefault(inst_name, JuniperRoutingInstance(name=inst_name))
        if len(toks) > 3:
            path = toks[3:]
            if path[0].lower() in {"instance-type", "route-distinguisher"} and len(path) > 1:
                if path[0].lower() == "instance-type": instance.instance_type = path[1]
                else: instance.route_distinguisher = path[1]
            elif path[0].lower() == "interface" and len(path) > 1: instance.interfaces.append(path[1])

        # Other routing-instance attributes
        safe_toks = sanitize_tokens(toks)
        context.source_attributes[f"routing_instance_{inst_name}_{'_'.join(safe_toks[3:])}"] = (
            sanitize_source_attributes({"raw": cmd.raw_sanitized})
        )
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    return False


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
        if len(toks) > 2:
            i = 2
            while i < len(toks):
                sub = toks[i].lower()
                if sub == "metric" and i + 1 < len(toks):
                    try:
                        nh.metric = int(toks[i + 1])
                    except ValueError:
                        pass
                    i += 2
                elif sub == "preference" and i + 1 < len(toks):
                    try:
                        nh.preference = int(toks[i + 1])
                    except ValueError:
                        pass
                    i += 2
                elif sub == "tag" and i + 1 < len(toks):
                    try:
                        nh.tag = int(toks[i + 1])
                    except ValueError:
                        pass
                    i += 2
                else:
                    i += 1
        route.next_hops.append(nh)
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif key == "qualified-next-hop" and len(toks) >= 2:
        nh_val = toks[1]
        nh = JuniperRouteNextHop(value=nh_val, qualified=True)
        if len(toks) > 2:
            i = 2
            while i < len(toks):
                sub = toks[i].lower()
                if sub == "metric" and i + 1 < len(toks):
                    try:
                        nh.metric = int(toks[i + 1])
                    except ValueError:
                        pass
                    i += 2
                elif sub == "preference" and i + 1 < len(toks):
                    try:
                        nh.preference = int(toks[i + 1])
                    except ValueError:
                        pass
                    i += 2
                elif sub == "tag" and i + 1 < len(toks):
                    try:
                        nh.tag = int(toks[i + 1])
                    except ValueError:
                        pass
                    i += 2
                else:
                    i += 1
        route.next_hops.append(nh)
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif key == "discard":
        route.discard = True
        route.action = "discard"
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif key == "reject":
        route.reject = True
        route.action = "reject"
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif key == "receive":
        route.receive = True
        route.action = "receive"
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif key == "next-table" and len(toks) >= 2:
        route.next_table = toks[1]
        route.action = "next-table"
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif key in {"receive", "reject", "discard"}:
        route.action = key
        setattr(route, key, True)
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif key == "metric" and len(toks) >= 2:
        try:
            route.metric = int(toks[1])
            cmd.extraction_status = ExtractionStatus.NORMALIZED
        except ValueError:
            cmd.extraction_status = ExtractionStatus.PARSE_ERROR
        return True
    elif key == "preference" and len(toks) >= 2:
        try:
            route.preference = int(toks[1])
            cmd.extraction_status = ExtractionStatus.NORMALIZED
        except ValueError:
            cmd.extraction_status = ExtractionStatus.PARSE_ERROR
        return True
    elif key == "tag" and len(toks) >= 2:
        try:
            route.tag = int(toks[1])
            cmd.extraction_status = ExtractionStatus.NORMALIZED
        except ValueError:
            cmd.extraction_status = ExtractionStatus.PARSE_ERROR
        return True
    elif key == "disable":
        route.disabled = True
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif key == "retain":
        route.retain = True
        route.action = "retain"
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    safe_toks = sanitize_tokens(toks)
    route.source_attributes["_".join(safe_toks)] = sanitize_source_attributes(
        {"raw": cmd.raw_sanitized}
    )
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
