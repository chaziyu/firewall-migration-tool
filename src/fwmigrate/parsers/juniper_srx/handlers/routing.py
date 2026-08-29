"""Handler for Junos static routes and routing instances configuration hierarchy."""

from __future__ import annotations

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes
from fwmigrate.parsers.juniper_srx.model import (
    JuniperContextConfig,
    JuniperRoute,
    JuniperRouteNextHop,
)
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand, extract_value_list


def handle_routing_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    """
    Handle static routing commands across:
    1. Root static routes: 'set routing-options static route <dst> ...'
    2. Routing instances: 'set routing-instances <name> routing-options static route <dst> ...'
    """
    toks = cmd.tokens
    if len(toks) < 2:
        return False

    first = toks[1].lower()

    if first == "routing-options":
        cmd.consumed = True
        cmd.handler = "routing"
        if len(toks) >= 5 and toks[2].lower() == "static" and toks[3].lower() == "route":
            dst = toks[4]
            route = _get_or_create_route(context, dst, routing_instance=None)
            if len(toks) == 5:
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            return _parse_route_settings(cmd, toks[5:], route)

        # Other routing-options
        context.source_attributes["_".join(toks[1:])] = sanitize_source_attributes(
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
            and toks[4].lower() == "static"
            and toks[5].lower() == "route"
        ):
            dst = toks[6]
            route = _get_or_create_route(context, dst, routing_instance=inst_name)
            if len(toks) == 7:
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            return _parse_route_settings(cmd, toks[7:], route)

        # Other routing-instance attributes
        context.source_attributes[f"routing_instance_{inst_name}_{'_'.join(toks[3:])}"] = (
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


def _parse_route_settings(
    cmd: JunosCommand, toks: list[str], route: JuniperRoute
) -> bool:
    if not toks:
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True

    key = toks[0].lower()

    if key == "next-hop" and len(toks) >= 2:
        nhs = extract_value_list(toks[1:])
        for nh in nhs:
            if not any(n.value == nh for n in route.next_hops):
                route.next_hops.append(JuniperRouteNextHop(value=nh, qualified=False))
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif key == "qualified-next-hop" and len(toks) >= 2:
        nh_val = toks[1]
        q_nh = None
        for n in route.next_hops:
            if n.value == nh_val and n.qualified:
                q_nh = n
                break
        if not q_nh:
            q_nh = JuniperRouteNextHop(value=nh_val, qualified=True)
            route.next_hops.append(q_nh)

        if len(toks) >= 4:
            sub = toks[2].lower()
            if sub == "preference":
                try:
                    q_nh.preference = int(toks[3])
                except ValueError:
                    pass
            elif sub == "metric":
                try:
                    q_nh.metric = int(toks[3])
                except ValueError:
                    pass
            elif sub == "tag":
                try:
                    q_nh.tag = int(toks[3])
                except ValueError:
                    pass
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif key == "discard":
        route.discard = True
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif key == "reject":
        route.reject = True
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif key == "receive":
        route.receive = True
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    elif key == "next-table" and len(toks) >= 2:
        route.next_table = toks[1]
        cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
        cmd.requires_manual_review = True
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

    route.source_attributes["_".join(toks)] = sanitize_source_attributes(
        {"raw": cmd.raw_sanitized}
    )
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
