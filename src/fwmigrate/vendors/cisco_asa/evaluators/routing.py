"""ASA routing command evaluation."""

from __future__ import annotations

import ipaddress
import re
from typing import Optional, Tuple
from fwmigrate.vendors.cisco_asa.model.base import CiscoSourceRecord
from fwmigrate.vendors.cisco_asa.model.routing import CiscoSLAMonitor, CiscoTrack, CiscoStaticRoute, CiscoRouteMap, CiscoRouteMapRule
from fwmigrate.vendors.cisco_asa.net_utils import normalize_ipv4_network
from fwmigrate.extraction.sanitize import sanitize_raw_text
from . import _mark_explicit


class RoutingEvaluator:

    def _parse_route_line(self, line: str) -> Tuple[Optional[CiscoStaticRoute], Optional[str]]:
        tokens = line.split()
        ipv6 = len(tokens) >= 2 and tokens[0].lower() == "ipv6" and tokens[1].lower() == "route"
        index = 2 if ipv6 else 1
        interface = tokens[index] if len(tokens) > index else None
        null_route = not ipv6 and interface and interface.lower() == "null0"
        required = 3
        if len(tokens) - index < required:
            return CiscoStaticRoute(interface=interface, address_family="ipv6" if ipv6 else "ipv4", raw_line=line,
                                    extraction_status="PARSE_ERROR", requires_manual_review=True,
                                    explicit_fields={"interface", "address_family"}), "Incomplete static route statement"
        if ipv6:
            destination, mask, gateway = tokens[index + 1], None, tokens[index + 2]
            index += 3
            try:
                ipaddress.IPv6Network(destination, strict=False)
                ipaddress.IPv6Address(gateway)
            except ValueError:
                return CiscoStaticRoute(
                    interface=interface, destination=destination, gateway=gateway,
                    address_family="ipv6", raw_line=line, extraction_status="PARSE_ERROR",
                    requires_manual_review=True, explicit_fields={"interface", "destination", "gateway", "address_family"},
                ), "Invalid IPv6 route prefix or next hop"
        elif null_route:
            destination, mask = tokens[index + 1:index + 3]
            gateway = None
            index += 3
        else:
            destination, mask = tokens[index + 1:index + 3]
            index += 3
            gateway = None
            if index < len(tokens):
                try:
                    ipaddress.IPv4Address(tokens[index])
                except ValueError:
                    if not tokens[index].isdigit() and tokens[index].lower() not in {"track", "tunneled"}:
                        return CiscoStaticRoute(
                            interface=interface, destination=destination, mask=mask, gateway=tokens[index],
                            address_family="ipv4", raw_line=line, extraction_status="PARSE_ERROR",
                            requires_manual_review=True,
                            explicit_fields={"interface", "destination", "mask", "gateway", "address_family"},
                        ), "Invalid IPv4 route next hop"
                else:
                    gateway = tokens[index]
                    index += 1
        route = CiscoStaticRoute(
            interface=interface, destination=destination, mask=mask, gateway=gateway,
            address_family="ipv6" if ipv6 else "ipv4", raw_line=line,
            explicit_fields={"interface", "destination", "address_family"} | ({"gateway"} if gateway is not None else set()) | (set() if ipv6 else {"mask"}),
        )
        if not ipv6 and normalize_ipv4_network(destination, mask or "") is None:
            route.extraction_status = "PARSE_ERROR"
            route.requires_manual_review = True
            return route, "Invalid IPv4 route destination/netmask"
        optional_tokens = tokens[index:]
        if not ipv6 and not null_route and gateway is None:
            route.extraction_status = "PARTIAL"
            route.requires_manual_review = True
            route.review_reasons.append("Gateway-absent route validity depends on transparent-mode context")
        while index < len(tokens):
            token = tokens[index].lower()
            if token.isdigit() and route.administrative_distance is None:
                distance = int(token)
                if not 1 <= distance <= 255:
                    route.extraction_status = "PARSE_ERROR"
                    route.requires_manual_review = True
                    route.review_reasons.append("Route administrative distance must be between 1 and 255")
                else:
                    route.administrative_distance = distance
                    _mark_explicit(route, "administrative_distance")
                index += 1
            elif token == "track" and index + 1 < len(tokens) and tokens[index + 1].isdigit():
                route.track_id = int(tokens[index + 1])
                _mark_explicit(route, "track_id")
                index += 2
            elif token == "tunneled":
                route.tunneled = True
                _mark_explicit(route, "tunneled")
                index += 1
            else:
                route.raw_options.append(tokens[index])
                route.raw_extra.setdefault("unparsed_options", []).append(sanitize_raw_text(tokens[index]))
                index += 1
        route.source_attributes.update({"source_line": line, "optional_tokens": optional_tokens})
        if route.track_id is not None:
            route.review_reasons.append("Route tracking dependency requires target review")
        if route.tunneled:
            route.review_reasons.append("ASA tunneled route semantics require target review")
        if route.raw_options:
            route.review_reasons.append(f"Unparsed route options: {' '.join(route.raw_options)}")
        if route.review_reasons and route.extraction_status != "PARSE_ERROR":
            route.extraction_status = "PARTIAL"
            route.requires_manual_review = True
        return route, None

    def _parse_route_map_block(self, lines, i, line_number, line, route_map_match):
        route_map = CiscoRouteMap(name=route_map_match.group(1), raw_lines=[line])
        rule = CiscoRouteMapRule(
            name=route_map.name, sequence=int(route_map_match.group(3)),
            action=route_map_match.group(2).lower(), raw_lines=[line],
            source_attributes={"raw_header": line},
        )
        i += 1
        while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
            sub = lines[i].strip()
            rule.raw_lines.append(sub)
            route_map.raw_lines.append(sub)
            match_acl = re.match(r"^match\s+(?:ip\s+address|access-list)\s+(.+)$", sub, re.IGNORECASE)
            next_hop = re.match(r"^set\s+ip\s+next-hop(?:\s+verify-availability)?\s+(.+)$", sub, re.IGNORECASE)
            set_interface = re.match(r"^set\s+interface\s+(.+)$", sub, re.IGNORECASE)
            if match_acl:
                rule.match_acls.extend(
                    value for value in match_acl.group(1).split()
                    if value not in rule.match_acls
                )
                rule.match_acl = rule.match_acls[0] if rule.match_acls else None
            elif next_hop:
                candidates = [
                    token for token in next_hop.group(1).split()
                    if _valid_ip(token)
                ]
                if candidates:
                    rule.next_hops.extend(value for value in candidates if value not in rule.next_hops)
                    rule.set_next_hop = rule.next_hops[0] if rule.next_hops else None
                    rule.source_attributes["next_hops"] = candidates
                    if len(candidates) > 1 or "verify-availability" in sub.lower():
                        rule.source_attributes["next_hop_options"] = sub
                else:
                    tokens = next_hop.group(1).split()
                    rule.next_hops.extend(value for value in tokens if value not in rule.next_hops)
                    rule.set_next_hop = rule.next_hops[0] if rule.next_hops else None
                    rule.raw_options.append(sub)
            elif set_interface:
                rule.output_interfaces.extend(
                    value for value in set_interface.group(1).split()
                    if value not in rule.output_interfaces
                )
                rule.set_interface = rule.output_interfaces[0] if rule.output_interfaces else None
            else:
                rule.raw_options.append(sub)
            i += 1
        route_map = self._with_source_context(route_map, line_number)
        existing = next((item for item in self.config.route_maps if item.name == route_map.name and item.source_context == route_map.source_context), None)
        if existing is None:
            route_map.rules.append(rule)
            self.config.route_maps.append(route_map)
        else:
            existing.rules.append(rule)
            existing.raw_lines.extend(route_map.raw_lines)
        for acl_name in rule.match_acls:
        return i

    def _parse_routing_source_only(self, line, index, children):
        lower = line.lower()
        if re.match(r"^track\s+\d+\s+", lower):
            track_id = int(line.split()[1])
            parts = line.split()
            record = CiscoTrack(name=f"track:{track_id}", track_id=track_id, track_type=parts[2] if len(parts) > 2 else None,
                                 sla_id=int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else None,
                                 raw_lines=[line], source_attributes={"raw_command": line})
            self.config.tracks.append(self._with_source_context(record, index + 1))
        elif re.match(r"^sla\s+monitor\s+\d+\b", lower):
            parts = line.split()
            sla_id = int(parts[2])
            record = CiscoSLAMonitor(name=f"sla:{sla_id}", sla_id=sla_id, operation=" ".join(parts[3:]),
                                     raw_lines=[line], source_attributes={"raw_command": line})
            for child in children:
                record.raw_lines.append(child)
                record.source_attributes.setdefault("raw_commands", []).append(child)
                child_parts = child.split()
                if child_parts[:1] == ["frequency"] and len(child_parts) == 2 and child_parts[1].isdigit():
                    record.frequency = int(child_parts[1])
                elif child_parts[:1] == ["ip sla"]:
                    record.target = child_parts[-1]
            self.config.sla_monitors.append(self._with_source_context(record, index + 1))
        elif re.match(r"^router\s+\S+", lower):
            record = CiscoSourceRecord(name=f"router:{index + 1}", raw_lines=[line] + children,
                                        source_attributes={"protocol": line.split()[1], "raw_command": line})
            self.config.dynamic_routing.append(self._with_source_context(record, index + 1))


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

