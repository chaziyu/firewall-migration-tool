"""PAN-OS device-network routing extraction."""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, Optional, Tuple
import xml.etree.ElementTree as ET

from fwmigrate.ir.core import IRRoute
from fwmigrate.extraction.models import ExtractionStatus

from .extraction import add_source_section, record_normalized, record_partial, record_parse_error
from .source_model import PANScope
from .xml_utils import collect_unknown_children, structured_xml_capture, text_or_none


class PANRouteExtractor:
    @staticmethod
    def _integer(entry: ET.Element, path: str) -> Tuple[Optional[int], Optional[str]]:
        raw = text_or_none(entry, path)
        if raw is None:
            return None, None
        try:
            return int(raw), None
        except ValueError:
            return None, f"{path} must be an integer, found {raw!r}"

    @staticmethod
    def _extract_route(
        scope: PANScope,
        vr_name: str,
        entry: ET.Element,
        family: str,
        extraction,
    ) -> bool:
        name = entry.get("name")
        source_path = (
            f"network/virtual-router/entry[@name='{vr_name}']/routing-table/"
            f"{'ip' if family == 'ipv4' else 'ipv6'}/static-route/entry[@name='{name}']"
        )
        evidence: Dict[str, Any] = {
            "pan_virtual_router": vr_name,
            "pan_address_family": family,
            "pan_source_path": source_path,
            "pan_source_entry": structured_xml_capture(entry),
        }
        destination = text_or_none(entry, "./destination")
        if not name or not destination:
            record_parse_error(
                extraction, "routes", source_path, scope, name, evidence,
                notes=["PAN-OS static route is missing its name or required destination."],
            )
            return False
        try:
            normalized_destination = str(ipaddress.ip_network(destination, strict=False))
            expected_version = 4 if family == "ipv4" else 6
            if ipaddress.ip_network(destination, strict=False).version != expected_version:
                raise ValueError(f"destination address family does not match {family}")
        except ValueError as error:
            evidence["pan_destination"] = destination
            record_parse_error(
                extraction, "routes", source_path, scope, name, evidence,
                notes=[f"Malformed PAN-OS static-route destination: {error}."],
            )
            return False

        next_hop_node = entry.find("./nexthop")
        next_hop_values = {}
        if next_hop_node is not None:
            for child in next_hop_node:
                next_hop_values[child.tag] = (child.text or "").strip() or structured_xml_capture(child)
        evidence["pan_nexthop"] = next_hop_values
        supported_next_hops = {
            "ip-address": "ip-address",
            "ipv6-address": "ip-address",
            "discard": "discard",
            "fqdn": "fqdn",
            "next-vr": "next-vr",
        }
        configured = [key for key in next_hop_values if key in supported_next_hops]
        partial_reasons = []
        next_hop = None
        blackhole = None
        if len(configured) > 1:
            partial_reasons.append("ambiguous-next-hop")
        elif configured:
            variant = configured[0]
            value = next_hop_values[variant]
            evidence["pan_next_hop_type"] = supported_next_hops[variant]
            if variant == "discard":
                blackhole = True
                next_hop = None
            else:
                next_hop = value if isinstance(value, str) else None
            if variant in {"fqdn", "next-vr"}:
                partial_reasons.append(f"next-hop-{variant}")
        elif next_hop_node is not None:
            partial_reasons.append("unsupported-next-hop")

        metric, metric_error = PANRouteExtractor._integer(entry, "./metric")
        admin_distance, admin_error = PANRouteExtractor._integer(entry, "./admin-dist")
        if metric_error or admin_error:
            record_parse_error(
                extraction, "routes", source_path, scope, name, evidence,
                notes=[error for error in (metric_error, admin_error) if error],
            )
            return False
        evidence["pan_metric_explicit"] = metric is not None
        evidence["pan_admin_distance_explicit"] = admin_distance is not None

        interface = text_or_none(entry, "./interface")
        bfd = entry.find("./bfd")
        path_monitor = entry.find("./path-monitor")
        route_table = entry.find("./route-table")
        if bfd is not None:
            evidence["pan_bfd"] = structured_xml_capture(bfd)
            partial_reasons.append("bfd")
        if path_monitor is not None:
            evidence["pan_path_monitor"] = structured_xml_capture(path_monitor)
            partial_reasons.append("path-monitor")
        if route_table is not None:
            evidence["pan_route_table"] = structured_xml_capture(route_table)
            partial_reasons.append("route-table-installation")

        known = ["destination", "nexthop", "interface", "metric", "admin-dist",
                 "bfd", "path-monitor", "route-table"]
        unknown = collect_unknown_children(entry, known)
        if unknown:
            evidence["pan_unknown_fields"] = unknown
            partial_reasons.append("unknown-fields")
        partial_reasons = list(dict.fromkeys(partial_reasons))
        route = IRRoute(
            name=name,
            source_context=f"{scope.kind}:{scope.name}:virtual-router:{vr_name}",
            address_family=family,
            destination=normalized_destination,
            source_destination=destination,
            source_prefix=destination,
            interface=interface,
            next_hop=next_hop,
            administrative_distance=admin_distance,
            metric=metric,
            blackhole=blackhole,
            migration_status="PARTIALLY_NORMALIZED" if partial_reasons else "NORMALIZED",
            review_reasons=partial_reasons,
            requires_manual_review=bool(partial_reasons),
            source_attributes=evidence,
        )
        extraction.canonical_ir.routes.append(route)
        if partial_reasons:
            record_partial(
                extraction, "routes", source_path, scope, name, evidence,
                notes=[f"PAN-OS static route requires review: {', '.join(partial_reasons)}."],
            )
        else:
            record_normalized(extraction, "routes", source_path, scope, name, evidence)
        return True

    @staticmethod
    def extract_static_routes(scope: PANScope, network_root: ET.Element, extraction) -> None:
        """Extract virtual-router routes from the device ``network`` subtree."""
        for family, path in (
            ("ipv4", "./routing-table/ip/static-route/entry"),
            ("ipv6", "./routing-table/ipv6/static-route/entry"),
        ):
            source_count = parsed_count = normalized_count = 0
            for vr_entry in network_root.findall("./virtual-router/entry"):
                vr_name = vr_entry.get("name") or "<unnamed>"
                entries = vr_entry.findall(path)
                source_count += len(entries)
                for entry in entries:
                    before = len(extraction.canonical_ir.routes)
                    handled = PANRouteExtractor._extract_route(
                        scope, vr_name, entry, family, extraction
                    )
                    parsed_count += int(handled)
                    if len(extraction.canonical_ir.routes) > before:
                        route = extraction.canonical_ir.routes[-1]
                        normalized_count += int(route.migration_status == "NORMALIZED")
            if source_count:
                status = (
                    ExtractionStatus.NORMALIZED
                    if normalized_count == source_count else ExtractionStatus.PARTIALLY_NORMALIZED
                )
                add_source_section(
                    extraction, f"network/virtual-router/{family}/static-route", status,
                    source_count, parsed_count, normalized_count,
                    "PANRouteExtractor.extract_static_routes",
                    source_context=f"{scope.kind}:{scope.name}",
                )
