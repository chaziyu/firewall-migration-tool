"""PAN-OS device-network routing extraction."""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, Optional, Tuple
import xml.etree.ElementTree as ET

from fwmigrate.ir.core import IRRoute
from fwmigrate.extraction.models import ExtractionStatus

from .extraction import add_source_section, record_normalized, record_partial, record_parse_error
from .source_model import PANScope
from .resolver import PANResolver
from .routing_instances import PANRoutingInstance, discover_routing_instances, static_route_entries
from .xml_utils import collect_unknown_children, structured_xml_capture, text_or_none
from .dynamic_routing import extract_dynamic_routing


class PANRouteExtractor:
    extract_dynamic_routing = staticmethod(extract_dynamic_routing)
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
    def _resolve_destination(
        destination: str, family: str, scope: PANScope, resolver: PANResolver,
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Dict[str, Any]]:
        expected_version = 4 if family == "ipv4" else 6
        try:
            network = ipaddress.ip_network(destination, strict=False)
            if network.version != expected_version:
                raise ValueError(f"destination address family does not match {family}")
            return str(network), None, None, {}
        except ValueError as literal_error:
            resolved = resolver.resolve(destination, "address-reference", scope)
            if resolved is None:
                # Tokens that look like IP syntax are malformed literals; other
                # tokens are retained as unresolved source references.
                if any(char in destination for char in ".:/"):
                    raise literal_error
                return None, destination, "unresolved-destination-reference", {
                    "pan_destination": destination,
                    "pan_destination_reference": destination,
                    "pan_destination_reference_canonical": destination,
                    "pan_destination_resolution": "unresolved-reference",
                }

            reference = resolved.canonical_name or destination
            evidence = {
                "pan_destination": destination,
                "pan_destination_reference": destination,
                "pan_destination_reference_canonical": reference,
                "pan_destination_reference_kind": resolved.kind,
                "pan_destination_reference_source_path": resolved.source_path,
                "pan_destination_reference_scope": (
                    f"{resolved.scope.kind}:{resolved.scope.name}"
                    if resolved.scope else None
                ),
            }
            if resolved.kind == "address-group":
                evidence["pan_destination_resolution"] = "address-group"
                return None, reference, "destination-address-group-reference", evidence

            source_type = resolved.attributes.get("pan_source_type")
            source_value = resolved.attributes.get("pan_source_value")
            evidence.update({
                "pan_destination_source_type": source_type,
                "pan_destination_source_value": source_value,
            })
            if source_type != "ip-netmask" or not source_value:
                evidence["pan_destination_resolution"] = "unsupported-address-object"
                return None, reference, "unsupported-destination-reference-type", evidence

            network = ipaddress.ip_network(source_value, strict=False)
            evidence["pan_destination_resolution"] = "address-object"
            evidence["pan_resolved_destination"] = str(network)
            if network.version != expected_version:
                return None, reference, "destination-address-family-mismatch", evidence
            return str(network), reference, "destination-address-reference", evidence

    @staticmethod
    def _extract_route(
        scope: PANScope,
        routing_instance: PANRoutingInstance,
        entry: ET.Element,
        family: str,
        extraction,
        resolver: PANResolver,
        resolution_scope: Optional[PANScope] = None,
    ) -> bool:
        name = entry.get("name")
        instance_path = routing_instance.source_path or "network/routing-instance"
        source_path = f"{instance_path}/routing-table/{'ip' if family == 'ipv4' else 'ipv6'}/static-route/entry[@name='{name}']"
        evidence: Dict[str, Any] = {
            "pan_routing_instance_type": routing_instance.instance_type,
            "pan_virtual_router": routing_instance.virtual_router_name,
            "pan_logical_router": routing_instance.logical_router_name,
            "pan_vrf": routing_instance.vrf_name,
            "pan_address_family": family,
            "pan_source_path": source_path,
            "pan_source_entry": structured_xml_capture(entry),
        }
        if scope.device_serial:
            evidence["pan_device_serial"] = scope.device_serial
        evidence = {key: value for key, value in evidence.items() if value is not None}
        destination = text_or_none(entry, "./destination")
        if not name or not destination:
            note = ("PAN-OS static route is missing its required name."
                    if not name else f"{family.upper()} route missing required destination.")
            record_parse_error(
                extraction, "routes", source_path, scope, name, evidence,
                notes=[note],
            )
            return False
        try:
            (normalized_destination, destination_reference, destination_reason,
             destination_evidence) = PANRouteExtractor._resolve_destination(
                destination, family, resolution_scope or scope, resolver
            )
        except ValueError as error:
            evidence["pan_destination"] = destination
            record_parse_error(
                extraction, "routes", source_path, scope, name, evidence,
                notes=[f"Malformed PAN-OS static-route destination: {error}."],
            )
            return False
        evidence.update({key: value for key, value in destination_evidence.items() if value is not None})

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
        partial_reasons = [destination_reason] if destination_reason else []
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
        scope_identity = f"{scope.kind}:{scope.name}"
        if scope.device_serial:
            scope_identity += f":device:{scope.device_serial}"
        if routing_instance.instance_type == "virtual-router":
            route_context = f"{scope_identity}:virtual-router:{routing_instance.virtual_router_name}"
        else:
            route_context = (
                f"{scope_identity}:logical-router:{routing_instance.logical_router_name}"
                f":vrf:{routing_instance.vrf_name}"
            )
        route = IRRoute(
            name=name,
            source_context=route_context,
            address_family=family,
            destination=normalized_destination,
            source_destination=destination,
            source_destination_reference=destination_reference,
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
    def extract_static_routes(
        scope: PANScope, network_root: ET.Element, extraction, resolver: PANResolver,
        resolution_scope: Optional[PANScope] = None,
    ) -> None:
        """Extract routes from both legacy VRs and logical-router VRFs."""
        instances = list(discover_routing_instances(network_root))
        for family in ("ipv4", "ipv6"):
            source_count = parsed_count = normalized_count = 0
            for routing_instance in instances:
                _, entries = static_route_entries(routing_instance, family)
                source_count += len(entries)
                for entry in entries:
                    before = len(extraction.canonical_ir.routes)
                    handled = PANRouteExtractor._extract_route(
                        scope, routing_instance, entry, family, extraction, resolver,
                        resolution_scope,
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
                    extraction, f"network/routing-instances/{family}/static-route", status,
                    source_count, parsed_count, normalized_count,
                    "PANRouteExtractor.extract_static_routes",
                    source_context=f"{scope.kind}:{scope.name}",
                )
