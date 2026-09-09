"""Final PAN-OS coverage fixes for policy/NAT-relevant parsing.

This layer closes context and hierarchy gaps that cannot be fixed safely by
loosening the base parser.  Vendor-specific semantics remain explicit source
evidence when canonical IR has no equivalent representation.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple
import xml.etree.ElementTree as ET

from fwmigrate.extraction.models import ExtractionStatus

from .extraction import add_inventory_section_accounting
from .policy_order import apply_effective_policy_order, sync_effective_order_to_ir
from .safe_completeness import PANOSSourceParser as _SafePANOSSourceParser
from .source_model import PANScope
from .xml_utils import member_texts, structured_xml_capture, text_or_none


_EFFECTIVE_ORDER_KEYS = (
    "effective_policy_layer",
    "effective_policy_rank",
    "effective_scope_chain",
    "effective_rule_index",
    "effective_order_complete",
    "pan_effective_order_by_context",
)


class PANOSSourceParser(_SafePANOSSourceParser):
    """PAN-OS parser with complete policy/NAT context accounting."""

    @staticmethod
    def _configured_zone_types(entry: ET.Element) -> Tuple[List[str], Dict[str, List[str]]]:
        network = entry.find("./network")
        if network is None:
            return [], {}
        configured: List[str] = []
        members: Dict[str, List[str]] = {}
        for zone_type in ("layer3", "layer2", "virtual-wire", "tap", "external", "tunnel"):
            node = network.find(f"./{zone_type}")
            if node is None:
                continue
            configured.append(zone_type)
            values = member_texts(network, f"./{zone_type}/member")
            if values:
                members[zone_type] = values
        return configured, members

    def _enhance_zones(self, scope: PANScope, search_root: ET.Element, extraction, zones: List[Any]) -> None:
        super()._enhance_zones(scope, search_root, extraction, zones)
        by_name = {zone.name: zone for zone in zones}
        for entry in search_root.findall("./zone/entry"):
            name = entry.get("name")
            zone = by_name.get(name)
            if zone is None:
                continue

            configured, members = self._configured_zone_types(entry)
            if configured:
                zone.source_attributes["pan_zone_types"] = configured
                zone.source_attributes["pan_zone_type"] = configured[0] if len(configured) == 1 else None
            if len(configured) == 1:
                zone.zone_type = configured[0]

            external_members = members.get("external", [])
            if external_members:
                # External-zone members are VSYS/external-system relationships,
                # not physical interface members.  Preserve them separately so
                # they are never resolved as interfaces.
                zone.source_attributes["pan_external_members"] = external_members
                reason = "external-zone-members-source-specific"
                if reason not in zone.review_reasons:
                    zone.review_reasons.append(reason)

            network = entry.find("./network")
            tunnel = network.find("./tunnel") if network is not None else None
            if tunnel is not None:
                zone.source_attributes["pan_tunnel_zone_configured"] = True
                if list(tunnel) or (tunnel.text and tunnel.text.strip()):
                    zone.source_attributes["pan_tunnel_zone_settings"] = structured_xml_capture(tunnel)

            unknown_network = zone.source_attributes.get("pan_network_settings")
            if isinstance(unknown_network, dict):
                unknown_network.pop("external", None)
                unknown_network.pop("tunnel", None)
                if not unknown_network:
                    zone.source_attributes.pop("pan_network_settings", None)
                    zone.review_reasons = [
                        reason for reason in zone.review_reasons
                        if reason != "Unknown zone fields retained as source evidence."
                    ]

            multiple_reason_prefix = "Multiple effective network types configured:"
            zone.review_reasons = [
                reason for reason in zone.review_reasons
                if not reason.startswith(multiple_reason_prefix)
            ]
            if len(configured) > 1:
                zone.review_reasons.append(
                    f"Multiple effective network types configured: {', '.join(configured)}"
                )

            zone.requires_manual_review = bool(zone.review_reasons)
            zone.migration_status = "PARTIALLY_NORMALIZED" if zone.review_reasons else "NORMALIZED"
            item = self._inventory_item(extraction, "zones", scope, name)
            if item is not None:
                item.source_attributes.update(zone.source_attributes)
                item.requires_manual_review = zone.requires_manual_review
                item.status = (
                    ExtractionStatus.PARTIALLY_NORMALIZED
                    if zone.requires_manual_review else ExtractionStatus.NORMALIZED
                )
                item.notes = list(zone.review_reasons)

    def _extract_template_interfaces(self, content: str, extraction) -> None:
        super()._extract_template_interfaces(content, extraction)
        root = self._unwrap_config(content)
        if root is None:
            return
        for template in self._panorama_template_entries(root):
            template_name = template.get("name")
            if not template_name:
                continue
            for device in template.findall("./config/devices/entry"):
                for vsys in device.findall("./vsys/entry"):
                    vsys_name = vsys.get("name") or "vsys1"
                    for entry in vsys.findall("./zone/entry"):
                        name = entry.get("name")
                        if not name:
                            continue
                        configured, members = self._configured_zone_types(entry)
                        for zone in extraction.canonical_ir.zones:
                            attrs = zone.source_attributes
                            if zone.name != name or attrs.get("pan_template_name") != template_name or attrs.get("pan_vsys") != vsys_name:
                                continue
                            if configured:
                                attrs["pan_zone_types"] = configured
                                attrs["pan_zone_type"] = configured[0] if len(configured) == 1 else None
                            if len(configured) == 1:
                                zone.zone_type = configured[0]
                            if members.get("external"):
                                attrs["pan_external_members"] = members["external"]
                                zone.requires_manual_review = True
                                zone.migration_status = "PARTIALLY_NORMALIZED"
                                if "external-zone-members-source-specific" not in zone.review_reasons:
                                    zone.review_reasons.append("external-zone-members-source-specific")
                            network = entry.find("./network")
                            tunnel = network.find("./tunnel") if network is not None else None
                            if tunnel is not None:
                                attrs["pan_tunnel_zone_configured"] = True
                                if list(tunnel) or (tunnel.text and tunnel.text.strip()):
                                    attrs["pan_tunnel_zone_settings"] = structured_xml_capture(tunnel)

    @staticmethod
    def _panorama_template_entries(root: ET.Element) -> Iterable[ET.Element]:
        # Keep template discovery constrained to the same documented containers
        # used by PANPanoramaExtractor without importing its private internals.
        seen = set()
        for path in ("./template/entry", "./templates/entry", "./panorama/template/entry", "./panorama/templates/entry"):
            for entry in root.findall(path):
                if id(entry) in seen:
                    continue
                seen.add(id(entry))
                yield entry

    def _enhance_nat_rule(self, scope: PANScope, entry: ET.Element, extraction, rule) -> None:
        super()._enhance_nat_rule(scope, entry, extraction, rule)
        attrs = rule.source_attributes

        target = self._target_details(entry.find("./target"))
        if target is not None:
            attrs["pan_target"] = target
            unknown = attrs.get("pan_unknown_fields")
            if isinstance(unknown, dict):
                unknown.pop("target", None)
                if not unknown:
                    attrs.pop("pan_unknown_fields", None)
                    if "unknown-fields" in rule.review_reasons:
                        rule.review_reasons.remove("unknown-fields")
            if "panorama-target-context" not in rule.review_reasons:
                rule.review_reasons.append("panorama-target-context")

        source_translation = entry.find("./source-translation")
        if source_translation is not None and len(list(source_translation)) == 1:
            node = list(source_translation)[0]
            source_semantics: Dict[str, Any] = {
                "type": node.tag,
                "source_entry": structured_xml_capture(node),
            }
            translated = member_texts(node, "./translated-address/member")
            scalar = text_or_none(node, "./translated-address")
            if not translated and scalar:
                translated = [scalar]
            if translated:
                source_semantics["translated_address"] = translated
            if node.tag == "persistent-dynamic-ip-and-port":
                source_semantics["persistent"] = True
            interface_address = attrs.get("pan_interface_address_details")
            if interface_address:
                source_semantics["interface_address"] = interface_address
            fallback = attrs.get("pan_source_translation_fallback_details")
            if fallback:
                source_semantics["fallback"] = fallback
            if node.tag == "static-ip" and "pan_static_ip_bi_directional" in attrs:
                source_semantics["bi_directional"] = attrs["pan_static_ip_bi_directional"]
            attrs["pan_source_translation_semantics"] = source_semantics

        destination = entry.find("./dynamic-destination-translation")
        dynamic_destination = destination is not None
        if destination is None:
            destination = entry.find("./destination-translation")
        if destination is not None:
            destination_semantics: Dict[str, Any] = {
                "type": "dynamic-destination-translation" if dynamic_destination else "destination-translation",
                "source_entry": structured_xml_capture(destination),
            }
            translated = member_texts(destination, "./translated-address/member")
            scalar = text_or_none(destination, "./translated-address")
            if not translated and scalar:
                translated = [scalar]
            if translated:
                destination_semantics["translated_address"] = translated
            port = text_or_none(destination, "./translated-port")
            if port is not None:
                destination_semantics["translated_port"] = port
            distribution = text_or_none(destination, "./distribution")
            if distribution is not None:
                destination_semantics["distribution"] = distribution
            attrs["pan_destination_translation_semantics"] = destination_semantics

        rule.review_reasons = list(dict.fromkeys(rule.review_reasons))
        rule.requires_manual_review = bool(rule.review_reasons)
        rule.migration_status = "PARTIALLY_NORMALIZED" if rule.review_reasons else "NORMALIZED"
        item = self._inventory_item(extraction, "nat", scope, entry.get("name"))
        if item is not None:
            item.source_attributes.update(attrs)
            item.requires_manual_review = rule.requires_manual_review
            item.status = (
                ExtractionStatus.PARTIALLY_NORMALIZED
                if rule.requires_manual_review else ExtractionStatus.NORMALIZED
            )
            if rule.review_reasons:
                item.notes = [f"PAN-OS NAT rule requires review: {', '.join(rule.review_reasons)}."]

    @staticmethod
    def _unwrap_source_config(content: str) -> Optional[ET.Element]:
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return None
        if root.tag == "response":
            root = root.find("./result/config")
        return root if root is not None and root.tag == "config" else None

    def _extract_panorama_vsys_rule_views(self, content: str, extraction) -> None:
        root = self._unwrap_source_config(content)
        if root is None:
            return
        entries = list(root.findall("./panorama/vsys/entry"))
        entries.extend(root.findall("./readonly/panorama/vsys/entry"))
        seen = set()
        for entry in entries:
            if id(entry) in seen:
                continue
            seen.add(id(entry))
            name = entry.get("name") or "vsys1"
            scope = PANScope(kind="panorama-vsys", name=name, vsys=name)
            policy_before = len(extraction.canonical_ir.policies)
            nat_before = len(extraction.canonical_ir.nat_rules)
            inventory_before = len(extraction.inventory_items)
            self._parse_rules(scope, entry, extraction)

            for policy in extraction.canonical_ir.policies[policy_before:]:
                policy.source_extra_settings["pan_pushed_policy_view"] = True
                policy.source_extra_settings["pan_pushed_policy_path"] = f"panorama/vsys/entry[@name='{name}']"
                if "pushed-panorama-vsys-view" not in policy.review_reasons:
                    policy.review_reasons.append("pushed-panorama-vsys-view")
                policy.requires_manual_review = True
                policy.migration_status = "PARTIALLY_NORMALIZED"
            for rule in extraction.canonical_ir.nat_rules[nat_before:]:
                rule.source_attributes["pan_pushed_policy_view"] = True
                rule.source_attributes["pan_pushed_policy_path"] = f"panorama/vsys/entry[@name='{name}']"
                if "pushed-panorama-vsys-view" not in rule.review_reasons:
                    rule.review_reasons.append("pushed-panorama-vsys-view")
                rule.requires_manual_review = True
                rule.migration_status = "PARTIALLY_NORMALIZED"
            for item in extraction.inventory_items[inventory_before:]:
                if item.domain not in {"policies", "nat", "default_security_rules"}:
                    continue
                item.source_attributes["pan_pushed_policy_view"] = True
                item.source_attributes["pan_pushed_policy_path"] = f"panorama/vsys/entry[@name='{name}']"
                item.requires_manual_review = True
                if item.status == ExtractionStatus.NORMALIZED:
                    item.status = ExtractionStatus.PARTIALLY_NORMALIZED
                note = "PAN-OS pushed Panorama VSYS policy view is retained separately from source device-group policy."
                if note not in item.notes:
                    item.notes.append(note)

    @staticmethod
    def _target_applicability(target: Optional[Dict[str, Any]], context: str) -> str:
        if not target:
            return "applicable"
        if target.get("tags"):
            # Dynamic target tags require managed-device tag state that is not
            # present in a normal config export.
            return "unknown"
        devices = target.get("devices") or []
        if not devices:
            return "applicable"

        serial: Optional[str] = None
        vsys: Optional[str] = None
        if context.startswith("device:") and ":vsys:" in context:
            serial, vsys = context[len("device:"):].split(":vsys:", 1)
        elif context.startswith("vsys:"):
            vsys = context[len("vsys:"):]
        elif context.startswith("panorama-vsys:"):
            # Pushed policy views are already scoped by Panorama.
            return "applicable"
        else:
            return "unknown"

        if serial is not None:
            matched = any(
                device.get("name") == serial
                and (not device.get("vsys") or vsys in device.get("vsys", []))
                for device in devices
            )
            status = "applicable" if matched else "not-applicable"
        else:
            candidates = [
                device for device in devices
                if not device.get("vsys") or vsys in device.get("vsys", [])
            ]
            status = "not-applicable" if not candidates else "unknown"

        if str(target.get("negate", "no")).lower() == "yes":
            if status == "applicable":
                return "not-applicable"
            if status == "not-applicable":
                return "applicable"
        return status

    @staticmethod
    def _inventory_order_map(item) -> Optional[Dict[str, Dict[str, Any]]]:
        value = item.source_attributes.get("pan_effective_order_by_context")
        return value if isinstance(value, dict) else None

    def _apply_target_applicability(self, extraction) -> None:
        for item in extraction.inventory_items:
            if item.domain not in {"policies", "nat"}:
                continue
            target = item.source_attributes.get("pan_target")
            order_map = self._inventory_order_map(item)
            if not target or not order_map:
                continue
            applicability: Dict[str, str] = {}
            for context in list(order_map):
                status = self._target_applicability(target, context)
                applicability[context] = status
                if status == "not-applicable":
                    order_map.pop(context, None)
                elif status == "unknown":
                    order_map[context]["effective_order_complete"] = False
            item.source_attributes["pan_target_applicability_by_context"] = applicability

        # Target filtering can remove a rule from only one managed device.
        # Re-rank every remaining concrete context independently.
        for domain in ("policies", "nat"):
            contexts = sorted({
                context
                for item in extraction.inventory_items if item.domain == domain
                for context in (self._inventory_order_map(item) or {})
            })
            for context in contexts:
                items = [
                    item for item in extraction.inventory_items
                    if item.domain == domain and context in (self._inventory_order_map(item) or {})
                ]
                items.sort(key=lambda item: (
                    (self._inventory_order_map(item) or {})[context].get("effective_policy_rank", 2**31),
                    item.source_attributes.get("pan_source_rule_index", 2**31),
                ))
                for rank, item in enumerate(items):
                    position = (self._inventory_order_map(item) or {})[context]
                    position["effective_policy_rank"] = rank
                    position["effective_rule_index"] = rank

        for item in extraction.inventory_items:
            if item.domain not in {"policies", "nat"}:
                continue
            order_map = self._inventory_order_map(item)
            if order_map is None:
                continue
            for key in _EFFECTIVE_ORDER_KEYS[:-1]:
                item.source_attributes.pop(key, None)
            if order_map:
                first_context = sorted(order_map)[0]
                item.source_attributes.update(order_map[first_context])

    @staticmethod
    def _mark_nat_hierarchy_completeness(extraction) -> None:
        hierarchy_error = any(
            item.domain == "panorama_hierarchy" and item.status == ExtractionStatus.PARSE_ERROR
            for item in extraction.inventory_items
        )
        if not hierarchy_error:
            return
        for item in extraction.inventory_items:
            if item.domain != "nat":
                continue
            order_map = item.source_attributes.get("pan_effective_order_by_context")
            if isinstance(order_map, dict):
                for position in order_map.values():
                    position["effective_order_complete"] = False
            if "effective_order_complete" in item.source_attributes:
                item.source_attributes["effective_order_complete"] = False

    @staticmethod
    def _annotate_pushed_view_order(extraction) -> None:
        for domain in ("policies", "nat"):
            grouped: Dict[str, List[Any]] = {}
            for item in extraction.inventory_items:
                if item.domain != domain or item.source_attributes.get("scope_kind") != "panorama-vsys":
                    continue
                grouped.setdefault(item.source_attributes.get("scope_name") or "vsys1", []).append(item)
            for name, items in grouped.items():
                context = f"panorama-vsys:{name}"
                position_order = {"pre": 0, "local": 1, "post": 2}
                items.sort(key=lambda item: (
                    position_order.get(item.source_attributes.get("pan_rulebase_position"), 99),
                    item.source_attributes.get("pan_source_rule_index", 2**31),
                ))
                for rank, item in enumerate(items):
                    source_position = item.source_attributes.get("pan_rulebase_position") or "local"
                    position = {
                        "effective_policy_layer": f"pushed-{source_position}-rules",
                        "effective_policy_rank": rank,
                        "effective_scope_chain": [context],
                        "effective_rule_index": rank,
                        "effective_order_complete": True,
                    }
                    item.source_attributes.setdefault("pan_effective_order_by_context", {})[context] = position
                    item.source_attributes.update(position)

    @staticmethod
    def _refresh_extraction_accounting(extraction) -> None:
        extraction.source_sections = [
            section for section in extraction.source_sections
            if section.parser_handler != "palo_alto.inventory_terminal_accounting"
        ]
        add_inventory_section_accounting(extraction)
        review_items = [item for item in extraction.inventory_items if item.requires_manual_review]
        blocking_items = [
            item for item in extraction.inventory_items
            if item.status in {
                ExtractionStatus.PARTIALLY_NORMALIZED,
                ExtractionStatus.UNSUPPORTED,
                ExtractionStatus.PARSE_ERROR,
                ExtractionStatus.EXTRACT_ONLY,
            } and item.requires_manual_review
        ]
        extraction.requires_manual_review = bool(review_items)
        extraction.migration_complete = not any(
            item.status in {ExtractionStatus.UNSUPPORTED, ExtractionStatus.PARSE_ERROR}
            for item in extraction.inventory_items
        )
        extraction.generation_safe = not blocking_items
        extraction.blocking_reasons = list(dict.fromkeys(
            f"{item.source_path}: {item.notes[0] if item.notes else item.status.value}"
            for item in blocking_items
        ))

    def extract(self, content: str, zone_mapping: Optional[Dict[str, str]] = None):
        extraction = super().extract(content, zone_mapping)
        self._extract_panorama_vsys_rule_views(content, extraction)

        # New pushed-view rules are added after the base pass.  Reapply source
        # ordering, then make Panorama targets effective per managed device.
        apply_effective_policy_order(extraction, self.resolver)
        self._annotate_pushed_view_order(extraction)
        self._apply_target_applicability(extraction)
        self._mark_nat_hierarchy_completeness(extraction)
        sync_effective_order_to_ir(extraction)
        self._refresh_extraction_accounting(extraction)
        return extraction
