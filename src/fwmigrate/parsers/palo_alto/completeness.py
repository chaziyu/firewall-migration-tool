"""Completeness extensions for policy/NAT-relevant PAN-OS parsing.

This module subclasses the main PAN-OS parser without broadening scope beyond
interfaces, zones, Security policy, NAT, schedules, tags, and security-profile
references.  It converts source semantics that were previously retained only
as residual evidence into explicit, validated parser output where the existing
IR already has a suitable representation.
"""
from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.ir.core import IRInterfaceSecondaryIP, IRNATPortRange, IRZone

from .interfaces import apply_routing_instance_associations, extract_interfaces
from .panorama import PANPanoramaExtractor
from .parser import PANOSSourceParser as _BasePANOSSourceParser, _configured_pan_zone_types
from .source_model import PANScope, pan_scope_identity
from .xml_utils import member_texts, structured_xml_capture, text_or_none


class PANOSSourceParser(_BasePANOSSourceParser):
    """PAN-OS parser with lossless handling for previously partial fields."""

    @staticmethod
    def _inventory_item(extraction, domain: str, scope: PANScope, name: Optional[str]):
        for item in reversed(extraction.inventory_items):
            if item.domain != domain or item.name != name:
                continue
            attrs = item.source_attributes
            if attrs.get("scope_kind") != scope.kind or attrs.get("scope_name") != scope.name:
                continue
            item_serial = attrs.get("scope_device_serial")
            if scope.device_serial:
                if item_serial != scope.device_serial:
                    continue
            elif item_serial:
                continue
            return item
        return None

    def _resolve_tag_references(self, scope: PANScope, values: List[str]) -> tuple[List[str], List[str]]:
        resolved: List[str] = []
        unresolved: List[str] = []
        for value in values:
            obj = self.resolver.resolve(value, "tag", scope)
            if obj is None:
                unresolved.append(value)
                resolved.append(value)
            else:
                resolved.append(obj.canonical_name or value)
        return resolved, unresolved

    @staticmethod
    def _target_details(target: Optional[ET.Element]) -> Optional[Dict[str, Any]]:
        if target is None:
            return None
        devices: List[Dict[str, Any]] = []
        for device in target.findall("./devices/entry"):
            devices.append({
                "name": device.get("name"),
                "vsys": [
                    entry.get("name")
                    for entry in device.findall("./vsys/entry")
                    if entry.get("name")
                ],
                "source_entry": structured_xml_capture(device),
            })
        tags = member_texts(target, "./tags/member")
        if not tags:
            tags = member_texts(target, "./tag/member")
        return {
            key: value
            for key, value in {
                "negate": text_or_none(target, "./negate"),
                "devices": devices,
                "tags": tags,
                "source_entry": structured_xml_capture(target),
            }.items()
            if value not in (None, [], {})
        }

    def _enhance_security_policy(
        self,
        scope: PANScope,
        entry: ET.Element,
        extraction,
        policy,
    ) -> None:
        evidence = policy.source_extra_settings
        evidence["pan_source_entry"] = structured_xml_capture(entry)

        categories = member_texts(entry, "./category/member")
        evidence["pan_url_categories"] = categories

        profile_groups = member_texts(entry, "./profile-setting/group/member")
        if profile_groups:
            evidence["pan_profile_groups"] = profile_groups

        direct_profiles = {
            family: member_texts(entry, f"./profile-setting/profiles/{family}/member")
            for family in (
                "virus", "vulnerability", "spyware", "url-filtering",
                "file-blocking", "wildfire-analysis", "data-filtering",
            )
        }
        direct_profiles = {key: values for key, values in direct_profiles.items() if values}

        audit_refs: Dict[str, str] = {}
        audit_status: Dict[str, str] = {}
        unresolved_audit: Dict[str, str] = {}

        for index, value in enumerate(profile_groups):
            key = f"profile-group[{index}]"
            audit_refs[key] = value
            obj = self.resolver.resolve(value, "profile-group", scope)
            if obj is None:
                audit_status[key] = "unresolved"
                unresolved_audit[key] = value
            else:
                audit_status[key] = "resolved"

        for family, values in direct_profiles.items():
            for index, value in enumerate(values):
                key = f"{family}[{index}]"
                audit_refs[key] = value
                obj = self.resolver.resolve(
                    value, f"security-profile:{family}", scope
                )
                if obj is None:
                    audit_status[key] = "unresolved"
                    unresolved_audit[key] = value
                else:
                    audit_status[key] = "resolved"

        policy.source_security_profile_references = audit_refs
        policy.security_profile_reference_statuses = audit_status
        policy.unresolved_security_profile_references = unresolved_audit

        tags = member_texts(entry, "./tag/member")
        resolved_tags, unresolved_tags = self._resolve_tag_references(scope, tags)
        evidence["pan_resolved_tags"] = resolved_tags
        if unresolved_tags:
            evidence["pan_unresolved_tags"] = unresolved_tags
            if "unresolved-tags" not in policy.review_reasons:
                policy.review_reasons.append("unresolved-tags")

        target = self._target_details(entry.find("./target"))
        if target is not None:
            evidence["pan_target"] = target
            unknown = evidence.get("pan_unknown_fields")
            if isinstance(unknown, dict):
                unknown.pop("target", None)
                if not unknown:
                    evidence.pop("pan_unknown_fields", None)
                    if "unknown-fields" in policy.review_reasons:
                        policy.review_reasons.remove("unknown-fields")
            if "panorama-target-context" not in policy.review_reasons:
                policy.review_reasons.append("panorama-target-context")

        if policy.review_reasons:
            policy.requires_manual_review = True
            policy.migration_status = "PARTIALLY_NORMALIZED"

        item = self._inventory_item(extraction, "policies", scope, entry.get("name"))
        if item is not None:
            item.source_attributes.update(evidence)
            if policy.review_reasons:
                item.status = ExtractionStatus.PARTIALLY_NORMALIZED
                item.requires_manual_review = True

    def _parse_security_rule(
        self,
        scope: PANScope,
        entry: ET.Element,
        extraction,
        rulebase_position: str,
        source_rule_index: int,
        path_prefix: str,
    ):
        before = len(extraction.canonical_ir.policies)
        super()._parse_security_rule(
            scope,
            entry,
            extraction,
            rulebase_position,
            source_rule_index,
            path_prefix,
        )
        if len(extraction.canonical_ir.policies) == before:
            return
        policy = extraction.canonical_ir.policies[-1]
        self._enhance_security_policy(scope, entry, extraction, policy)

    @staticmethod
    def _zone_source_attributes(z_entry: ET.Element) -> Dict[str, Any]:
        network = z_entry.find("./network")
        attrs: Dict[str, Any] = {}
        for field in (
            "zone-protection-profile",
            "enable-packet-buffer-protection",
            "log-setting",
            "net-inspection",
        ):
            node = network.find(f"./{field}") if network is not None else None
            if node is not None:
                attrs[f"pan_{field.replace('-', '_')}"] = structured_xml_capture(node)
                scalar = text_or_none(network, f"./{field}")
                if scalar is not None:
                    attrs[f"pan_{field.replace('-', '_')}_value"] = scalar
        return attrs

    def _enhance_zones(self, scope: PANScope, search_root: ET.Element, extraction, zones: List[Any]) -> None:
        by_name = {zone.name: zone for zone in zones}
        for z_entry in search_root.findall("./zone/entry"):
            name = z_entry.get("name")
            zone = by_name.get(name)
            if zone is None:
                continue
            zone.source_context = pan_scope_identity(scope)

            zone_types = _configured_pan_zone_types(z_entry)
            if len(zone_types) == 1:
                zone.zone_type = zone_types[0]

            zone.source_attributes.update(self._zone_source_attributes(z_entry))
            network = z_entry.find("./network")
            if network is not None:
                log_setting = text_or_none(network, "./log-setting")
                if log_setting is not None:
                    zone.source_log_setting = log_setting

            # These fields were previously classified as unknown because they
            # were searched at the zone root instead of under zone/network.
            unknown_network = zone.source_attributes.get("pan_network_settings")
            if isinstance(unknown_network, dict):
                for handled in (
                    "zone-protection-profile",
                    "enable-packet-buffer-protection",
                    "log-setting",
                    "net-inspection",
                ):
                    unknown_network.pop(handled, None)
                if not unknown_network:
                    zone.source_attributes.pop("pan_network_settings", None)
                    zone.review_reasons = [
                        reason
                        for reason in zone.review_reasons
                        if reason != "Unknown zone fields retained as source evidence."
                    ]

            item = self._inventory_item(extraction, "zones", scope, name)
            if item is not None:
                item.source_attributes.update(zone.source_attributes)
                if not zone.source_attributes.get("pan_network_settings"):
                    item.notes = [
                        note
                        for note in item.notes
                        if note != "Unknown zone fields retained as source evidence."
                    ]

    def _enhance_profile_groups(
        self,
        scope: PANScope,
        extraction,
        groups: List[Any],
    ) -> None:
        for group in groups:
            item = self._inventory_item(extraction, "profile_groups", scope, group.name)
            if item is None:
                continue
            evidence = dict(item.source_attributes)
            members = evidence.get("pan_profile_members", {})
            group.source_context = pan_scope_identity(scope)
            group.source_attributes = evidence

            # IRSecurityProfileGroup has a string-valued audit map.  Indexing
            # the keys keeps every source member without collapsing repeats.
            refs: Dict[str, str] = {}
            for family, values in members.items():
                for index, value in enumerate(values):
                    refs[f"{family}[{index}]"] = value
            if refs:
                group.source_profile_references = refs
                group.source_attributes["pan_complete_profile_references"] = refs

    def _parse_schedules(self, scope: PANScope, search_root: ET.Element, extraction):
        before = len(extraction.canonical_ir.schedules)
        super()._parse_schedules(scope, search_root, extraction)

        for schedule in extraction.canonical_ir.schedules[before:]:
            schedule.source_context = pan_scope_identity(scope)
            source_windows = schedule.source_attributes.get("pan_schedule_windows", {})
            daily = source_windows.get("daily", [])
            weekly = source_windows.get("weekly", {})
            non_recurring = source_windows.get("non_recurring", [])

            windows: List[Dict[str, Any]] = []
            for window in daily:
                windows.append({
                    "kind": "daily",
                    "start": window.get("start"),
                    "end": window.get("end"),
                    "raw_value": window.get("raw_value"),
                })
            for day, day_windows in weekly.items():
                for window in day_windows:
                    windows.append({
                        "kind": "weekly",
                        "day": day,
                        "start": window.get("start"),
                        "end": window.get("end"),
                        "raw_value": window.get("raw_value"),
                    })
            for window in non_recurring:
                windows.append({
                    "kind": "non-recurring",
                    "start": window.get("start"),
                    "end": window.get("end"),
                    "raw_value": window.get("raw_value"),
                })

            schedule.windows = windows
            if daily:
                schedule.schedule_type = "recurring"
                schedule.recurrence = {"kind": "daily", "windows": daily}
            elif weekly:
                schedule.schedule_type = "recurring"
                schedule.recurrence = {"kind": "weekly", "days": weekly}
            elif non_recurring:
                schedule.schedule_type = "non-recurring"
                schedule.recurrence = {"kind": "non-recurring", "windows": non_recurring}

            item = self._inventory_item(extraction, "schedules", scope, schedule.name)
            if item is not None:
                item.source_attributes["pan_schedule_windows"] = source_windows
                item.notes = [
                    note for note in item.notes
                    if "multiple-or-differing-windows" not in note
                ]
                if (
                    windows
                    and not schedule.source_attributes.get("pan_unknown_fields")
                    and not schedule.source_attributes.get("pan_description")
                    and not schedule.source_attributes.get("pan_tags")
                ):
                    item.status = ExtractionStatus.NORMALIZED
                    item.requires_manual_review = False

    def _parse_objects(self, scope: PANScope, search_root: ET.Element, extraction):
        zone_before = len(extraction.canonical_ir.zones)
        profile_before = len(extraction.canonical_ir.security_profile_groups)
        super()._parse_objects(scope, search_root, extraction)
        self._enhance_zones(
            scope,
            search_root,
            extraction,
            extraction.canonical_ir.zones[zone_before:],
        )
        self._enhance_profile_groups(
            scope,
            extraction,
            extraction.canonical_ir.security_profile_groups[profile_before:],
        )

    @staticmethod
    def _parse_interface_address(node: Optional[ET.Element]) -> Optional[Dict[str, Any]]:
        if node is None:
            return None
        ip_values = member_texts(node, "./ip/member")
        if not ip_values:
            scalar_ip = text_or_none(node, "./ip")
            if scalar_ip:
                ip_values = [scalar_ip]
        return {
            key: value
            for key, value in {
                "interface": text_or_none(node, "./interface"),
                "ip": ip_values,
                "source_entry": structured_xml_capture(node),
            }.items()
            if value not in (None, [], {})
        }

    def _resolve_interface_reference(self, scope: PANScope, interface_name: str):
        if not interface_name or interface_name.lower() == "any":
            return None, "builtin-any"
        if scope.kind == "vsys":
            if not (scope.device_name or scope.device_serial):
                return None, "context-dependent"
            interface_scope = PANScope(
                kind="device",
                name=scope.device_name or scope.device_serial or scope.name,
                device_name=scope.device_name,
                device_serial=scope.device_serial,
            )
        elif scope.kind == "device":
            interface_scope = scope
        else:
            return None, "context-dependent"
        resolved = self.resolver.resolve(interface_name, "interface", interface_scope)
        return resolved, "resolved" if resolved is not None else "unresolved"

    def _enhance_nat_rule(self, scope: PANScope, entry: ET.Element, extraction, rule) -> None:
        attrs = rule.source_attributes

        tags = member_texts(entry, "./tag/member")
        resolved_tags, unresolved_tags = self._resolve_tag_references(scope, tags)
        attrs["pan_resolved_tags"] = resolved_tags
        if unresolved_tags:
            attrs["pan_unresolved_tags"] = unresolved_tags
            if "unresolved-tags" not in rule.review_reasons:
                rule.review_reasons.append("unresolved-tags")

        to_interface = text_or_none(entry, "./to-interface")
        if to_interface:
            resolved_interface, status = self._resolve_interface_reference(scope, to_interface)
            attrs["pan_to_interface_resolution"] = status
            if resolved_interface is not None:
                attrs["pan_resolved_to_interface"] = resolved_interface.canonical_name or to_interface
            elif status == "unresolved":
                attrs["pan_unresolved_to_interface"] = to_interface
                if "unresolved-to-interface" not in rule.review_reasons:
                    rule.review_reasons.append("unresolved-to-interface")
            if status in {"resolved", "builtin-any"} and "to-interface" in rule.review_reasons:
                rule.review_reasons.remove("to-interface")

        snat = entry.find("./source-translation")
        if snat is not None and len(list(snat)) == 1:
            source_node = list(snat)[0]
            family = source_node.tag
            attrs["pan_source_translation_mode"] = family
            if family == "persistent-dynamic-ip-and-port":
                attrs["pan_persistent_dipp"] = True

            interface_address = source_node.find("./interface-address")
            if interface_address is not None:
                details = self._parse_interface_address(interface_address)
                attrs["pan_interface_address_details"] = details
                if details and details.get("interface"):
                    resolved, status = self._resolve_interface_reference(
                        scope, details["interface"]
                    )
                    details["resolution"] = status
                    if resolved is not None:
                        details["resolved_interface"] = (
                            resolved.canonical_name or details["interface"]
                        )

            fallback = source_node.find("./fallback")
            if fallback is not None:
                fallback_data: Dict[str, Any] = {
                    "source_entry": structured_xml_capture(fallback),
                    "branches": [child.tag for child in fallback],
                }
                fallback_interface = fallback.find(".//interface-address")
                if fallback_interface is not None:
                    fallback_data["interface_address"] = self._parse_interface_address(
                        fallback_interface
                    )
                fallback_addresses = member_texts(
                    fallback, ".//translated-address/member"
                )
                if fallback_addresses:
                    fallback_data["translated_address"] = fallback_addresses
                attrs["pan_source_translation_fallback_details"] = fallback_data

            if family == "static-ip":
                bidirectional = text_or_none(source_node, "./bi-directional")
                if bidirectional is not None:
                    normalized = bidirectional.strip().lower()
                    if normalized in {"yes", "no"}:
                        attrs["pan_static_ip_bi_directional"] = normalized == "yes"
                        attrs["pan_static_ip_bi_directional_raw"] = normalized
                    else:
                        attrs["pan_static_ip_bi_directional_invalid"] = bidirectional

        destination_node = entry.find("./destination-translation")
        if destination_node is None:
            destination_node = entry.find("./dynamic-destination-translation")
        translated_port = (
            text_or_none(destination_node, "./translated-port")
            if destination_node is not None
            else None
        )
        if translated_port is not None:
            if translated_port.isdigit() and 1 <= int(translated_port) <= 65535:
                port = int(translated_port)
                attrs["pan_translated_port_int"] = port
                rule.translated_destination_ports = [IRNATPortRange(start=port)]
            else:
                attrs["pan_invalid_translated_port"] = translated_port
                if "invalid-translated-port" not in rule.review_reasons:
                    rule.review_reasons.append("invalid-translated-port")

        dynamic_destination = entry.find("./dynamic-destination-translation")
        if dynamic_destination is not None:
            distribution = text_or_none(dynamic_destination, "./distribution")
            if distribution is not None:
                attrs["pan_dynamic_destination_distribution_value"] = distribution

        # Preserve address-object backed translation pools as explicit
        # references as well as the resolved translated address values.
        source_classifications = attrs.get("pan_translated_source_values", [])
        rule.source_pool_references = list(dict.fromkeys(
            item.get("resolved_value") or item.get("value")
            for item in source_classifications
            if item.get("classification") == "object-reference"
            and (item.get("resolved_value") or item.get("value"))
        ))
        destination_classifications = attrs.get("pan_translated_destination_values", [])
        rule.destination_pool_references = list(dict.fromkeys(
            item.get("resolved_value") or item.get("value")
            for item in destination_classifications
            if item.get("classification") == "object-reference"
            and (item.get("resolved_value") or item.get("value"))
        ))

        if not unresolved_tags and "tag" in rule.review_reasons:
            rule.review_reasons.remove("tag")
        rule.review_reasons = list(dict.fromkeys(rule.review_reasons))
        rule.requires_manual_review = bool(rule.review_reasons)
        rule.migration_status = (
            "PARTIALLY_NORMALIZED" if rule.review_reasons else "NORMALIZED"
        )

        item = self._inventory_item(extraction, "nat", scope, entry.get("name"))
        if item is not None:
            item.source_attributes.update(attrs)
            item.status = (
                ExtractionStatus.PARTIALLY_NORMALIZED
                if rule.review_reasons
                else ExtractionStatus.NORMALIZED
            )
            item.requires_manual_review = bool(rule.review_reasons)

    def _parse_rules(self, scope: PANScope, search_root: ET.Element, extraction):
        nat_before = len(extraction.canonical_ir.nat_rules)
        super()._parse_rules(scope, search_root, extraction)

        entries: Dict[tuple[str, int], ET.Element] = {}
        for position, path in (
            ("pre", "./pre-rulebase/nat/rules/entry"),
            ("local", "./rulebase/nat/rules/entry"),
            ("post", "./post-rulebase/nat/rules/entry"),
        ):
            for index, entry in enumerate(search_root.findall(path)):
                entries[(position, index)] = entry

        for rule in extraction.canonical_ir.nat_rules[nat_before:]:
            attrs = rule.source_attributes
            entry = entries.get((
                attrs.get("pan_rulebase_position"),
                attrs.get("pan_source_rule_index"),
            ))
            if entry is not None:
                self._enhance_nat_rule(scope, entry, extraction, rule)

    def _enhance_interfaces(self, extraction) -> None:
        interfaces = extraction.canonical_ir.interfaces
        by_scope_name: Dict[tuple[str, str], Any] = {
            (interface.source_context or "", interface.name): interface
            for interface in interfaces
        }
        for interface in interfaces:
            attrs = interface.source_attributes
            if not (
                attrs.get("pan_interface_family")
                or attrs.get("pan_interface_mode")
            ):
                continue

            ipv4 = list(attrs.get("pan_ipv4_addresses", []))
            if ipv4:
                interface.ip = ipv4[0]
                secondary: List[IRInterfaceSecondaryIP] = []
                for value in ipv4[1:]:
                    try:
                        parsed = ipaddress.ip_interface(value)
                        normalized = str(parsed) if parsed.version == 4 else value
                    except ValueError:
                        normalized = value
                    secondary.append(
                        IRInterfaceSecondaryIP(source_ip=value, ip=normalized)
                    )
                interface.secondary_ips = secondary

            if interface.source_mtu is not None:
                interface.mtu = interface.source_mtu

            aggregate_parent = attrs.get("pan_aggregate_group_name")
            if aggregate_parent:
                interface.source_aggregate_parent = aggregate_parent
                parent = by_scope_name.get(
                    (interface.source_context or "", aggregate_parent)
                )
                if parent is not None and interface.name not in parent.members:
                    parent.members.append(interface.name)

            mode = attrs.get("pan_interface_mode")
            family = attrs.get("pan_interface_family") or interface.interface_type
            if mode:
                attrs["pan_effective_interface_type"] = (
                    f"{family}:{mode}" if family else mode
                )

            imported = attrs.get("pan_imported_by_vsys")
            if imported:
                attrs["pan_vsys_associations"] = list(dict.fromkeys(imported))

            for item in extraction.inventory_items:
                if item.domain != "interfaces" or item.name != interface.name:
                    continue
                if (
                    item.source_context != interface.source_context
                    and item.source_attributes.get("scope_device_serial")
                    != attrs.get("pan_device_serial")
                ):
                    continue
                item.source_attributes.update(attrs)
                if interface.secondary_ips:
                    item.notes = [
                        note
                        for note in item.notes
                        if note
                        != "Multiple IPv4 addresses exceed the canonical scalar interface field."
                    ]
                if aggregate_parent:
                    item.notes = [
                        note
                        for note in item.notes
                        if note != "Aggregate-group semantics remain source-oriented."
                    ]

    @staticmethod
    def _unwrap_config(content: str) -> Optional[ET.Element]:
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return None
        if root.tag == "response":
            root = root.find("./result/config")
        return root if root is not None and root.tag == "config" else None

    def _extract_template_interfaces(self, content: str, extraction) -> None:
        root = self._unwrap_config(content)
        if root is None:
            return
        templates = PANPanoramaExtractor.template_entries(root)
        if not templates:
            return

        stack_map: Dict[str, List[Dict[str, Any]]] = {}
        for stack in PANPanoramaExtractor.template_entries(root, stack=True):
            stack_name = stack.get("name")
            ordered_templates = [
                entry.get("name")
                for entry in stack.findall("./templates/entry")
                if entry.get("name")
            ]
            ordered_templates.extend(member_texts(stack, "./templates/member"))
            devices = [
                entry.get("name")
                for entry in stack.findall("./devices/entry")
                if entry.get("name")
            ]
            for template_name in ordered_templates:
                stack_map.setdefault(template_name, []).append({
                    "name": stack_name,
                    "templates": ordered_templates,
                    "devices": devices,
                })

        for template in templates:
            template_name = template.get("name")
            if not template_name:
                continue
            network = template.find("./config/devices/entry/network")
            if network is None:
                network = template.find("./network")
            if network is None:
                continue

            scope = PANScope(kind="template", name=template_name)
            before = len(extraction.canonical_ir.interfaces)
            extract_interfaces(
                network,
                scope,
                extraction.canonical_ir,
                self.resolver,
                extraction,
            )
            apply_routing_instance_associations(
                network,
                scope,
                extraction.canonical_ir,
                extraction,
            )
            new_interfaces = extraction.canonical_ir.interfaces[before:]
            for interface in new_interfaces:
                interface.source_attributes["pan_template_name"] = template_name
                if template_name in stack_map:
                    interface.source_attributes["pan_template_stacks"] = stack_map[
                        template_name
                    ]

            # Template VSYS imports and zones are directly relevant to policy
            # zone/interface meaning, so retain those relationships too.
            for device in template.findall("./config/devices/entry"):
                for vsys in device.findall("./vsys/entry"):
                    vsys_name = vsys.get("name") or "vsys1"
                    imported = member_texts(vsys, "./import/network/interface/member")
                    for interface_name in imported:
                        for interface in new_interfaces:
                            if interface.name == interface_name:
                                associations = interface.source_attributes.setdefault(
                                    "pan_vsys_associations", []
                                )
                                if vsys_name not in associations:
                                    associations.append(vsys_name)

                    for z_entry in vsys.findall("./zone/entry"):
                        z_name = z_entry.get("name")
                        if not z_name:
                            continue
                        members: List[str] = []
                        zone_types: List[str] = []
                        for zone_type in (
                            "layer3", "layer2", "virtual-wire", "tap", "tunnel"
                        ):
                            values = member_texts(
                                z_entry, f"./network/{zone_type}/member"
                            )
                            if values:
                                zone_types.append(zone_type)
                                members.extend(values)

                        zone = IRZone(
                            name=z_name,
                            zone_type=zone_types[0] if len(zone_types) == 1 else "system",
                            source_context=f"template:{template_name}:vsys:{vsys_name}",
                            interfaces=members,
                            source_log_setting=text_or_none(
                                z_entry, "./network/log-setting"
                            ),
                            source_user_identification_enabled=(
                                text_or_none(z_entry, "./enable-user-identification")
                                == "yes"
                                if z_entry.find("./enable-user-identification") is not None
                                else None
                            ),
                            source_attributes={
                                "pan_source_context": (
                                    f"template:{template_name}:vsys:{vsys_name}"
                                ),
                                "pan_template_name": template_name,
                                "pan_vsys": vsys_name,
                                "pan_zone_types": zone_types,
                                **self._zone_source_attributes(z_entry),
                            },
                        )
                        extraction.canonical_ir.zones.append(zone)

                        for interface_name in members:
                            for interface in new_interfaces:
                                if interface.name != interface_name:
                                    continue
                                relationships = interface.source_attributes.setdefault(
                                    "pan_template_zones", []
                                )
                                relationship = {
                                    "vsys": vsys_name,
                                    "zone": z_name,
                                    "zone_types": zone_types,
                                }
                                if relationship not in relationships:
                                    relationships.append(relationship)
                                if interface.zone is None:
                                    interface.zone = z_name
                                elif interface.zone != z_name:
                                    interface.requires_manual_review = True
                                    interface.migration_status = "PARTIALLY_NORMALIZED"
                                    if "multiple-template-zones" not in interface.review_reasons:
                                        interface.review_reasons.append(
                                            "multiple-template-zones"
                                        )

    def extract(self, content: str, zone_mapping: Optional[Dict[str, str]] = None):
        extraction = super().extract(content, zone_mapping)
        self._extract_template_interfaces(content, extraction)
        self._enhance_interfaces(extraction)
        return extraction
