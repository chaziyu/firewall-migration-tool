import ipaddress
from datetime import datetime
import xml.etree.ElementTree as ET
from typing import Any, Optional, Dict, List
from fwmigrate.core.base_parser import BaseSourceParser
from fwmigrate.ir.core import (
    IRConfig, IRMetadata, IRZone, IRInterface, IRAddress, IRAddressGroup,
    IRService, IRServicePort, IRServiceGroup, IRSchedule, IRPolicy, IRNATRule, IRRoute,
    IRSecurityProfileGroup
)
from pydantic import ValidationError
from fwmigrate.ir.enums import AddressType, ServiceProtocol, PolicyAction, NATType

from fwmigrate.extraction.models import ExtractionResult, SourceInventoryItem, ExtractionStatus
from .resolver import PANResolver
from .source_model import PANScope, PANSourceObject
from .nat import PANNatRuleExtractor
from .routing import PANRouteExtractor
from .network import PANVsysImportExtractor
from .panorama import PANPanoramaExtractor
from .extraction import (
    add_inventory_section_accounting, add_source_section, record_extract_only, record_normalized, record_parse_error, record_partial,
    record_unsupported,
)
from .residual import PANResidualExtractor
from .xml_utils import collect_unknown_children, member_texts, structured_xml_capture, text_or_none


class PANOSSourceParser(BaseSourceParser):
    """Parses Palo Alto Networks PAN-OS XML configuration exports into canonical IRConfig."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.resolver = PANResolver()

    @property
    def vendor_id(self) -> str:
        return "palo_alto"

    @property
    def display_name(self) -> str:
        return "Palo Alto Networks (PAN-OS)"

    @property
    def supported_extensions(self) -> List[str]:
        return [".xml"]

    @staticmethod
    def _parse_address_value(source_type: str, source_value: str) -> Dict[str, Any]:
        if source_type == "ip-netmask":
            parsed = ipaddress.ip_interface(source_value)
            family = f"ipv{parsed.version}"
            return {
                "type": AddressType.HOST if parsed.network.prefixlen == parsed.max_prefixlen else AddressType.NETWORK,
                "subnet": source_value,
                "address_family": family,
                "is_ipv6": parsed.version == 6,
            }

        if source_type == "ip-range":
            if source_value.count("-") != 1:
                raise ValueError("IP range must contain exactly one hyphen separator.")
            start_text, end_text = (part.strip() for part in source_value.split("-", 1))
            start = ipaddress.ip_address(start_text)
            end = ipaddress.ip_address(end_text)
            if start.version != end.version:
                raise ValueError("IP range endpoints must use the same address family.")
            if int(start) > int(end):
                raise ValueError("IP range start must not be greater than its end.")
            return {
                "type": AddressType.RANGE,
                "ip_range_start": start_text,
                "ip_range_end": end_text,
                "address_family": f"ipv{start.version}",
                "is_ipv6": start.version == 6,
            }

        if source_type == "ip-wildcard":
            if source_value.count("/") != 1:
                raise ValueError("IP wildcard must contain exactly one slash separator.")
            address_text, mask_text = (part.strip() for part in source_value.split("/", 1))
            ipaddress.IPv4Address(address_text)
            ipaddress.IPv4Address(mask_text)
            return {
                "type": AddressType.WILDCARD_MASK,
                "wildcard_mask": source_value,
                "address_family": "ipv4",
                "is_ipv6": False,
            }

        if source_type == "fqdn":
            return {"type": AddressType.FQDN, "fqdn": source_value}

        raise ValueError(f"Unsupported PAN-OS address type: {source_type}")

    def _parse_addresses(self, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult):
        for entry in search_root.findall("./address/entry"):
            self._parse_address_object(scope, entry, extraction)

    def _parse_address_object(self, scope: PANScope, entry: ET.Element, extraction: ExtractionResult) -> Optional[IRAddress]:
        source_name = entry.get("name")
        source_path = f"address/entry[@name='{source_name}']" if source_name else "address/entry"
        description = text_or_none(entry, "./description")
        tags = member_texts(entry, "./tag/member")
        tag_element = entry.find("./tag")
        unknown_tag_fields = (
            collect_unknown_children(tag_element, known_children=["member"])
            if tag_element is not None else {}
        )
        unknown_fields = collect_unknown_children(
            entry,
            known_children=["ip-netmask", "ip-range", "ip-wildcard", "fqdn", "description", "tag"],
        )
        type_candidates = {
            source_type: text_or_none(entry, f"./{source_type}")
            for source_type in ("ip-netmask", "ip-range", "ip-wildcard", "fqdn")
        }
        configured_types = [source_type for source_type, value in type_candidates.items() if value]
        evidence: Dict[str, Any] = {}
        present_types = [
            source_type for source_type in type_candidates
            if entry.find(f"./{source_type}") is not None
        ]
        empty_types = [source_type for source_type in present_types if not type_candidates[source_type]]
        if description is not None:
            evidence["pan_description"] = description
        if tags:
            evidence["pan_tags"] = tags
        if unknown_fields:
            evidence["pan_unknown_fields"] = unknown_fields
        if unknown_tag_fields:
            evidence["pan_unknown_tag_fields"] = unknown_tag_fields
        if empty_types:
            evidence["pan_empty_address_type_fields"] = empty_types

        if not source_name:
            evidence["pan_configured_address_values"] = {
                key: value for key, value in type_candidates.items() if value
            }
            record_parse_error(
                extraction, domain="addresses", source_path=source_path, scope=scope,
                attributes=evidence, notes=["PAN-OS address entry is missing its required name."],
            )
            return None

        if len(configured_types) != 1:
            evidence["pan_configured_address_values"] = {
                key: value for key, value in type_candidates.items() if value
            }
            reason = (
                "PAN-OS address entry has no supported non-empty address type."
                if not configured_types
                else f"PAN-OS address entry has multiple configured address types: {', '.join(configured_types)}."
            )
            record_parse_error(
                extraction, domain="addresses", source_path=source_path, scope=scope,
                name=source_name, attributes=evidence, notes=[reason],
            )
            return None

        source_type = configured_types[0]
        source_value = type_candidates[source_type]
        evidence.update({"pan_source_type": source_type, "pan_source_value": source_value})

        if self.resolver.resolve_exact(source_name, "address", scope):
            record_parse_error(
                extraction, domain="addresses", source_path=source_path, scope=scope,
                name=source_name, attributes=evidence,
                notes=["Duplicate PAN-OS address name in the same scope."],
            )
            return None

        try:
            value_kwargs = self._parse_address_value(source_type, source_value)
            if value_kwargs.get("address_family") == "ipv6":
                evidence["pan_address_family"] = "ipv6"
            ir_address = IRAddress(
                name=source_name,
                description=description,
                tags=tags,
                source_type=source_type,
                source_attributes=evidence,
                **value_kwargs,
            )
        except (ValueError, ValidationError) as error:
            record_parse_error(
                extraction, domain="addresses", source_path=source_path, scope=scope,
                name=source_name, attributes=evidence,
                notes=[f"Invalid PAN-OS {source_type} value: {error}"],
            )
            return None

        extraction.canonical_ir.addresses.append(ir_address)
        source_object = PANSourceObject(
            name=source_name,
            kind="address",
            domain="address",
            source_path=source_path,
            scope=scope,
            attributes=evidence,
            ir_object=ir_address,
        )
        if not self.resolver.register_object(source_object, "address"):
            extraction.canonical_ir.addresses.remove(ir_address)
            record_parse_error(
                extraction, domain="addresses", source_path=source_path, scope=scope,
                name=source_name, attributes=evidence,
                notes=["Duplicate PAN-OS address name in the same scope."],
            )
            return None

        residual_fields = list(unknown_fields)
        if unknown_tag_fields:
            residual_fields.append("tag")
        residual_fields.extend(empty_types)
        if residual_fields:
            record_partial(
                extraction, domain="addresses", source_path=source_path, scope=scope,
                name=source_name, attributes=evidence,
                notes=[f"Unrepresented PAN-OS address fields retained: {', '.join(residual_fields)}."],
            )
        else:
            record_normalized(
                extraction, domain="addresses", source_path=source_path, scope=scope,
                name=source_name, attributes=evidence,
            )
        return ir_address

    @staticmethod
    def _validate_port_expression(value: str) -> str:
        tokens = value.strip().split(",")
        if not tokens or any(not token.strip() for token in tokens):
            raise ValueError("Port expression contains an empty token.")
        normalized: List[str] = []
        for raw_token in tokens:
            token = raw_token.strip()
            if token.count("-") > 1:
                raise ValueError(f"Invalid port token: {token}")
            if "-" in token:
                start_text, end_text = (part.strip() for part in token.split("-", 1))
                if not start_text.isdigit() or not end_text.isdigit():
                    raise ValueError(f"Invalid port range: {token}")
                start, end = int(start_text), int(end_text)
                if not 0 <= start <= 65535 or not 0 <= end <= 65535:
                    raise ValueError(f"Port range is outside 0-65535: {token}")
                if start > end:
                    raise ValueError(f"Port range start exceeds end: {token}")
                normalized.append(f"{start_text}-{end_text}")
            else:
                if not token.isdigit() or not 0 <= int(token) <= 65535:
                    raise ValueError(f"Port is outside 0-65535: {token}")
                normalized.append(token)
        return ",".join(normalized)

    @staticmethod
    def _structured_unknown_children(entry: ET.Element, known_children: List[str]) -> Dict[str, Any]:
        unknown: Dict[str, Any] = {}
        for child in entry:
            if child.tag not in known_children:
                text = (child.text or "").strip()
                captured = text if text and not child.attrib and len(child) == 0 else structured_xml_capture(child)
                if child.tag in unknown:
                    if not isinstance(unknown[child.tag], list):
                        unknown[child.tag] = [unknown[child.tag]]
                    unknown[child.tag].append(captured)
                else:
                    unknown[child.tag] = captured
        return unknown

    def _parse_address_groups(self, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult):
        ir = extraction.canonical_ir
        for entry in search_root.findall("./address-group/entry"):
            name = entry.get("name")
            source_path = f"address-group/entry[@name='{name}']" if name else "address-group/entry"
            description = text_or_none(entry, "./description")
            tags = member_texts(entry, "./tag/member")
            static_node = entry.find("./static")
            dynamic_node = entry.find("./dynamic")
            members = member_texts(entry, "./static/member")
            dynamic_filter = text_or_none(entry, "./dynamic/filter")
            unknown = self._structured_unknown_children(
                entry, ["static", "dynamic", "description", "tag"]
            )
            evidence: Dict[str, Any] = {
                "pan_source_members": members,
                "pan_tags": tags,
            }
            if description is not None:
                evidence["pan_description"] = description
            if dynamic_filter is not None:
                evidence["pan_dynamic_filter"] = dynamic_filter
            definition_node = static_node if static_node is not None else dynamic_node
            if definition_node is not None:
                evidence["pan_group_definition_source"] = structured_xml_capture(definition_node)
            if unknown:
                evidence["pan_unknown_fields"] = unknown

            if not name:
                record_parse_error(
                    extraction, "address_groups", source_path, scope,
                    attributes=evidence, notes=["PAN-OS address group is missing its required name."],
                )
                continue
            if static_node is not None and dynamic_node is not None:
                record_parse_error(
                    extraction, "address_groups", source_path, scope, name, evidence,
                    notes=["PAN-OS address group configures both static and dynamic types."],
                )
                continue
            if static_node is None and dynamic_node is None:
                record_parse_error(
                    extraction, "address_groups", source_path, scope, name, evidence,
                    notes=["PAN-OS address group has neither a static nor dynamic definition."],
                )
                continue
            if static_node is not None and not members:
                record_parse_error(
                    extraction, "address_groups", source_path, scope, name, evidence,
                    notes=["PAN-OS static address group has no members."],
                )
                continue
            if dynamic_node is not None and not dynamic_filter:
                record_parse_error(
                    extraction, "address_groups", source_path, scope, name, evidence,
                    notes=["PAN-OS dynamic address group has no filter."],
                )
                continue

            existing_address = self.resolver.resolve_exact(name, "address", scope)
            existing_group = self.resolver.resolve_exact(name, "address-group", scope)
            if existing_address or existing_group:
                reason = (
                    "Address object and address group use the same name in the same scope."
                    if existing_address else "Duplicate PAN-OS address-group name in the same scope."
                )
                record_parse_error(
                    extraction, "address_groups", source_path, scope, name, evidence,
                    notes=[reason],
                )
                continue

            group_type = "static" if static_node is not None else "dynamic"
            evidence["pan_source_group_type"] = group_type
            group = IRAddressGroup(
                name=name,
                members=members,
                description=description,
                tags=tags,
                is_dynamic=group_type == "dynamic",
                dynamic_filter=dynamic_filter,
                source_group_type=group_type,
                source_attributes=evidence,
            )
            ir.address_groups.append(group)
            self.resolver.register_object(
                PANSourceObject(
                    name=name, kind="address-group", domain="address",
                    source_path=source_path, scope=scope, attributes=evidence, ir_object=group,
                ),
                "address-group",
            )

    def _parse_services(self, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult):
        ir = extraction.canonical_ir
        for entry in search_root.findall("./service/entry"):
            name = entry.get("name")
            source_path = f"service/entry[@name='{name}']" if name else "service/entry"
            description = text_or_none(entry, "./description")
            tags = member_texts(entry, "./tag/member")
            tcp = entry.find("./protocol/tcp")
            udp = entry.find("./protocol/udp")
            configured = [("tcp", tcp), ("udp", udp)]
            configured = [(protocol, node) for protocol, node in configured if node is not None]
            unknown = self._structured_unknown_children(entry, ["protocol", "description", "tag"])
            evidence: Dict[str, Any] = {
                "pan_tags": tags,
                "pan_protocol_source": structured_xml_capture(entry.find("./protocol")),
            }
            if description is not None:
                evidence["pan_description"] = description
            if unknown:
                evidence["pan_unknown_fields"] = unknown

            if not name:
                record_parse_error(
                    extraction, "services", source_path, scope,
                    attributes=evidence, notes=["PAN-OS service is missing its required name."],
                )
                continue
            if len(configured) != 1:
                reason = (
                    "PAN-OS service has no TCP or UDP protocol definition."
                    if not configured else "PAN-OS service configures both TCP and UDP protocols."
                )
                record_parse_error(
                    extraction, "services", source_path, scope, name, evidence, notes=[reason],
                )
                continue

            protocol_name, protocol_node = configured[0]
            destination = text_or_none(protocol_node, "./port")
            source_port = text_or_none(protocol_node, "./source-port")
            evidence["pan_protocol"] = protocol_name
            evidence["pan_destination_port"] = destination
            if source_port is not None:
                evidence["pan_source_port"] = source_port

            override = protocol_node.find("./override")
            timeout_fields = {}
            if override is not None:
                evidence["pan_timeout_override"] = structured_xml_capture(override)
                yes_node = override.find("./yes")
                timeout_root = yes_node if yes_node is not None else override
                evidence["pan_timeout_mode"] = "yes" if yes_node is not None else (override.text or "configured").strip()
                for field in ("timeout", "halfclose-timeout", "timewait-timeout"):
                    value = text_or_none(timeout_root, f"./{field}")
                    if value is not None:
                        timeout_fields[field] = value
                        evidence[f"pan_{field.replace('-', '_')}"] = value
            protocol_unknown = self._structured_unknown_children(
                protocol_node, ["port", "source-port", "override"]
            )
            if protocol_unknown:
                evidence["pan_unknown_protocol_fields"] = protocol_unknown

            if destination is None:
                record_parse_error(
                    extraction, "services", source_path, scope, name, evidence,
                    notes=["PAN-OS service is missing its required destination port."],
                )
                continue
            try:
                destination = self._validate_port_expression(destination)
                if source_port is not None:
                    source_port = self._validate_port_expression(source_port)
            except ValueError as error:
                record_parse_error(
                    extraction, "services", source_path, scope, name, evidence,
                    notes=[f"Invalid PAN-OS service port expression: {error}"],
                )
                continue
            if self.resolver.resolve_exact(name, "service", scope):
                record_parse_error(
                    extraction, "services", source_path, scope, name, evidence,
                    notes=["Duplicate PAN-OS service name in the same scope."],
                )
                continue

            unrepresented = []
            if tags:
                unrepresented.append("tag")
            if override is not None:
                unrepresented.append("override")
            unrepresented.extend(unknown)
            unrepresented.extend(protocol_unknown)
            service = IRService(
                name=name,
                ports=[IRServicePort(
                    protocol=ServiceProtocol(protocol_name),
                    port=destination,
                    source_port=source_port,
                )],
                description=description,
                source_protocol_configured=protocol_name,
                source_protocol=protocol_name,
                source_unmodeled_semantic_settings=unrepresented,
                source_attributes=evidence,
                migration_status="PARTIALLY_NORMALIZED" if unrepresented else "NORMALIZED",
                requires_manual_review=bool(unrepresented),
            )
            ir.services.append(service)
            self.resolver.register_object(
                PANSourceObject(
                    name=name, kind="service", domain="service", source_path=source_path,
                    scope=scope, attributes=evidence, ir_object=service,
                ),
                "service",
            )
            if unrepresented:
                record_partial(
                    extraction, "services", source_path, scope, name, evidence,
                    notes=[f"PAN-OS service fields retained as source-only: {', '.join(unrepresented)}."],
                )
            else:
                record_normalized(extraction, "services", source_path, scope, name, evidence)

    def _parse_service_groups(self, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult):
        ir = extraction.canonical_ir
        for entry in search_root.findall("./service-group/entry"):
            name = entry.get("name")
            source_path = f"service-group/entry[@name='{name}']" if name else "service-group/entry"
            members = member_texts(entry, "./members/member")
            description = text_or_none(entry, "./description")
            tags = member_texts(entry, "./tag/member")
            unknown = self._structured_unknown_children(entry, ["members", "description", "tag"])
            evidence: Dict[str, Any] = {"pan_source_members": members, "pan_tags": tags}
            members_node = entry.find("./members")
            if members_node is not None:
                evidence["pan_members_source"] = structured_xml_capture(members_node)
            if description is not None:
                evidence["pan_description"] = description
            if unknown:
                evidence["pan_unknown_fields"] = unknown
            if not name or not members:
                record_parse_error(
                    extraction, "service_groups", source_path, scope, name, evidence,
                    notes=["PAN-OS service group requires a name and at least one member."],
                )
                continue
            existing_service = self.resolver.resolve_exact(name, "service", scope)
            existing_group = self.resolver.resolve_exact(name, "service-group", scope)
            if existing_service or existing_group:
                reason = (
                    "Service and service group use the same name in the same scope."
                    if existing_service else "Duplicate PAN-OS service-group name in the same scope."
                )
                record_parse_error(
                    extraction, "service_groups", source_path, scope, name, evidence, notes=[reason],
                )
                continue
            group = IRServiceGroup(
                name=name, members=members, description=description, source_attributes=evidence
            )
            ir.service_groups.append(group)
            self.resolver.register_object(
                PANSourceObject(
                    name=name, kind="service-group", domain="service", source_path=source_path,
                    scope=scope, attributes=evidence, ir_object=group,
                ),
                "service-group",
            )

    @staticmethod
    def _parse_time_window(value: str) -> Dict[str, str]:
        if value.count("-") != 1:
            raise ValueError(f"Invalid recurring schedule window: {value}")
        start, end = (part.strip() for part in value.split("-", 1))
        start_time = datetime.strptime(start, "%H:%M")
        end_time = datetime.strptime(end, "%H:%M")
        if start_time > end_time:
            raise ValueError(f"Recurring schedule start exceeds end: {value}")
        return {"start": start, "end": end, "raw_value": value.strip()}

    @staticmethod
    def _parse_date_window(value: str) -> Dict[str, str]:
        if value.count("-") != 1:
            raise ValueError(f"Invalid non-recurring schedule window: {value}")
        start, end = (part.strip() for part in value.split("-", 1))
        start_time = datetime.strptime(start, "%Y/%m/%d@%H:%M")
        end_time = datetime.strptime(end, "%Y/%m/%d@%H:%M")
        if start_time > end_time:
            raise ValueError(f"Non-recurring schedule start exceeds end: {value}")
        return {"start": start, "end": end, "raw_value": value.strip()}

    def _parse_schedules(self, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult):
        weekdays = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
        for entry in search_root.findall("./schedule/entry"):
            name = entry.get("name")
            source_path = f"schedule/entry[@name='{name}']" if name else "schedule/entry"
            daily_values = member_texts(entry, "./schedule-type/recurring/daily/member")
            weekly_values = {
                day: member_texts(entry, f"./schedule-type/recurring/weekly/{day}/member")
                for day in weekdays
            }
            weekly_values = {day: values for day, values in weekly_values.items() if values}
            non_recurring_values = member_texts(entry, "./schedule-type/non-recurring/member")
            description = text_or_none(entry, "./description")
            tags = member_texts(entry, "./tag/member")
            unknown = self._structured_unknown_children(entry, ["schedule-type", "description", "tag"])
            evidence: Dict[str, Any] = {
                "pan_tags": tags,
                "pan_schedule_type_source": structured_xml_capture(entry.find("./schedule-type")),
            }
            if description is not None:
                evidence["pan_description"] = description
            if unknown:
                evidence["pan_unknown_fields"] = unknown

            configured_families = sum(bool(value) for value in (daily_values, weekly_values, non_recurring_values))
            if not name or configured_families != 1:
                reason = (
                    "PAN-OS schedule requires exactly one daily, weekly, or non-recurring definition."
                )
                record_parse_error(
                    extraction, "schedules", source_path, scope, name, evidence, notes=[reason],
                )
                continue
            try:
                daily = [self._parse_time_window(value) for value in daily_values]
                weekly = {
                    day: [self._parse_time_window(value) for value in values]
                    for day, values in weekly_values.items()
                }
                non_recurring = [self._parse_date_window(value) for value in non_recurring_values]
            except ValueError as error:
                evidence["pan_schedule_raw"] = {
                    "daily": daily_values, "weekly": weekly_values,
                    "non_recurring": non_recurring_values,
                }
                record_parse_error(
                    extraction, "schedules", source_path, scope, name, evidence,
                    notes=[f"Invalid PAN-OS schedule: {error}"],
                )
                continue

            windows = {"daily": daily, "weekly": weekly, "non_recurring": non_recurring}
            evidence["pan_schedule_windows"] = windows
            exact = False
            schedule_kwargs: Dict[str, Any] = {}
            if len(daily) == 1:
                exact = True
                schedule_kwargs = {
                    "start": daily[0]["start"], "end": daily[0]["end"],
                    "days": [], "schedule_type": "recurring",
                }
            elif weekly and all(len(day_windows) == 1 for day_windows in weekly.values()):
                distinct = {(day_windows[0]["start"], day_windows[0]["end"]) for day_windows in weekly.values()}
                if len(distinct) == 1:
                    exact = True
                    start, end = next(iter(distinct))
                    schedule_kwargs = {
                        "start": start, "end": end, "days": list(weekly),
                        "schedule_type": "recurring",
                    }
            elif len(non_recurring) == 1:
                exact = True
                schedule_kwargs = {
                    "start": non_recurring[0]["start"], "end": non_recurring[0]["end"],
                    "days": [], "schedule_type": "non-recurring",
                }
            if not exact:
                schedule_kwargs = {"schedule_type": "source-only"}

            if self.resolver.resolve_exact(name, "schedule", scope):
                record_parse_error(
                    extraction, "schedules", source_path, scope, name, evidence,
                    notes=["Duplicate PAN-OS schedule name in the same scope."],
                )
                continue
            schedule = IRSchedule(name=name, source_attributes=evidence, **schedule_kwargs)
            extraction.canonical_ir.schedules.append(schedule)
            self.resolver.register_object(
                PANSourceObject(
                    name=name, kind="schedule", domain="schedule", source_path=source_path,
                    scope=scope, attributes=evidence, ir_object=schedule,
                ),
                "schedule",
            )
            partial_fields = list(unknown)
            if description is not None:
                partial_fields.append("description")
            if tags:
                partial_fields.append("tag")
            if not exact:
                partial_fields.append("multiple-or-differing-windows")
            if partial_fields:
                record_partial(
                    extraction, "schedules", source_path, scope, name, evidence,
                    notes=[f"PAN-OS schedule semantics retained as source evidence: {', '.join(partial_fields)}."],
                )
            else:
                record_normalized(extraction, "schedules", source_path, scope, name, evidence)

    def _parse_applications(self, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult):
        known = [
            "category", "subcategory", "technology", "risk", "description", "default",
            "timeout", "tcp-timeout", "udp-timeout", "tcp-half-closed-timeout",
            "tcp-time-wait-timeout", "signature", "tag", "depends-on", "parent-app",
        ]
        for entry in search_root.findall("./application/entry"):
            name = entry.get("name")
            source_path = f"application/entry[@name='{name}']" if name else "application/entry"
            attributes: Dict[str, Any] = {
                "pan_category": text_or_none(entry, "./category"),
                "pan_subcategory": text_or_none(entry, "./subcategory"),
                "pan_technology": text_or_none(entry, "./technology"),
                "pan_risk": text_or_none(entry, "./risk"),
                "pan_description": text_or_none(entry, "./description"),
                "pan_tags": member_texts(entry, "./tag/member"),
                "pan_dependencies": member_texts(entry, "./depends-on/member"),
                "pan_parent_app": text_or_none(entry, "./parent-app"),
            }
            attributes = {key: value for key, value in attributes.items() if value not in (None, [], {})}
            default_node = entry.find("./default")
            signature_node = entry.find("./signature")
            if default_node is not None:
                attributes["pan_default"] = structured_xml_capture(default_node)
            for timeout_name in (
                "timeout", "tcp-timeout", "udp-timeout", "tcp-half-closed-timeout", "tcp-time-wait-timeout"
            ):
                value = text_or_none(entry, f"./{timeout_name}")
                if value is not None:
                    attributes[f"pan_{timeout_name.replace('-', '_')}"] = value
            if signature_node is not None:
                attributes["pan_signatures"] = structured_xml_capture(signature_node)
            unknown = self._structured_unknown_children(entry, known)
            if unknown:
                attributes["pan_unknown_fields"] = unknown
            if not name:
                record_parse_error(
                    extraction, "applications", source_path, scope,
                    attributes=attributes, notes=["PAN-OS custom application is missing its required name."],
                )
                continue
            self.resolver.register_object(
                PANSourceObject(
                    name=name, kind="application", domain="application", source_path=source_path,
                    scope=scope, attributes=attributes,
                ),
                "application",
            )
            record_extract_only(
                extraction, "applications", source_path, scope, name, attributes,
                notes=["PAN-OS custom App-ID retained as structured inventory; no portable canonical application definition exists."],
            )

    def _parse_application_groups(self, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult):
        for entry in search_root.findall("./application-group/entry"):
            name = entry.get("name")
            source_path = f"application-group/entry[@name='{name}']" if name else "application-group/entry"
            attributes: Dict[str, Any] = {
                "pan_source_members": member_texts(entry, "./members/member"),
                "pan_description": text_or_none(entry, "./description"),
                "pan_tags": member_texts(entry, "./tag/member"),
            }
            attributes = {key: value for key, value in attributes.items() if value not in (None, [], {})}
            unknown = self._structured_unknown_children(entry, ["members", "description", "tag"])
            if unknown:
                attributes["pan_unknown_fields"] = unknown
            if not name:
                record_parse_error(
                    extraction, "application_groups", source_path, scope,
                    attributes=attributes, notes=["PAN-OS application group is missing its required name."],
                )
                continue
            self.resolver.register_object(
                PANSourceObject(
                    name=name, kind="application-group", domain="application", source_path=source_path,
                    scope=scope, attributes=attributes,
                ),
                "application-group",
            )
            record_extract_only(
                extraction, "application_groups", source_path, scope, name, attributes,
                notes=["PAN-OS application group retained as structured inventory."],
            )

    def _parse_application_filters(self, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult):
        for entry in search_root.findall("./application-filter/entry"):
            name = entry.get("name")
            source_path = f"application-filter/entry[@name='{name}']" if name else "application-filter/entry"
            criteria = self._structured_unknown_children(entry, [])
            attributes = {"pan_filter_criteria": criteria}
            if not name:
                record_parse_error(
                    extraction, "application_filters", source_path, scope,
                    attributes=attributes, notes=["PAN-OS application filter is missing its required name."],
                )
                continue
            self.resolver.register_object(
                PANSourceObject(
                    name=name, kind="application-filter", domain="application", source_path=source_path,
                    scope=scope, attributes=attributes,
                ),
                "application-filter",
            )
            record_extract_only(
                extraction, "application_filters", source_path, scope, name, attributes,
                notes=["Dynamic PAN-OS application filter retained without content-update-dependent expansion."],
            )

    def _parse_tags(self, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult):
        for entry in search_root.findall("./tag/entry"):
            name = entry.get("name")
            source_path = f"tag/entry[@name='{name}']" if name else "tag/entry"
            attributes: Dict[str, Any] = {
                "pan_color": text_or_none(entry, "./color"),
                "pan_comments": text_or_none(entry, "./comments"),
            }
            attributes = {key: value for key, value in attributes.items() if value is not None}
            unknown = self._structured_unknown_children(entry, ["color", "comments"])
            if unknown:
                attributes["pan_unknown_fields"] = unknown
            if not name:
                record_parse_error(
                    extraction, "tags", source_path, scope,
                    attributes=attributes, notes=["PAN-OS tag object is missing its required name."],
                )
                continue
            self.resolver.register_object(
                PANSourceObject(
                    name=name, kind="tag", domain="tag", source_path=source_path,
                    scope=scope, attributes=attributes,
                ),
                "tag",
            )
            record_extract_only(
                extraction, "tags", source_path, scope, name, attributes,
                notes=["PAN-OS tag definition retained as source inventory."],
            )

    def _finalize_group_references(self, extraction: ExtractionResult):
        def address_reference_is_unsafe(source_object: PANSourceObject, seen: set) -> bool:
            identity = (source_object.scope.kind, source_object.scope.name, source_object.kind, source_object.name)
            if identity in seen:
                return True
            if source_object.kind == "address":
                return bool(getattr(source_object.ir_object, "requires_manual_review", False))
            seen = seen | {identity}
            if source_object.attributes.get("pan_unknown_fields"):
                return True
            if source_object.attributes.get("pan_source_group_type") == "dynamic":
                return False
            for member in source_object.attributes.get("pan_source_members", []):
                resolved = self.resolver.resolve(member, "address-reference", source_object.scope)
                if resolved is None or address_reference_is_unsafe(resolved, seen):
                    return True
            return False

        def service_reference_is_unsafe(source_object: PANSourceObject, seen: set) -> bool:
            identity = (source_object.scope.kind, source_object.scope.name, source_object.kind, source_object.name)
            if identity in seen:
                return True
            if source_object.kind == "service":
                return bool(getattr(source_object.ir_object, "requires_manual_review", False))
            seen = seen | {identity}
            if source_object.attributes.get("pan_tags") or source_object.attributes.get("pan_unknown_fields"):
                return True
            for member in source_object.attributes.get("pan_source_members", []):
                resolved = self.resolver.resolve(member, "service-reference", source_object.scope)
                if resolved is None or service_reference_is_unsafe(resolved, seen):
                    return True
            return False

        for scope_key, types in self.resolver._objects.items():
            scope = PANScope(kind=scope_key[0], name=scope_key[1])
            for source_object in types.get("address-group", {}).values():
                group = source_object.ir_object
                if group is None:
                    continue
                evidence = dict(source_object.attributes)
                issues = list(evidence.get("pan_unknown_fields", {}))
                unresolved: List[str] = []
                unsafe: List[str] = []
                if not group.is_dynamic:
                    rewritten = []
                    for member in evidence.get("pan_source_members", []):
                        resolved = self.resolver.resolve(member, "address-reference", scope)
                        if resolved is None:
                            unresolved.append(member)
                            rewritten.append(member)
                        else:
                            rewritten.append(resolved.canonical_name or member)
                            if address_reference_is_unsafe(resolved, set()):
                                unsafe.append(member)
                    group.members = rewritten
                if unresolved:
                    evidence["pan_unresolved_members"] = unresolved
                    issues.append("unresolved-members")
                if unsafe:
                    evidence["pan_unsafe_members"] = unsafe
                    issues.append("unsafe-members")
                group.source_attributes = evidence
                group.requires_manual_review = bool(issues)
                group.migration_status = "PARTIALLY_NORMALIZED" if issues else "NORMALIZED"
                if issues:
                    record_partial(
                        extraction, "address_groups", source_object.source_path, scope,
                        source_object.name, evidence,
                        notes=[f"PAN-OS address group requires review: {', '.join(issues)}."],
                    )
                else:
                    record_normalized(
                        extraction, "address_groups", source_object.source_path, scope,
                        source_object.name, evidence,
                    )

            for source_object in types.get("service-group", {}).values():
                group = source_object.ir_object
                if group is None:
                    continue
                evidence = dict(source_object.attributes)
                issues = list(evidence.get("pan_unknown_fields", {}))
                if evidence.get("pan_tags"):
                    issues.append("tag")
                unresolved: List[str] = []
                unsafe: List[str] = []
                rewritten = []
                for member in evidence.get("pan_source_members", []):
                    resolved = self.resolver.resolve(member, "service-reference", scope)
                    if resolved is None:
                        unresolved.append(member)
                        rewritten.append(member)
                    else:
                        rewritten.append(resolved.canonical_name or member)
                        if service_reference_is_unsafe(resolved, set()):
                            unsafe.append(member)
                if unresolved:
                    evidence["pan_unresolved_members"] = unresolved
                    issues.append("unresolved-members")
                if unsafe:
                    evidence["pan_unsafe_members"] = unsafe
                    issues.append("unsafe-members")
                group.members = rewritten
                group.unsafe_members = list(dict.fromkeys(unresolved + unsafe))
                group.source_attributes = evidence
                group.requires_manual_review = bool(issues)
                group.migration_status = "PARTIALLY_NORMALIZED" if issues else "NORMALIZED"
                if issues:
                    record_partial(
                        extraction, "service_groups", source_object.source_path, scope,
                        source_object.name, evidence,
                        notes=[f"PAN-OS service group requires review: {', '.join(issues)}."],
                    )
                else:
                    record_normalized(
                        extraction, "service_groups", source_object.source_path, scope,
                        source_object.name, evidence,
                    )

    def extract(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> ExtractionResult:
        # A parser instance may be reused; definitions from an earlier source
        # must never participate in current-scope reference resolution.
        self.resolver = PANResolver()
        try:
            root = ET.fromstring(content)
        except ET.ParseError as e:
            # Handle possible surrounding whitespace or partial tags
            try:
                cleaned = content.strip()
                if not cleaned:
                    raise ValueError("Empty configuration input.")
                root = ET.fromstring(cleaned)
            except ET.ParseError:
                # Check for PAN-OS CLI
                if cleaned.startswith("set "):
                    raise ValueError("PAN-OS CLI 'set' format is not supported. Please provide XML configuration.")
                raise ValueError(f"Malformed XML input: {str(e)}")

        # PAN-OS operational/API exports may wrap the configuration in
        # response/result/config.  Only unwrap that exact hierarchy.
        if root.tag == "response":
            wrapped = root.find("./result/config")
            if wrapped is None:
                raise ValueError("Unsupported PAN-OS XML response: missing response/result/config.")
            root = wrapped

        if root.tag != "config":
            raise ValueError(f"Unsupported XML format: expected root element '<config>', found '<{root.tag}>'.")

        # 1. Metadata
        hostname = None
        host_elem = root.find(".//system/hostname")
        if host_elem is None:
            host_elem = root.find(".//deviceconfig/system/hostname")
        if host_elem is not None and host_elem.text:
            hostname = host_elem.text.strip()

        ir = IRConfig(
            metadata=IRMetadata(
                hostname=hostname,
                source_vendor="palo_alto",
                source_version=root.get("version")
            )
        )
        extraction = ExtractionResult(canonical_ir=ir)

        # Topology must be known before objects/rules are resolved.
        PANPanoramaExtractor.discover(root, self.resolver, extraction)
        vsys_imports = PANVsysImportExtractor.extract(root, extraction)

        # Find all scopes: shared, vsys, device-group
        
        # Pass 1: Objects
        devices = root.findall(".//devices/entry")
        for dev in devices:
            dev_name = dev.get("name") or "localhost.localdomain"
            dev_scope = PANScope(kind="device", name=dev_name)
            
            network_elem = dev.find("./network")
            if network_elem is not None:
                self._parse_network(extraction, ir, dev_scope, network_elem)

        PANVsysImportExtractor.associate(vsys_imports, extraction)

        shared_root = root.find(".//shared")
        if shared_root is not None:
            self._parse_objects(PANScope(kind="shared", name="shared"), shared_root, extraction)
            
        for vsys_entry in root.findall(".//vsys/entry"):
            vsys_name = vsys_entry.get("name") or "vsys1"
            self._parse_objects(PANScope(kind="vsys", name=vsys_name), vsys_entry, extraction)
            
        for dg_entry in root.findall(".//device-group/entry"):
            dg_name = dg_entry.get("name") or "dg1"
            self._parse_objects(PANScope(kind="device-group", name=dg_name), dg_entry, extraction)

        if root.find(".//vsys/entry") is None and root.find(".//device-group/entry") is None and shared_root is None:
            self._parse_objects(PANScope(kind="vsys", name="vsys1"), root, extraction)
            
        # Build canonical names
        self.resolver.build_canonical_names()
        self._finalize_group_references(extraction)

        # Pass 2: Rules
        if shared_root is not None:
            self._parse_rules(PANScope(kind="shared", name="shared"), shared_root, extraction)
            
        for vsys_entry in root.findall(".//vsys/entry"):
            vsys_name = vsys_entry.get("name") or "vsys1"
            self._parse_rules(PANScope(kind="vsys", name=vsys_name), vsys_entry, extraction)
            
        for dg_entry in root.findall(".//device-group/entry"):
            dg_name = dg_entry.get("name") or "dg1"
            self._parse_rules(PANScope(kind="device-group", name=dg_name), dg_entry, extraction)

        if root.find(".//vsys/entry") is None and root.find(".//device-group/entry") is None and shared_root is None:
            self._parse_rules(PANScope(kind="vsys", name="vsys1"), root, extraction)

        # Interface Accounting
        for intf in ir.interfaces:
            # Interfaces are stored under "device" scopes
            source_obj = None
            for sk, types_dict in self.resolver._objects.items():
                if "interface" in types_dict and intf.name in types_dict["interface"]:
                    source_obj = types_dict["interface"][intf.name]
                    break
            
            if source_obj:
                issues = []
                attrs = intf.source_attributes
                if len(attrs.get("pan_ipv4_addresses", [])) > 1:
                    issues.append("Multiple IPv4 addresses exceed the canonical scalar interface field.")
                if attrs.get("pan_ipv6_addresses"):
                    issues.append("IPv6 entry attributes remain source-only.")
                if attrs.get("pan_dhcp_client"):
                    issues.append("DHCP client settings remain source-only.")
                if attrs.get("pan_pppoe"):
                    issues.append("PPPoE settings remain source-only.")
                if attrs.get("pan_unknown_layer3_fields"):
                    issues.append("Unknown Layer 3 interface fields were retained.")
                if attrs.get("pan_unknown_physical_fields"):
                    issues.append("Unknown physical interface fields were retained.")
                if attrs.get("pan_link_state") == "auto":
                    issues.append("Original link-state auto is retained in source evidence.")
                if issues:
                    intf.requires_manual_review = True
                    record_partial(extraction, domain="interfaces", source_path=source_obj.source_path, scope=source_obj.scope, name=intf.name, attributes=attrs, notes=issues)
                else:
                    record_normalized(extraction, domain="interfaces", source_path=source_obj.source_path, scope=source_obj.scope, name=intf.name, attributes=attrs)
        extraction.canonical_ir = ir
        add_inventory_section_accounting(extraction)
        review_items = [item for item in extraction.inventory_items if item.requires_manual_review]
        blocking_items = [item for item in extraction.inventory_items if item.status in {
            ExtractionStatus.PARTIALLY_NORMALIZED, ExtractionStatus.UNSUPPORTED,
            ExtractionStatus.PARSE_ERROR,
        } and item.requires_manual_review]
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
        return extraction

    def _parse_l3_interface_node(self, config_node: ET.Element, interface_name: str, interface_type: str, parent: Optional[str], scope: PANScope, physical_node: Optional[ET.Element] = None) -> tuple[IRInterface, dict]:
        """Parses a specific logical interface node and returns the IRInterface and source_attributes dict."""
        source_attrs = {}
        ip = None
        secondary_ips = []
        
        # IPv4
        all_ipv4 = []
        for ip_elem in config_node.findall("./ip/entry"):
            addr = ip_elem.get("name")
            if addr:
                all_ipv4.append(addr)
        if all_ipv4:
            source_attrs["pan_ipv4_addresses"] = all_ipv4
            ip = all_ipv4[0]
            # We don't populate secondary_ips to avoid fake semantics
        
        # IPv6
        all_ipv6 = []
        for ipv6_elem in config_node.findall("./ipv6/address/entry"):
            addr = ipv6_elem.get("name")
            if addr:
                v6_attrs = {"address": addr, "source_entry": structured_xml_capture(ipv6_elem)}
                enable = text_or_none(ipv6_elem, "./enable")
                if enable is not None:
                    v6_attrs["enable"] = enable
                all_ipv6.append(v6_attrs)
        if all_ipv6:
            source_attrs["pan_ipv6_addresses"] = all_ipv6

        # Description
        desc_elem = config_node.find("./comment")
        if desc_elem is None and physical_node is not None:
            desc_elem = physical_node.find("./comment")
        desc = desc_elem.text if desc_elem is not None else None
        
        # Management profile
        mgmt_elem = config_node.find("./interface-management-profile")
        mgmt_prof = mgmt_elem.text if mgmt_elem is not None else None
        
        # Explicit status
        status_kwargs = {}
        state_root = physical_node if physical_node is not None else config_node
        state_elem = state_root.find("./link-state")
        if state_elem is not None and state_elem.text:
            source_attrs["status_explicit"] = True
            link_state = state_elem.text.strip().lower()
            source_attrs["pan_link_state"] = link_state
            if link_state in {"auto", "up", "down"}:
                status_kwargs["status"] = link_state != "down"
            else:
                source_attrs["pan_link_state_invalid"] = True
        else:
            source_attrs["status_explicit"] = False
            
        # Addressing mode
        addr_mode = None
        if config_node.find("./dhcp-client") is not None:
            addr_mode = "dhcp-client"
            source_attrs["pan_dhcp_client"] = structured_xml_capture(config_node.find("./dhcp-client"))
        elif config_node.find("./pppoe") is not None:
            addr_mode = "pppoe"
            source_attrs["pan_pppoe"] = structured_xml_capture(config_node.find("./pppoe"))
        elif all_ipv4:
            addr_mode = "static"

        unknown = collect_unknown_children(
            config_node,
            ["ip", "ipv6", "comment", "interface-management-profile", "dhcp-client",
             "pppoe", "tag", "units", "link-state"],
        )
        if unknown:
            source_attrs["pan_unknown_layer3_fields"] = unknown
        if physical_node is not None:
            physical_unknown = collect_unknown_children(
                physical_node,
                ["layer3", "layer2", "virtual-wire", "tap", "ha", "decrypt-mirror",
                 "comment", "link-state"],
            )
            if physical_unknown:
                source_attrs["pan_unknown_physical_fields"] = physical_unknown
            
        # VLAN tag
        vlanid = None
        tag_elem = config_node.find("./tag")
        if tag_elem is not None and tag_elem.text and tag_elem.text.isdigit():
            vlanid = int(tag_elem.text.strip())
            
        ir_intf = IRInterface(
            name=interface_name,
            ip=ip,
            description=desc,
            interface_type=interface_type,
            parent=parent,
            management_profile=mgmt_prof,
            addressing_mode=addr_mode,
            vlanid=vlanid,
            source_attributes=source_attrs,
            **status_kwargs
        )
        return ir_intf, source_attrs

    def _parse_network(self, extraction: ExtractionResult, ir: IRConfig, scope: PANScope, network_root: ET.Element):
        intfs_root = network_root.find("./interface")

        # Explicitly support physical and subinterfaces
        families = [
            ("ethernet", "./ethernet/entry", True),
            ("aggregate-ethernet", "./aggregate-ethernet/entry", True),
            ("loopback", "./loopback/units/entry", False),
            ("tunnel", "./tunnel/units/entry", False),
            ("vlan", "./vlan/units/entry", False)
        ]
        
        for family_type, path, has_layer3 in families if intfs_root is not None else []:
            for i_entry in intfs_root.findall(path):
                i_name = i_entry.get("name")
                if not i_name: continue
                
                # For physical interfaces, we look at layer3
                # For logical interfaces, the entry itself is the node
                
                if has_layer3:
                    configured_modes = [child.tag for child in i_entry if child.tag in {
                        "layer3", "layer2", "virtual-wire", "tap", "ha", "decrypt-mirror"
                    }]
                    for mode in configured_modes:
                        if mode != "layer3":
                            record_extract_only(
                                extraction, "interfaces",
                                f"network/interface/{family_type}/entry[@name='{i_name}']/{mode}",
                                scope, i_name,
                                {"pan_interface_mode": mode,
                                 "pan_source_entry": structured_xml_capture(i_entry.find(f'./{mode}'))},
                                notes=[f"PAN-OS {mode} interface mode is inventoried but not canonicalized."],
                            )
                    l3_node = i_entry.find("./layer3")
                    if l3_node is not None:
                        ir_intf, source_attrs = self._parse_l3_interface_node(l3_node, i_name, family_type, None, scope, i_entry)
                        ir.interfaces.append(ir_intf)
                        self.resolver.register_object(PANSourceObject(name=i_name, kind='interface', domain='interface', source_path=f"network/interface/{family_type}/entry[@name='{i_name}']/layer3", scope=scope, attributes=source_attrs, ir_object=ir_intf), "interface")
                    
                    # Subinterfaces
                    for unit_entry in i_entry.findall("./layer3/units/entry"):
                        u_name = unit_entry.get("name")
                        if not u_name: continue
                        ir_intf, source_attrs = self._parse_l3_interface_node(unit_entry, u_name, f"{family_type}-subinterface", i_name, scope)
                        ir.interfaces.append(ir_intf)
                        self.resolver.register_object(PANSourceObject(name=u_name, kind='interface', domain='interface', source_path=f"network/interface/{family_type}/entry[@name='{i_name}']/layer3/units/entry[@name='{u_name}']", scope=scope, attributes=source_attrs, ir_object=ir_intf), "interface")
                else:
                    ir_intf, source_attrs = self._parse_l3_interface_node(i_entry, i_name, family_type, None, scope)
                    ir.interfaces.append(ir_intf)
                    self.resolver.register_object(PANSourceObject(name=i_name, kind='interface', domain='interface', source_path=f"network/interface/{family_type}/units/entry[@name='{i_name}']", scope=scope, attributes=source_attrs, ir_object=ir_intf), "interface")
        
        # Additional parsing for loopback/tunnel/vlan directly under their types if some PAN-OS versions don't use 'units'
        for family_type in ["loopback", "tunnel", "vlan"] if intfs_root is not None else []:
            for i_entry in intfs_root.findall(f"./{family_type}/entry"):
                i_name = i_entry.get("name")
                if not i_name: continue
                # if already parsed via units/entry, skip
                if any(i.name == i_name for i in ir.interfaces): continue
                
                ir_intf, source_attrs = self._parse_l3_interface_node(i_entry, i_name, family_type, None, scope)
                ir.interfaces.append(ir_intf)
                self.resolver.register_object(PANSourceObject(name=i_name, kind='interface', domain='interface', source_path=f"network/interface/{family_type}/entry[@name='{i_name}']", scope=scope, attributes=source_attrs, ir_object=ir_intf), "interface")

        PANRouteExtractor.extract_static_routes(scope, network_root, extraction)
        PANResidualExtractor.extract_network_residuals(scope, network_root, extraction)

    def _parse_objects(self, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult):
        ir = extraction.canonical_ir
        
        # 2. Zones
        for z_entry in search_root.findall("./zone/entry"):
            z_name = z_entry.get("name")
            if not z_name: continue
            
            intfs = []
            zone_types = []
            
            for n_type in ["layer3", "layer2", "virtual-wire", "tap", "tunnel"]:
                type_members = member_texts(z_entry, f"./network/{n_type}/member")
                if type_members:
                    zone_types.append(n_type)
                    intfs.extend(type_members)
                    
            source_attrs = {}
            if zone_types:
                source_attrs["pan_zone_types"] = zone_types
                source_attrs["pan_zone_type"] = zone_types[0] if len(zone_types) == 1 else None
            security_fields = [
                "enable-user-identification", "enable-device-identification",
                "zone-protection-profile", "packet-buffer-protection", "log-setting",
                "user-acl", "device-acl", "network-inspection",
            ]
            present_security_fields = []
            for field in security_fields:
                node = z_entry.find(f"./{field}")
                if node is not None:
                    source_attrs[f"pan_{field.replace('-', '_')}"] = structured_xml_capture(node)
                    present_security_fields.append(field)
            network_node = z_entry.find("./network")
            unknown_network = collect_unknown_children(
                network_node, ["layer3", "layer2", "virtual-wire", "tap", "tunnel"]
            ) if network_node is not None else {}
            if unknown_network:
                source_attrs["pan_network_settings"] = unknown_network
            unknown_zone = collect_unknown_children(z_entry, ["network", *security_fields])
            if unknown_zone:
                source_attrs["pan_unknown_fields"] = unknown_zone
                
            ir_zone = IRZone(name=z_name, interfaces=intfs, source_attributes=source_attrs)
            ir.zones.append(ir_zone)
            
            zone_issues = []
            if len(zone_types) > 1:
                zone_issues.append(f"Multiple effective network types configured: {', '.join(zone_types)}")
            if present_security_fields:
                zone_issues.append(f"Security-relevant source settings retained: {', '.join(present_security_fields)}")
            if unknown_network or unknown_zone:
                zone_issues.append("Unknown zone fields retained as source evidence.")
            
            for intf in intfs:
                existing = next((i for i in ir.interfaces if i.name == intf), None)
                if not existing:
                    zone_issues.append(f"Unresolved interface reference: {intf}")
                else:
                    if existing.zone is None:
                        existing.zone = z_name
                    elif existing.zone != z_name:
                        # Conflict: interface in multiple zones
                        zone_issues.append(f"Interface {intf} conflict: belongs to multiple zones ({existing.zone} and {z_name})")
                        
            if zone_issues:
                ir_zone.requires_manual_review = True
                ir_zone.migration_status = "PARTIALLY_NORMALIZED"
                ir_zone.review_reasons = zone_issues
                record_partial(
                    extraction, domain="zones",
                    source_path=f"zone/entry[@name='{z_name}']",
                    scope=scope, name=z_name, attributes=source_attrs, notes=zone_issues
                )
            else:
                record_normalized(
                    extraction, domain="zones",
                    source_path=f"zone/entry[@name='{z_name}']",
                    scope=scope, name=z_name, attributes=source_attrs
                )

        # 3. Addresses
        self._parse_addresses(scope, search_root, extraction)

        # 4. Address Groups
        self._parse_address_groups(scope, search_root, extraction)

        # 5. Services
        self._parse_services(scope, search_root, extraction)

        # 6. Service Groups
        self._parse_service_groups(scope, search_root, extraction)

        # 6.1 Schedules and application inventories
        self._parse_schedules(scope, search_root, extraction)
        self._parse_applications(scope, search_root, extraction)
        self._parse_application_groups(scope, search_root, extraction)
        self._parse_application_filters(scope, search_root, extraction)
        self._parse_tags(scope, search_root, extraction)

        # 6.5 Security Profile Groups
        for pg_entry in search_root.findall("./profile-group/entry"):
            pg_name = pg_entry.get("name")
            if not pg_name:
                record_parse_error(extraction, "profile_groups", "profile-group/entry", scope,
                                   attributes={"pan_source_entry": structured_xml_capture(pg_entry)},
                                   notes=["PAN-OS profile group is missing its required name."])
                continue
            profile_paths = {
                "virus": "antivirus", "vulnerability": "vulnerability",
                "spyware": "anti_spyware", "url-filtering": "url_filtering",
                "file-blocking": "file_blocking", "wildfire-analysis": "wildfire",
                "data-filtering": "data_filtering",
            }
            members = {key: member_texts(pg_entry, f"./{key}/member") for key in profile_paths}
            description = text_or_none(pg_entry, "./description")
            unknown = collect_unknown_children(pg_entry, [*profile_paths, "description"])
            evidence = {"pan_profile_members": members, "pan_description": description,
                        "pan_source_entry": structured_xml_capture(pg_entry)}
            if unknown:
                evidence["pan_unknown_fields"] = unknown
            cardinality = [key for key, values in members.items() if len(values) > 1]
            partial_reasons = []
            if cardinality:
                partial_reasons.append(f"multiple-members:{','.join(cardinality)}")
            if members["data-filtering"]:
                partial_reasons.append("data-filtering-source-only")
            if unknown:
                partial_reasons.append("unknown-fields")

            profile_group = IRSecurityProfileGroup(
                name=pg_name,
                antivirus=members["virus"][0] if len(members["virus"]) == 1 else None,
                vulnerability=members["vulnerability"][0] if len(members["vulnerability"]) == 1 else None,
                anti_spyware=members["spyware"][0] if len(members["spyware"]) == 1 else None,
                url_filtering=members["url-filtering"][0] if len(members["url-filtering"]) == 1 else None,
                file_blocking=members["file-blocking"][0] if len(members["file-blocking"]) == 1 else None,
                wildfire=members["wildfire-analysis"][0] if len(members["wildfire-analysis"]) == 1 else None,
                description=description,
                migration_status="PARTIALLY_NORMALIZED" if partial_reasons else "NORMALIZED",
                requires_manual_review=bool(partial_reasons),
                source_profile_references={key: values[0] for key, values in members.items() if len(values) == 1},
            )
            ir.security_profile_groups.append(profile_group)
            self.resolver.register_object(
                PANSourceObject(
                    name=pg_name, kind="profile-group", domain="profile-group",
                    source_path=f"profile-group/entry[@name='{pg_name}']",
                    scope=scope, ir_object=profile_group,
                ),
                "profile-group",
            )
            if partial_reasons:
                record_partial(extraction, "profile_groups", f"profile-group/entry[@name='{pg_name}']",
                               scope, pg_name, evidence,
                               notes=[f"PAN-OS profile group requires review: {', '.join(partial_reasons)}."])
            else:
                record_normalized(extraction, "profile_groups", f"profile-group/entry[@name='{pg_name}']",
                                  scope, pg_name, evidence)

    @staticmethod
    def _parse_explicit_yes_no(entry: ET.Element, field: str) -> tuple[Optional[bool], bool, Optional[str]]:
        element = entry.find(f"./{field}")
        if element is None:
            return None, False, None
        value = (element.text or "").strip().lower()
        if value not in {"yes", "no"}:
            raise ValueError(f"{field} must be 'yes' or 'no', found {value!r}.")
        return value == "yes", True, value

    @staticmethod
    def _parse_explicit_yes_no_path(entry: ET.Element, path: str) -> tuple[Optional[bool], bool, Optional[str]]:
        element = entry.find(path)
        if element is None:
            return None, False, None
        value = (element.text or "").strip().lower()
        if value not in {"yes", "no"}:
            raise ValueError(f"{path} must be 'yes' or 'no', found {value!r}.")
        return value == "yes", True, value

    def _parse_security_rules(self, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult):
        rulebases = [
            ("pre", "./pre-rulebase/security/rules/entry", "pre-rulebase"),
            ("local", "./rulebase/security/rules/entry", "rulebase"),
            ("post", "./post-rulebase/security/rules/entry", "post-rulebase"),
        ]
        for position, path, path_prefix in rulebases:
            entries = search_root.findall(path)
            parsed_count = normalized_count = 0
            for source_rule_index, entry in enumerate(entries):
                policies_before = len(extraction.canonical_ir.policies)
                inventory_before = len(extraction.inventory_items)
                self._parse_security_rule(
                    scope, entry, extraction, position, source_rule_index, path_prefix
                )
                parsed_count += int(len(extraction.canonical_ir.policies) > policies_before)
                if len(extraction.inventory_items) > inventory_before:
                    normalized_count += int(extraction.inventory_items[-1].status == ExtractionStatus.NORMALIZED)
            if entries:
                add_source_section(
                    extraction, f"{path_prefix}/security/rules",
                    ExtractionStatus.NORMALIZED if normalized_count == len(entries) else ExtractionStatus.PARTIALLY_NORMALIZED,
                    len(entries), parsed_count, normalized_count,
                    "PANOSSourceParser._parse_security_rule",
                    source_context=f"{scope.kind}:{scope.name}",
                )
        default_paths = [
            ("local", "./rulebase/default-security-rules/rules/entry", "rulebase"),
            ("pre", "./pre-rulebase/default-security-rules/rules/entry", "pre-rulebase"),
            ("post", "./post-rulebase/default-security-rules/rules/entry", "post-rulebase"),
            # Some exports omit the intermediate rules container.
            ("local", "./rulebase/default-security-rules/entry", "rulebase"),
        ]
        seen = set()
        for position, path, prefix in default_paths:
            for source_rule_index, entry in enumerate(search_root.findall(path)):
                identity = id(entry)
                if identity in seen:
                    continue
                seen.add(identity)
                self._parse_default_security_rule(scope, entry, extraction, position,
                                                  source_rule_index, prefix)

    def _parse_default_security_rule(self, scope: PANScope, entry: ET.Element,
                                     extraction: ExtractionResult, position: str,
                                     source_index: int, prefix: str) -> None:
        name = entry.get("name")
        path = f"{prefix}/default-security-rules/entry[@name='{name}']"
        evidence = {
            "pan_scope_kind": scope.kind, "pan_scope_name": scope.name,
            "pan_rulebase_position": position, "pan_source_rule_index": source_index,
            "pan_source_rule_id": f"palo_alto:{scope.kind}:{scope.name}:{position}:default:{source_index}:{name}",
            "pan_action": text_or_none(entry, "./action"),
            "pan_description": text_or_none(entry, "./description"),
            "pan_tags": member_texts(entry, "./tag/member"),
            "pan_group_tag": text_or_none(entry, "./group-tag"),
            "pan_log_start": text_or_none(entry, "./log-start"),
            "pan_log_end": text_or_none(entry, "./log-end"),
            "pan_log_setting": text_or_none(entry, "./log-setting"),
            "pan_profile_setting": structured_xml_capture(entry.find("./profile-setting")),
            "pan_option": structured_xml_capture(entry.find("./option")),
            "pan_icmp_unreachable": text_or_none(entry, "./icmp-unreachable"),
            "pan_override_present": len(entry) > 0,
            "pan_source_entry": structured_xml_capture(entry),
        }
        if not name:
            record_parse_error(extraction, "default_security_rules", path, scope,
                               attributes=evidence,
                               notes=["PAN-OS default security rule is missing its name."])
            return
        record_extract_only(
            extraction, "default_security_rules", path, scope, name, evidence,
            notes=["PAN-OS default security-rule behavior is retained as source inventory; canonical policy matching does not model implicit defaults."],
        )

    def _parse_security_rule(
        self,
        scope: PANScope,
        entry: ET.Element,
        extraction: ExtractionResult,
        rulebase_position: str,
        source_rule_index: int,
        path_prefix: str,
    ):
        name = entry.get("name")
        source_path = (
            f"{path_prefix}/security/rules/entry[@name='{name}']"
            if name else f"{path_prefix}/security/rules/entry"
        )
        from_zones = member_texts(entry, "./from/member")
        to_zones = member_texts(entry, "./to/member")
        sources = member_texts(entry, "./source/member")
        destinations = member_texts(entry, "./destination/member")
        source_users = member_texts(entry, "./source-user/member")
        applications = member_texts(entry, "./application/member")
        services = member_texts(entry, "./service/member")
        categories = member_texts(entry, "./category/member")
        source_hip = member_texts(entry, "./source-hip/member")
        destination_hip = member_texts(entry, "./destination-hip/member")
        tags = member_texts(entry, "./tag/member")
        group_tag = text_or_none(entry, "./group-tag")
        schedule_source = text_or_none(entry, "./schedule")
        source_action = text_or_none(entry, "./action")
        source_action = source_action.lower() if source_action else None
        description = text_or_none(entry, "./description")
        rule_type = text_or_none(entry, "./rule-type")
        log_setting = text_or_none(entry, "./log-setting")
        saas_user_list = member_texts(entry, "./saas-user-list/member")
        saas_tenant_list = member_texts(entry, "./saas-tenant-list/member")
        if not saas_user_list:
            scalar = text_or_none(entry, "./saas-user-list")
            saas_user_list = [scalar] if scalar else []
        if not saas_tenant_list:
            scalar = text_or_none(entry, "./saas-tenant-list")
            saas_tenant_list = [scalar] if scalar else []
        profile_groups = member_texts(entry, "./profile-setting/group/member")
        profile_names = [
            "virus", "vulnerability", "spyware", "url-filtering", "file-blocking",
            "wildfire-analysis", "data-filtering",
        ]
        direct_profiles = {
            profile: member_texts(entry, f"./profile-setting/profiles/{profile}/member")
            for profile in profile_names
        }
        direct_profiles = {profile: values for profile, values in direct_profiles.items() if values}
        profile_setting_node = entry.find("./profile-setting")
        profiles_node = entry.find("./profile-setting/profiles")
        unknown_profile_setting = (
            self._structured_unknown_children(profile_setting_node, ["group", "profiles"])
            if profile_setting_node is not None else {}
        )
        unknown_direct_profile_types = (
            self._structured_unknown_children(profiles_node, profile_names)
            if profiles_node is not None else {}
        )
        unknown = self._structured_unknown_children(
            entry,
            [
                "from", "to", "source", "destination", "source-user", "application",
                "service", "category", "source-hip", "destination-hip", "negate-source",
                "negate-destination", "action", "disabled", "description", "tag",
                "group-tag", "schedule", "rule-type", "log-start", "log-end",
                "log-setting", "profile-setting", "disable-inspect",
                "option", "disable-server-response-inspection", "icmp-unreachable",
                "saas-user-list", "saas-tenant-list",
            ],
        )
        evidence: Dict[str, Any] = {
            "pan_scope_kind": scope.kind,
            "pan_scope_name": scope.name,
            "pan_rulebase_position": rulebase_position,
            "pan_source_rule_index": source_rule_index,
            "pan_source_path": source_path,
            "pan_source_rule_name": name,
            "pan_from": from_zones,
            "pan_to": to_zones,
            "pan_source": sources,
            "pan_destination": destinations,
            "pan_source_user": source_users,
            "pan_application": applications,
            "pan_service": services,
            "pan_category": categories,
            "pan_source_hip": source_hip,
            "pan_destination_hip": destination_hip,
            "pan_tags": tags,
            "pan_group_tag": group_tag,
            "pan_schedule": schedule_source,
            "pan_source_action": source_action,
            "pan_description": description,
            "pan_rule_type": rule_type,
            "pan_log_setting": log_setting,
            "pan_saas_user_list": saas_user_list,
            "pan_saas_tenant_list": saas_tenant_list,
            "pan_profile_groups": profile_groups,
            "pan_direct_profiles": direct_profiles,
            "pan_source_entry": structured_xml_capture(entry),
        }
        # Empty direct match lists are meaningful evidence: absent must never
        # be confused with an explicit PAN "any" member.
        evidence = {key: value for key, value in evidence.items() if value is not None}
        if unknown:
            evidence["pan_unknown_fields"] = unknown
        if unknown_profile_setting:
            evidence["pan_unknown_profile_setting"] = unknown_profile_setting
        if unknown_direct_profile_types:
            evidence["pan_unknown_direct_profile_types"] = unknown_direct_profile_types
        option_node = entry.find("./option")
        unknown_option = (
            self._structured_unknown_children(option_node, ["disable-server-response-inspection"])
            if option_node is not None else {}
        )
        if unknown_option:
            evidence["pan_unknown_option_fields"] = unknown_option
        icmp_unreachable = text_or_none(entry, "./icmp-unreachable")
        if icmp_unreachable is not None:
            evidence["pan_icmp_unreachable"] = icmp_unreachable
        for field in (
            "disabled", "log-start", "log-end", "disable-inspect",
            "disable-server-response-inspection", "negate-source", "negate-destination",
        ):
            element = entry.find(f"./{field}")
            key = field.replace("-", "_")
            evidence[f"pan_{key}_explicit"] = element is not None
            if element is not None:
                evidence[f"pan_{key}_value"] = (element.text or "").strip().lower()

        if not name:
            record_parse_error(
                extraction, "policies", source_path, scope, attributes=evidence,
                notes=["PAN-OS security rule is missing its required name."],
            )
            return

        action_map = {
            "allow": PolicyAction.ALLOW,
            "deny": PolicyAction.DENY,
            "drop": PolicyAction.DENY,
            "reset-client": PolicyAction.DENY,
            "reset-server": PolicyAction.DENY,
            "reset-both": PolicyAction.DENY,
        }
        if source_action is None:
            record_partial(
                extraction, "policies", source_path, scope, name, evidence,
                notes=["Missing required action; canonical policy withheld."],
            )
            return
        if source_action not in action_map:
            record_unsupported(
                extraction, "policies", source_path, scope, name, evidence,
                notes=[f"Unsupported PAN-OS security-rule action: {source_action}."],
            )
            return

        missing_fields = [
            field for field, value in (
                ("from", from_zones), ("to", to_zones), ("source", sources),
                ("destination", destinations), ("service", services),
            ) if not value
        ]
        if missing_fields:
            record_partial(
                extraction, "policies", source_path, scope, name, evidence,
                notes=[f"Missing required fields ({', '.join(missing_fields)}); canonical policy withheld."],
            )
            return

        try:
            disabled, disabled_explicit, disabled_value = self._parse_explicit_yes_no(entry, "disabled")
            log_start, log_start_explicit, log_start_value = self._parse_explicit_yes_no(entry, "log-start")
            log_end, log_end_explicit, log_end_value = self._parse_explicit_yes_no(entry, "log-end")
            disable_inspect, disable_inspect_explicit, disable_inspect_value = self._parse_explicit_yes_no(entry, "disable-inspect")
            nested_disable_server = self._parse_explicit_yes_no_path(
                entry, "./option/disable-server-response-inspection"
            )
            direct_disable_server = self._parse_explicit_yes_no(
                entry, "disable-server-response-inspection"
            )
            disable_server, disable_server_explicit, disable_server_value = (
                nested_disable_server if nested_disable_server[1] else direct_disable_server
            )
            negate_source, negate_source_explicit, negate_source_value = self._parse_explicit_yes_no(entry, "negate-source")
            negate_destination, negate_destination_explicit, negate_destination_value = self._parse_explicit_yes_no(
                entry, "negate-destination"
            )
        except ValueError as error:
            record_parse_error(
                extraction, "policies", source_path, scope, name, evidence,
                notes=[f"Malformed PAN-OS security-rule value: {error}"],
            )
            return

        presence_fields = {
            "disabled": (disabled_explicit, disabled_value),
            "log_start": (log_start_explicit, log_start_value),
            "log_end": (log_end_explicit, log_end_value),
            "disable_inspect": (disable_inspect_explicit, disable_inspect_value),
            "disable_server_response_inspection": (disable_server_explicit, disable_server_value),
            "negate_source": (negate_source_explicit, negate_source_value),
            "negate_destination": (negate_destination_explicit, negate_destination_value),
        }
        if nested_disable_server[1]:
            evidence["pan_disable_server_response_inspection_form"] = "option"
        elif direct_disable_server[1]:
            evidence["pan_disable_server_response_inspection_form"] = "direct"
        if nested_disable_server[1] and direct_disable_server[1] and nested_disable_server[2] != direct_disable_server[2]:
            evidence["pan_disable_server_response_inspection_conflict"] = {
                "option": nested_disable_server[2], "direct": direct_disable_server[2]
            }
        for field, (explicit, value) in presence_fields.items():
            evidence[f"pan_{field}_explicit"] = explicit
            if explicit:
                evidence[f"pan_{field}_value"] = value

        if len(profile_groups) > 1:
            record_parse_error(
                extraction, "policies", source_path, scope, name, evidence,
                notes=["PAN-OS security rule contains multiple profile-group members."],
            )
            return

        unresolved_sources: List[str] = []
        unresolved_destinations: List[str] = []
        unresolved_services: List[str] = []
        unresolved_applications: List[str] = []

        def resolve_members(values: List[str], namespace: str, builtins: set, unresolved: List[str]) -> List[str]:
            rewritten = []
            for value in values:
                if value.lower() in builtins:
                    rewritten.append(value)
                    continue
                resolved = self.resolver.resolve(value, namespace, scope)
                if resolved is None:
                    unresolved.append(value)
                    rewritten.append(value)
                else:
                    rewritten.append(resolved.canonical_name or value)
            return rewritten

        canonical_sources = resolve_members(sources, "address-reference", {"any"}, unresolved_sources)
        canonical_destinations = resolve_members(destinations, "address-reference", {"any"}, unresolved_destinations)
        canonical_services = resolve_members(
            services, "service-reference",
            {"any", "application-default", "service-http", "service-https"},
            unresolved_services,
        )
        recognized_predefined_services = [
            service for service in services if service.lower() in {"service-http", "service-https"}
        ]
        if recognized_predefined_services:
            evidence["pan_recognized_predefined_services"] = recognized_predefined_services
        known_predefined_applications = {
            "ssl", "web-browsing", "dns", "ping", "ssh",
        }
        predefined_references = [
            value for value in applications if value.lower() in known_predefined_applications
        ]
        canonical_applications = resolve_members(
            applications, "application-reference", {"any"},
            unresolved_applications
        )
        if predefined_references:
            evidence["pan_predefined_application_references"] = predefined_references

        canonical_schedule = schedule_source
        unresolved_schedule: List[str] = []
        if schedule_source:
            resolved_schedule = self.resolver.resolve(schedule_source, "schedule", scope)
            if resolved_schedule is None:
                unresolved_schedule.append(schedule_source)
            else:
                canonical_schedule = resolved_schedule.canonical_name or schedule_source

        profile_group = profile_groups[0] if profile_groups else None
        unresolved_profile_group: List[str] = []
        if profile_group:
            resolved_profile = self.resolver.resolve(profile_group, "profile-group", scope)
            if resolved_profile is None:
                unresolved_profile_group.append(profile_group)
            else:
                profile_group = resolved_profile.canonical_name or profile_group

        unresolved_sets = {
            "pan_unresolved_sources": unresolved_sources,
            "pan_unresolved_destinations": unresolved_destinations,
            "pan_unresolved_services": unresolved_services,
            "pan_unresolved_applications": unresolved_applications,
            "pan_unresolved_schedule": unresolved_schedule,
            "pan_unresolved_profile_group": unresolved_profile_group,
        }
        for key, values in unresolved_sets.items():
            if values:
                evidence[key] = values

        partial_reasons: List[str] = []
        for key, values in unresolved_sets.items():
            if values:
                partial_reasons.append(key.removeprefix("pan_").replace("_", "-"))
        if source_action not in {"allow", "deny"}:
            partial_reasons.append("source-action-variant")
        if source_users and source_users != ["any"]:
            partial_reasons.append("source-user")
        if categories:
            partial_reasons.append("category")
        if source_hip:
            partial_reasons.append("source-hip")
        if destination_hip:
            partial_reasons.append("destination-hip")
        if predefined_references:
            partial_reasons.append("predefined-application-reference")
        if negate_source_explicit or negate_destination_explicit:
            partial_reasons.append("address-negation")
        if tags:
            partial_reasons.append("tag")
        if group_tag:
            partial_reasons.append("group-tag")
        if rule_type:
            partial_reasons.append("rule-type")
        if disable_inspect_explicit or disable_server_explicit:
            partial_reasons.append("inspection-flags")
        if icmp_unreachable is not None:
            partial_reasons.append("icmp-unreachable")
        if unknown_option:
            partial_reasons.append("unknown-option-fields")
        if evidence.get("pan_disable_server_response_inspection_conflict"):
            partial_reasons.append("inspection-option-conflict")
        if saas_user_list or saas_tenant_list:
            partial_reasons.append("saas-selectors")
        if direct_profiles:
            partial_reasons.append("security-profiles")
        if profile_group and direct_profiles:
            partial_reasons.append("mixed-profile-assignment")
        if unknown:
            partial_reasons.append("unknown-fields")
        if unknown_profile_setting or unknown_direct_profile_types:
            partial_reasons.append("unknown-profile-fields")
        partial_reasons = list(dict.fromkeys(partial_reasons))

        policy = IRPolicy(
            name=name,
            from_zone=from_zones,
            to_zone=to_zones,
            source=canonical_sources,
            destination=canonical_destinations,
            service=canonical_services,
            applications=canonical_applications,
            action=action_map[source_action],
            source_rule_id=f"palo_alto:{scope.kind}:{scope.name}:{rulebase_position}:{source_rule_index}:{name}",
            source_address_references=sources,
            destination_address_references=destinations,
            source_service_references=services,
            source_address_negate_setting=negate_source_value if negate_source_explicit else None,
            destination_address_negate_setting=negate_destination_value if negate_destination_explicit else None,
            source_action=source_action,
            source_schedule=schedule_source,
            source_users=source_users,
            identity_dependency_review=bool(source_users and source_users != ["any"]),
            source_log_setting=log_setting,
            source_log_start_setting=log_start_value if log_start_explicit else None,
            source_profile_type="group" if profile_group and not direct_profiles else ("profiles" if direct_profiles and not profile_group else "mixed" if profile_group else None),
            source_profile_group=profile_groups[0] if profile_groups else None,
            source_extra_settings=evidence,
            migration_status="PARTIALLY_NORMALIZED" if partial_reasons else "NORMALIZED",
            review_reasons=partial_reasons,
            requires_manual_review=bool(partial_reasons),
            description=description,
            schedule=canonical_schedule,
            log_start=log_start,
            log_end=log_end,
            disabled=disabled,
            security_profile_group=profile_group,
            antivirus=direct_profiles.get("virus", [None])[0],
            ips_sensor=direct_profiles.get("vulnerability", [None])[0],
            webfilter=direct_profiles.get("url-filtering", [None])[0],
            unresolved_security_profiles=unresolved_profile_group,
            security_profile_semantics_review=bool(direct_profiles or unresolved_profile_group),
        )
        extraction.canonical_ir.policies.append(policy)
        if partial_reasons:
            record_partial(
                extraction, "policies", source_path, scope, name, evidence,
                notes=[f"PAN-OS security rule requires review: {', '.join(partial_reasons)}."],
            )
        else:
            record_normalized(extraction, "policies", source_path, scope, name, evidence)

    def _parse_rules(self, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult):
        ir = extraction.canonical_ir

        # 7. Security Policies
        self._parse_security_rules(scope, search_root, extraction)

        # 8. NAT Rules -- preserve local/pre/post provenance independently.
        nat_paths = [
            ("pre", "./pre-rulebase/nat/rules/entry", "pre-rulebase"),
            ("local", "./rulebase/nat/rules/entry", "rulebase"),
            ("post", "./post-rulebase/nat/rules/entry", "post-rulebase"),
        ]
        for position, path, prefix in nat_paths:
            entries = search_root.findall(path)
            normalized_count = 0
            parsed_count = 0
            for source_index, entry in enumerate(entries):
                rule, status, evidence, notes = PANNatRuleExtractor.extract_rule(
                    entry, scope, self.resolver, position, source_index, prefix
                )
                name = entry.get("name")
                source_path = evidence.get("pan_source_path", f"{prefix}/nat/rules/entry")
                if rule is not None:
                    ir.nat_rules.append(rule)
                    parsed_count += 1
                if status == "NORMALIZED":
                    normalized_count += 1
                    record_normalized(extraction, "nat", source_path, scope, name, evidence, notes)
                elif status == "PARTIALLY_NORMALIZED":
                    record_partial(extraction, "nat", source_path, scope, name, evidence, notes)
                elif status == "EXTRACT_ONLY":
                    record_extract_only(extraction, "nat", source_path, scope, name, evidence, notes)
                elif status == "PARSE_ERROR":
                    record_parse_error(extraction, "nat", source_path, scope, name, evidence, notes)
                else:
                    record_unsupported(extraction, "nat", source_path, scope, name, evidence, notes)
            if entries:
                section_status = (
                    ExtractionStatus.NORMALIZED if normalized_count == len(entries)
                    else ExtractionStatus.PARTIALLY_NORMALIZED
                )
                add_source_section(
                    extraction, f"{prefix}/nat/rules", section_status,
                    len(entries), parsed_count, normalized_count,
                    "PANNatRuleExtractor.extract_rule",
                    source_context=f"{scope.kind}:{scope.name}",
                )

        # 9. Path-level policy and scope residual accounting.
        PANResidualExtractor.extract_policy_residuals(scope, search_root, extraction)
        PANResidualExtractor.extract_scope_residuals(scope, search_root, extraction)

    def parse(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> IRConfig:
        return self.extract(content, zone_mapping).canonical_ir
