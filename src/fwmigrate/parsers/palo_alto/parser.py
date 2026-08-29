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
from .nat import PANNatRuleExtractor, PANSourceTranslation, PANDestinationTranslation
from .routing import PANRouteExtractor
from .extraction import record_partial, record_extract_only, record_normalized, record_parse_error
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
        return [".xml", ".txt", ".conf"]

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

        # Find all scopes: shared, vsys, device-group
        
        # Pass 1: Objects
        devices = root.findall(".//devices/entry")
        for dev in devices:
            dev_name = dev.get("name") or "localhost.localdomain"
            dev_scope = PANScope(kind="device", name=dev_name)
            
            network_elem = dev.find("./network")
            if network_elem is not None:
                self._parse_network(extraction, ir, dev_scope, network_elem)

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
                # If there are unresolved PAN semantics, it would be marked PARTIALLY_NORMALIZED
                if "pan_ipv4_addresses" in source_obj.attributes and len(source_obj.attributes["pan_ipv4_addresses"]) > 1:
                    record_partial(extraction, domain="interfaces", source_path=source_obj.source_path, scope=source_obj.scope, name=intf.name, notes=["Multiple IPv4 addresses on interface not canonicalized."])
                elif "pan_ipv6_addresses" in source_obj.attributes:
                    record_partial(extraction, domain="interfaces", source_path=source_obj.source_path, scope=source_obj.scope, name=intf.name, notes=["IPv6 addresses on interface not canonicalized."])
                else:
                    record_normalized(extraction, domain="interfaces", source_path=source_obj.source_path, scope=source_obj.scope, name=intf.name)
        extraction.canonical_ir = ir
        return extraction

    def _parse_l3_interface_node(self, config_node: ET.Element, interface_name: str, interface_type: str, parent: Optional[str], scope: PANScope) -> tuple[IRInterface, dict]:
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
                # Can collect more attributes inside if present
                v6_attrs = {"address": addr}
                enable_elem = ipv6_elem.find("enable")
                if enable_elem is not None and enable_elem.text:
                    v6_attrs["enable"] = enable_elem.text.strip()
                all_ipv6.append(v6_attrs)
        if all_ipv6:
            source_attrs["pan_ipv6_addresses"] = all_ipv6

        # Description
        desc_elem = config_node.find("./comment")
        desc = desc_elem.text if desc_elem is not None else None
        
        # Management profile
        mgmt_elem = config_node.find("./interface-management-profile")
        mgmt_prof = mgmt_elem.text if mgmt_elem is not None else None
        
        # Explicit status
        status_kwargs = {}
        state_elem = config_node.find("./link-state")
        if state_elem is not None and state_elem.text:
            source_attrs["status_explicit"] = True
            status_kwargs["status"] = (state_elem.text.strip().lower() != "down")
        else:
            source_attrs["status_explicit"] = False
            
        # Addressing mode
        addr_mode = None
        if config_node.find("./dhcp-client") is not None:
            addr_mode = "dhcp-client"
        elif config_node.find("./pppoe") is not None:
            addr_mode = "pppoe"
        elif all_ipv4:
            addr_mode = "static"
            
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
            **status_kwargs
        )
        return ir_intf, source_attrs

    def _parse_network(self, extraction: ExtractionResult, ir: IRConfig, scope: PANScope, network_root: ET.Element):
        intfs_root = network_root.find("./interface")
        if intfs_root is None:
            return

        # Explicitly support physical and subinterfaces
        families = [
            ("ethernet", "./ethernet/entry", True),
            ("aggregate-ethernet", "./aggregate-ethernet/entry", True),
            ("loopback", "./loopback/units/entry", False),
            ("tunnel", "./tunnel/units/entry", False),
            ("vlan", "./vlan/units/entry", False)
        ]
        
        for family_type, path, has_layer3 in families:
            for i_entry in intfs_root.findall(path):
                i_name = i_entry.get("name")
                if not i_name: continue
                
                # For physical interfaces, we look at layer3
                # For logical interfaces, the entry itself is the node
                
                if has_layer3:
                    l3_node = i_entry.find("./layer3")
                    if l3_node is not None:
                        ir_intf, source_attrs = self._parse_l3_interface_node(l3_node, i_name, family_type, None, scope)
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
        for family_type in ["loopback", "tunnel", "vlan"]:
            for i_entry in intfs_root.findall(f"./{family_type}/entry"):
                i_name = i_entry.get("name")
                if not i_name: continue
                # if already parsed via units/entry, skip
                if any(i.name == i_name for i in ir.interfaces): continue
                
                ir_intf, source_attrs = self._parse_l3_interface_node(i_entry, i_name, family_type, None, scope)
                ir.interfaces.append(ir_intf)
                self.resolver.register_object(PANSourceObject(name=i_name, kind='interface', domain='interface', source_path=f"network/interface/{family_type}/entry[@name='{i_name}']", scope=scope, attributes=source_attrs, ir_object=ir_intf), "interface")

    def _parse_objects(self, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult):
        ir = extraction.canonical_ir
        
        # 2. Zones
        for z_entry in search_root.findall("./zone/entry"):
            z_name = z_entry.get("name")
            if not z_name: continue
            
            intfs = []
            zone_type = None
            
            for n_type in ["layer3", "layer2", "virtual-wire", "tap", "tunnel"]:
                type_members = [m.text for m in z_entry.findall(f".//network/{n_type}/member") if m.text]
                if type_members:
                    zone_type = n_type
                    intfs.extend(type_members)
                    
            source_attrs = {}
            if zone_type:
                source_attrs["pan_zone_type"] = zone_type
                
            ir_zone = IRZone(name=z_name, interfaces=intfs)
            ir.zones.append(ir_zone)
            
            zone_issues = []
            
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
                record_partial(
                    extraction, domain="zones",
                    source_path=f"zone/entry[@name='{z_name}']",
                    scope=scope, name=z_name, notes=zone_issues
                )
            else:
                record_normalized(
                    extraction, domain="zones",
                    source_path=f"zone/entry[@name='{z_name}']",
                    scope=scope, name=z_name
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
                continue
            v_members = [m.text for m in pg_entry.findall(".//virus/member") if m.text]
            vuln_members = [m.text for m in pg_entry.findall(".//vulnerability/member") if m.text]
            spy_members = [m.text for m in pg_entry.findall(".//spyware/member") if m.text]
            url_members = [m.text for m in pg_entry.findall(".//url-filtering/member") if m.text]
            fb_members = [m.text for m in pg_entry.findall(".//file-blocking/member") if m.text]
            wf_members = [m.text for m in pg_entry.findall(".//wildfire-analysis/member") if m.text]

            ir.security_profile_groups.append(IRSecurityProfileGroup(
                name=pg_name,
                antivirus=v_members[0] if v_members else None,
                vulnerability=vuln_members[0] if vuln_members else None,
                anti_spyware=spy_members[0] if spy_members else None,
                url_filtering=url_members[0] if url_members else None,
                file_blocking=fb_members[0] if fb_members else None,
                wildfire=wf_members[0] if wf_members else None
            ))

    def _parse_rules(self, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult):
        ir = extraction.canonical_ir

        # 7. Security Policies
        rules_paths = ["./rulebase/security/rules/entry", "./pre-rulebase/security/rules/entry", "./post-rulebase/security/rules/entry"]
        for path in rules_paths:
            for p_entry in search_root.findall(path):
                p_name = p_entry.get("name")
                if not p_name:
                    continue

                from_zones = [m.text for m in p_entry.findall(".//from/member") if m.text]
                to_zones = [m.text for m in p_entry.findall(".//to/member") if m.text]
                sources = [m.text for m in p_entry.findall(".//source/member") if m.text]
                destinations = [m.text for m in p_entry.findall(".//destination/member") if m.text]
                applications = [m.text for m in p_entry.findall(".//application/member") if m.text]
                services = [m.text for m in p_entry.findall(".//service/member") if m.text]

                act_elem = p_entry.find("action")
                act_text = act_elem.text.strip().lower() if act_elem is not None and act_elem.text else None
                action = PolicyAction.DENY if act_text in ["deny", "drop", "reset-client", "reset-server", "reset-both"] else (PolicyAction.ALLOW if act_text else None)

                # Safety check
                if not action:
                    record_partial(
                        extraction, domain="policies", 
                        source_path=f"rulebase/security/rules/entry[@name='{p_name}']", 
                        scope=scope, name=p_name, notes=["Missing required action"]
                    )
                    continue

                if not from_zones or not to_zones or not sources or not destinations:
                    record_partial(
                        extraction, domain="policies", 
                        source_path=f"rulebase/security/rules/entry[@name='{p_name}']", 
                        scope=scope, name=p_name, notes=["Missing required fields"]
                    )
                    continue

                desc_elem = p_entry.find("description")
                desc = desc_elem.text if desc_elem is not None else None

                disabled_elem = p_entry.find("disabled")
                disabled = (disabled_elem is not None and disabled_elem.text and disabled_elem.text.strip().lower() == "yes")

                log_end_elem = p_entry.find(".//log-end")
                log_end = (log_end_elem is None or (log_end_elem.text and log_end_elem.text.strip().lower() == "yes"))

                log_start_elem = p_entry.find(".//log-start")
                log_start = (log_start_elem is not None and log_start_elem.text and log_start_elem.text.strip().lower() == "yes")

                spg_elem = p_entry.find(".//profile-setting/group/member")
                spg_name = spg_elem.text.strip() if spg_elem is not None and spg_elem.text else None

                sched_elem = p_entry.find(".//schedule")
                sched = sched_elem.text.strip() if sched_elem is not None and sched_elem.text else None
                
                missing_refs = []
                for s in sources:
                    if s not in ("any",) and not self.resolver.resolve(s, "address-reference", scope):
                        missing_refs.append(s)
                for d in destinations:
                    if d not in ("any",) and not self.resolver.resolve(d, "address-reference", scope):
                        missing_refs.append(d)
                for svc in services:
                    if svc not in ("any", "application-default") and not self.resolver.resolve(svc, "service-reference", scope):
                        missing_refs.append(svc)
                        
                sources = [self.resolver.canonical_name_for(s, "address-reference", scope) or s for s in sources]
                destinations = [self.resolver.canonical_name_for(d, "address-reference", scope) or d for d in destinations]
                services = [self.resolver.canonical_name_for(svc, "service-reference", scope) or svc for svc in services]
                
                pol = IRPolicy(
                    name=p_name, from_zone=from_zones, to_zone=to_zones, source=sources, destination=destinations,
                    applications=applications, service=services, action=action, description=desc, disabled=disabled,
                    schedule=sched, log_end=log_end, log_start=log_start, security_profile_group=spg_name
                )
                
                if missing_refs:
                    pol.migration_status = "PARTIALLY_NORMALIZED"
                    pol.requires_manual_review = True
                    pol.review_reasons.append(f"Unresolved references: {', '.join(missing_refs)}")
                    record_partial(
                        extraction, domain="policies",
                        source_path=f"rulebase/security/rules/entry[@name='{p_name}']",
                        scope=scope, name=p_name, notes=[f"Unresolved references: {', '.join(missing_refs)}"]
                    )
                else:
                    record_normalized(
                        extraction, domain="policies",
                        source_path=f"rulebase/security/rules/entry[@name='{p_name}']",
                        scope=scope, name=p_name
                    )
                    
                ir.policies.append(pol)

        # 8. NAT Rules
        paths = ["./rulebase/nat/rules/entry", "./pre-rulebase/nat/rules/entry", "./post-rulebase/nat/rules/entry"]
        for path in paths:
            for n_entry in search_root.findall(path):
                n_name = n_entry.get("name")
                if not n_name: continue
                
                from_z = [m.text for m in n_entry.findall(".//from/member") if m.text]
                to_z = [m.text for m in n_entry.findall(".//to/member") if m.text]
                src = [m.text for m in n_entry.findall(".//source/member") if m.text]
                dst = [m.text for m in n_entry.findall(".//destination/member") if m.text]
                srv = [m.text for m in n_entry.findall(".//service/member") if m.text]
                
                snat_elem = n_entry.find(".//source-translation")
                dnat_elem = n_entry.find(".//destination-translation")
                dyn_dnat_elem = n_entry.find(".//dynamic-destination-translation")
                
                s_trans = PANNatRuleExtractor.extract_source_translation(snat_elem)
                d_trans = PANNatRuleExtractor.extract_destination_translation(dnat_elem)
                dyn_d_trans = PANNatRuleExtractor.extract_dynamic_destination_translation(dyn_dnat_elem)
                
                if not s_trans and not d_trans and not dyn_d_trans:
                    record_extract_only(
                        extraction, domain="nat",
                        source_path=f"nat/rules/entry[@name='{n_name}']",
                        scope=scope, name=n_name,
                        notes=["NAT rule has no translation"]
                    )
                    continue
                
                # Determine NAT type
                nat_type = NATType.SOURCE
                if s_trans and (d_trans or dyn_d_trans):
                    nat_type = NATType.TWICE
                elif d_trans or dyn_d_trans:
                    nat_type = NATType.DESTINATION
                    
                nat_rule = IRNATRule(
                    name=n_name, type=nat_type, from_zone=from_z, to_zone=to_z, 
                    source=src, destination=dst, services=srv
                )
                
                if s_trans and s_trans.translated_address:
                    nat_rule.translated_sources = [self.resolver.canonical_name_for(a, "address-reference", scope) or a for a in s_trans.translated_address]
                if d_trans and d_trans.translated_address:
                    nat_rule.translated_destinations = [self.resolver.canonical_name_for(d_trans.translated_address, "address-reference", scope) or d_trans.translated_address]
                    
                ir.nat_rules.append(nat_rule)
                record_normalized(
                    extraction, domain="nat",
                    source_path=f"nat/rules/entry[@name='{n_name}']",
                    scope=scope, name=n_name
                )

        # 9. Static Routes
        PANRouteExtractor.extract_static_routes(scope, search_root, extraction)
        
        # 10. Residual accounting
        PANResidualExtractor.extract_residual_scope(scope, search_root, extraction)

    def parse(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> IRConfig:
        return self.extract(content, zone_mapping).canonical_ir
