from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional

from fwmigrate.core.constants import IR_KEYWORD_ANY, IR_KEYWORD_ANY_IPV4, IR_KEYWORD_ANY_IPV6
from fwmigrate.ir.address import IRAddress, IRAddressGroup
from fwmigrate.ir import IRConfig
from fwmigrate.ir.enums import AddressType, NATTranslationMode, NATType, PolicyAction
from fwmigrate.ir.metadata import IRMetadata
from fwmigrate.ir.network import IRInterface, IRZone
from fwmigrate.ir.nat import IRNATRule
from fwmigrate.ir.policy import IRLocalDeviceAccessRule, IRPolicy
from fwmigrate.ir.routing import IRPolicyRoute, IRRoute
from fwmigrate.ir.service import IRSchedule, IRService, IRServiceGroup
from fwmigrate.vendors.cisco_asa.acl_parser import KNOWN_PROTOCOLS
from fwmigrate.vendors.cisco_asa.model import (
    CiscoAccessRule,
    CiscoNamedGroupMember,
    CiscoServicePort,
)
from fwmigrate.vendors.cisco_asa.net_utils import normalize_ipv4_network
from fwmigrate.vendors.cisco_asa.parser import _nat_port_range, _pbr_acl_match_evidence, _safe_name
from . import audit_fixes as audit
from . import remaining_fixes as remaining
from . import standard_acl_ir_fix as standard_acl


class ASAtoIRTransformer:
    """Transform the parsed Cisco ASA source model into canonical IR."""

    def __init__(self, parser: Any):
        self.parser = parser
        self.config = None

    def transform(self) -> IRConfig:
        self.config = self.parser.parse_raw()
        ir = self._build_ir()
        ir = audit.apply_audit_ir_fixes(ir, self.config)
        ir = standard_acl.apply_standard_acl_ir_fixes(ir, self.config)
        return remaining.apply_remaining_nat_fixes(ir, self.config)

    def _build_ir(self) -> IRConfig:
        cfg = self.config
        ir = IRConfig(metadata=IRMetadata(hostname=cfg.hostname, source_vendor="cisco_asa", source_product="Cisco ASA"))

        explicit_zones: Dict[tuple[Optional[str], str], IRZone] = {
            (zone.source_context, zone.name): IRZone(
                name=zone.name, source_context=zone.source_context,
                interfaces=list(dict.fromkeys(zone.members)),
                source_attributes={"raw_lines": zone.raw_lines},
            )
            for zone in cfg.traffic_zones
        }
        for interface in cfg.interfaces:
            configured_zones = list(interface.traffic_zone_members)
            configured_zones.extend(
                zone.name for zone in cfg.traffic_zones
                if interface.name in zone.members and zone.name not in configured_zones
            )
            mapped_zone = self.parser.zone_mapping.get(interface.name) or self.parser.zone_mapping.get(interface.nameif or "")
            if mapped_zone and not configured_zones:
                configured_zones.append(mapped_zone)
            zone = configured_zones[0] if configured_zones else None
            for zone_name in configured_zones:
                ir_zone = explicit_zones.setdefault(
                    (interface.source_context, zone_name),
                    IRZone(name=zone_name, source_context=interface.source_context),
                )
                if interface.name not in ir_zone.interfaces:
                    ir_zone.interfaces.append(interface.name)
            ip_value = normalize_ipv4_network(interface.ip or "", interface.mask or "") if interface.ip_mode == "static" else None
            parse_errors = []
            if interface.ip_mode == "static" and ip_value is None:
                parse_errors.append(f"Invalid IPv4 address/netmask: {interface.ip or ''} {interface.mask or ''}".strip())
            ir.interfaces.append(IRInterface(
                name=interface.name, source_context=interface.source_context, zone=zone, ip=ip_value, description=interface.description,
                status=not interface.shutdown, addressing_mode=interface.ip_mode,
                interface_type=interface.interface_type, parent=interface.parent_interface,
                vlanid=interface.vlan_id, mtu=interface.mtu, members=interface.redundant_interface_members,
                dhcp_client=True if interface.ip_mode == "dhcp" else None,
                ipv6_source_settings={
                    "addresses": [item.model_dump() for item in interface.ipv6_addresses],
                    "autoconfig": interface.ipv6_autoconfig,
                    "dhcp": interface.ipv6_dhcp,
                    "dhcp_setroute": interface.ipv6_dhcp_setroute,
                },
                requires_manual_review=interface.requires_manual_review or bool(parse_errors),
                parse_errors=parse_errors, source_attributes={
                    **interface.source_attributes,
                    "nameif": interface.nameif,
                    "security_level": interface.security_level,
                    "standby_ip": interface.standby_ip,
                    "dhcp_setroute": interface.dhcp_setroute,
                    "management_only": interface.management_only,
                    "interface_type": interface.interface_type,
                    "parent_interface": interface.parent_interface,
                    "vlan_id": interface.vlan_id,
                    "interface_suffix_vlan_id": interface.interface_suffix_vlan_id,
                    "secondary_vlan_ids": interface.secondary_vlan_ids,
                    "secondary_vlan_ranges": interface.secondary_vlan_ranges,
                    "port_channel_id": interface.port_channel_id,
                    "channel_group": interface.channel_group,
                    "channel_group_mode": interface.channel_group_mode,
                    "redundant_interface_members": interface.redundant_interface_members,
                    "bridge_group": interface.bridge_group,
                    "bvi_id": interface.bvi_id,
                    "routing_context": interface.routing_context,
                    "vrf": interface.vrf,
                    "administrative_state": interface.administrative_state,
                    "administrative_state_explicit": interface.administrative_state_explicit,
                    "administrative_state_effective": interface.administrative_state_effective,
                    "policy_route_maps": interface.policy_route_maps,
                    "tunnel_source": interface.tunnel_source,
                    "tunnel_destination": interface.tunnel_destination,
                    "ipsec_profile": interface.ipsec_profile,
                    "traffic_zone_members": interface.traffic_zone_members,
                    "raw_lines": interface.raw_lines,
                },
                migration_status=interface.migration_status,
            ))
        ir.zones = list(explicit_zones.values())

        inline_addresses: Dict[tuple[Optional[str], str], IRAddress] = {}
        for obj in cfg.network_objects:
            if obj.type is None or obj.value is None:
                continue
            kwargs = dict(
                name=obj.name, source_context=obj.source_context, description=obj.description, source_type=obj.type,
                address_family=obj.address_family,
                source_attributes={**obj.source_attributes, "raw_lines": obj.raw_lines},
                migration_status=obj.migration_status, requires_manual_review=obj.requires_manual_review,
            )
            if obj.type == "host":
                kwargs.update(type=AddressType.HOST, subnet=obj.value, is_ipv6=obj.address_family == "ipv6")
            elif obj.type == "subnet":
                kwargs.update(type=AddressType.NETWORK, subnet=obj.value, is_ipv6=obj.address_family == "ipv6")
            elif obj.type == "range":
                start, end = obj.value.split("-", 1)
                kwargs.update(type=AddressType.RANGE, ip_range_start=start, ip_range_end=end, is_ipv6=obj.address_family == "ipv6")
            else:
                kwargs.update(type=AddressType.FQDN, fqdn=obj.value)
            ir.addresses.append(IRAddress(**kwargs))

        for group in cfg.network_groups:
            for entry in group.member_entries:
                if entry.type == "host":
                    name = _safe_name("asa_inline_host", entry.value)
                    inline_addresses[(group.source_context, name)] = IRAddress(
                        name=name, source_context=group.source_context, type=AddressType.HOST, subnet=entry.value, raw_value=entry.raw,
                        address_family=entry.address_family, is_ipv6=entry.address_family == "ipv6",
                    )
                elif entry.type == "inline_network":
                    name = _safe_name("asa_inline_net", entry.value)
                    inline_addresses[(group.source_context, name)] = IRAddress(
                        name=name, source_context=group.source_context, type=AddressType.NETWORK, subnet=entry.value, raw_value=entry.raw,
                        address_family=entry.address_family, is_ipv6=entry.address_family == "ipv6",
                    )
            ir.address_groups.append(IRAddressGroup(
                name=group.name, source_context=group.source_context, members=group.members, description=group.description,
                migration_status=group.migration_status, requires_manual_review=group.requires_manual_review,
                address_family=group.address_family,
                source_attributes={
                    **group.source_attributes, "raw_lines": group.raw_lines,
                    "review_reasons": list(group.review_reasons),
                    "member_entries": [entry.model_dump() for entry in group.member_entries],
                },
            ))

        for obj in cfg.service_objects:
            ports, errors = self.parser._ir_service_ports(obj.ports)
            if not ports:
                continue
            ir.services.append(IRService(
                name=obj.name, source_context=obj.source_context, ports=ports, description=obj.description,
                source_protocol=obj.ports[0].protocol if len({item.protocol for item in obj.ports}) == 1 else None,
                source_protocol_number=int(obj.ports[0].protocol) if len(obj.ports) == 1 and obj.ports[0].protocol.isdigit() else None,
                source_attributes={**obj.source_attributes, "raw_lines": obj.raw_lines},
                migration_status="PARTIALLY_NORMALIZED" if errors else obj.migration_status,
                requires_manual_review=obj.requires_manual_review or bool(errors),
                audit_note="; ".join(errors) or None,
            ))

        for group in cfg.service_groups:
            members = list(group.members)
            if group.service_objects:
                name = _safe_name("asa_group_service", group.name)
                ports, errors = self.parser._ir_service_ports(group.service_objects)
                if ports:
                    ir.services.append(IRService(
                        name=name, source_context=group.source_context, ports=ports, description=f"Inline services for {group.name}",
                        source_protocol=group.protocol,
                        migration_status="PARTIALLY_NORMALIZED" if errors else group.migration_status,
                        requires_manual_review=group.requires_manual_review or bool(errors),
                        audit_note="; ".join(errors) or None,
                        source_attributes={**group.source_attributes, "raw_lines": group.raw_lines},
                    ))
                    members.append(name)
            ir.service_groups.append(IRServiceGroup(
                name=group.name, source_context=group.source_context, members=members, description=group.description,
                migration_status=group.migration_status, requires_manual_review=group.requires_manual_review,
                source_attributes={"protocol": group.protocol, **group.source_attributes, "raw_lines": group.raw_lines,
                                   "member_entries": [entry.model_dump() for entry in group.member_entries],
                                   "review_reasons": list(group.review_reasons)},
            ))

        for group in [*cfg.protocol_groups, *cfg.icmp_type_groups]:
            members: List[str] = []
            entries = group.member_entries or [CiscoNamedGroupMember(
                type="protocol" if group.group_type == "protocol" else "icmp_type",
                value=raw.split()[1], raw=raw, resolved=True,
            ) for raw in group.members if len(raw.split()) >= 2]
            for entry in entries:
                raw = entry.raw
                parts = raw.split()
                if entry.type in {"protocol", "icmp_type"}:
                    value = entry.value
                    service_name = _safe_name(f"asa_{group.group_type}", f"{group.name}:{value}")
                    protocol_value = value if group.group_type == "protocol" else "icmp"
                    source_port = CiscoServicePort(
                        protocol=protocol_value,
                        icmp_type=value if group.group_type == "icmp-type" else None,
                        raw=raw,
                    )
                    ports, errors = self.parser._ir_service_ports([source_port])
                    if ports:
                        ir.services.append(IRService(
                            name=service_name, source_context=group.source_context, ports=ports, source_protocol=protocol_value,
                            source_protocol_number=int(value) if value.isdigit() and group.group_type == "protocol" else None,
                            migration_status="PARTIALLY_NORMALIZED", requires_manual_review=True,
                            audit_note="; ".join(errors) or f"ASA {group.group_type} member requires target review",
                            source_attributes={"raw_line": raw, "owning_group": group.name},
                        ))
                        members.append(service_name)
                elif entry.type in {"protocol_group", "icmp_group"}:
                    members.append(entry.value)
            ir.service_groups.append(IRServiceGroup(
                name=group.name, source_context=group.source_context, members=members, unsafe_members=list(members),
                description=group.description, migration_status="PARTIALLY_NORMALIZED",
                requires_manual_review=True,
                source_attributes={"group_type": group.group_type, "raw_lines": group.raw_lines,
                                   "member_entries": [entry.model_dump() for entry in group.member_entries],
                                   "review_reasons": list(group.review_reasons)},
            ))

        for schedule in cfg.time_ranges:
            first = schedule.clauses[0] if schedule.clauses else None
            ir.schedules.append(IRSchedule(
                name=schedule.name, source_context=schedule.source_context,
                start=first.start if first else None,
                end=first.end if first else None,
                days=first.days if first else [],
                schedule_type=first.clause_type if first else "source-only",
                windows=[{
                    "type": clause.clause_type, "start": clause.start, "end": clause.end,
                    "days": clause.days, "end_days": clause.end_days,
                    "source_order": clause.source_order, "raw": clause.raw,
                } for clause in schedule.clauses],
                source_attributes={
                    "clauses": [item.model_dump() for item in schedule.clauses],
                    "raw_lines": schedule.raw_lines,
                    "migration_status": schedule.migration_status,
                    "requires_manual_review": schedule.requires_manual_review,
                    "review_reasons": schedule.review_reasons,
                },
            ))

        synthetic_services: Dict[tuple[Optional[str], str], IRService] = {}

        def endpoint_reference(rule: CiscoAccessRule, source: bool) -> List[str]:
            endpoint = rule.source_endpoint if source else rule.destination_endpoint
            if endpoint is None or not endpoint.valid or endpoint.value is None:
                return []
            if endpoint.type == "any":
                if endpoint.value == "any4":
                    rule.requires_manual_review = True
                    rule.migration_status = "PARTIALLY_NORMALIZED"
                    rule.review_reasons.append("IPv4-only universal address requires family-aware target support")
                    return [IR_KEYWORD_ANY_IPV4]
                if endpoint.value == "any6":
                    rule.requires_manual_review = True
                    rule.migration_status = "PARTIALLY_NORMALIZED"
                    rule.review_reasons.append("IPv6-only universal address requires family-aware target support")
                    return [IR_KEYWORD_ANY_IPV6]
                return [IR_KEYWORD_ANY]
            if endpoint.type in {"inline", "host"}:
                value = endpoint.value
                if endpoint.type == "host" and "/" not in value:
                    value = f"{value}/128" if ":" in value else f"{value}/32"
                prefix = "asa_inline_host" if endpoint.type == "host" or "/32" in value or "/128" in value else "asa_inline_net"
                name = _safe_name(prefix, value)
                addr_type = AddressType.HOST if prefix.endswith("host") else AddressType.NETWORK
                inline_addresses[(rule.source_context, name)] = IRAddress(
                    name=name, type=addr_type, subnet=value, raw_value=endpoint.raw,
                    address_family=endpoint.address_family, is_ipv6=endpoint.address_family == "ipv6",
                )
                return [name]
            if endpoint.type in {"interface", "object-group-network-service"}:
                rule.requires_manual_review = True
                rule.migration_status = "PARTIALLY_NORMALIZED"
                reason = (
                    "Interface-address endpoint cannot be converted safely" if endpoint.type == "interface"
                    else "Network-service endpoint is retained as a combined address/service selector"
                )
                if reason not in rule.review_reasons:
                    rule.review_reasons.append(reason)
                return [endpoint.value] if endpoint.type == "object-group-network-service" else []
            return [endpoint.value]

        def service_reference(rule: CiscoAccessRule) -> List[str]:
            if rule.protocol in {"object", "object-group"} and rule.protocol_object:
                return [rule.protocol_object]
            if rule.icmp_object_group:
                return [rule.icmp_object_group]
            if rule.destination_port and rule.destination_port.operator in {"object", "object-group"}:
                rule.requires_manual_review = True
                rule.migration_status = "PARTIALLY_NORMALIZED"
                rule.review_reasons.append("Referenced ACL port object/group requires target service validation")
                return [rule.destination_port.object_name] if rule.destination_port.object_name else []
            if rule.source_port and rule.source_port.operator in {"object", "object-group"}:
                rule.requires_manual_review = True
                rule.migration_status = "PARTIALLY_NORMALIZED"
                rule.review_reasons.append("Source-port object/group relationship is source-preserved")
                return []
            if rule.protocol == "ip" and not rule.destination_port and not rule.source_port:
                return [IR_KEYWORD_ANY]
            if (rule.protocol or "").lower() not in KNOWN_PROTOCOLS and not (rule.protocol or "").isdigit():
                return []
            port_model = CiscoServicePort(
                protocol=rule.protocol or "", source=rule.source_port, destination=rule.destination_port,
                icmp_type=rule.icmp_type, icmp_code=rule.icmp_code, raw=rule.raw_line,
            )
            ports, errors = self.parser._ir_service_ports([port_model])
            if not ports:
                rule.requires_manual_review = True
                rule.migration_status = "PARTIALLY_NORMALIZED"
                rule.review_reasons.extend(errors)
                return []
            expression = f"{rule.protocol}:{rule.source_port.raw if rule.source_port else '*'}:{rule.destination_port.raw if rule.destination_port else '*'}:{rule.icmp_type or ''}"
            name = _safe_name("asa_inline_service", expression)
            if errors:
                rule.requires_manual_review = True
                rule.migration_status = "PARTIALLY_NORMALIZED"
                rule.review_reasons.extend(errors)
            source_protocol = rule.protocol or ""
            synthetic_services[(rule.source_context, name)] = IRService(
                name=name, source_context=rule.source_context, ports=ports,
                source_protocol=source_protocol,
                source_protocol_number=int(source_protocol) if source_protocol.isdigit() else None,
                migration_status="PARTIALLY_NORMALIZED" if errors else "NORMALIZED",
                requires_manual_review=bool(errors), audit_note="; ".join(errors) or None,
                source_attributes={"source_expression": expression},
            )
            return [name]

        def add_local_device_rule(
            *, name: str, source_order: int, action: Optional[str], interface: Optional[str],
            source: List[str], destination: Optional[List[str]] = None,
            service: Optional[List[str]] = None, protocol: Optional[str] = None,
            source_attributes: Optional[Dict[str, Any]] = None,
            migration_status: str = "PARTIALLY_NORMALIZED",
            requires_manual_review: bool = False,
            review_reasons: Optional[List[str]] = None,
        ) -> None:
            attrs = dict(source_attributes or {})
            attrs.update({
                "action": action, "intf": interface, "srcaddr": source,
                "dstaddr": destination or [], "service": service or [], "protocol": protocol,
            })
            ir.local_in_policies.append(IRLocalDeviceAccessRule(
                family="cisco-asa-local-device-access", name=name, source_id=name,
                source_order=source_order, source_context=cfg.system_settings.source_context,
                enabled=True, effective_action=action, interface=interface,
                source=source, destination=destination or [], service=service or [],
                protocol=protocol, action=action, source_attributes=attrs,
                migration_status=migration_status, requires_manual_review=requires_manual_review,
                review_reasons=review_reasons or [],
            ))

        for item in cfg.management_access_rules:
            source = []
            if item.source and item.mask_or_prefix:
                normalized = normalize_ipv4_network(item.source, item.mask_or_prefix)
                source = [normalized or f"{item.source} {item.mask_or_prefix}"]
            add_local_device_rule(
                name=item.name, source_order=item.source_order, action="permit",
                interface=item.interface, source=source, service=[item.protocol], protocol=item.protocol,
                source_attributes={"origin": "asa-management-command", "raw_line": item.raw_line, "port": item.port},
                migration_status=item.migration_status, requires_manual_review=item.requires_manual_review,
                review_reasons=list(item.review_reasons),
            )
        if cfg.system_settings.management_access_interface:
            add_local_device_rule(
                name="management-access", source_order=0, action="permit",
                interface=cfg.system_settings.management_access_interface, source=[IR_KEYWORD_ANY],
                service=["management-access"], protocol="management-access",
                source_attributes={"origin": "asa-management-access", "raw_lines": cfg.system_settings.raw_lines},
            )
        for item in cfg.icmp_management_rules:
            add_local_device_rule(
                name=item.name, source_order=item.source_order, action=item.action,
                interface=item.interface, source=[item.source] if item.source else [],
                service=[item.icmp_type or "icmp"], protocol="icmp",
                source_attributes={"origin": "asa-icmp-management", "raw_line": item.raw_line, "icmp_type": item.icmp_type},
                migration_status=item.migration_status, requires_manual_review=item.requires_manual_review,
                review_reasons=list(item.review_reasons),
            )

        bindings: Dict[tuple[Optional[str], str], List] = {}
        for binding in cfg.acl_bindings:
            bindings.setdefault((binding.source_context, binding.acl_name), []).append(binding)
        interface_zones: Dict[tuple[Optional[str], str], str] = {}
        for interface in cfg.interfaces:
            zone_names = list(interface.traffic_zone_members)
            zone_names.extend(
                zone.name for zone in cfg.traffic_zones
                if interface.name in zone.members and zone.name not in zone_names
            )
            mapped_zone = self.parser.zone_mapping.get(interface.name) or self.parser.zone_mapping.get(interface.nameif or "")
            if mapped_zone and not zone_names:
                zone_names.append(mapped_zone)
            for zone_name in zone_names:
                interface_zones[(interface.source_context, interface.name)] = zone_name
                if interface.nameif:
                    interface_zones[(interface.source_context, interface.nameif)] = zone_name

        rules_by_acl: Dict[tuple[Optional[str], str], List[CiscoAccessRule]] = {}
        acl_order: List[tuple[Optional[str], str]] = []
        for rule in cfg.access_rules:
            key = (rule.source_context, rule.acl_name)
            if key not in rules_by_acl:
                acl_order.append(key)
            rules_by_acl.setdefault(key, []).append(rule)
        ordered_access_rules: List[CiscoAccessRule] = []
        for acl_key in acl_order:
            acl_rules = rules_by_acl[acl_key]
            sequences = [rule.source_sequence for rule in acl_rules if rule.source_sequence is not None]
            repeated = {sequence for sequence in sequences if sequences.count(sequence) > 1}
            unusual = bool(sequences and sequences != sorted(sequences))
            mixed = bool(sequences and len(sequences) != len(acl_rules))
            ordered = sorted(
                acl_rules,
                key=lambda rule: (
                    rule.source_sequence is None,
                    rule.source_sequence if rule.source_sequence is not None else 0,
                    rule.source_order if rule.source_order is not None else rule.source_line_number or 0,
                ),
            )
            for effective_order, rule in enumerate(ordered, 1):
                rule.effective_source_order = effective_order
                rule.source_attributes.update({
                    "source_order": rule.source_order,
                    "effective_source_order": effective_order,
                })
                ordering_reasons = []
                if rule.source_sequence in repeated:
                    ordering_reasons.append("Repeated ACL sequence number; source order retained as secondary ordering")
                    rule.id = f"{rule.id}_{rule.source_line_number}"
                if unusual:
                    ordering_reasons.append("ACL sequence order differs from source order; sequence order preserved with review")
                if mixed:
                    ordering_reasons.append("ACL mixes sequenced and unsequenced entries")
                for reason in ordering_reasons:
                    if reason not in rule.review_reasons:
                        rule.review_reasons.append(reason)
                if ordering_reasons:
                    rule.requires_manual_review = True
                    if rule.migration_status == "NORMALIZED":
                        rule.migration_status = "PARTIALLY_NORMALIZED"
            ordered_access_rules.extend(ordered)

        for rule in ordered_access_rules:
            rule_bindings = bindings.get((rule.source_context, rule.acl_name)) or []
            # ACL definitions used by crypto, class-map, capture, AAA, or no known
            # consumer are retained in the source model and are not transit rules.
            if not rule_bindings:
                continue
            for binding in rule_bindings:
                from_zone: List[str] = []
                to_zone: List[str] = []
                source_from: List[str] = []
                source_to: List[str] = []
                review = list(rule.review_reasons)
                status = rule.migration_status
                manual = rule.requires_manual_review
                extra = {**rule.source_attributes, "acl_name": rule.acl_name, "raw_line": rule.raw_line}
                suffix = "unbound"
                if binding is not None:
                    suffix = f"{binding.interface or 'global'}_{binding.direction or 'unknown'}"
                    extra.update({
                        "binding_direction": binding.direction, "binding_interface": binding.interface,
                        "global": binding.direction == "global", "control_plane": binding.control_plane,
                        "per_user_override": binding.per_user_override,
                        **binding.source_attributes,
                    })
                    zone = interface_zones.get((binding.source_context, binding.interface or ""))
                    if binding.direction == "in":
                        source_from = [binding.interface] if binding.interface else []
                        from_zone = [zone] if zone else []
                    elif binding.direction == "out":
                        source_to = [binding.interface] if binding.interface else []
                        to_zone = [zone] if zone else []
                    if binding.direction == "global" or binding.control_plane or binding.per_user_override:
                        manual = True
                        status = "EXTRACT_ONLY" if binding.control_plane else "PARTIALLY_NORMALIZED"
                        review.append("ACL binding context cannot be represented as an ordinary transit policy")
                source_refs = endpoint_reference(rule, True)
                if rule.acl_type == "standard":
                    destination_refs = []
                    services = []
                    manual = True
                    status = "PARTIALLY_NORMALIZED"
                    review.append("Standard ACL has no extended protocol, destination, or service operands")
                else:
                    destination_refs = endpoint_reference(rule, False)
                    services = service_reference(rule)
                manual = manual or rule.requires_manual_review
                if rule.migration_status != "NORMALIZED":
                    status = rule.migration_status
                if binding.control_plane:
                    status = "EXTRACT_ONLY"
                review.extend(reason for reason in rule.review_reasons if reason not in review)
                if not source_refs or not destination_refs or not services:
                    manual = True
                    status = "PARSE_ERROR" if status == "NORMALIZED" else status
                    review.append("Policy has unresolved address or service semantics")
                name = f"{rule.id}__{re.sub(r'[^A-Za-z0-9_]+', '_', suffix)}"
                if binding.control_plane:
                    add_local_device_rule(
                        name=name, source_order=rule.source_order or rule.source_line_number or 0,
                        action=rule.action, interface=binding.interface, source=source_refs,
                        destination=destination_refs, service=services, protocol=rule.protocol,
                        source_attributes={**extra, "origin": "asa-control-plane-acl"},
                        migration_status="EXTRACT_ONLY", requires_manual_review=manual,
                        review_reasons=list(dict.fromkeys(review)),
                    )
                    continue
                if rule.time_range:
                    schedule = next((item for item in cfg.time_ranges if item.name == rule.time_range and item.source_context == rule.source_context), None)
                    if schedule is None:
                        manual = True
                        status = "PARTIALLY_NORMALIZED"
                        review.append(f"Schedule '{rule.time_range}' is unresolved")
                    elif schedule.requires_manual_review:
                        manual = True
                        status = "PARTIALLY_NORMALIZED"
                        review.extend(schedule.review_reasons or [f"Schedule '{rule.time_range}' requires review"])
                ir.policies.append(IRPolicy(
                    name=name, source_context=rule.source_context, source_rule_id=rule.id, from_zone=from_zone, to_zone=to_zone,
                    source=source_refs, destination=destination_refs, service=services,
                    action=PolicyAction.ALLOW if rule.action == "permit" else PolicyAction.DENY if rule.action == "deny" else None,
                    source_from_interfaces=source_from, source_to_interfaces=source_to,
                    source_address_references=source_refs, destination_address_references=destination_refs,
                    source_service_references=services, source_action=rule.action,
                    source_schedule=rule.time_range, schedule=rule.time_range,
                    source_users=[rule.user] if rule.user else [], source_user_groups=[rule.user_group] if rule.user_group else [],
                    identity_dependency_review=bool(rule.user or rule.user_group), source_log_setting=rule.log_raw,
                    source_extra_settings=extra | {
                        "source_security_group_type": rule.source_security_group_type,
                        "source_security_group_value": rule.source_security_group_value,
                        "destination_security_group_type": rule.destination_security_group_type,
                        "destination_security_group_value": rule.destination_security_group_value,
                        "icmp_object_group": rule.icmp_object_group,
                    },
                    migration_status=status, review_reasons=list(dict.fromkeys(review)), requires_manual_review=manual,
                    description=rule.remark, disabled=rule.inactive, log_end=rule.log_enabled,
                ))

        ir.addresses.extend(inline_addresses.values())
        ir.services.extend(synthetic_services.values())

        def scoped_names(items: Iterable[Any], source_context: Optional[str]) -> set[str]:
            return {item.name for item in items if item.source_context == source_context}

        def address_names_for(source_context: Optional[str]) -> set[str]:
            network_services = {
                item.name for item in [*cfg.network_service_objects, *cfg.network_service_groups]
                if item.source_context == source_context
            }
            return scoped_names(ir.addresses, source_context) | scoped_names(ir.address_groups, source_context) | network_services | {
                IR_KEYWORD_ANY, IR_KEYWORD_ANY_IPV4, IR_KEYWORD_ANY_IPV6,
            }

        def service_names_for(source_context: Optional[str]) -> set[str]:
            return scoped_names(ir.services, source_context) | scoped_names(ir.service_groups, source_context) | {IR_KEYWORD_ANY}

        def unsafe_names(items: Iterable[Any], source_context: Optional[str]) -> set[str]:
            return {item.name for item in items if item.source_context == source_context and (
                item.requires_manual_review or item.migration_status != "NORMALIZED"
            )}

        address_names = address_names_for(None)
        service_names = service_names_for(None)
        unsafe_addresses = unsafe_names([*ir.addresses, *ir.address_groups], None)
        unsafe_services = unsafe_names([*ir.services, *ir.service_groups], None)
        service_group_by_name = {(group.source_context, group.name): group for group in cfg.service_groups}
        for group in cfg.service_groups:
            group_address_names = service_names_for(group.source_context)
            errors = [
                f"Unresolved service-group reference: {member}"
                for member in group.members if member not in group_address_names
            ]
            visiting: set[str] = set()
            visited: set[str] = set()

            def visit_service(name: str) -> bool:
                if name in visiting:
                    return True
                if name in visited or (group.source_context, name) not in service_group_by_name:
                    return False
                visiting.add(name)
                cyclic = any(visit_service(member) for member in service_group_by_name[(group.source_context, name)].members)
                visiting.remove(name)
                visited.add(name)
                return cyclic

            if visit_service(group.name):
                errors.append("Cyclic nested service-group reference")
            if errors:
                group.migration_status = "PARTIALLY_NORMALIZED"
                group.requires_manual_review = True
                group.source_attributes["reference_validation"] = errors
                ir_group = next(item for item in ir.service_groups if item.name == group.name and item.source_context == group.source_context)
                ir_group.migration_status = group.migration_status
                ir_group.requires_manual_review = True
                ir_group.source_attributes["reference_validation"] = errors

        acl_names = {(rule.source_context, rule.acl_name) for rule in cfg.access_rules}
        for binding in cfg.acl_bindings:
            if (binding.source_context, binding.acl_name) not in acl_names:
                binding.migration_status = "PARTIALLY_NORMALIZED"
                binding.requires_manual_review = True
                binding.review_reasons.append(f"Unresolved ACL reference: {binding.acl_name}")
        for acl_name, consumers in cfg.acl_consumers.items():
            if not any((consumer.get("source_context"), acl_name) in acl_names for consumer in consumers):
                for consumer in consumers:
                    self.parser._record_diagnostic(
                        consumer["line_number"], consumer["raw_line"],
                        f"Unresolved ACL reference: {acl_name}", consumer["consumer_type"],
                        migration_effect="PARTIALLY_NORMALIZED",
                    )
        for policy in ir.policies:
            policy_address_names = address_names_for(policy.source_context)
            policy_service_names = service_names_for(policy.source_context)
            policy_unsafe_addresses = unsafe_names([*ir.addresses, *ir.address_groups], policy.source_context)
            policy_unsafe_services = unsafe_names([*ir.services, *ir.service_groups], policy.source_context)
            unresolved = [ref for ref in policy.source + policy.destination if ref not in policy_address_names]
            unresolved += [ref for ref in policy.service if ref not in policy_service_names]
            if unresolved:
                policy.requires_manual_review = True
                policy.migration_status = "PARTIALLY_NORMALIZED"
                policy.review_reasons.append(f"Unresolved references: {', '.join(sorted(set(unresolved)))}")
            unsafe = set(policy.source + policy.destination).intersection(policy_unsafe_addresses)
            unsafe.update(set(policy.service).intersection(policy_unsafe_services))
            if unsafe:
                policy.requires_manual_review = True
                policy.migration_status = "PARTIALLY_NORMALIZED"
                policy.review_reasons.append(f"References source semantics requiring review: {', '.join(sorted(unsafe))}")

        ordered_nat_rules = sorted(cfg.nat_rules, key=lambda item: item.effective_source_order or 0)
        for index, nat in enumerate(ordered_nat_rules, 1):
            nat_address_names = address_names_for(nat.source_context)
            nat_service_names = service_names_for(nat.source_context)
            source = [nat.real_source] if nat.real_source else []
            # ASA destination twice-NAT is written MAPPED REAL: the first
            # operand matches the original packet and the second is translated.
            destination = [nat.mapped_destination] if nat.mapped_destination else []
            services = [nat.original_service] if nat.original_service else [IR_KEYWORD_ANY] if source else []
            nat_type = NATType.TWICE if nat.destination_mode else NATType.SOURCE
            translated_refs = [ref for ref in [nat.mapped_source, nat.real_destination] if ref and ref != "interface"]
            def unresolved_nat_ref(ref: str) -> bool:
                if ref in nat_address_names or ref in {"any", "interface"}:
                    return False
                try:
                    ipaddress.ip_address(ref)
                    return False
                except ValueError:
                    return True
            service_refs = [ref for ref in [nat.original_service, nat.translated_service] if ref]
            source_ports = _nat_port_range(nat.original_service) if not nat.destination_mode else []
            translated_source_ports = _nat_port_range(nat.translated_service) if not nat.destination_mode else []
            destination_ports = _nat_port_range(nat.original_service) if nat.destination_mode else []
            translated_destination_ports = _nat_port_range(nat.translated_service) if nat.destination_mode else []
            missing_refs = [ref for ref in source + destination + translated_refs if unresolved_nat_ref(ref)]
            missing_services = [ref for ref in service_refs if ref not in nat_service_names and not ref.isdigit()]
            manual = nat.requires_manual_review or bool(missing_refs)
            manual = manual or bool(missing_services)
            status = "PARTIALLY_NORMALIZED" if manual and nat.migration_status == "NORMALIZED" else nat.migration_status
            reasons = list(nat.review_reasons)
            if missing_refs:
                reasons.append(f"Unresolved NAT references: {', '.join(sorted(set(missing_refs)))}")
            if missing_services:
                reasons.append(f"Unresolved NAT service references: {', '.join(sorted(set(missing_services)))}")
            ir.nat_rules.append(IRNATRule(
                name=nat.name, source_context=nat.source_context, type=nat_type, sequence=nat.sequence if nat.sequence is not None else index,
                enabled="inactive" not in nat.options,
                source_from_interfaces=[nat.source_interface] if nat.source_interface else [],
                source_to_interfaces=[nat.destination_interface] if nat.destination_interface else [],
                from_zone=[nat.source_interface] if nat.source_interface else [], to_zone=[nat.destination_interface] if nat.destination_interface else [],
                source=source, destination=destination, services=services,
                source_translation_mode=(
                    NATTranslationMode.INTERFACE_ADDRESS if nat.mapped_source_mode == "interface"
                    else NATTranslationMode.POOL if nat.mapped_source_mode == "pat_pool"
                    else NATTranslationMode.STATIC if nat.source_mode == "static"
                    else NATTranslationMode.DYNAMIC_IP_AND_PORT if nat.source_mode == "dynamic"
                    else None
                ),
                 source_pool_references=[nat.pat_pool] if nat.pat_pool else [],
                 identity=nat.identity_nat, exemption=nat.nat_exemption,
                 original_source_ports=source_ports,
                 translated_source_ports=translated_source_ports,
                 original_destination_ports=destination_ports,
                 translated_destination_ports=translated_destination_ports,
                 protocol_name=nat.service_protocol,
                 source_translation_bidirectional=(
                     not nat.unidirectional if nat.source_mode == "static" else None
                 ),
                 destination_translation_mode=(
                     NATTranslationMode.STATIC if nat.destination_mode == "static" else None
                 ),
                translated_sources=[nat.mapped_source] if nat.mapped_source else [],
                translated_destinations=[nat.real_destination] if nat.real_destination else [],
                translated_services=[nat.translated_service] if nat.translated_service else [],
                source_rule_id=str(nat.sequence or index), source_attributes={
                    **nat.source_attributes,
                    "raw_line": nat.raw_line,
                    "section": nat.section, "syntax_family": nat.syntax_family, "section_order": nat.section_order,
                    "source_sequence": nat.source_sequence,
                    "source_order": nat.source_order,
                    "source_order_within_section": nat.source_order_within_section,
                    "effective_source_order": nat.effective_source_order,
                    "owning_object": nat.owning_object, "source_mode": nat.source_mode,
                    "access_list": nat.access_list, "identity_nat": nat.identity_nat,
                    "nat_exemption": nat.nat_exemption, "object_nat_precedence": nat.object_nat_precedence,
                    "object_nat_specificity": nat.object_nat_specificity,
                    "effective_order_inputs": nat.effective_order_inputs,
                    "mapped_source_mode": nat.mapped_source_mode,
                    "mapped_source_address_family": nat.mapped_source_address_family,
                    "pat_pool": nat.pat_pool, "pat_pool_options": nat.pat_pool_options,
                    "destination_mode": nat.destination_mode,
                    "service_protocol": nat.service_protocol,
                    "service_translation_direction": "destination" if nat.destination_mode else "source" if nat.original_service else None,
                    "dns": nat.dns, "no_proxy_arp": nat.no_proxy_arp,
                    "route_lookup": nat.route_lookup, "unidirectional": nat.unidirectional,
                    "inactive": nat.inactive, "net_to_net": nat.net_to_net,
                    "options": nat.options, "raw_options": nat.raw_options, "raw_line": nat.raw_line,
                }, migration_status=status, requires_manual_review=manual, review_reasons=reasons,
            ))

        for interface in cfg.interfaces:
            for route_map_name in interface.policy_route_maps:
                route_map = next((item for item in cfg.route_maps if item.name == route_map_name and item.source_context == interface.source_context), None)
                if route_map is None:
                    continue
                interface_names = {item.name for item in cfg.interfaces}
                interface_names.update(item.nameif for item in cfg.interfaces if item.nameif)
                acl_names = {item.acl_name for item in cfg.access_rules if item.source_context == route_map.source_context}
                for rule in route_map.rules:
                    reasons = list(rule.source_attributes.get("review_reasons", []))
                    match_acls = rule.match_acls or ([rule.match_acl] if rule.match_acl else [])
                    next_hops = rule.next_hops or rule.source_attributes.get("next_hops", [])
                    output_interfaces = rule.output_interfaces or ([rule.set_interface] if rule.set_interface else [])
                    for acl_name in match_acls:
                        if acl_name not in acl_names:
                            reasons.append(f"Unresolved PBR ACL reference: {acl_name}")
                    for output_interface in output_interfaces:
                        if output_interface not in interface_names:
                            reasons.append(f"Unresolved PBR set interface reference: {output_interface}")
                    if rule.raw_options:
                        reasons.append("Unsupported ASA PBR match/set clauses are source-preserved")
                    if rule.source_attributes.get("next_hop_options"):
                        reasons.append("ASA PBR next-hop availability options are source-preserved")
                    evidence = _pbr_acl_match_evidence(match_acls, cfg.access_rules)
                    criteria = [
                        f"{item['acl']}: {item['protocol'] or 'ip'} {item['source'] or ''} -> {item['destination'] or ''}"
                        for item in evidence
                    ]
                    manual = bool(reasons)
                    ir.policy_route_rules.append(IRPolicyRoute(
                        name=f"{route_map.name}__{rule.sequence}",
                        source_context=interface.source_context,
                        source_rule_id=f"{route_map.name}:{rule.sequence}",
                        source_order=rule.sequence,
                        action=rule.action,
                        match_acl=match_acls[0] if match_acls else None,
                        match_acls=match_acls,
                        resolved_match_criteria=criteria,
                        match_evidence=evidence,
                        ingress_interface=interface.name,
                        next_hop=next_hops[0] if next_hops else None,
                        next_hops=next_hops,
                        output_interface=output_interfaces[0] if output_interfaces else None,
                        output_interfaces=output_interfaces,
                        enabled=True,
                        migration_status="PARTIALLY_NORMALIZED" if manual else "NORMALIZED",
                        requires_manual_review=manual,
                        review_reasons=reasons,
                        source_attributes={
                            "route_map": route_map.name,
                            "route_map_raw_lines": route_map.raw_lines,
                            "raw_lines": rule.raw_lines,
                            "raw_options": rule.raw_options,
                            "match_acls": match_acls,
                            "next_hops": next_hops,
                            "output_interfaces": output_interfaces,
                            "pbr_match_evidence": evidence,
                            "interface_attachment": interface.name,
                        },
                    ))

        for index, route in enumerate(cfg.static_routes, 1):
            destination = route.destination if route.address_family == "ipv6" else normalize_ipv4_network(route.destination, route.mask or "")
            errors = [] if destination else [f"Invalid route destination/netmask: {route.destination} {route.mask or ''}".strip()]
            ir.routes.append(IRRoute(
                name=f"route_{route.interface}_{index}", source_context=route.source_context, destination=destination,
                address_family=route.address_family,
                source_destination=route.destination if route.address_family == "ipv6" else f"{route.destination} {route.mask}", interface=route.interface,
                next_hop=route.gateway, administrative_distance=route.effective_administrative_distance,
                migration_status="PARSE_ERROR" if errors else route.migration_status,
                parse_error=errors[0] if errors else None, review_reasons=errors + route.review_reasons,
                requires_manual_review=route.requires_manual_review or bool(errors),
            source_attributes={
                "raw_line": route.raw_line, "track_id": route.track_id,
                "tunneled": route.tunneled, "raw_options": route.raw_options,
                "routing_context": route.routing_context,
                "configured_administrative_distance": route.administrative_distance,
                "effective_administrative_distance": route.effective_administrative_distance,
                **route.source_attributes,
            },
            ))
        return ir
