from __future__ import annotations

import hashlib
import re
from typing import Dict, Iterable, List, Optional, Tuple

from fwmigrate.core.constants import IR_KEYWORD_ANY
from fwmigrate.ir.core import (
    IRAddress,
    IRAddressGroup,
    IRConfig,
    IRInterface,
    IRMetadata,
    IRNATRule,
    IRPolicy,
    IRRoute,
    IRService,
    IRServiceGroup,
    IRServicePort,
    IRZone,
)
from fwmigrate.ir.enums import AddressType, NATType, PolicyAction, ServiceProtocol
from fwmigrate.parsers.cisco_asa.acl_parser import parse_acl_binding, parse_acl_line
from fwmigrate.parsers.cisco_asa.model import (
    CiscoASAConfig,
    CiscoAccessRule,
    CiscoInterface,
    CiscoNATRule,
    CiscoNetworkGroup,
    CiscoNetworkObject,
    CiscoPortSpec,
    CiscoServiceGroup,
    CiscoServiceObject,
    CiscoServicePort,
    CiscoStaticRoute,
)
from fwmigrate.parsers.cisco_asa.net_utils import normalize_ipv4_network, parse_ipv4_netmask
from fwmigrate.parsers.cisco_asa.service_parser import parse_service_clause


def mask_to_cidr(mask: str) -> Optional[int]:
    """Backward-compatible strict mask helper. Invalid masks return ``None``."""
    return parse_ipv4_netmask(mask)


def _safe_name(prefix: str, expression: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_]+", "_", expression).strip("_").lower()
    clean = clean[:48] or "value"
    digest = hashlib.sha1(expression.encode("utf-8")).hexdigest()[:8]
    return f"{prefix}_{clean}_{digest}"


class CiscoASAParser:
    """Deterministic offline parser for Cisco ASA running configuration."""

    def __init__(self, content: str, zone_mapping: Optional[Dict[str, str]] = None):
        self.raw_lines = content.splitlines()
        self.zone_mapping = zone_mapping or {}
        self.config = CiscoASAConfig()

    def _record_unsupported(self, line_number: int, line: str, reason: str) -> None:
        self.config.unsupported_commands.append(
            {"line_number": line_number, "raw_line": line, "reason": reason}
        )

    def _parse_network_object(self, name: str, block: List[str]) -> CiscoNetworkObject:
        obj = CiscoNetworkObject(name=name, raw_lines=list(block))
        for sub in block:
            parts = sub.split()
            lower = sub.lower()
            if lower.startswith("host ") and len(parts) >= 2:
                obj.type, obj.value = "host", parts[1]
            elif lower.startswith("subnet ") and len(parts) >= 3:
                value = normalize_ipv4_network(parts[1], parts[2])
                if value is None:
                    obj.migration_status = "PARSE_ERROR"
                    obj.requires_manual_review = True
                    obj.source_attributes["invalid_subnet"] = " ".join(parts[1:3])
                else:
                    obj.type, obj.value = "subnet", value
            elif lower.startswith("range ") and len(parts) >= 3:
                obj.type, obj.value = "range", f"{parts[1]}-{parts[2]}"
            elif lower.startswith("fqdn "):
                values = parts[1:]
                if values and values[0].lower() in {"v4", "v6"}:
                    obj.source_attributes["address_family"] = values.pop(0).lower()
                if values:
                    obj.type, obj.value = "fqdn", " ".join(values)
            elif lower.startswith("description "):
                obj.description = sub.split(maxsplit=1)[1]
            elif lower.startswith("nat "):
                obj.nat_lines.append(sub)
            else:
                obj.source_attributes.setdefault("unmodeled_lines", []).append(sub)
        if obj.type is None or obj.value is None:
            obj.migration_status = "PARSE_ERROR"
            obj.requires_manual_review = True
        elif obj.source_attributes.get("unmodeled_lines"):
            obj.migration_status = "PARTIALLY_NORMALIZED"
            obj.requires_manual_review = True
        return obj

    def parse_raw(self) -> CiscoASAConfig:
        self.config = CiscoASAConfig()
        lines = [line.rstrip() for line in self.raw_lines]
        remarks: Dict[str, List[str]] = {}
        i = 0
        while i < len(lines):
            raw = lines[i]
            line = raw.strip()
            line_number = i + 1
            if not line or line.startswith((":", "!")):
                i += 1
                continue
            if line.lower().startswith("hostname "):
                parts = line.split(maxsplit=1)
                if len(parts) == 2:
                    self.config.hostname = parts[1]
                i += 1
                continue

            match = re.match(r"^interface\s+(\S+)", line, re.IGNORECASE)
            if match:
                interface = CiscoInterface(name=match.group(1))
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    sub = lines[i].strip()
                    interface.raw_lines.append(sub)
                    parts = sub.split()
                    lower = sub.lower()
                    if lower.startswith("nameif "):
                        interface.nameif = sub.split(maxsplit=1)[1]
                    elif lower.startswith("security-level "):
                        try:
                            interface.security_level = int(parts[1])
                        except (IndexError, ValueError):
                            interface.requires_manual_review = True
                    elif lower.startswith("ip address "):
                        if len(parts) >= 3 and parts[2].lower() == "dhcp":
                            interface.ip_mode = "dhcp"
                            interface.source_attributes["ip_address"] = " ".join(parts[2:])
                        elif len(parts) >= 4:
                            interface.ip_mode, interface.ip, interface.mask = "static", parts[2], parts[3]
                    elif lower.startswith("description "):
                        interface.description = sub.split(maxsplit=1)[1]
                    elif lower == "shutdown":
                        interface.shutdown = True
                    else:
                        interface.source_attributes.setdefault("unmodeled_lines", []).append(sub)
                    i += 1
                if interface.ip_mode == "static" and normalize_ipv4_network(interface.ip or "", interface.mask or "") is None:
                    interface.migration_status = "PARSE_ERROR"
                    interface.requires_manual_review = True
                    interface.source_attributes["invalid_ip_address"] = f"{interface.ip or ''} {interface.mask or ''}".strip()
                elif interface.source_attributes.get("unmodeled_lines"):
                    interface.requires_manual_review = True
                self.config.interfaces.append(interface)
                continue

            match = re.match(r"^object\s+network\s+(\S+)", line, re.IGNORECASE)
            if match:
                i += 1
                block: List[str] = []
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    block.append(lines[i].strip())
                    i += 1
                obj = self._parse_network_object(match.group(1), block)
                self.config.network_objects.append(obj)
                for nat_line in obj.nat_lines:
                    self._parse_nat_line(nat_line, line_number, owning_object=obj.name)
                continue

            match = re.match(r"^object-group\s+network\s+(\S+)", line, re.IGNORECASE)
            if match:
                group = CiscoNetworkGroup(name=match.group(1))
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    sub = lines[i].strip()
                    group.raw_lines.append(sub)
                    parts = sub.split()
                    lower = sub.lower()
                    if lower.startswith("network-object host ") and len(parts) >= 3:
                        group.members.append(_safe_name("asa_inline_host", parts[2]))
                    elif lower.startswith("network-object object ") and len(parts) >= 3:
                        group.members.append(parts[2])
                    elif lower.startswith("network-object ") and len(parts) >= 3:
                        value = normalize_ipv4_network(parts[1], parts[2])
                        if value:
                            group.members.append(_safe_name("asa_inline_net", value))
                        else:
                            group.migration_status = "PARSE_ERROR"
                            group.requires_manual_review = True
                    elif lower.startswith("group-object ") and len(parts) >= 2:
                        group.members.append(parts[1])
                    elif lower.startswith("description "):
                        group.description = sub.split(maxsplit=1)[1]
                    else:
                        group.migration_status = "PARTIALLY_NORMALIZED"
                        group.requires_manual_review = True
                    i += 1
                self.config.network_groups.append(group)
                continue

            match = re.match(r"^object\s+service\s+(\S+)", line, re.IGNORECASE)
            if match:
                obj = CiscoServiceObject(name=match.group(1))
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    sub = lines[i].strip()
                    obj.raw_lines.append(sub)
                    if sub.lower().startswith("service "):
                        ports, error = parse_service_clause(sub.split()[1:])
                        obj.ports.extend(ports)
                        if error:
                            obj.migration_status = "PARSE_ERROR"
                            obj.requires_manual_review = True
                    elif sub.lower().startswith("description "):
                        obj.description = sub.split(maxsplit=1)[1]
                    else:
                        obj.migration_status = "PARTIALLY_NORMALIZED"
                        obj.requires_manual_review = True
                    i += 1
                if not obj.ports:
                    obj.migration_status = "PARSE_ERROR"
                    obj.requires_manual_review = True
                self.config.service_objects.append(obj)
                continue

            match = re.match(r"^object-group\s+service\s+(\S+)(?:\s+(\S+))?", line, re.IGNORECASE)
            if match:
                group = CiscoServiceGroup(name=match.group(1), protocol=match.group(2))
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    sub = lines[i].strip()
                    group.raw_lines.append(sub)
                    parts = sub.split()
                    lower = sub.lower()
                    if lower.startswith("group-object ") and len(parts) >= 2:
                        group.members.append(parts[1])
                    elif lower.startswith("service-object object ") and len(parts) >= 3:
                        group.members.append(parts[2])
                    elif lower.startswith("service-object "):
                        ports, error = parse_service_clause(parts[1:])
                        group.service_objects.extend(ports)
                        if error:
                            group.migration_status = "PARSE_ERROR"
                            group.requires_manual_review = True
                    elif lower.startswith("port-object "):
                        if not group.protocol:
                            group.migration_status = "PARTIALLY_NORMALIZED"
                            group.requires_manual_review = True
                        else:
                            pseudo = [group.protocol, "destination", *parts[1:]]
                            ports, error = parse_service_clause(pseudo)
                            group.service_objects.extend(ports)
                            if error:
                                group.migration_status = "PARSE_ERROR"
                                group.requires_manual_review = True
                    elif lower.startswith("description "):
                        group.description = sub.split(maxsplit=1)[1]
                    else:
                        group.migration_status = "PARTIALLY_NORMALIZED"
                        group.requires_manual_review = True
                    i += 1
                self.config.service_groups.append(group)
                continue

            if line.lower().startswith("access-list "):
                rule, error = parse_acl_line(line, line_number, remarks)
                if rule:
                    self.config.access_rules.append(rule)
                if error:
                    self._record_unsupported(line_number, line, error)
                i += 1
                continue
            if line.lower().startswith("access-group "):
                binding = parse_acl_binding(line, line_number)
                if binding:
                    self.config.acl_bindings.append(binding)
                else:
                    self._record_unsupported(line_number, line, "Malformed access-group binding")
                i += 1
                continue
            if line.lower().startswith("nat "):
                self._parse_nat_line(line, line_number)
                i += 1
                continue
            match = re.match(r"^route\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\d+))?", line, re.IGNORECASE)
            if match:
                route = CiscoStaticRoute(
                    interface=match.group(1), destination=match.group(2), mask=match.group(3),
                    gateway=match.group(4), administrative_distance=int(match.group(5)) if match.group(5) else None,
                    raw_line=line,
                )
                if normalize_ipv4_network(route.destination, route.mask) is None:
                    route.migration_status = "PARSE_ERROR"
                    route.requires_manual_review = True
                self.config.static_routes.append(route)
                i += 1
                continue
            self._record_unsupported(line_number, line, "No Cisco ASA extraction handler")
            i += 1
        return self.config

    def _parse_nat_line(self, line: str, line_number: int, owning_object: Optional[str] = None) -> None:
        match = re.match(r"^nat\s+\(([^,]*),([^)]*)\)\s+(.+)$", line, re.IGNORECASE)
        if not match:
            self._record_unsupported(line_number, line, "Malformed NAT statement")
            return
        src_if = match.group(1).strip() or None
        dst_if = match.group(2).strip() or None
        tail = match.group(3).split()
        section = "after-auto" if tail and tail[0].lower() == "after-auto" else "object" if owning_object else "manual"
        if section == "after-auto":
            tail = tail[1:]
        sequence = None
        if tail and tail[0].isdigit():
            sequence = int(tail.pop(0))
        rule = CiscoNATRule(
            name=f"nat_{section}_{line_number}", source_interface=src_if, destination_interface=dst_if,
            section=section, sequence=sequence, owning_object=owning_object, raw_line=line,
        )
        options = {"dns", "no-proxy-arp", "route-lookup", "unidirectional", "inactive"}
        rule.options = [token for token in tail if token.lower() in options]
        try:
            if owning_object and tail and tail[0].lower() in {"static", "dynamic"}:
                rule.source_mode = tail[0].lower()
                rule.real_source = owning_object
                rule.mapped_source = tail[1] if len(tail) > 1 else None
            else:
                index = 0
                if index < len(tail) and tail[index].lower() == "source":
                    rule.source_mode = tail[index + 1].lower() if index + 1 < len(tail) else None
                    rule.real_source = tail[index + 2] if index + 2 < len(tail) else None
                    rule.mapped_source = tail[index + 3] if index + 3 < len(tail) else None
                    index += 4
                if index < len(tail) and tail[index].lower() == "destination":
                    rule.destination_mode = tail[index + 1].lower() if index + 1 < len(tail) else None
                    rule.real_destination = tail[index + 2] if index + 2 < len(tail) else None
                    rule.mapped_destination = tail[index + 3] if index + 3 < len(tail) else None
                    index += 4
                if index < len(tail) and tail[index].lower() == "service":
                    rule.original_service = tail[index + 1] if index + 1 < len(tail) else None
                    rule.translated_service = tail[index + 2] if index + 2 < len(tail) else None
        except (IndexError, ValueError):
            pass
        if not src_if or not dst_if or not rule.real_source or not rule.mapped_source:
            rule.migration_status = "PARSE_ERROR"
            rule.requires_manual_review = True
            rule.review_reasons.append("NAT operands or interface context are incomplete")
        if rule.destination_mode or rule.original_service or any(opt in rule.options for opt in {"unidirectional", "inactive"}):
            rule.migration_status = "PARTIALLY_NORMALIZED"
            rule.requires_manual_review = True
            rule.review_reasons.append("Advanced ASA NAT semantics require target review")
        self.config.nat_rules.append(rule)

    @staticmethod
    def _protocol(protocol: str) -> Optional[ServiceProtocol]:
        return {
            "tcp": ServiceProtocol.TCP, "udp": ServiceProtocol.UDP, "sctp": ServiceProtocol.SCTP,
            "icmp": ServiceProtocol.ICMP, "icmp6": ServiceProtocol.ICMPV6, "ip": ServiceProtocol.IP,
        }.get(protocol.lower())

    @staticmethod
    def _port_value(spec: Optional[CiscoPortSpec]) -> Optional[str]:
        if spec is None:
            return None
        if spec.operator == "eq" and spec.values:
            return spec.values[0]
        if spec.operator == "range" and len(spec.values) == 2:
            return f"{spec.values[0]}-{spec.values[1]}"
        return None

    def _ir_service_ports(self, ports: Iterable[CiscoServicePort]) -> Tuple[List[IRServicePort], List[str]]:
        result: List[IRServicePort] = []
        errors: List[str] = []
        for item in ports:
            protocol = self._protocol(item.protocol)
            if protocol is None:
                errors.append(f"Unknown protocol '{item.protocol}'")
                continue
            destination = self._port_value(item.destination)
            source = self._port_value(item.source)
            if item.destination and destination is None:
                errors.append(f"Unsupported destination-port operator '{item.destination.operator}'")
                continue
            if item.source and source is None:
                errors.append(f"Unsupported source-port operator '{item.source.operator}'")
                continue
            port = destination or ("any" if protocol in {ServiceProtocol.ICMP, ServiceProtocol.ICMPV6, ServiceProtocol.IP} else "1-65535")
            icmp_type = int(item.icmp_type) if item.icmp_type and item.icmp_type.isdigit() else None
            result.append(IRServicePort(
                protocol=protocol, port=port, source_port=source, raw_source_value=item.raw,
                icmptype=icmp_type, icmpcode=item.icmp_code,
            ))
            if item.icmp_type and icmp_type is None:
                errors.append(f"Named ICMP type '{item.icmp_type}' requires review")
        return result, errors

    def transform_to_ir(self) -> IRConfig:
        cfg = self.parse_raw()
        ir = IRConfig(metadata=IRMetadata(hostname=cfg.hostname, source_vendor="cisco_asa", source_product="Cisco ASA"))

        explicit_zones: Dict[str, IRZone] = {}
        for interface in cfg.interfaces:
            zone = interface.nameif or self.zone_mapping.get(interface.name)
            if zone:
                explicit_zones.setdefault(zone, IRZone(name=zone)).interfaces.append(interface.name)
            ip_value = normalize_ipv4_network(interface.ip or "", interface.mask or "") if interface.ip_mode == "static" else None
            parse_errors = []
            if interface.ip_mode == "static" and ip_value is None:
                parse_errors.append(f"Invalid IPv4 address/netmask: {interface.ip or ''} {interface.mask or ''}".strip())
            ir.interfaces.append(IRInterface(
                name=interface.name, zone=zone, ip=ip_value, description=interface.description,
                status=not interface.shutdown, addressing_mode=interface.ip_mode,
                dhcp_client=True if interface.ip_mode == "dhcp" else None,
                requires_manual_review=interface.requires_manual_review or bool(parse_errors),
                parse_errors=parse_errors, source_attributes={
                    **interface.source_attributes,
                    "nameif": interface.nameif,
                    "security_level": interface.security_level,
                    "raw_lines": interface.raw_lines,
                },
            ))
        ir.zones = list(explicit_zones.values())

        inline_addresses: Dict[str, IRAddress] = {}
        for obj in cfg.network_objects:
            if obj.type is None or obj.value is None:
                continue
            kwargs = dict(
                name=obj.name, description=obj.description, source_type=obj.type,
                source_attributes={**obj.source_attributes, "raw_lines": obj.raw_lines},
                migration_status=obj.migration_status, requires_manual_review=obj.requires_manual_review,
            )
            if obj.type == "host":
                kwargs.update(type=AddressType.HOST, subnet=obj.value)
            elif obj.type == "subnet":
                kwargs.update(type=AddressType.NETWORK, subnet=obj.value)
            elif obj.type == "range":
                start, end = obj.value.split("-", 1)
                kwargs.update(type=AddressType.RANGE, ip_range_start=start, ip_range_end=end)
            else:
                kwargs.update(type=AddressType.FQDN, fqdn=obj.value)
            ir.addresses.append(IRAddress(**kwargs))

        for group in cfg.network_groups:
            for raw in group.raw_lines:
                parts = raw.split()
                if raw.lower().startswith("network-object host ") and len(parts) >= 3:
                    name = _safe_name("asa_inline_host", parts[2])
                    inline_addresses[name] = IRAddress(name=name, type=AddressType.HOST, subnet=parts[2], raw_value=raw)
                elif raw.lower().startswith("network-object ") and len(parts) >= 3 and parts[1].lower() not in {"object", "host"}:
                    value = normalize_ipv4_network(parts[1], parts[2])
                    if value:
                        name = _safe_name("asa_inline_net", value)
                        inline_addresses[name] = IRAddress(name=name, type=AddressType.NETWORK, subnet=value, raw_value=raw)
            ir.address_groups.append(IRAddressGroup(
                name=group.name, members=group.members, description=group.description,
                migration_status=group.migration_status, requires_manual_review=group.requires_manual_review,
                source_attributes={"raw_lines": group.raw_lines},
            ))

        for obj in cfg.service_objects:
            ports, errors = self._ir_service_ports(obj.ports)
            if not ports:
                continue
            ir.services.append(IRService(
                name=obj.name, ports=ports, description=obj.description,
                source_attributes={"raw_lines": obj.raw_lines},
                migration_status="PARTIALLY_NORMALIZED" if errors else obj.migration_status,
                requires_manual_review=obj.requires_manual_review or bool(errors),
                audit_note="; ".join(errors) or None,
            ))

        for group in cfg.service_groups:
            members = list(group.members)
            if group.service_objects:
                name = _safe_name("asa_group_service", group.name)
                ports, errors = self._ir_service_ports(group.service_objects)
                if ports:
                    ir.services.append(IRService(
                        name=name, ports=ports, description=f"Inline services for {group.name}",
                        migration_status="PARTIALLY_NORMALIZED" if errors else group.migration_status,
                        requires_manual_review=group.requires_manual_review or bool(errors),
                        audit_note="; ".join(errors) or None,
                    ))
                    members.append(name)
            ir.service_groups.append(IRServiceGroup(
                name=group.name, members=members, description=group.description,
                migration_status=group.migration_status, requires_manual_review=group.requires_manual_review,
                source_attributes={"protocol": group.protocol, "raw_lines": group.raw_lines},
            ))

        synthetic_services: Dict[str, IRService] = {}

        def endpoint_reference(rule: CiscoAccessRule, source: bool) -> List[str]:
            endpoint = rule.source_endpoint if source else rule.destination_endpoint
            if endpoint is None or not endpoint.valid or endpoint.value is None:
                return []
            if endpoint.type == "any":
                return [IR_KEYWORD_ANY]
            if endpoint.type in {"inline", "host"}:
                value = endpoint.value
                if endpoint.type == "host" and "/" not in value:
                    value = f"{value}/128" if ":" in value else f"{value}/32"
                prefix = "asa_inline_host" if endpoint.type == "host" or "/32" in value or "/128" in value else "asa_inline_net"
                name = _safe_name(prefix, value)
                addr_type = AddressType.HOST if prefix.endswith("host") else AddressType.NETWORK
                inline_addresses[name] = IRAddress(name=name, type=addr_type, subnet=value, raw_value=endpoint.raw)
                return [name]
            return [endpoint.value]

        def service_reference(rule: CiscoAccessRule) -> List[str]:
            if rule.protocol in {"object", "object-group"} and rule.protocol_object:
                return [rule.protocol_object]
            if rule.protocol == "ip" and not rule.destination_port and not rule.source_port:
                return [IR_KEYWORD_ANY]
            protocol = self._protocol(rule.protocol or "")
            if protocol is None:
                return []
            port_model = CiscoServicePort(
                protocol=rule.protocol or "", source=rule.source_port, destination=rule.destination_port,
                icmp_type=rule.icmp_type, icmp_code=rule.icmp_code, raw=rule.raw_line,
            )
            ports, errors = self._ir_service_ports([port_model])
            if not ports or errors:
                rule.requires_manual_review = True
                rule.migration_status = "PARTIALLY_NORMALIZED"
                rule.review_reasons.extend(errors)
                return []
            expression = f"{rule.protocol}:{rule.source_port.raw if rule.source_port else '*'}:{rule.destination_port.raw if rule.destination_port else '*'}:{rule.icmp_type or ''}"
            name = _safe_name("asa_inline_service", expression)
            synthetic_services[name] = IRService(name=name, ports=ports, source_attributes={"source_expression": expression})
            return [name]

        bindings: Dict[str, List] = {}
        for binding in cfg.acl_bindings:
            bindings.setdefault(binding.acl_name, []).append(binding)
        interface_zones = {interface.nameif: (interface.nameif or self.zone_mapping.get(interface.name)) for interface in cfg.interfaces if interface.nameif}
        interface_zones.update({interface.name: (interface.nameif or self.zone_mapping.get(interface.name)) for interface in cfg.interfaces})

        for rule in cfg.access_rules:
            rule_bindings = bindings.get(rule.acl_name) or [None]
            for binding in rule_bindings:
                from_zone: List[str] = []
                to_zone: List[str] = []
                source_from: List[str] = []
                source_to: List[str] = []
                review = list(rule.review_reasons)
                status = rule.migration_status
                manual = rule.requires_manual_review
                extra = {"acl_name": rule.acl_name, "raw_line": rule.raw_line}
                suffix = "unbound"
                if binding is None:
                    manual = True
                    status = "PARTIALLY_NORMALIZED"
                    review.append("ACL has no access-group binding")
                else:
                    suffix = f"{binding.interface or 'global'}_{binding.direction or 'unknown'}"
                    extra.update({
                        "binding_direction": binding.direction, "binding_interface": binding.interface,
                        "global": binding.direction == "global", "control_plane": binding.control_plane,
                        "per_user_override": binding.per_user_override,
                    })
                    zone = interface_zones.get(binding.interface or "")
                    if binding.direction == "in":
                        source_from = [binding.interface] if binding.interface else []
                        from_zone = [zone] if zone else []
                    elif binding.direction == "out":
                        source_to = [binding.interface] if binding.interface else []
                        to_zone = [zone] if zone else []
                    if binding.direction == "global" or binding.control_plane or not zone and binding.direction != "global":
                        manual = True
                        status = "EXTRACT_ONLY" if binding.control_plane else "PARTIALLY_NORMALIZED"
                        review.append("ACL binding context cannot be represented as an ordinary transit policy")
                source_refs = endpoint_reference(rule, True)
                destination_refs = endpoint_reference(rule, False)
                services = service_reference(rule)
                if not source_refs or not destination_refs or not services:
                    manual = True
                    status = "PARSE_ERROR" if status == "NORMALIZED" else status
                    review.append("Policy has unresolved address or service semantics")
                if rule.time_range:
                    manual = True
                    status = "PARTIALLY_NORMALIZED"
                    review.append(f"Schedule '{rule.time_range}' is not yet defined in canonical IR")
                name = f"{rule.id}__{re.sub(r'[^A-Za-z0-9_]+', '_', suffix)}"
                ir.policies.append(IRPolicy(
                    name=name, source_rule_id=rule.id, from_zone=from_zone, to_zone=to_zone,
                    source=source_refs, destination=destination_refs, service=services,
                    action=PolicyAction.ALLOW if rule.action == "permit" else PolicyAction.DENY if rule.action == "deny" else None,
                    source_from_interfaces=source_from, source_to_interfaces=source_to,
                    source_address_references=source_refs, destination_address_references=destination_refs,
                    source_service_references=services, source_action=rule.action,
                    source_schedule=rule.time_range, schedule=rule.time_range,
                    source_users=[rule.user] if rule.user else [], source_user_groups=[rule.user_group] if rule.user_group else [],
                    identity_dependency_review=bool(rule.user or rule.user_group), source_log_setting=rule.log_raw,
                    source_extra_settings=extra | ({"security_group": rule.security_group} if rule.security_group else {}),
                    migration_status=status, review_reasons=list(dict.fromkeys(review)), requires_manual_review=manual,
                    description=rule.remark, disabled=rule.inactive, log_end=rule.log_enabled,
                ))

        ir.addresses.extend(inline_addresses.values())
        ir.services.extend(synthetic_services.values())

        address_names = {item.name for item in ir.addresses} | {item.name for item in ir.address_groups} | {IR_KEYWORD_ANY}
        service_names = {item.name for item in ir.services} | {item.name for item in ir.service_groups} | {IR_KEYWORD_ANY}
        for policy in ir.policies:
            unresolved = [ref for ref in policy.source + policy.destination if ref not in address_names]
            unresolved += [ref for ref in policy.service if ref not in service_names]
            if unresolved:
                policy.requires_manual_review = True
                policy.migration_status = "PARTIALLY_NORMALIZED"
                policy.review_reasons.append(f"Unresolved references: {', '.join(sorted(set(unresolved)))}")

        for index, nat in enumerate(cfg.nat_rules, 1):
            source = [nat.real_source] if nat.real_source else []
            destination = [nat.real_destination] if nat.real_destination else []
            services = [nat.original_service] if nat.original_service else [IR_KEYWORD_ANY] if source else []
            nat_type = NATType.TWICE if nat.destination_mode else NATType.SOURCE
            missing_refs = [ref for ref in source + destination if ref not in address_names and ref not in {"any", "interface"}]
            manual = nat.requires_manual_review or bool(missing_refs)
            status = "PARTIALLY_NORMALIZED" if manual and nat.migration_status == "NORMALIZED" else nat.migration_status
            reasons = list(nat.review_reasons)
            if missing_refs:
                reasons.append(f"Unresolved NAT references: {', '.join(sorted(set(missing_refs)))}")
            ir.nat_rules.append(IRNATRule(
                name=nat.name, type=nat_type, sequence=nat.sequence if nat.sequence is not None else index,
                enabled="inactive" not in nat.options,
                source_from_interfaces=[nat.source_interface] if nat.source_interface else [],
                source_to_interfaces=[nat.destination_interface] if nat.destination_interface else [],
                from_zone=[nat.source_interface] if nat.source_interface else [], to_zone=[nat.destination_interface] if nat.destination_interface else [],
                source=source, destination=destination, services=services,
                translated_sources=[nat.mapped_source] if nat.mapped_source else [],
                translated_destinations=[nat.mapped_destination] if nat.mapped_destination else [],
                translated_services=[nat.translated_service] if nat.translated_service else [],
                source_rule_id=str(nat.sequence or index), source_attributes={
                    "section": nat.section, "owning_object": nat.owning_object, "source_mode": nat.source_mode,
                    "destination_mode": nat.destination_mode, "options": nat.options, "raw_line": nat.raw_line,
                }, migration_status=status, requires_manual_review=manual, review_reasons=reasons,
            ))

        for index, route in enumerate(cfg.static_routes, 1):
            destination = normalize_ipv4_network(route.destination, route.mask)
            errors = [] if destination else [f"Invalid route destination/netmask: {route.destination} {route.mask}"]
            ir.routes.append(IRRoute(
                name=f"route_{route.interface}_{index}", destination=destination,
                source_destination=f"{route.destination} {route.mask}", interface=route.interface,
                next_hop=route.gateway, administrative_distance=route.administrative_distance,
                migration_status="PARSE_ERROR" if errors else route.migration_status,
                parse_error=errors[0] if errors else None, review_reasons=errors,
                requires_manual_review=route.requires_manual_review or bool(errors),
                source_attributes={"raw_line": route.raw_line},
            ))
        return ir
