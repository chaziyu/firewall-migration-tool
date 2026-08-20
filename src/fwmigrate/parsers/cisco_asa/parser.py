import re
from typing import List, Dict, Optional, Tuple
from fwmigrate.parsers.cisco_asa.model import (
    CiscoASAConfig, CiscoInterface, CiscoNetworkObject, CiscoNetworkGroup,
    CiscoServiceObject, CiscoServiceGroup, CiscoServicePort,
    CiscoAccessRule, CiscoNATRule, CiscoStaticRoute
)
from fwmigrate.ir.core import (
    IRConfig, IRMetadata, IRZone, IRInterface, IRAddress, IRAddressGroup,
    IRService, IRServicePort, IRServiceGroup, IRPolicy, IRNATRule, IRRoute,
    IRAuditEntry
)
from fwmigrate.ir.enums import AddressType, ServiceProtocol, PolicyAction, NATType, MigrationConfidence

def mask_to_cidr(mask: str) -> int:
    try:
        return sum(bin(int(x)).count('1') for x in mask.split('.'))
    except Exception:
        return 32

class CiscoASAParser:
    """Parser for Cisco ASA / Firepower CLI configuration files."""

    def __init__(self, content: str, zone_mapping: Optional[Dict[str, str]] = None):
        self.raw_lines = content.splitlines()
        self.zone_mapping = zone_mapping or {}
        self.config = CiscoASAConfig()

    def parse_raw(self) -> CiscoASAConfig:
        lines = [line.rstrip() for line in self.raw_lines]
        i = 0
        current_interface: Optional[CiscoInterface] = None
        current_net_obj: Optional[CiscoNetworkObject] = None
        current_net_grp: Optional[CiscoNetworkGroup] = None
        current_svc_obj: Optional[CiscoServiceObject] = None
        current_svc_grp: Optional[CiscoServiceGroup] = None
        pending_remark: Optional[str] = None
        acl_to_interface: Dict[str, str] = {}

        # Bug 8 fix: Pre-scan for access-group directives first (two-pass approach)
        for line in lines:
            stripped = line.strip()
            m_acc_grp = re.match(r'^access-group\s+(\S+)\s+(?:in|out)\s+interface\s+(\S+)', stripped, re.IGNORECASE)
            if m_acc_grp:
                acl_name, intf_name = m_acc_grp.group(1), m_acc_grp.group(2)
                acl_to_interface[acl_name] = intf_name

        while i < len(lines):
            line = lines[i].strip()
            if not line or line.startswith(':'):
                i += 1
                continue

            # Hostname
            if line.startswith('hostname '):
                self.config.hostname = line.split()[1]
                i += 1
                continue

            # Access-group mapping: access-group <acl_name> in interface <intf_name>
            m_acc_grp = re.match(r'^access-group\s+(\S+)\s+(?:in|out)\s+interface\s+(\S+)', line, re.IGNORECASE)
            if m_acc_grp:
                acl_name, intf_name = m_acc_grp.group(1), m_acc_grp.group(2)
                acl_to_interface[acl_name] = intf_name
                i += 1
                continue

            # Route: route <interface> <dst_ip> <mask> <gateway> [metric]
            m_route = re.match(r'^route\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\d+))?', line, re.IGNORECASE)
            if m_route:
                intf, dst, mask, gw, metric = m_route.group(1), m_route.group(2), m_route.group(3), m_route.group(4), m_route.group(5)
                self.config.static_routes.append(CiscoStaticRoute(
                    interface=intf, destination=dst, mask=mask, gateway=gw, metric=int(metric) if metric else 1
                ))
                i += 1
                continue

            # Interface block
            m_intf = re.match(r'^interface\s+(\S+)', line, re.IGNORECASE)
            if m_intf:
                current_interface = CiscoInterface(name=m_intf.group(1))
                self.config.interfaces.append(current_interface)
                i += 1
                while i < len(lines):
                    sub = lines[i].strip()
                    if not sub or sub.startswith('!') or sub.startswith('interface ') or sub.startswith('object ') or sub.startswith('object-group ') or sub.startswith('access-list ') or sub.startswith('nat ') or sub.startswith('route '):
                        break
                    if sub.startswith('nameif '):
                        current_interface.nameif = sub.split(maxsplit=1)[1].strip()
                    elif sub.startswith('security-level '):
                        try:
                            current_interface.security_level = int(sub.split()[1])
                        except Exception:
                            pass
                    elif sub.startswith('ip address '):
                        parts = sub.split()
                        if len(parts) >= 4:
                            current_interface.ip = parts[2]
                            current_interface.mask = parts[3]
                    elif sub.startswith('description '):
                        current_interface.description = sub.split(maxsplit=1)[1].strip()
                    elif sub == 'shutdown':
                        current_interface.shutdown = True
                    i += 1
                continue

            # Object network
            m_obj_net = re.match(r'^object\s+network\s+(\S+)', line, re.IGNORECASE)
            if m_obj_net:
                obj_name = m_obj_net.group(1)
                obj_type = "host"
                obj_val = "0.0.0.0"
                desc = None
                i += 1
                while i < len(lines):
                    sub = lines[i].strip()
                    if not sub or sub.startswith('!') or sub.startswith('interface ') or sub.startswith('object ') or sub.startswith('object-group ') or sub.startswith('access-list ') or sub.startswith('nat ') or sub.startswith('route '):
                        break
                    if sub.startswith('host '):
                        obj_type = "host"
                        obj_val = sub.split()[1]
                    elif sub.startswith('subnet '):
                        parts = sub.split()
                        if len(parts) >= 3:
                            obj_type = "subnet"
                            cidr = mask_to_cidr(parts[2])
                            obj_val = f"{parts[1]}/{cidr}"
                    elif sub.startswith('range '):
                        parts = sub.split()
                        if len(parts) >= 3:
                            obj_type = "range"
                            obj_val = f"{parts[1]}-{parts[2]}"
                    elif sub.startswith('fqdn '):
                        obj_type = "fqdn"
                        obj_val = sub.split(maxsplit=1)[1].strip().replace('v4 ', '').replace('v6 ', '')
                    elif sub.startswith('description '):
                        desc = sub.split(maxsplit=1)[1].strip()
                    i += 1
                self.config.network_objects.append(CiscoNetworkObject(
                    name=obj_name, type=obj_type, value=obj_val, description=desc
                ))
                continue

            # Object-group network
            m_grp_net = re.match(r'^object-group\s+network\s+(\S+)', line, re.IGNORECASE)
            if m_grp_net:
                grp_name = m_grp_net.group(1)
                members = []
                desc = None
                i += 1
                while i < len(lines):
                    sub = lines[i].strip()
                    if not sub or sub.startswith('!') or sub.startswith('interface ') or sub.startswith('object ') or sub.startswith('object-group ') or sub.startswith('access-list ') or sub.startswith('nat ') or sub.startswith('route '):
                        break
                    if sub.startswith('network-object host '):
                        members.append(sub.split()[2])
                    elif sub.startswith('network-object object '):
                        members.append(sub.split()[2])
                    elif sub.startswith('network-object '):
                        parts = sub.split()
                        if len(parts) >= 3:
                            cidr = mask_to_cidr(parts[2])
                            members.append(f"{parts[1]}/{cidr}")
                        elif len(parts) == 2:
                            members.append(parts[1])
                    elif sub.startswith('group-object '):
                        members.append(sub.split()[1])
                    elif sub.startswith('description '):
                        desc = sub.split(maxsplit=1)[1].strip()
                    i += 1
                self.config.network_groups.append(CiscoNetworkGroup(
                    name=grp_name, members=members, description=desc
                ))
                continue

            # Object-group service
            m_grp_svc = re.match(r'^object-group\s+service\s+(\S+)(?:\s+(\S+))?', line, re.IGNORECASE)
            if m_grp_svc:
                grp_name = m_grp_svc.group(1)
                proto_override = m_grp_svc.group(2)
                members = []
                svc_ports = []
                desc = None
                i += 1
                while i < len(lines):
                    sub = lines[i].strip()
                    if not sub or sub.startswith('!') or sub.startswith('interface ') or sub.startswith('object ') or sub.startswith('object-group ') or sub.startswith('access-list ') or sub.startswith('nat ') or sub.startswith('route '):
                        break
                    if sub.startswith('port-object eq '):
                        p = sub.split()[2]
                        proto = proto_override if proto_override else "tcp"
                        svc_ports.append(CiscoServicePort(protocol=proto, port=p))
                    elif sub.startswith('port-object range '):
                        parts = sub.split()
                        proto = proto_override if proto_override else "tcp"
                        svc_ports.append(CiscoServicePort(protocol=proto, port=f"{parts[2]}-{parts[3]}"))
                    elif sub.startswith('service-object '):
                        parts = sub.split()
                        if len(parts) >= 4 and parts[2] == 'destination' and parts[3] == 'eq':
                            svc_ports.append(CiscoServicePort(protocol=parts[1], port=parts[4]))
                        elif len(parts) >= 6 and parts[2] == 'source' and parts[3] == 'eq' and parts[4] == 'destination' and parts[5] == 'eq':
                            # Bug 16 fix: Handle 'service-object tcp source eq X destination eq Y'
                            svc_ports.append(CiscoServicePort(protocol=parts[1], port=parts[6] if len(parts) > 6 else "any"))
                        elif len(parts) >= 3 and parts[1] in ['tcp', 'udp', 'icmp', 'ip']:
                            svc_ports.append(CiscoServicePort(protocol=parts[1], port=parts[2] if len(parts) > 2 else "any"))
                        elif len(parts) == 3 and parts[1] == 'object':
                            members.append(parts[2])
                    elif sub.startswith('group-object '):
                        members.append(sub.split()[1])
                    elif sub.startswith('description '):
                        desc = sub.split(maxsplit=1)[1].strip()
                    i += 1
                self.config.service_groups.append(CiscoServiceGroup(
                    name=grp_name, protocol=proto_override, members=members, service_objects=svc_ports, description=desc
                ))
                continue

            # Object service
            m_obj_svc = re.match(r'^object\s+service\s+(\S+)', line, re.IGNORECASE)
            if m_obj_svc:
                svc_name = m_obj_svc.group(1)
                svc_ports = []
                desc = None
                i += 1
                while i < len(lines):
                    sub = lines[i].strip()
                    if not sub or sub.startswith('!') or sub.startswith('interface ') or sub.startswith('object ') or sub.startswith('object-group ') or sub.startswith('access-list ') or sub.startswith('nat ') or sub.startswith('route '):
                        break
                    if sub.startswith('service '):
                        parts = sub.split()
                        proto = parts[1] if len(parts) > 1 else "tcp"
                        port = "any"
                        if 'destination eq' in sub:
                            idx = parts.index('eq')
                            if idx + 1 < len(parts):
                                port = parts[idx + 1]
                        elif 'destination range' in sub:
                            idx = parts.index('range')
                            if idx + 2 < len(parts):
                                port = f"{parts[idx + 1]}-{parts[idx + 2]}"
                        svc_ports.append(CiscoServicePort(protocol=proto, port=port))
                    elif sub.startswith('description '):
                        desc = sub.split(maxsplit=1)[1].strip()
                    i += 1
                self.config.service_objects.append(CiscoServiceObject(
                    name=svc_name, ports=svc_ports, description=desc
                ))
                continue

            # Access-list remark
            if line.startswith('access-list ') and ' remark ' in line:
                m_rem = re.match(r'^access-list\s+\S+\s+remark\s+(.+)$', line, re.IGNORECASE)
                if m_rem:
                    pending_remark = m_rem.group(1).strip()
                i += 1
                continue

            # Access-list extended: access-list <name> extended permit/deny <proto> <src> <dst> [eq <port>] [log] [inactive]
            if line.startswith('access-list ') and ' extended ' in line:
                tokens = line.split()
                acl_name = tokens[1]
                action = tokens[3].lower()  # permit / deny
                proto = tokens[4].lower()   # ip, tcp, udp, icmp, object-group, etc.

                # Parse remaining tokens
                src_list, dst_list, svc_list, log, inactive = self._parse_acl_tail(tokens[5:], proto)
                rule_id = f"{acl_name}_{len(self.config.access_rules) + 1}"
                intf = acl_to_interface.get(acl_name)

                self.config.access_rules.append(CiscoAccessRule(
                    id=rule_id,
                    acl_name=acl_name,
                    interface=intf,
                    action=action,
                    protocol=proto,
                    source=src_list,
                    destination=dst_list,
                    service=svc_list,
                    log=log,
                    inactive=inactive,
                    remark=pending_remark
                ))
                pending_remark = None
                i += 1
                continue

            # NAT rules: nat (<src_intf>,<dst_intf>) source/dynamic/static ...
            m_nat = re.match(r'^nat\s+\(([^,]+),([^)]+)\)\s+(.+)$', line, re.IGNORECASE)
            if m_nat:
                src_intf = m_nat.group(1).strip()
                dst_intf = m_nat.group(2).strip()
                nat_tail = m_nat.group(3).strip()
                self._parse_nat_line(src_intf, dst_intf, nat_tail)
                i += 1
                continue

            i += 1

        return self.config

    def _parse_acl_tail(self, tokens: List[str], base_proto: str) -> Tuple[List[str], List[str], List[str], bool, bool]:
        src = []
        dst = []
        svc = []
        log = False
        inactive = False

        idx = 0
        def parse_endpoint(idx: int) -> Tuple[List[str], int]:
            if idx >= len(tokens):
                return ["any"], idx
            tok = tokens[idx]
            if tok == 'any' or tok == 'any4' or tok == 'any6':
                return ["any"], idx + 1
            elif tok == 'host' and idx + 1 < len(tokens):
                return [tokens[idx + 1]], idx + 2
            elif tok == 'object' and idx + 1 < len(tokens):
                return [tokens[idx + 1]], idx + 2
            elif tok == 'object-group' and idx + 1 < len(tokens):
                return [tokens[idx + 1]], idx + 2
            elif re.match(r'^\d+\.\d+\.\d+\.\d+$', tok) and idx + 1 < len(tokens) and re.match(r'^\d+\.\d+\.\d+\.\d+$', tokens[idx + 1]):
                cidr = mask_to_cidr(tokens[idx + 1])
                return [f"{tok}/{cidr}"], idx + 2
            return [tok], idx + 1

        src, idx = parse_endpoint(idx)
        dst, idx = parse_endpoint(idx)

        # Service / port tail
        while idx < len(tokens):
            tok = tokens[idx]
            if tok == 'eq' and idx + 1 < len(tokens):
                svc.append(f"{base_proto}_{tokens[idx + 1]}")
                idx += 2
            elif tok == 'range' and idx + 2 < len(tokens):
                svc.append(f"{base_proto}_{tokens[idx + 1]}-{tokens[idx + 2]}")
                idx += 3
            elif tok == 'object-group' and idx + 1 < len(tokens):
                svc.append(tokens[idx + 1])
                idx += 2
            elif tok == 'log' or tok == 'log-interval':
                log = True
                idx += 1
            elif tok == 'inactive':
                inactive = True
                idx += 1
            else:
                idx += 1

        if not svc:
            svc = ["any" if base_proto == "ip" else base_proto]

        return src, dst, svc, log, inactive

    def _parse_nat_line(self, src_intf: str, dst_intf: str, tail: str):
        rule_num = len(self.config.nat_rules) + 1
        name = f"nat_{src_intf}_to_{dst_intf}_{rule_num}"
        nat_type = "source"
        real_src = None
        mapped_src = None
        real_dst = None
        mapped_dst = None

        tokens = tail.split()
        if 'source' in tokens:
            s_idx = tokens.index('source')
            if s_idx + 2 < len(tokens):
                # source static/dynamic <real> <mapped>
                nat_type = "source"
                real_src = tokens[s_idx + 2]
                if s_idx + 3 < len(tokens):
                    mapped_src = tokens[s_idx + 3]
        elif 'static' in tokens:
            s_idx = tokens.index('static')
            if s_idx + 1 < len(tokens):
                mapped_src = tokens[s_idx + 1]

        self.config.nat_rules.append(CiscoNATRule(
            name=name,
            source_interface=src_intf,
            destination_interface=dst_intf,
            type=nat_type,
            real_source=real_src,
            mapped_source=mapped_src,
            real_destination=real_dst,
            mapped_destination=mapped_dst
        ))

    def transform_to_ir(self) -> IRConfig:
        cfg = self.parse_raw()
        ir = IRConfig(metadata=IRMetadata(hostname=cfg.hostname, source_vendor="cisco_asa"))

        # 1. Zones & Interfaces
        zone_map: Dict[str, IRZone] = {}
        for intf in cfg.interfaces:
            z_name = intf.nameif or self.zone_mapping.get(intf.name, "untrust")
            if z_name not in zone_map:
                zone_map[z_name] = IRZone(name=z_name)
            zone_map[z_name].interfaces.append(intf.name)

            ip_cidr = None
            if intf.ip and intf.mask:
                cidr = mask_to_cidr(intf.mask)
                ip_cidr = f"{intf.ip}/{cidr}"

            ir.interfaces.append(IRInterface(
                name=intf.name,
                zone=z_name,
                ip=ip_cidr,
                description=intf.description
            ))

        ir.zones = list(zone_map.values()) if zone_map else [IRZone(name="untrust")]

        # 2. Addresses
        for net_obj in cfg.network_objects:
            addr_kwargs = {
                "name": net_obj.name,
                "description": net_obj.description
            }
            if net_obj.type == 'subnet':
                addr_kwargs["type"] = AddressType.NETWORK
                addr_kwargs["subnet"] = net_obj.value
            elif net_obj.type == 'range':
                addr_kwargs["type"] = AddressType.RANGE
                parts = net_obj.value.replace(' ', '').split('-')
                addr_kwargs["ip_range_start"] = parts[0]
                addr_kwargs["ip_range_end"] = parts[1] if len(parts) > 1 else parts[0]
            elif net_obj.type == 'fqdn':
                addr_kwargs["type"] = AddressType.FQDN
                addr_kwargs["fqdn"] = net_obj.value
            else:
                addr_kwargs["type"] = AddressType.HOST
                addr_kwargs["subnet"] = net_obj.value

            ir.addresses.append(IRAddress(**addr_kwargs))

        # 3. Address Groups
        for grp in cfg.network_groups:
            ir.address_groups.append(IRAddressGroup(
                name=grp.name,
                members=grp.members,
                description=grp.description
            ))

        # 4. Services
        for svc_obj in cfg.service_objects:
            ports = []
            for p in svc_obj.ports:
                proto = ServiceProtocol.TCP if p.protocol.lower() == 'tcp' else ServiceProtocol.UDP if p.protocol.lower() == 'udp' else ServiceProtocol.ICMP if p.protocol.lower() == 'icmp' else ServiceProtocol.IP
                ports.append(IRServicePort(protocol=proto, port=p.port))
            ir.services.append(IRService(
                name=svc_obj.name,
                ports=ports if ports else [IRServicePort(protocol=ServiceProtocol.TCP, port="any")],
                description=svc_obj.description
            ))

        # 5. Service Groups
        for sgrp in cfg.service_groups:
            # Bug 17 fix: copy members to avoid mutating the parsed model
            group_members = list(sgrp.members)
            if sgrp.service_objects:
                # Create synthetic service object for group's inline ports if needed
                ports = []
                for p in sgrp.service_objects:
                    proto = ServiceProtocol.TCP if p.protocol.lower() == 'tcp' else ServiceProtocol.UDP if p.protocol.lower() == 'udp' else ServiceProtocol.ICMP if p.protocol.lower() == 'icmp' else ServiceProtocol.IP
                    ports.append(IRServicePort(protocol=proto, port=p.port))
                ir.services.append(IRService(
                    name=f"svc_{sgrp.name}",
                    ports=ports,
                    description=sgrp.description
                ))
                group_members.append(f"svc_{sgrp.name}")

            ir.service_groups.append(IRServiceGroup(
                name=sgrp.name,
                members=group_members,
                description=sgrp.description
            ))

        # 6. Policies (Access-lists)
        # Bug 10 fix: Build nameif-to-zone lookup for proper zone resolution
        nameif_to_zone: Dict[str, str] = {}
        for intf in cfg.interfaces:
            if intf.nameif:
                nameif_to_zone[intf.nameif] = intf.nameif  # nameif IS the zone name in ASA

        for rule in cfg.access_rules:
            from_z = [rule.interface] if rule.interface else ["any"]
            action = PolicyAction.ALLOW if rule.action == 'permit' else PolicyAction.DENY

            ir.policies.append(IRPolicy(
                name=rule.id,
                from_zone=from_z,
                to_zone=["any"],
                source=rule.source,
                destination=rule.destination,
                service=rule.service,
                action=action,
                description=rule.remark,
                disabled=rule.inactive,
                log_end=rule.log
            ))

        # 7. NAT Rules
        for n in cfg.nat_rules:
            nat_t = NATType.SOURCE if n.type == 'source' else NATType.DESTINATION
            ir.nat_rules.append(IRNATRule(
                name=n.name,
                type=nat_t,
                from_zone=[n.source_interface] if n.source_interface != "any" else ["any"],
                to_zone=[n.destination_interface] if n.destination_interface != "any" else ["any"],
                source=[n.real_source] if n.real_source else ["any"],
                destination=[n.real_destination] if n.real_destination else ["any"],
                translated_source=n.mapped_source,
                translated_destination=n.mapped_destination,
                description=n.description
            ))

        # 8. Routes
        for idx, r in enumerate(cfg.static_routes, 1):
            cidr = mask_to_cidr(r.mask)
            ir.routes.append(IRRoute(
                name=f"route_{r.interface}_{idx}",
                destination=f"{r.destination}/{cidr}",
                interface=r.interface,
                next_hop=r.gateway,
                metric=r.metric
            ))

        return ir
