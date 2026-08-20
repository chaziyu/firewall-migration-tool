from typing import Dict, List, Set
from fwmigrate.parsers.fortigate.model import FGConfig, FGInterface
from fwmigrate.ir.core import (
    IRConfig, IRMetadata, IRZone, IRInterface, IRAddress, AddressType,
    IRAddressGroup, IRService, IRServicePort, ServiceProtocol, IRServiceGroup,
    IRSchedule, IRPolicy, PolicyAction, IRNATRule, NATType, IRVPNTunnel,
    IRRoute, IRAuditEntry, MigrationConfidence, IRSecurityProfileGroup, IRInternetService
)
import re

class FGToIRTransformer:
    def __init__(self, fg_config: FGConfig, zone_mapping: Dict[str, str] = None):
        self.fg = fg_config
        self.ir = IRConfig(metadata=IRMetadata(
            hostname=fg_config.system_global.hostname if fg_config.system_global else "fortigate",
            source_vendor="fortigate"
        ))
        self.zone_mapping = zone_mapping or {}
        # Internal state for lookup
        self._intf_to_zone: Dict[str, str] = {}
        
        # Build map of member interface to FortiGate system zone (e.g. Azure-GSAP)
        self.fg_zone_intf_map: Dict[str, str] = {}
        for sz in self.fg.system_zones:
            for member_intf in sz.interface:
                self.fg_zone_intf_map[member_intf] = sz.name
            self.fg_zone_intf_map[sz.name] = sz.name
            self._intf_to_zone[sz.name] = sz.name
        
    def transform(self) -> IRConfig:
        self._transform_interfaces_and_zones()
        self._transform_addresses()
        self._transform_services()
        self._transform_schedules()
        self._transform_policies()
        self._transform_nat()
        self._transform_vpn()
        self._transform_routes()
        self._transform_internet_services()
        return self.ir

    def _transform_internet_services(self):
        for isdb in self.fg.internet_services:
            self.ir.internet_services.append(IRInternetService(
                name=isdb.name,
                description=isdb.comment
            ))

    def _get_zone_for_intf(self, intf: FGInterface) -> str:
        if intf.name in self.zone_mapping:
            return self.zone_mapping[intf.name]
        
        if intf.name in self.fg_zone_intf_map:
            return self.fg_zone_intf_map[intf.name]
        
        # If part of SDWAN, use the SDWAN zone if possible
        if self.fg.sdwan:
            for member in self.fg.sdwan.members:
                if member.interface == intf.name:
                    return member.zone
                    
        if intf.role != "undefined":
            # Map role to zone name: wan -> untrust, lan -> trust, dmz -> dmz
            role_map = {"wan": "untrust", "lan": "trust", "dmz": "dmz"}
            return role_map.get(intf.role, intf.role)
            
        # Heuristic inference based on interface alias and name
        text = f"{intf.name} {intf.alias or ''} {intf.description or ''}".lower()
        if any(k in text for k in ["lan", "internal", "inside", "trust", "polycom", "user", "corp", "server", "mgmt", "local"]):
            return "trust"
        if any(k in text for k in ["dmz"]):
            return "dmz"
        if any(k in text for k in ["wan", "internet", "outside", "untrust", "pppoe", "isp", "unifi"]):
            return "untrust"
        if intf.name.lower().startswith("internal"):
            return "trust"
        if intf.name.lower().startswith("wan") or intf.name.lower().startswith("port"):
            return "untrust"
            
        return "trust" if "internal" in intf.name.lower() else "untrust"

    def _transform_interfaces_and_zones(self):
        zones_map: Dict[str, IRZone] = {}
        
        # Initialize FortiGate system zones (e.g. Azure-GSAP)
        for sz in self.fg.system_zones:
            if sz.name not in zones_map:
                zones_map[sz.name] = IRZone(name=sz.name, interfaces=list(sz.interface))
        
        for intf in self.fg.interfaces:
            zone_name = self._get_zone_for_intf(intf)
            self._intf_to_zone[intf.name] = zone_name
            
            if zone_name not in zones_map:
                zones_map[zone_name] = IRZone(name=zone_name)
            
            if intf.name not in zones_map[zone_name].interfaces:
                zones_map[zone_name].interfaces.append(intf.name)
            
            # Format IP: 10.0.0.1 255.255.255.0 -> CIDR
            ip_cidr = None
            if intf.ip:
                parts = intf.ip.split()
                if len(parts) == 2:
                    ip, mask = parts
                    try:
                        bits = sum(bin(int(x)).count('1') for x in mask.split('.'))
                        cidr = f"/{bits}"
                    except Exception:
                        cidr = "/32"
                    # Bug 11 fix: 0.0.0.0/0 means unconfigured — treat as None
                    if ip == "0.0.0.0" and cidr == "/0":
                        ip_cidr = None
                    else:
                        ip_cidr = f"{ip}{cidr}"
                    
            self.ir.interfaces.append(IRInterface(
                name=intf.name,
                zone=zone_name,
                ip=ip_cidr,
                description=intf.description,
                parent=intf.interface,
                tag=intf.vlanid,
                alias=intf.alias,
                status=(intf.status != "down"),
                vlanid=intf.vlanid,
                pppoe_mode=intf.mode if intf.mode in ["pppoe"] else None,
                pppoe_username=intf.username
            ))
            
        self.ir.zones = list(zones_map.values())

    def _transform_addresses(self):
        for addr in self.fg.addresses:
            if addr.name == "all":
                continue
            addr_type = AddressType.NETWORK
            val = ""
            if addr.type == "ipmask" and addr.subnet:
                parts = addr.subnet.split()
                if len(parts) == 2:
                    ip, mask = parts
                    try:
                        bits = sum(bin(int(x)).count('1') for x in mask.split('.'))
                        val = f"{ip}/{bits}"
                    except Exception:
                        val = f"{ip}/32"
            elif addr.type == "fqdn" and addr.fqdn:
                addr_type = AddressType.FQDN
                val = addr.fqdn
                if val.startswith("*") and not val.startswith("*."):
                    norm_val = "*." + val[1:]
                    self.ir.audit_entries.append(IRAuditEntry(
                        id=addr.name, category="Address",
                        message=f"Wildcard FQDN '{val}' normalized to PAN-OS format '{norm_val}'. Note: Apex domain matching behavior may differ. Review for semantics.",
                        confidence=MigrationConfidence.PARTIAL
                    ))
                    val = norm_val
            elif addr.type == "iprange" and addr.start_ip and addr.end_ip:
                addr_type = AddressType.RANGE
                val = f"{addr.start_ip}-{addr.end_ip}"
            elif addr.type == "mac":
                addr_type = AddressType.MAC
                val = addr.subnet or "00:00:00:00:00:00"
            elif addr.type == "geography":
                addr_type = AddressType.GEO
                val = addr.subnet or "unknown"
            elif addr.type == "dynamic":
                # Bug 12 fix: Only create a DAG (address group), not a duplicate address object
                tag_name = addr.ems_tag_name or addr.name
                self.ir.address_groups.append(IRAddressGroup(
                    name=addr.name,
                    is_dynamic=True,
                    dynamic_filter=f"'{tag_name}'",
                    tags=[tag_name],
                    description=addr.comment or f"Migrated FortiClient EMS Dynamic Tag: {tag_name}"
                ))
                self.ir.audit_entries.append(IRAuditEntry(
                    id=addr.name, category="Address", message=f"Dynamic/EMS Tag '{addr.name}' automatically converted to Target Dynamic Address Group (DAG) with filter '{tag_name}'.",
                    confidence=MigrationConfidence.FULL
                ))
                continue  # Skip creating duplicate IRAddress for dynamic objects
                
            self.ir.addresses.append(IRAddress(
                name=addr.name, type=addr_type, value=val, description=addr.comment,
                is_ipv6=addr.is_ipv6, is_multicast=addr.is_multicast
            ))
            
        for fqdn in self.fg.wildcard_fqdns:
            val = fqdn.wildcard_fqdn
            if val.startswith("*") and not val.startswith("*."):
                norm_val = "*." + val[1:]
                self.ir.audit_entries.append(IRAuditEntry(
                    id=fqdn.name, category="Address",
                    message=f"Wildcard FQDN '{val}' normalized to PAN-OS format '{norm_val}'. Note: Apex domain matching behavior may differ. Review for semantics.",
                    confidence=MigrationConfidence.PARTIAL
                ))
                val = norm_val
            self.ir.addresses.append(IRAddress(
                name=fqdn.name, type=AddressType.WILDCARD_FQDN, value=val, description=fqdn.comment
            ))
            
        for grp in self.fg.address_groups:
            self.ir.address_groups.append(IRAddressGroup(
                name=grp.name, members=grp.member, description=grp.comment
            ))

    def _clean_port_range(self, port_str: str) -> str:
        """Extract destination port and normalize FortiGate [dst_port]:[src_port] syntax for a single port entry."""
        if not port_str:
            return "any"
        # Split on colon if present (e.g. 3299:0-65335 -> 3299)
        if ":" in port_str:
            dst_port = port_str.split(":")[0].strip()
        else:
            dst_port = port_str.strip()
            
        if dst_port in ["0-65535", "0-65335", "0"]:
            return "1-65535"
        return dst_port

    def _parse_port_ranges(self, port_str: str, protocol: ServiceProtocol) -> list:
        """Bug 4 fix: Handle multi-value port ranges (e.g. '80,443,8080' or '80 443 8080')."""
        if not port_str:
            return [IRServicePort(protocol=protocol, port="any")]
        # FortiGate may use comma or space to separate multiple port ranges
        parts = [p.strip() for p in port_str.replace(",", " ").split() if p.strip()]
        result = []
        for part in parts:
            cleaned = self._clean_port_range(part)
            result.append(IRServicePort(protocol=protocol, port=cleaned))
        return result if result else [IRServicePort(protocol=protocol, port="any")]

    def _transform_services(self):
        for svc in self.fg.services:
            ports = []
            if svc.tcp_portrange:
                ports.extend(self._parse_port_ranges(svc.tcp_portrange, ServiceProtocol.TCP))
            if svc.udp_portrange:
                ports.extend(self._parse_port_ranges(svc.udp_portrange, ServiceProtocol.UDP))
            if svc.protocol in ["ICMP", "ICMP6"]:
                ports.append(IRServicePort(protocol=ServiceProtocol.ICMP, port="any", icmptype=svc.icmptype, icmpcode=svc.icmpcode))
            elif svc.protocol == "IP" and svc.protocol_number:
                ports.append(IRServicePort(protocol=ServiceProtocol.IP, port=str(svc.protocol_number)))
                
            if not ports:
                # Default TCP if unspecified
                ports.append(IRServicePort(protocol=ServiceProtocol.TCP, port="any"))
                
            self.ir.services.append(IRService(
                name=svc.name, ports=ports, description=svc.comment
            ))
            
        for grp in self.fg.service_groups:
            self.ir.service_groups.append(IRServiceGroup(
                name=grp.name, members=grp.member, description=grp.comment
            ))

    def _transform_schedules(self):
        for sched in self.fg.schedules:
            self.ir.schedules.append(IRSchedule(
                name=sched.name, start=sched.start, end=sched.end, days=sched.day
            ))

    def _transform_policies(self):
        for pol in self.fg.policies:
            # Resolve zones from interfaces
            from_zones = list(set([self._intf_to_zone.get(intf, "untrust") for intf in pol.srcintf if intf != "any"]))
            to_zones = list(set([self._intf_to_zone.get(intf, "untrust") for intf in pol.dstintf if intf != "any"]))
            
            if "any" in pol.srcintf or not from_zones:
                from_zones = ["any"]
            if "any" in pol.dstintf or not to_zones:
                to_zones = ["any"]
                
            action = PolicyAction.DENY
            if pol.action == "accept":
                action = PolicyAction.ALLOW
                

            ir_pol = IRPolicy(
                name=pol.name or f"Rule_{pol.id}",
                from_zone=from_zones,
                to_zone=to_zones,
                source=["any" if a == "all" else a for a in pol.srcaddr],
                destination=["any" if a == "all" else a for a in pol.dstaddr],
                service=pol.service,
                action=action,
                description=pol.comments,
                # Bug 13 fix: logtraffic 'all' or 'utm' both enable full logging
                log_start=pol.logtraffic in ('all', 'utm'),
                log_end=pol.logtraffic in ('all', 'utm'),
                disabled=(pol.status == "disable"),
                internet_service=pol.internet_service_name
            )
            
            if pol.utm_status == "enable":
                # Build specific profile group based on active UTM features
                active_features = []
                if pol.av_profile:
                    active_features.append(f"AV_{pol.av_profile}")
                if pol.ips_sensor:
                    active_features.append(f"IPS_{pol.ips_sensor}")
                if pol.webfilter_profile:
                    active_features.append(f"WF_{pol.webfilter_profile}")
                if pol.application_list:
                    active_features.append(f"APP_{pol.application_list}")
                
                group_name = "SPG_" + "_".join(active_features) if active_features else "Migrated_Profiles"
                group_name = re.sub(r'[^a-zA-Z0-9_-]', '_', group_name)[:63]
                
                ir_pol.security_profile_group = group_name
                ir_pol.antivirus = pol.av_profile or "default"
                ir_pol.ips_sensor = pol.ips_sensor or "default"
                ir_pol.webfilter = pol.webfilter_profile or "default"
                ir_pol.application_list = pol.application_list
                ir_pol.ssl_ssh_profile = pol.ssl_ssh_profile
                
                # Check if group already created
                if not any(g.name == group_name for g in self.ir.security_profile_groups):
                    self.ir.security_profile_groups.append(IRSecurityProfileGroup(
                        name=group_name,
                        antivirus=pol.av_profile or "default",
                        vulnerability=pol.ips_sensor or "default",
                        anti_spyware="default",
                        url_filtering=pol.webfilter_profile or "default",
                        file_blocking="basic-file-blocking",
                        wildfire="default",
                        ssl_decryption=pol.ssl_ssh_profile,
                        description=f"Auto-generated profile group for FortiGate UTM ({', '.join(active_features) if active_features else 'General'})"
                    ))
                
                self.ir.audit_entries.append(IRAuditEntry(
                    id=str(pol.id), category="Policy", 
                    message=f"UTM profiles mapped to Security Profile Group '{group_name}'.",
                    confidence=MigrationConfidence.FULL
                ))
                
            self.ir.policies.append(ir_pol)

    def _transform_nat(self):
        # FortiGate ippool -> SNAT
        for pool in self.fg.ip_pools:
            self.ir.nat_rules.append(IRNATRule(
                name=pool.name,
                type=NATType.SOURCE,
                translated_source=f"{pool.startip}-{pool.endip}" if pool.startip != pool.endip else pool.startip,
                description=pool.comments
            ))
            
        # FortiGate vip -> DNAT
        for vip in self.fg.vips:
            # Determine zone
            ext_zone = self._intf_to_zone.get(vip.extintf, "any")
            
            # Bug 7 fix: Include port forwarding in DNAT description and service mapping
            nat_description = vip.comment
            nat_service = "any"
            translated_port = None
            if vip.portforward == "enable" and vip.extport:
                port_info = f"Port forward: {vip.extport}"
                
                # Determine protocol for service mapping (default to TCP)
                svc_proto = ServiceProtocol.UDP if getattr(vip, 'protocol', '').lower() == 'udp' else ServiceProtocol.TCP
                svc_name = f"svc_vip_{vip.name}_{vip.extport}"
                
                # Create the service object for the original port
                self.ir.services.append(IRService(
                    name=svc_name,
                    ports=[IRServicePort(protocol=svc_proto, port=self._clean_port_range(vip.extport))],
                    description=f"Auto-generated service for VIP {vip.name}"
                ))
                nat_service = svc_name
                
                if vip.mappedport:
                    port_info += f" -> {vip.mappedport}"
                    translated_port = self._clean_port_range(vip.mappedport)
                else:
                    # if mappedport is not provided but portforward is enable, mappedport defaults to extport
                    translated_port = self._clean_port_range(vip.extport)
                    
                nat_description = f"{vip.comment + '; ' if vip.comment else ''}{port_info}"
                # We can increase confidence to FULL now since the mapping is automated
                self.ir.audit_entries.append(IRAuditEntry(
                    id=vip.name, category="NAT",
                    message=f"VIP '{vip.name}' port forwarding ({vip.extport} -> {translated_port}) automatically migrated.",
                    confidence=MigrationConfidence.FULL
                ))
            
            self.ir.nat_rules.append(IRNATRule(
                name=vip.name,
                type=NATType.DESTINATION,
                from_zone=[ext_zone] if ext_zone != "any" else ["any"],
                destination=[vip.extip],
                service=nat_service,
                translated_destination=vip.mappedip,
                translated_port=translated_port,
                description=nat_description
            ))

    def _transform_vpn(self):
        for p1 in self.fg.phase1_interfaces:
            self.ir.vpn_tunnels.append(IRVPNTunnel(
                name=p1.name,
                peer_address=p1.remote_gw or "dynamic",
                local_interface=p1.interface,
                ike_version="v1" if p1.ike_version == "1" else "v2",
                psk=p1.psksecret,
                description=p1.comments
            ))
            self.ir.audit_entries.append(IRAuditEntry(
                id=p1.name, category="VPN",
                message="IPsec VPN mapped. Pre-Shared Key (PSK) is encrypted in backup file; retrieve unmasked PSK from FortiGate WebGUI or Azure Portal and set on the target IKE Gateway.",
                confidence=MigrationConfidence.PARTIAL
            ))

    def _mask_to_cidr_str(self, ip_mask_str: str) -> str:
        """Bug 6 fix: Convert 'IP MASK' format to CIDR notation."""
        parts = ip_mask_str.split()
        if len(parts) == 2:
            ip, mask = parts
            try:
                bits = sum(bin(int(x)).count('1') for x in mask.split('.'))
                return f"{ip}/{bits}"
            except Exception:
                return f"{ip}/0"
        # Already in CIDR or single IP
        if '/' in ip_mask_str:
            return ip_mask_str
        return f"{ip_mask_str}/32"

    def _transform_routes(self):
        for rt in self.fg.static_routes:
            dst_raw = rt.dst or "0.0.0.0 0.0.0.0"
            dst_cidr = self._mask_to_cidr_str(dst_raw)
            self.ir.routes.append(IRRoute(
                name=f"route_{rt.id}",
                destination=dst_cidr,
                interface=rt.device,
                next_hop=rt.gateway,
                metric=rt.distance,
                description=rt.comment
            ))
