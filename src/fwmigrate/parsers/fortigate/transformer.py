from typing import Dict, List, Set
from fwmigrate.parsers.fortigate.model import FGConfig, FGInterface
from fwmigrate.ir.core import (
    IRConfig, IRMetadata, IRZone, IRInterface, IRAddress, AddressType,
    IRAddressGroup, IRService, IRServicePort, ServiceProtocol, IRServiceGroup,
    IRSchedule, IRPolicy, PolicyAction, IRNATRule, NATType, IRVPNTunnel,
    IRRoute, IRAuditEntry, MigrationConfidence, IRSecurityProfileGroup
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
        
    def transform(self) -> IRConfig:
        self._transform_interfaces_and_zones()
        self._transform_addresses()
        self._transform_services()
        self._transform_schedules()
        self._transform_policies()
        self._transform_nat()
        self._transform_vpn()
        self._transform_routes()
        return self.ir

    def _get_zone_for_intf(self, intf: FGInterface) -> str:
        if intf.name in self.zone_mapping:
            return self.zone_mapping[intf.name]
        
        # If part of SDWAN, use the SDWAN zone if possible (simplified for MVP)
        if self.fg.sdwan:
            for member in self.fg.sdwan.members:
                if member.interface == intf.name:
                    return member.zone
                    
        if intf.role != "undefined":
            # Map role to zone name: wan -> untrust, lan -> trust, dmz -> dmz
            role_map = {"wan": "untrust", "lan": "trust", "dmz": "dmz"}
            return role_map.get(intf.role, intf.role)
            
        return "untrust" # default fallback

    def _transform_interfaces_and_zones(self):
        zones_map: Dict[str, IRZone] = {}
        
        for intf in self.fg.interfaces:
            zone_name = self._get_zone_for_intf(intf)
            self._intf_to_zone[intf.name] = zone_name
            
            if zone_name not in zones_map:
                zones_map[zone_name] = IRZone(name=zone_name)
            
            zones_map[zone_name].interfaces.append(intf.name)
            
            # Format IP: 10.0.0.1 255.255.255.0 -> CIDR
            ip_cidr = None
            if intf.ip:
                parts = intf.ip.split()
                if len(parts) == 2:
                    ip, mask = parts
                    # Simplistic mask to cidr for common masks
                    mask_map = {"255.255.255.0": "/24", "255.255.255.252": "/30", "255.255.255.255": "/32", "255.255.0.0": "/16", "255.0.0.0": "/8"}
                    cidr = mask_map.get(mask, "") # For MVP, fallback to empty or implement real logic
                    if not cidr:
                        # calculate bits
                        try:
                            bits = sum(bin(int(x)).count('1') for x in mask.split('.'))
                            cidr = f"/{bits}"
                        except Exception:
                            pass
                    ip_cidr = f"{ip}{cidr}"
                    
            self.ir.interfaces.append(IRInterface(
                name=intf.name,
                zone=zone_name,
                ip=ip_cidr,
                description=intf.description
            ))
            
        self.ir.zones = list(zones_map.values())

    def _transform_addresses(self):
        for addr in self.fg.addresses:
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
            elif addr.type == "iprange" and addr.start_ip and addr.end_ip:
                addr_type = AddressType.RANGE
                val = f"{addr.start_ip}-{addr.end_ip}"
            elif addr.type == "dynamic":
                addr_type = AddressType.DYNAMIC
                val = addr.sdn or "dynamic"
                self.ir.audit_entries.append(IRAuditEntry(
                    id=addr.name, category="Address", message="Dynamic/EMS Tag addresses are FortiGate specific.",
                    confidence=MigrationConfidence.MANUAL
                ))
                
            self.ir.addresses.append(IRAddress(
                name=addr.name, type=addr_type, value=val, description=addr.comment
            ))
            
        for fqdn in self.fg.wildcard_fqdns:
            self.ir.addresses.append(IRAddress(
                name=fqdn.name, type=AddressType.WILDCARD_FQDN, value=fqdn.wildcard_fqdn, description=fqdn.comment
            ))
            
        for grp in self.fg.address_groups:
            self.ir.address_groups.append(IRAddressGroup(
                name=grp.name, members=grp.member, description=grp.comment
            ))

    def _transform_services(self):
        for svc in self.fg.services:
            ports = []
            if svc.tcp_portrange:
                ports.append(IRServicePort(protocol=ServiceProtocol.TCP, port=svc.tcp_portrange.replace(':', '-')))
            if svc.udp_portrange:
                ports.append(IRServicePort(protocol=ServiceProtocol.UDP, port=svc.udp_portrange.replace(':', '-')))
            if svc.protocol == "ICMP":
                ports.append(IRServicePort(protocol=ServiceProtocol.ICMP, port="any"))
            elif svc.protocol == "IP" and svc.protocol_number:
                # E.g. OSPF (89), GRE (47)
                pass # PAN-OS usually handles these differently, might need a custom object
                
            if not ports:
                # Default TCP/UDP if unspecified or custom protocol
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
            # Minimal mapping for MVP
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
                source=pol.srcaddr,
                destination=pol.dstaddr,
                service=pol.service,
                action=action,
                description=pol.comments,
                disabled=(pol.status == "disable")
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
            self.ir.nat_rules.append(IRNATRule(
                name=vip.name,
                type=NATType.DESTINATION,
                from_zone=[ext_zone] if ext_zone != "any" else ["any"],
                destination=[vip.extip],
                translated_destination=vip.mappedip,
                description=vip.comment
            ))

    def _transform_vpn(self):
        # For MVP, link phase1 and phase2 by name loosely
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

    def _transform_routes(self):
        for rt in self.fg.static_routes:
            self.ir.routes.append(IRRoute(
                name=f"route_{rt.id}",
                destination=rt.dst or "0.0.0.0 0.0.0.0",
                interface=rt.device,
                next_hop=rt.gateway,
                metric=rt.distance,
                description=rt.comment
            ))
