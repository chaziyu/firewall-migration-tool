from typing import Dict, List, Set, Optional, Tuple
from pydantic import ValidationError
from fwmigrate.parsers.fortigate.model import FGConfig, FGInterface
from fwmigrate.ir.core import (
    IRConfig, IRMetadata, IRZone, IRInterface, IRAddress, AddressType,
    IRAddressGroup, IRService, IRServicePort, ServiceProtocol, IRServiceGroup,
    IRSchedule, IRPolicy, PolicyAction, IRIPPool, IRVirtualIP,
    IRVirtualIPRealServer, IRNATRule, NATType, NATTranslationMode, IRVPNTunnel,
    IRRoute, IRAuditEntry, MigrationConfidence, IRSecurityProfileGroup, IRInternetService
)
from fwmigrate.parsers.vendor_maps import normalize_to_ir
from fwmigrate.core.constants import IR_KEYWORD_ANY
from fwmigrate.core.stubs import create_unsupported_stub
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
        self._transform_ip_pools()
        self._transform_virtual_ips()
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

    def _create_ir_address(self, name, addr_type, val, description, is_ipv6=False, is_multicast=False):
        kwargs = {
            "name": name,
            "type": addr_type,
            "description": description,
            "is_ipv6": is_ipv6,
            "is_multicast": is_multicast
        }
        
        if addr_type in (AddressType.NETWORK, AddressType.HOST):
            kwargs["subnet"] = val
        elif addr_type == AddressType.RANGE:
            if "-" in val:
                kwargs["ip_range_start"] = val.split("-")[0]
                kwargs["ip_range_end"] = val.split("-")[1]
        elif addr_type in (AddressType.FQDN, AddressType.WILDCARD_FQDN):
            kwargs["fqdn"] = val
        elif addr_type == AddressType.MAC:
            kwargs["mac"] = val
        elif addr_type == AddressType.GEO:
            kwargs["geo_code"] = val
        elif addr_type == AddressType.WILDCARD_MASK:
            kwargs["wildcard_mask"] = val
        elif addr_type == AddressType.DYNAMIC:
            kwargs["dynamic_filter"] = val
        elif addr_type == AddressType.EMS_TAG:
            kwargs["tag_name"] = val

        try:
            return IRAddress(**kwargs)
        except ValidationError as e:
            # Rebuild kwargs for graceful degradation
            safe_kwargs = {
                "name": name,
                "type": addr_type,
                "description": description,
                "is_ipv6": is_ipv6,
                "is_multicast": is_multicast,
                "parse_error": str(e),
                "raw_value": val
            }
            self.ir.audit_entries.append(IRAuditEntry(
                id=name, category="Address", message=f"Address '{name}' failed strict validation: {str(e)}",
                confidence=MigrationConfidence.UNSUPPORTED
            ))
            return IRAddress(**safe_kwargs)

    def _transform_addresses(self):
        # 1. Build Reference Mappings for VPN dummy objects
        tunnel_routes = {}
        for rt in self.fg.static_routes:
            dst_raw = rt.dst or "0.0.0.0 0.0.0.0"
            if rt.device and dst_raw and dst_raw != "0.0.0.0 0.0.0.0":
                tunnel_routes[rt.device] = self._mask_to_cidr_str(dst_raw)
                
        local_subnets = []
        import ipaddress
        for intf in self.fg.interfaces:
            if intf.role in ['lan', 'trust'] and intf.ip:
                cidr_str = self._mask_to_cidr_str(intf.ip)
                try:
                    net = ipaddress.ip_network(cidr_str, strict=False)
                    local_subnets.append(str(net))
                except Exception:
                    local_subnets.append(cidr_str)
                    
        # Fallback if no explicit role is set
        if not local_subnets:
            for intf in self.fg.interfaces:
                if self._get_zone_for_intf(intf) == 'trust' and intf.ip:
                    cidr_str = self._mask_to_cidr_str(intf.ip)
                    try:
                        net = ipaddress.ip_network(cidr_str, strict=False)
                        local_subnets.append(str(net))
                    except Exception:
                        local_subnets.append(cidr_str)

        skip_addresses = {"all", "none", "FABRIC_DEVICE", "FIREWALL_AUTH_PORTAL_ADDRESS", "EIGRP", "OSPF", "SSLVPN_TUNNEL_IPv6_ADDR1"}
        for addr in self.fg.addresses:
            if addr.name in skip_addresses:
                continue
            addr_type = AddressType.NETWORK
            val = ""
            
            # --- Dummy Object Resolution ---
            if not addr.subnet and addr.type not in ["fqdn", "mac", "geography", "dynamic"]:
                if "remote_subnet" in addr.name:
                    tunnel_name = addr.name.split("_remote_subnet")[0]
                    if tunnel_name in tunnel_routes:
                        val = tunnel_routes[tunnel_name]
                        self.ir.audit_entries.append(IRAuditEntry(
                            id=addr.name, category="Address", 
                            message=f"Inferred empty VPN remote subnet '{addr.name}' from route pointing to '{tunnel_name}'.",
                            confidence=MigrationConfidence.FULL
                        ))
                elif "local_subnet" in addr.name:
                    if local_subnets:
                        val = local_subnets[0]
                        self.ir.audit_entries.append(IRAuditEntry(
                            id=addr.name, category="Address", 
                            message=f"Inferred empty VPN local subnet '{addr.name}' from primary local interface.",
                            confidence=MigrationConfidence.FULL
                        ))
            
            if not val:
                if addr.type == "ipmask" and addr.subnet:
                    parts = addr.subnet.split()
                    if len(parts) == 2:
                        ip, mask = parts
                        try:
                            bits = sum(bin(int(x)).count('1') for x in mask.split('.'))
                            val = f"{ip}/{bits}"
                        except Exception:
                            val = f"{ip}/32"
                elif (addr.type in ["ipmask", "iprange"] or addr.is_multicast) and addr.start_ip and addr.end_ip:
                    if addr.start_ip == addr.end_ip:
                        addr_type = AddressType.HOST
                        val = f"{addr.start_ip}/32"
                    else:
                        addr_type = AddressType.RANGE
                        val = f"{addr.start_ip}-{addr.end_ip}"
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
                    raw_mac = addr.macaddr or addr.mac or addr.subnet or "00:00:00:00:00:00"
                    stub_obj = create_unsupported_stub(
                        name=addr.name,
                        original_type="mac",
                        original_value=raw_mac,
                        description=addr.comment
                    )
                    self.ir.addresses.append(stub_obj)
                    self.ir.audit_entries.append(IRAuditEntry(
                        id=addr.name,
                        category="Address",
                        message=stub_obj.audit_note or f"Unsupported MAC object '{addr.name}' converted to RFC 5737 stub",
                        confidence=MigrationConfidence.MANUAL
                    ))
                    continue
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
                
            if not val:
                # If value is still empty (e.g. built-in routing placeholder with no subnet), safely skip
                continue

            self.ir.addresses.append(self._create_ir_address(
                name=addr.name, addr_type=addr_type, val=val, description=addr.comment,
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
            self.ir.addresses.append(self._create_ir_address(
                name=fqdn.name, addr_type=AddressType.WILDCARD_FQDN, val=val, description=fqdn.comment
            ))
            
        for grp in self.fg.address_groups:
            self.ir.address_groups.append(IRAddressGroup(
                name=grp.name, members=grp.member, description=grp.comment
            ))

    def _clean_port_range(self, port_str: str) -> str:
        """Extract destination port and normalize FortiGate [dst_port]:[src_port] syntax for a single port entry."""
        if not port_str:
            return IR_KEYWORD_ANY
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
            return [IRServicePort(protocol=protocol, port=IR_KEYWORD_ANY)]
        # FortiGate may use comma or space to separate multiple port ranges
        parts = [p.strip() for p in port_str.replace(",", " ").split() if p.strip()]
        result = []
        for part in parts:
            cleaned = self._clean_port_range(part)
            result.append(IRServicePort(protocol=protocol, port=cleaned))
        return result if result else [IRServicePort(protocol=protocol, port=IR_KEYWORD_ANY)]

    def _transform_services(self):
        for svc in self.fg.services:
            ports = []
            if svc.tcp_portrange:
                ports.extend(self._parse_port_ranges(svc.tcp_portrange, ServiceProtocol.TCP))
            if svc.udp_portrange:
                ports.extend(self._parse_port_ranges(svc.udp_portrange, ServiceProtocol.UDP))
            if svc.protocol in ["ICMP", "ICMP6"]:
                ports.append(IRServicePort(protocol=ServiceProtocol.ICMP, port=IR_KEYWORD_ANY, icmptype=svc.icmptype, icmpcode=svc.icmpcode))
            elif svc.protocol == "IP" and svc.protocol_number:
                ports.append(IRServicePort(protocol=ServiceProtocol.IP, port=str(svc.protocol_number)))
                
            if not ports:
                # Default TCP if unspecified
                ports.append(IRServicePort(protocol=ServiceProtocol.TCP, port=IR_KEYWORD_ANY))
                
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
            from_zones = list(dict.fromkeys(
                self._intf_to_zone.get(intf, "untrust") for intf in pol.srcintf if intf != "any"
            ))
            to_zones = list(dict.fromkeys(
                self._intf_to_zone.get(intf, "untrust") for intf in pol.dstintf if intf != "any"
            ))
            
            if "any" in pol.srcintf or not from_zones:
                from_zones = [IR_KEYWORD_ANY]
            if "any" in pol.dstintf or not to_zones:
                to_zones = [IR_KEYWORD_ANY]
                
            action = PolicyAction.DENY
            if pol.action == "accept":
                action = PolicyAction.ALLOW
                

            ir_pol = IRPolicy(
                name=pol.name or f"Rule_{pol.id}",
                source_rule_id=str(pol.id),
                source_uuid=pol.uuid,
                source_from_interfaces=list(pol.srcintf),
                source_to_interfaces=list(pol.dstintf),
                source_user_groups=list(pol.groups),
                source_users=list(pol.users),
                source_log_setting=pol.logtraffic,
                nat_enabled=(pol.nat == "enable"),
                nat_pool_enabled=(pol.ippool == "enable"),
                nat_pool_names=list(pol.poolname),
                from_zone=from_zones,
                to_zone=to_zones,
                source=[normalize_to_ir("fortigate", a) for a in pol.srcaddr],
                destination=[normalize_to_ir("fortigate", a) for a in pol.dstaddr],
                service=[normalize_to_ir("fortigate", s) for s in pol.service],
                action=action,
                description=pol.comments,
                schedule=pol.schedule if pol.schedule and pol.schedule != "always" else None,
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

    @staticmethod
    def _fortios_enabled(value: Optional[str]) -> Optional[bool]:
        if value is None:
            return None
        return value == "enable"

    def _transform_ip_pools(self):
        for pool in self.fg.ip_pools:
            self.ir.ip_pools.append(IRIPPool(
                name=pool.name,
                pool_type=pool.type,
                start_ip=pool.startip,
                end_ip=pool.endip,
                source_start_ip=pool.source_startip,
                source_end_ip=pool.source_endip,
                source_prefix6=pool.source_prefix6,
                start_port=pool.startport,
                end_port=pool.endport,
                associated_interface=pool.associated_interface,
                arp_reply=self._fortios_enabled(pool.arp_reply),
                arp_interface=pool.arp_intf,
                permit_any_host=self._fortios_enabled(pool.permit_any_host),
                excluded_ips=list(pool.exclude_ip),
                block_size=pool.block_size,
                blocks_per_user=pool.num_blocks_per_user,
                pba_timeout=pool.pba_timeout,
                pba_interim_log=pool.pba_interim_log,
                ports_per_user=pool.port_per_user,
                privileged_port_use_pba=self._fortios_enabled(pool.privileged_port_use_pba),
                nat64=self._fortios_enabled(pool.nat64),
                add_nat64_route=self._fortios_enabled(pool.add_nat64_route),
                client_prefix_length=pool.client_prefix_length,
                include_subnet_broadcast=self._fortios_enabled(pool.subnet_broadcast_in_ippool),
                tcp_session_quota=pool.tcp_session_quota,
                udp_session_quota=pool.udp_session_quota,
                icmp_session_quota=pool.icmp_session_quota,
                description=pool.comments,
            ))

    def _transform_virtual_ips(self):
        for vip in self.fg.vips:
            self.ir.virtual_ips.append(IRVirtualIP(
                name=vip.name,
                source_id=vip.id,
                source_uuid=vip.uuid,
                vip_type=vip.type,
                enabled=(vip.status != "disable"),
                external_ip=vip.extip,
                external_addresses=list(vip.extaddr),
                external_interface=vip.extintf,
                mapped_ips=list(vip.mappedip),
                mapped_address=vip.mapped_addr,
                port_forward=(vip.portforward == "enable"),
                protocol=vip.protocol,
                external_port=vip.extport,
                mapped_port=vip.mappedport,
                port_mapping_type=vip.portmapping_type,
                arp_reply=self._fortios_enabled(vip.arp_reply),
                gratuitous_arp_interval=vip.gratuitous_arp_interval,
                nat_source_vip=self._fortios_enabled(vip.nat_source_vip),
                source_filters=list(vip.src_filter),
                source_interface_filters=list(vip.srcintf_filter),
                services=list(vip.service),
                load_balance_method=vip.ldb_method,
                server_type=vip.server_type,
                persistence=vip.persistence,
                http_redirect=self._fortios_enabled(vip.http_redirect),
                monitors=list(vip.monitor),
                max_embryonic_connections=vip.max_embryonic_connections,
                real_servers=[
                    IRVirtualIPRealServer(
                        id=server.id,
                        address=server.ip,
                        port=server.port,
                        status=server.status,
                        weight=server.weight,
                        holddown_interval=server.holddown_interval,
                    )
                    for server in vip.realservers
                ],
                color=vip.color,
                description=vip.comment,
                extra_settings=dict(vip.extra_settings),
            ))

    def _transform_nat(self):
        """Correlate policy match semantics with referenced NAT resources."""
        pools_by_name = {pool.name: pool for pool in self.ir.ip_pools}
        vips_by_name = {vip.name: vip for vip in self.fg.vips}
        vip_groups_by_name = {group.name: group for group in self.fg.vip_groups}

        def audit(policy_id: int, message: str, confidence=MigrationConfidence.PARTIAL):
            self.ir.audit_entries.append(IRAuditEntry(
                id=f"nat-policy-{policy_id}",
                category="NAT",
                message=message,
                confidence=confidence,
            ))

        for policy_index, (pol, ir_pol) in enumerate(zip(self.fg.policies, self.ir.policies), 1):
            vip_matches = []
            ordinary_destinations = []

            for destination in pol.dstaddr:
                if destination in vips_by_name:
                    vip_matches.append((vips_by_name[destination], None))
                    continue

                vip_group = vip_groups_by_name.get(destination)
                if vip_group is None:
                    ordinary_destinations.append(normalize_to_ir("fortigate", destination))
                    continue

                for member in vip_group.member:
                    vip = vips_by_name.get(member)
                    if vip is None:
                        audit(
                            pol.id,
                            f"Policy {pol.id} VIP group '{vip_group.name}' references missing VIP '{member}'.",
                            MigrationConfidence.MANUAL,
                        )
                        continue
                    vip_matches.append((vip, vip_group.name))

            snat_enabled = pol.nat == "enable"
            source_mode = None
            pool_references = []
            pool_type = None
            translated_sources = []
            source_requires_review = False

            if snat_enabled and pol.ippool == "enable":
                source_mode = NATTranslationMode.POOL
                pool_references = list(pol.poolname)
                resolved_pool_types = []
                if not pool_references:
                    source_requires_review = True
                    audit(
                        pol.id,
                        f"Policy {pol.id} enables an IP pool but has no pool reference; interface NAT was not substituted.",
                        MigrationConfidence.MANUAL,
                    )
                for pool_name in pool_references:
                    pool = pools_by_name.get(pool_name)
                    if pool is None:
                        source_requires_review = True
                        audit(
                            pol.id,
                            f"Policy {pol.id} references missing IP pool '{pool_name}'; the unresolved name was preserved.",
                            MigrationConfidence.MANUAL,
                        )
                        continue
                    resolved_pool_types.append(pool.pool_type or "overload")
                    if pool.start_ip and pool.end_ip:
                        translated_sources.append(
                            pool.start_ip if pool.start_ip == pool.end_ip
                            else f"{pool.start_ip}-{pool.end_ip}"
                        )
                    elif pool.start_ip:
                        translated_sources.append(pool.start_ip)
                    else:
                        source_requires_review = True
                        audit(
                            pol.id,
                            f"Policy {pol.id} IP pool '{pool.name}' has no translated address range.",
                            MigrationConfidence.MANUAL,
                        )

                    if pool.pool_type not in (None, "overload", "one-to-one") or pool.nat64:
                        source_requires_review = True
                        audit(
                            pol.id,
                            f"Policy {pol.id} uses advanced IP pool '{pool.name}' type "
                            f"'{pool.pool_type}' that requires target-specific review.",
                        )
                if resolved_pool_types:
                    pool_type = resolved_pool_types[0] if len(set(resolved_pool_types)) == 1 else "mixed"
                    if pool_type == "one-to-one" and (
                        len(translated_sources) != 1 or "-" in translated_sources[0]
                    ):
                        source_requires_review = True
                        audit(
                            pol.id,
                            f"Policy {pol.id} one-to-one pool correlation was preserved but cannot be "
                            "rendered as one PAN-OS static source translation without review.",
                        )
            elif snat_enabled:
                source_mode = NATTranslationMode.INTERFACE_ADDRESS
                known_interfaces = {interface.name for interface in self.fg.interfaces}
                if (
                    len(pol.dstintf) != 1
                    or pol.dstintf[0] in ("any", "virtual-wan-link")
                    or pol.dstintf[0] not in known_interfaces
                ):
                    source_requires_review = True
                    audit(
                        pol.id,
                        f"Policy {pol.id} uses interface-address SNAT but its exact egress interface "
                        f"cannot be selected safely from {pol.dstintf!r}.",
                        MigrationConfidence.MANUAL,
                    )

            if pol.internet_service == "enable":
                source_requires_review = True
                audit(
                    pol.id,
                    f"Policy {pol.id} NAT match uses FortiGate Internet Service references; "
                    "they were preserved but require target-specific review.",
                )

            if snat_enabled and (not pol.srcaddr or not pol.dstaddr or not pol.service):
                source_requires_review = True
                audit(
                    pol.id,
                    f"Policy {pol.id} has incomplete ordinary NAT match fields; missing values were not replaced with 'any'.",
                    MigrationConfidence.MANUAL,
                )
            if vip_matches and (not pol.srcaddr or not pol.service):
                source_requires_review = True
                audit(
                    pol.id,
                    f"Policy {pol.id} has incomplete DNAT match fields; missing values were not replaced with 'any'.",
                    MigrationConfidence.MANUAL,
                )

            common = dict(
                source_policy_reference=str(pol.id),
                source_policy_uuid=pol.uuid,
                source_policy_name=pol.name,
                sequence=policy_index,
                enabled=(pol.status != "disable"),
                source_from_interfaces=list(pol.srcintf),
                source_to_interfaces=list(pol.dstintf),
                from_zone=list(ir_pol.from_zone),
                source=list(ir_pol.source),
                services=list(ir_pol.service),
                internet_services=list(pol.internet_service_name),
                source_translation_mode=source_mode,
                source_pool_references=pool_references,
                source_pool_type=pool_type,
                translated_sources=translated_sources,
                requires_manual_review=source_requires_review,
                description=pol.comments,
            )

            for vip, vip_group_name in vip_matches:
                external_destinations = [vip.extip] if vip.extip else list(vip.extaddr)
                translated_destinations = list(vip.mappedip)
                if not translated_destinations and vip.mapped_addr:
                    translated_destinations = [vip.mapped_addr]

                vip_requires_review = source_requires_review
                if not external_destinations or not translated_destinations:
                    vip_requires_review = True
                    audit(
                        pol.id,
                        f"Policy {pol.id} references VIP '{vip.name}' without complete external and mapped addresses.",
                        MigrationConfidence.MANUAL,
                    )
                if len(translated_destinations) > 1:
                    vip_requires_review = True
                    audit(
                        pol.id,
                        f"Policy {pol.id} VIP '{vip.name}' has multiple mapped destinations; all were preserved.",
                    )

                translated_port = None
                original_port = None
                if vip.portforward == "enable" and vip.extport:
                    original_port = self._clean_port_range(vip.extport)
                    translated_port = self._clean_port_range(vip.mappedport or vip.extport)
                    protocol = (vip.protocol or "tcp").lower()
                    if protocol in ("tcp", "udp"):
                        service_name = f"svc_nat_{protocol}_{original_port}"
                        if not any(service.name == service_name for service in self.ir.services):
                            self.ir.services.append(IRService(
                                name=service_name,
                                ports=[IRServicePort(
                                    protocol=(ServiceProtocol.UDP if protocol == "udp" else ServiceProtocol.TCP),
                                    port=original_port,
                                )],
                                description=f"Generated from VIP {vip.name} pre-NAT port",
                            ))
                    else:
                        vip_requires_review = True
                        audit(
                            pol.id,
                            f"Policy {pol.id} VIP '{vip.name}' uses unsupported port-forward protocol '{protocol}'.",
                            MigrationConfidence.MANUAL,
                        )

                if vip.extintf == "any":
                    nat_to_zone = [IR_KEYWORD_ANY]
                elif vip.extintf in self._intf_to_zone:
                    nat_to_zone = [self._intf_to_zone[vip.extintf]]
                else:
                    nat_to_zone = []
                    vip_requires_review = True
                    audit(
                        pol.id,
                        f"Policy {pol.id} VIP '{vip.name}' references unresolved external interface '{vip.extintf}'.",
                        MigrationConfidence.MANUAL,
                    )
                nat_type = NATType.TWICE if snat_enabled else NATType.DESTINATION
                prefix = "TWICE" if nat_type == NATType.TWICE else "DNAT"
                self.ir.nat_rules.append(IRNATRule(
                    name=f"{prefix}-P{pol.id}-{vip.name}",
                    type=nat_type,
                    to_zone=nat_to_zone,
                    destination=external_destinations,
                    translated_destinations=translated_destinations,
                    destination_protocol=vip.protocol,
                    original_destination_port=original_port,
                    translated_port=translated_port,
                    source_vip_reference=vip.name,
                    source_vip_group_reference=vip_group_name,
                    requires_manual_review=vip_requires_review,
                    **{key: value for key, value in common.items() if key != "requires_manual_review"},
                ))

            if snat_enabled and (not vip_matches or ordinary_destinations):
                suffix = "-ordinary" if vip_matches else ""
                self.ir.nat_rules.append(IRNATRule(
                    name=f"SNAT-P{pol.id}{suffix}",
                    type=NATType.SOURCE,
                    to_zone=list(ir_pol.to_zone),
                    destination=(ordinary_destinations if vip_matches else list(ir_pol.destination)),
                    **common,
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


def extract_nat_and_security(
    policy_data: dict,
    vip_inventory: Dict[str, dict],
    service_inventory: Optional[Dict[str, "IRServiceObject"]] = None
) -> Tuple["IRSecurityRule", List["IRNatRule"], List["IRServiceObject"]]:
    """
    Deprecated compatibility helper for the legacy fwmigrate.core.models NAT schema.

    Production FortiGate correlation is implemented by FGToIRTransformer._transform_nat
    and emits fwmigrate.ir.core.IRNATRule objects.
    
    Fixes:
    - Overly Permissive Security Rule: Bounds IRSecurityRule.services to specific PAT ports.
    - Missing Base Services: Captures policy_data['service'] for non-PAT policies.
    - Zone Overwrite Flaw: Aggregates and deduplicates post-NAT destination zones.
    """
    from fwmigrate.core.models import IRSecurityRule, IRNatRule, IRNatType, IRServiceObject, ServiceProtocol

    if service_inventory is None:
        service_inventory = {}

    base_services = list(policy_data.get("service", ["any"]))
    if not base_services:
        base_services = ["any"]

    ir_sec_rule = IRSecurityRule(
        name=policy_data.get("name", "unnamed_policy"),
        from_zones=list(policy_data.get("srcintf", ["any"])),
        to_zones=list(policy_data.get("dstintf", ["any"])),
        sources=list(policy_data.get("srcaddr", ["any"])),
        destinations=list(policy_data.get("dstaddr", ["any"])),
        services=base_services,
        action=policy_data.get("action", "deny"),
        description=policy_data.get("comments")
    )

    ir_nat_rules: List[IRNatRule] = []
    generated_services: List[IRServiceObject] = []
    mapped_post_nat_zones: List[str] = []
    mapped_vip_services: List[str] = []

    # 1. Policy-Level SNAT Extraction
    if policy_data.get("nat") == "enable":
        snat_rule = IRNatRule(
            name=f"SNAT_{ir_sec_rule.name}",
            nat_type=IRNatType.SNAT_DIPP,
            from_zones=list(ir_sec_rule.from_zones),
            to_zones=list(ir_sec_rule.to_zones),
            sources=list(ir_sec_rule.sources),
            destinations=list(ir_sec_rule.destinations),
            service=base_services[0] if base_services else "any",
            translated_sources=policy_data.get("poolname", ["interface-address"]),
            description=f"SNAT for policy {ir_sec_rule.name}"
        )
        ir_nat_rules.append(snat_rule)

    # 2. DNAT (VIP) & PAT Extraction
    for dst in ir_sec_rule.destinations:
        if dst in vip_inventory:
            vip = vip_inventory[dst]
            
            is_portforward = (vip.get("portforward") == "enable" or "extport" in vip)
            service_name = "any"

            if is_portforward and vip.get("extport"):
                raw_proto = vip.get("protocol", "tcp").lower()
                proto = ServiceProtocol.UDP if raw_proto == "udp" else ServiceProtocol.TCP
                ext_port = str(vip["extport"]).strip()
                service_name = f"svc_{proto.value}_{ext_port.replace('-', '_').replace(':', '_')}"
                
                mapped_vip_services.append(service_name)
                
                if service_name not in service_inventory and not any(s.name == service_name for s in generated_services):
                    svc_obj = IRServiceObject(
                        name=service_name,
                        protocol=proto,
                        port=ext_port,
                        description=f"Auto-generated Service for VIP {dst} ({proto.value.upper()}/{ext_port})"
                    )
                    generated_services.append(svc_obj)
                    service_inventory[service_name] = svc_obj

            ext_port_str = str(vip.get("extport", ""))
            mapped_port_str = str(vip.get("mappedport", ext_port_str))

            dnat_rule = IRNatRule(
                name=f"DNAT_{dst}",
                nat_type=IRNatType.DNAT_STATIC,
                from_zones=list(ir_sec_rule.from_zones),
                to_zones=list(ir_sec_rule.from_zones),  # Pre-NAT ingress zone
                sources=list(ir_sec_rule.sources),
                destinations=[vip["extip"]],           # Pre-NAT IP / Object
                service=service_name,
                translated_destinations=[vip["mappedip"]],  # Post-NAT IP
                translated_port=mapped_port_str if is_portforward else None,
                description=f"DNAT VIP {dst} ({ext_port_str} -> {mapped_port_str})" if is_portforward else f"DNAT VIP {dst}"
            )
            ir_nat_rules.append(dnat_rule)

            # Bi-directional 1-to-1 Outbound SNAT Check
            if vip.get("extintf") == "any" and not is_portforward:
                bi_snat_rule = IRNatRule(
                    name=f"SNAT_Outbound_{dst}",
                    nat_type=IRNatType.SNAT_STATIC,
                    from_zones=[vip.get("mapped_interface", "trust")],
                    to_zones=list(ir_sec_rule.from_zones),
                    sources=[vip["mappedip"]],
                    destinations=["any"],
                    service="any",
                    translated_sources=[vip["extip"]],
                    description=f"Bi-directional outbound SNAT for VIP {dst}"
                )
                ir_nat_rules.append(bi_snat_rule)

            # Track Post-NAT Destination Zone
            if vip.get("mapped_interface"):
                mapped_post_nat_zones.append(vip["mapped_interface"])

    # 3. Security Rule Service & Zone Aggregation Fixes
    if mapped_post_nat_zones:
        ir_sec_rule.to_zones = list(dict.fromkeys(mapped_post_nat_zones))

    if mapped_vip_services:
        ir_sec_rule.services = list(dict.fromkeys(mapped_vip_services))
    else:
        cleaned_services = ["any" if s.upper() in ["ALL", "ANY"] else s for s in base_services]
        ir_sec_rule.services = list(dict.fromkeys(cleaned_services))

    return ir_sec_rule, ir_nat_rules, generated_services

