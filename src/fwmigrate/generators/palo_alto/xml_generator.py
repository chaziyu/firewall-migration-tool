import xml.etree.ElementTree as ET
from typing import List
from lxml import etree
from fwmigrate.core.base_generator import BaseGenerator, MigrationArtifact
from fwmigrate.ir.core import IRConfig
from fwmigrate.generators.palo_alto.transformer import IRToPANOSTransformer
from fwmigrate.generators.palo_alto.model import PANConfig

class PANOSXMLGenerator(BaseGenerator):
    def generate(self, ir: IRConfig) -> List[MigrationArtifact]:
        # 1. Transform IR to PAN-OS semantic model
        transformer = IRToPANOSTransformer(ir)
        pan_config = transformer.transform()
        
        # 2. Generate XML from semantic model
        root = self._build_xml(pan_config)
        
        # 3. Format and return
        xml_bytes = etree.tostring(root, pretty_print=True, encoding="UTF-8", xml_declaration=True)
        xml_str = xml_bytes.decode("utf-8")
        
        return [
            MigrationArtifact(
                filename="palo_alto_config.xml",
                content=xml_str,
                format="xml"
            )
        ]
        
    def _build_xml(self, config: PANConfig) -> etree.Element:
        # Create root <config> element
        root = etree.Element("config", version=config.version, urldb="paloaltonetworks")
        
        devices = etree.SubElement(root, "devices")
        entry = etree.SubElement(devices, "entry", name=config.device_config.hostname)
        
        # Network (interfaces, routing, IPsec)
        network = etree.SubElement(entry, "network")
        
        # Interfaces
        if config.interfaces or config.vpn_tunnels:
            interface_elem = etree.SubElement(network, "interface")
            
            # Ethernet Interfaces
            ethernet_interfaces = [i for i in config.interfaces if not i.name.startswith("tunnel")]
            if ethernet_interfaces:
                ethernet_elem = etree.SubElement(interface_elem, "ethernet")
                for intf in ethernet_interfaces:
                    intf_entry = etree.SubElement(ethernet_elem, "entry", name=intf.name)
                    if intf.ip:
                        layer3 = etree.SubElement(intf_entry, "layer3")
                        ip_elem = etree.SubElement(layer3, "ip")
                        etree.SubElement(ip_elem, "entry", name=intf.ip)
                    if intf.description:
                        etree.SubElement(intf_entry, "comment").text = intf.description
                        
            # Tunnel Interfaces
            tunnel_interfaces = [i for i in config.interfaces if i.name.startswith("tunnel")]
            if config.vpn_tunnels or tunnel_interfaces:
                tunnel_elem = etree.SubElement(interface_elem, "tunnel")
                for vpn in config.vpn_tunnels:
                    tunnel_name = vpn.name if vpn.name.startswith("tunnel.") else f"tunnel.{vpn.name}"
                    t_entry = etree.SubElement(tunnel_elem, "entry", name=tunnel_name)
                    if vpn.description:
                        etree.SubElement(t_entry, "comment").text = f"Auto-generated for VPN {vpn.name}"

        # Virtual Router
        if config.routes:
            vr_elem = etree.SubElement(network, "virtual-router")
            vr_entry = etree.SubElement(vr_elem, "entry", name="default")
            routing_table = etree.SubElement(vr_entry, "routing-table")
            ip_table = etree.SubElement(routing_table, "ip")
            static_route = etree.SubElement(ip_table, "static-route")
            for rt in config.routes:
                if not rt.safe_for_target_generation:
                    continue
                rt_entry = etree.SubElement(static_route, "entry", name=rt.name)
                etree.SubElement(rt_entry, "destination").text = rt.destination
                if rt.next_hop:
                    nexthop = etree.SubElement(rt_entry, "nexthop")
                    etree.SubElement(nexthop, "ip-address").text = rt.next_hop
                if rt.interface:
                    etree.SubElement(rt_entry, "interface").text = rt.interface
                if rt.metric:
                    etree.SubElement(rt_entry, "metric").text = str(rt.metric)

        # IKE/IPsec VPNs
        if config.vpn_tunnels:
            ike_elem = etree.SubElement(network, "ike")
            gateway_elem = etree.SubElement(ike_elem, "gateway")
            ipsec_elem = etree.SubElement(network, "ipsec")
            vpn_tunnel_elem = etree.SubElement(ipsec_elem, "tunnel")
            
            for vpn in config.vpn_tunnels:
                # IKE Gateway
                gw_entry = etree.SubElement(gateway_elem, "entry", name=f"IKE-{vpn.name}")
                if vpn.psk:
                    auth = etree.SubElement(gw_entry, "authentication")
                    psk_elem = etree.SubElement(auth, "pre-shared-key")
                    etree.SubElement(psk_elem, "key").text = vpn.psk
                if vpn.peer_address:
                    peer = etree.SubElement(gw_entry, "peer-address")
                    etree.SubElement(peer, "ip").text = vpn.peer_address
                if vpn.local_interface:
                    local = etree.SubElement(gw_entry, "local-address")
                    etree.SubElement(local, "interface").text = vpn.local_interface
                
                # IPsec Tunnel
                t_entry = etree.SubElement(vpn_tunnel_elem, "entry", name=vpn.name)
                auto = etree.SubElement(t_entry, "auto-key")
                ike_gw = etree.SubElement(auto, "ike-gateway")
                etree.SubElement(ike_gw, "entry", name=f"IKE-{vpn.name}")
        
        # VSYS
        vsys = etree.SubElement(entry, "vsys")
        vsys_entry = etree.SubElement(vsys, "entry", name=config.vsys.name)
        
        # Tags (Global / VSYS Tag Inventory)
        if config.vsys.tags:
            tag_elem = etree.SubElement(vsys_entry, "tag")
            for t in config.vsys.tags:
                t_entry = etree.SubElement(tag_elem, "entry", name=t.name)
                if t.color:
                    etree.SubElement(t_entry, "color").text = t.color
                if t.comments:
                    etree.SubElement(t_entry, "comments").text = t.comments

        # Zones
        if config.vsys.zones:
            zone_elem = etree.SubElement(vsys_entry, "zone")
            for z in config.vsys.zones:
                z_entry = etree.SubElement(zone_elem, "entry", name=z.name)
                net = etree.SubElement(z_entry, "network")
                if z.network.layer3:
                    l3 = etree.SubElement(net, "layer3")
                    for member in z.network.layer3:
                        etree.SubElement(l3, "member").text = member
                        
        # Addresses
        if config.vsys.addresses:
            addr_elem = etree.SubElement(vsys_entry, "address")
            for a in config.vsys.addresses:
                a_entry = etree.SubElement(addr_elem, "entry", name=a.name)
                if a.ip_netmask:
                    etree.SubElement(a_entry, "ip-netmask").text = a.ip_netmask
                elif a.fqdn:
                    etree.SubElement(a_entry, "fqdn").text = a.fqdn
                elif a.ip_range:
                    etree.SubElement(a_entry, "ip-range").text = a.ip_range
                if a.description:
                    etree.SubElement(a_entry, "description").text = a.description
                if a.tag:
                    a_tag = etree.SubElement(a_entry, "tag")
                    for member in a.tag:
                        etree.SubElement(a_tag, "member").text = member
                    
        # Address Groups
        if config.vsys.address_groups:
            ag_elem = etree.SubElement(vsys_entry, "address-group")
            for ag in config.vsys.address_groups:
                ag_entry = etree.SubElement(ag_elem, "entry", name=ag.name)
                if ag.dynamic:
                    dyn = etree.SubElement(ag_entry, "dynamic")
                    etree.SubElement(dyn, "filter").text = ag.dynamic
                elif ag.static:
                    static = etree.SubElement(ag_entry, "static")
                    for member in ag.static:
                        etree.SubElement(static, "member").text = member
                if ag.description:
                    etree.SubElement(ag_entry, "description").text = ag.description
                        
        # Services
        if config.vsys.services:
            svc_elem = None
            for s in config.vsys.services:
                if not s.protocol.tcp and not s.protocol.udp:
                    continue
                if svc_elem is None:
                    svc_elem = etree.SubElement(vsys_entry, "service")
                s_entry = etree.SubElement(svc_elem, "entry", name=s.name)
                proto = etree.SubElement(s_entry, "protocol")
                if s.protocol.tcp:
                    tcp = etree.SubElement(proto, "tcp")
                    etree.SubElement(tcp, "port").text = s.protocol.tcp.port
                elif s.protocol.udp:
                    udp = etree.SubElement(proto, "udp")
                    etree.SubElement(udp, "port").text = s.protocol.udp.port
                if s.description:
                    etree.SubElement(s_entry, "description").text = s.description

        # Service Groups
        if config.vsys.service_groups:
            sg_elem = None
            for sg in config.vsys.service_groups:
                if not sg.members:
                    continue
                if sg_elem is None:
                    sg_elem = etree.SubElement(vsys_entry, "service-group")
                sg_entry = etree.SubElement(sg_elem, "entry", name=sg.name)
                members = etree.SubElement(sg_entry, "members")
                for member in sg.members:
                    etree.SubElement(members, "member").text = member

        # Security Profile Groups
        if config.vsys.profile_groups:
            pg_elem = etree.SubElement(vsys_entry, "profile-group")
            for pg in config.vsys.profile_groups:
                pg_entry = etree.SubElement(pg_elem, "entry", name=pg.name)
                if pg.virus:
                    v_elem = etree.SubElement(pg_entry, "virus")
                    for m in pg.virus:
                        etree.SubElement(v_elem, "member").text = m
                if pg.vulnerability:
                    vuln_elem = etree.SubElement(pg_entry, "vulnerability")
                    for m in pg.vulnerability:
                        etree.SubElement(vuln_elem, "member").text = m
                if pg.spyware:
                    spy_elem = etree.SubElement(pg_entry, "spyware")
                    for m in pg.spyware:
                        etree.SubElement(spy_elem, "member").text = m
                if pg.url_filtering:
                    url_elem = etree.SubElement(pg_entry, "url-filtering")
                    for m in pg.url_filtering:
                        etree.SubElement(url_elem, "member").text = m
                if pg.file_blocking:
                    fb_elem = etree.SubElement(pg_entry, "file-blocking")
                    for m in pg.file_blocking:
                        etree.SubElement(fb_elem, "member").text = m
                if pg.wildfire_analysis:
                    wf_elem = etree.SubElement(pg_entry, "wildfire-analysis")
                    for m in pg.wildfire_analysis:
                        etree.SubElement(wf_elem, "member").text = m
                        
        # Rulebase
        if config.vsys.security_rules or config.vsys.nat_rules:
            rulebase = etree.SubElement(vsys_entry, "rulebase")
            
            # Security Rules
            if config.vsys.security_rules:
                sec = etree.SubElement(rulebase, "security")
                rules = etree.SubElement(sec, "rules")
                for r in config.vsys.security_rules:
                    r_entry = etree.SubElement(rules, "entry", name=r.name)
                    
                    for field in ["to", "from", "source", "destination", "source-user", "category", "application", "service", "source-hip", "destination-hip"]:
                        py_name = field.replace("-", "_")
                        if py_name == "to": py_name = "to_zones"
                        if py_name == "from": py_name = "from_zones"
                        
                        values = getattr(r, py_name)
                        if values:
                            elem = etree.SubElement(r_entry, field)
                            for val in values:
                                etree.SubElement(elem, "member").text = val
                                
                    etree.SubElement(r_entry, "action").text = r.action
                    etree.SubElement(r_entry, "log-start").text = r.log_start
                    etree.SubElement(r_entry, "log-end").text = r.log_end
                    if r.disabled == "yes":
                        etree.SubElement(r_entry, "disabled").text = "yes"
                    if r.description:
                        etree.SubElement(r_entry, "description").text = r.description
                    if r.profile_setting_group:
                        ps = etree.SubElement(r_entry, "profile-setting")
                        grp = etree.SubElement(ps, "group")
                        etree.SubElement(grp, "member").text = r.profile_setting_group
                        
            # NAT Rules
            if config.vsys.nat_rules:
                nat = etree.SubElement(rulebase, "nat")
                rules = etree.SubElement(nat, "rules")
                for n in config.vsys.nat_rules:
                    n_entry = etree.SubElement(rules, "entry", name=n.name)
                    
                    for field in ["to", "from", "source", "destination"]:
                        py_name = field
                        if field == "to": py_name = "to_zones"
                        if field == "from": py_name = "from_zones"
                        
                        values = getattr(n, py_name)
                        if values:
                            elem = etree.SubElement(n_entry, field)
                            for val in values:
                                etree.SubElement(elem, "member").text = val
                                
                    etree.SubElement(n_entry, "service").text = n.service
                    
                    if n.source_translation_mode == "interface-address":
                        st = etree.SubElement(n_entry, "source-translation")
                        dipp = etree.SubElement(st, "dynamic-ip-and-port")
                        interface_address = etree.SubElement(dipp, "interface-address")
                        etree.SubElement(interface_address, "interface").text = n.source_translation_interface
                    elif n.source_translation_mode == "dynamic-ip-and-port" and n.source_translations:
                        st = etree.SubElement(n_entry, "source-translation")
                        dipp = etree.SubElement(st, "dynamic-ip-and-port")
                        translated_address = etree.SubElement(dipp, "translated-address")
                        for address in n.source_translations:
                            etree.SubElement(translated_address, "member").text = address
                    elif n.source_translation_mode == "static" and n.source_translations:
                        st = etree.SubElement(n_entry, "source-translation")
                        static_ip = etree.SubElement(st, "static-ip")
                        etree.SubElement(static_ip, "translated-address").text = n.source_translations[0]
                        
                    if n.destination_translation:
                        dt = etree.SubElement(n_entry, "destination-translation")
                        etree.SubElement(dt, "translated-address").text = n.destination_translation
                        if getattr(n, 'destination_translated_port', None):
                            etree.SubElement(dt, "translated-port").text = str(n.destination_translated_port)

                    if n.disabled == "yes":
                        etree.SubElement(n_entry, "disabled").text = "yes"
                    if n.description:
                        etree.SubElement(n_entry, "description").text = n.description

        return root


def generate_panos_dnat_xml(ir_nat_rule: "IRNatRule") -> str:
    """
    Deprecated helper for fwmigrate.core.models.IRNatRule compatibility tests.

    Production XML generation consumes fwmigrate.ir.core.IRNATRule through
    IRToPANOSTransformer.

    Renders PAN-OS XML for a Destination NAT policy.
    Enforces Pre-NAT zones and Pre-NAT destination IPs, with optional port translation.
    """
    from_zone_xml = "".join(f"<member>{z}</member>" for z in (ir_nat_rule.from_zones or []))
    to_zone_xml = "".join(f"<member>{z}</member>" for z in (ir_nat_rule.to_zones or []))
    src_xml = "".join(f"<member>{s}</member>" for s in (ir_nat_rule.sources or []))
    dst_xml = "".join(f"<member>{d}</member>" for d in (ir_nat_rule.destinations or []))
    svc_str = ir_nat_rule.service if getattr(ir_nat_rule, 'service', None) else "any"
    
    port_xml = ""
    if getattr(ir_nat_rule, 'translated_port', None):
        port_xml = f"\n            <translated-port>{ir_nat_rule.translated_port}</translated-port>"

    translated_dst = ir_nat_rule.translated_destinations[0] if ir_nat_rule.translated_destinations else ""

    return f"""    <entry name="{ir_nat_rule.name}">
        <to>{to_zone_xml}</to>
        <from>{from_zone_xml}</from>
        <source>{src_xml}</source>
        <destination>{dst_xml}</destination>
        <service>{svc_str}</service>
        <destination-translation>
            <translated-address>{translated_dst}</translated-address>{port_xml}
        </destination-translation>
    </entry>
"""

