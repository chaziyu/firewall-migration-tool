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
        
        # Network placeholder (interfaces, routing)
        network = etree.SubElement(entry, "network")
        etree.SubElement(network, "interface")
        etree.SubElement(network, "virtual-router")
        
        # VSYS
        vsys = etree.SubElement(entry, "vsys")
        vsys_entry = etree.SubElement(vsys, "entry", name=config.vsys.name)
        
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
                    
        # Address Groups
        if config.vsys.address_groups:
            ag_elem = etree.SubElement(vsys_entry, "address-group")
            for ag in config.vsys.address_groups:
                ag_entry = etree.SubElement(ag_elem, "entry", name=ag.name)
                if ag.static:
                    static = etree.SubElement(ag_entry, "static")
                    for member in ag.static:
                        etree.SubElement(static, "member").text = member
                        
        # Services
        if config.vsys.services:
            svc_elem = etree.SubElement(vsys_entry, "service")
            for s in config.vsys.services:
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
            sg_elem = etree.SubElement(vsys_entry, "service-group")
            for sg in config.vsys.service_groups:
                sg_entry = etree.SubElement(sg_elem, "entry", name=sg.name)
                if sg.members:
                    members = etree.SubElement(sg_entry, "members")
                    for member in sg.members:
                        etree.SubElement(members, "member").text = member
                        
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
                    
                    if n.source_translation:
                        st = etree.SubElement(n_entry, "source-translation")
                        dt = etree.SubElement(st, "dynamic-ip-and-port")
                        t_addr = etree.SubElement(dt, "translated-address")
                        etree.SubElement(t_addr, "member").text = n.source_translation
                        
                    if n.destination_translation:
                        dt = etree.SubElement(n_entry, "destination-translation")
                        t_addr = etree.SubElement(dt, "translated-address")
                        etree.SubElement(t_addr, "member").text = n.destination_translation

        return root
