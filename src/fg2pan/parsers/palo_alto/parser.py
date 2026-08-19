import xml.etree.ElementTree as ET
from typing import Optional, Dict, List
from fg2pan.core.base_parser import BaseSourceParser
from fg2pan.ir.core import (
    IRConfig, IRMetadata, IRZone, IRInterface, IRAddress, IRAddressGroup,
    IRService, IRServicePort, IRServiceGroup, IRPolicy, IRNATRule, IRRoute
)
from fg2pan.ir.enums import AddressType, ServiceProtocol, PolicyAction, NATType

class PANOSSourceParser(BaseSourceParser):
    """Parses Palo Alto Networks PAN-OS XML configuration exports into canonical IRConfig."""

    @property
    def vendor_id(self) -> str:
        return "palo_alto"

    @property
    def display_name(self) -> str:
        return "Palo Alto Networks (PAN-OS)"

    @property
    def supported_extensions(self) -> List[str]:
        return [".xml", ".txt", ".conf"]

    def parse(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> IRConfig:
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            # Handle possible surrounding whitespace or partial tags
            cleaned = content.strip()
            root = ET.fromstring(cleaned)

        # 1. Metadata
        hostname = "palo-alto-fw"
        host_elem = root.find(".//system/hostname")
        if host_elem is None:
            host_elem = root.find(".//deviceconfig/system/hostname")
        if host_elem is not None and host_elem.text:
            hostname = host_elem.text.strip()

        ir = IRConfig(
            metadata=IRMetadata(
                hostname=hostname,
                source_vendor="palo_alto"
            )
        )

        # Find vsys root or shared root
        vsys_elem = root.find(".//vsys/entry")
        search_root = vsys_elem if vsys_elem is not None else root

        # 2. Zones
        zones_dict: Dict[str, List[str]] = {}
        for z_entry in search_root.findall(".//zone/entry"):
            z_name = z_entry.get("name")
            if z_name:
                intfs = [m.text for m in z_entry.findall(".//network/layer3/member") if m.text]
                zones_dict[z_name] = intfs
                ir.zones.append(IRZone(name=z_name, interfaces=intfs))
                for intf in intfs:
                    ir.interfaces.append(IRInterface(name=intf, zone=z_name))

        # 3. Addresses
        for a_entry in search_root.findall(".//address/entry"):
            a_name = a_entry.get("name")
            if not a_name:
                continue

            desc_elem = a_entry.find("description")
            desc = desc_elem.text if desc_elem is not None else None

            ip_netmask = a_entry.find("ip-netmask")
            ip_range = a_entry.find("ip-range")
            fqdn = a_entry.find("fqdn")

            if ip_netmask is not None and ip_netmask.text:
                val = ip_netmask.text.strip()
                if val.endswith("/32") or "/128" in val:
                    a_type = AddressType.HOST
                else:
                    a_type = AddressType.NETWORK if "/" in val else AddressType.HOST
                ir.addresses.append(IRAddress(name=a_name, type=a_type, value=val, description=desc))
            elif ip_range is not None and ip_range.text:
                ir.addresses.append(IRAddress(name=a_name, type=AddressType.RANGE, value=ip_range.text.strip(), description=desc))
            elif fqdn is not None and fqdn.text:
                ir.addresses.append(IRAddress(name=a_name, type=AddressType.FQDN, value=fqdn.text.strip(), description=desc))

        # 4. Address Groups
        for g_entry in search_root.findall(".//address-group/entry"):
            g_name = g_entry.get("name")
            if not g_name:
                continue
            desc_elem = g_entry.find("description")
            desc = desc_elem.text if desc_elem is not None else None

            members = [m.text for m in g_entry.findall(".//static/member") if m.text]
            ir.address_groups.append(IRAddressGroup(name=g_name, members=members, description=desc))

        # 5. Services
        for s_entry in search_root.findall(".//service/entry"):
            s_name = s_entry.get("name")
            if not s_name:
                continue
            desc_elem = s_entry.find("description")
            desc = desc_elem.text if desc_elem is not None else None

            ports: List[IRServicePort] = []
            tcp_port = s_entry.find(".//protocol/tcp/port")
            if tcp_port is not None and tcp_port.text:
                ports.append(IRServicePort(protocol=ServiceProtocol.TCP, port=tcp_port.text.strip()))

            udp_port = s_entry.find(".//protocol/udp/port")
            if udp_port is not None and udp_port.text:
                ports.append(IRServicePort(protocol=ServiceProtocol.UDP, port=udp_port.text.strip()))

            if ports:
                ir.services.append(IRService(name=s_name, ports=ports, description=desc))

        # 6. Service Groups
        for sg_entry in search_root.findall(".//service-group/entry"):
            sg_name = sg_entry.get("name")
            if not sg_name:
                continue
            members = [m.text for m in sg_entry.findall(".//members/member") if m.text]
            ir.service_groups.append(IRServiceGroup(name=sg_name, members=members))

        # 7. Security Policies
        for p_entry in search_root.findall(".//rulebase/security/rules/entry"):
            p_name = p_entry.get("name")
            if not p_name:
                continue

            from_zones = [m.text for m in p_entry.findall(".//from/member") if m.text]
            to_zones = [m.text for m in p_entry.findall(".//to/member") if m.text]
            sources = [m.text for m in p_entry.findall(".//source/member") if m.text]
            destinations = [m.text for m in p_entry.findall(".//destination/member") if m.text]
            services = [m.text for m in p_entry.findall(".//service/member") if m.text]

            act_elem = p_entry.find("action")
            act_text = act_elem.text.strip().lower() if act_elem is not None and act_elem.text else "allow"
            action = PolicyAction.DENY if act_text in ["deny", "drop", "reset-client", "reset-server", "reset-both"] else PolicyAction.ALLOW

            desc_elem = p_entry.find("description")
            desc = desc_elem.text if desc_elem is not None else None

            disabled_elem = p_entry.find("disabled")
            disabled = (disabled_elem is not None and disabled_elem.text and disabled_elem.text.strip().lower() == "yes")

            log_end_elem = p_entry.find(".//log-end")
            log_end = (log_end_elem is None or (log_end_elem.text and log_end_elem.text.strip().lower() == "yes"))

            ir.policies.append(IRPolicy(
                name=p_name,
                from_zone=from_zones or ["any"],
                to_zone=to_zones or ["any"],
                source=sources or ["any"],
                destination=destinations or ["any"],
                service=services or ["any"],
                action=action,
                description=desc,
                disabled=disabled,
                log_end=log_end
            ))

        # 8. NAT Rules
        for n_entry in search_root.findall(".//rulebase/nat/rules/entry"):
            n_name = n_entry.get("name")
            if not n_name:
                continue

            from_z = [m.text for m in n_entry.findall(".//from/member") if m.text]
            to_z = [m.text for m in n_entry.findall(".//to/member") if m.text]
            src = [m.text for m in n_entry.findall(".//source/member") if m.text]
            dst = [m.text for m in n_entry.findall(".//destination/member") if m.text]

            snat_elem = n_entry.find(".//source-translation")
            dnat_elem = n_entry.find(".//destination-translation")

            if dnat_elem is not None:
                trans_dst_elem = dnat_elem.find("translated-address")
                trans_dst = trans_dst_elem.text.strip() if trans_dst_elem is not None and trans_dst_elem.text else None
                ir.nat_rules.append(IRNATRule(
                    name=n_name,
                    type=NATType.DESTINATION,
                    from_zone=from_z or ["any"],
                    to_zone=to_z or ["any"],
                    source=src or ["any"],
                    destination=dst or ["any"],
                    translated_destination=trans_dst
                ))
            else:
                trans_src = None
                if snat_elem is not None:
                    dip = snat_elem.find(".//dynamic-ip-and-port/interface-address/ip")
                    if dip is not None and dip.text:
                        trans_src = dip.text.strip()
                    else:
                        trans_src = "interface"
                ir.nat_rules.append(IRNATRule(
                    name=n_name,
                    type=NATType.SOURCE,
                    from_zone=from_z or ["any"],
                    to_zone=to_z or ["any"],
                    source=src or ["any"],
                    destination=dst or ["any"],
                    translated_source=trans_src
                ))

        # 9. Static Routes
        for r_entry in root.findall(".//virtual-router/entry//static-route/entry"):
            r_name = r_entry.get("name") or "static-route"
            dest_elem = r_entry.find("destination")
            dest = dest_elem.text.strip() if dest_elem is not None and dest_elem.text else "0.0.0.0/0"

            nh_elem = r_entry.find(".//nexthop/ip-address")
            nh = nh_elem.text.strip() if nh_elem is not None and nh_elem.text else None

            intf_elem = r_entry.find("interface")
            intf = intf_elem.text.strip() if intf_elem is not None and intf_elem.text else None

            metric_elem = r_entry.find("metric")
            metric = int(metric_elem.text.strip()) if metric_elem is not None and metric_elem.text else 10

            ir.routes.append(IRRoute(
                name=r_name,
                destination=dest,
                next_hop=nh,
                interface=intf,
                metric=metric
            ))

        return ir
