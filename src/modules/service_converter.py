import csv
import os
import xml.etree.ElementTree as ET

def convert_services(csv_dir, xml_parent):
    service_csv = os.path.join(csv_dir, 'firewall_service_custom.csv')
    servicegrp_csv = os.path.join(csv_dir, 'firewall_service_group.csv')
    
    if os.path.exists(service_csv):
        service_node = ET.SubElement(xml_parent, 'service')
        with open(service_csv, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = row.get('edit_id')
                if not name:
                    continue
                
                # Fortigate can have both TCP and UDP portranges in one service
                # Palo Alto usually splits them or uses <tcp> and <udp>.
                # We'll map the primary one, or duplicate if both exist (though PA schema prefers one protocol under protocol)
                # PA format: <protocol><tcp><port>123</port></tcp></protocol>
                tcp_ports = row.get('tcp-portrange', '')
                udp_ports = row.get('udp-portrange', '')
                proto_type = row.get('protocol', '')
                
                if tcp_ports or udp_ports or proto_type in ['TCP/UDP/SCTP', 'TCP', 'UDP']:
                    entry = ET.SubElement(service_node, 'entry', name=name)
                    protocol_node = ET.SubElement(entry, 'protocol')
                    
                    if tcp_ports:
                        # cleanup ranges (FG uses ':' sometimes or '-')
                        tcp_ports = tcp_ports.replace(':', '-')
                        tcp_node = ET.SubElement(protocol_node, 'tcp')
                        ET.SubElement(tcp_node, 'port').text = tcp_ports
                    elif udp_ports:
                        udp_ports = udp_ports.replace(':', '-')
                        udp_node = ET.SubElement(protocol_node, 'udp')
                        ET.SubElement(udp_node, 'port').text = udp_ports
                    else:
                        # Default to tcp if unspecified but it's a TCP/UDP service
                        tcp_node = ET.SubElement(protocol_node, 'tcp')
                        ET.SubElement(tcp_node, 'port').text = '0-65535'

    if os.path.exists(servicegrp_csv):
        servicegrp_node = ET.SubElement(xml_parent, 'service-group')
        with open(servicegrp_csv, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = row.get('edit_id')
                if not name:
                    continue
                entry = ET.SubElement(servicegrp_node, 'entry', name=name)
                members_str = row.get('member', '')
                if members_str:
                    members = [m.strip() for m in members_str.split(',')]
                    # PA members tag
                    members_node = ET.SubElement(entry, 'members')
                    for m in members:
                        if m:
                            ET.SubElement(members_node, 'member').text = m
