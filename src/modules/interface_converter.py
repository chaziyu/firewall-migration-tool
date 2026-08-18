import csv
import os
import xml.etree.ElementTree as ET

def convert_interfaces(csv_dir, xml_parent):
    interface_csv = os.path.join(csv_dir, 'system_interface.csv')
    
    if os.path.exists(interface_csv):
        network_node = ET.SubElement(xml_parent, 'network')
        interface_node = ET.SubElement(network_node, 'interface')
        ethernet_node = ET.SubElement(interface_node, 'ethernet')
        
        with open(interface_csv, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = row.get('edit_id')
                if not name:
                    continue
                
                # PA maps interfaces generally to ethernet. 
                # Tunnels go to tunnel, loopbacks to loopback, etc.
                # For simplicity, map all to ethernet here unless we do deeper inspection
                entry = ET.SubElement(ethernet_node, 'entry', name=name)
                
                # Assume Layer 3 interface
                layer3_node = ET.SubElement(entry, 'layer3')
                
                ip_str = row.get('ip', '')
                if ip_str and '0.0.0.0' not in ip_str:
                    parts = [p.strip() for p in ip_str.split(',')]
                    if len(parts) >= 2:
                        ip, mask = parts[0], parts[1]
                        mask_dict = {
                            "255.255.255.255": "32", "255.255.255.0": "24",
                            "255.255.0.0": "16", "255.0.0.0": "8", "0.0.0.0": "0"
                        }
                        cidr = mask_dict.get(mask, mask) 
                        val = f"{ip}/{cidr}"
                        
                        ip_node = ET.SubElement(layer3_node, 'ip')
                        ET.SubElement(ip_node, 'entry', name=val)
