import csv
import os
import xml.etree.ElementTree as ET

def convert_addresses(csv_dir, xml_parent):
    address_csv = os.path.join(csv_dir, 'firewall_address.csv')
    addrgrp_csv = os.path.join(csv_dir, 'firewall_addrgrp.csv')
    
    if os.path.exists(address_csv):
        address_node = ET.SubElement(xml_parent, 'address')
        with open(address_csv, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = row.get('edit_id')
                if not name:
                    continue
                entry = ET.SubElement(address_node, 'entry', name=name)
                
                addr_type = row.get('type', 'ipmask')
                if addr_type == 'ipmask' or row.get('subnet'):
                    val = row.get('subnet', '0.0.0.0 0.0.0.0')
                    parts = val.split()
                    if len(parts) == 2:
                        ip, mask = parts
                        ip = ip.replace(',', '')
                        mask = mask.replace(',', '')
                        mask_dict = {
                            "255.255.255.255": "32", "255.255.255.0": "24",
                            "255.255.0.0": "16", "255.0.0.0": "8", "0.0.0.0": "0"
                        }
                        cidr = mask_dict.get(mask, mask) 
                        val = f"{ip}/{cidr}"
                    ET.SubElement(entry, 'ip-netmask').text = val
                elif addr_type == 'fqdn':
                    ET.SubElement(entry, 'fqdn').text = row.get('fqdn', '')
                elif addr_type == 'iprange':
                    ET.SubElement(entry, 'ip-range').text = f"{row.get('start-ip', '')}-{row.get('end-ip', '')}"
                else:
                    ET.SubElement(entry, 'ip-netmask').text = row.get('subnet', '')

    if os.path.exists(addrgrp_csv):
        addrgrp_node = ET.SubElement(xml_parent, 'address-group')
        with open(addrgrp_csv, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = row.get('edit_id')
                if not name:
                    continue
                entry = ET.SubElement(addrgrp_node, 'entry', name=name)
                static = ET.SubElement(entry, 'static')
                members_str = row.get('member', '')
                if members_str:
                    members = [m.strip() for m in members_str.split(',')]
                    for m in members:
                        if m:
                            ET.SubElement(static, 'member').text = m
