import csv
import os
import xml.etree.ElementTree as ET

def build_member_list(parent_node, item_str, default="any"):
    if not item_str:
        ET.SubElement(parent_node, 'member').text = default
        return
        
    # Fortigate can sometimes put "all", we might map it to "any" in PA
    items = [x.strip() for x in item_str.split(',') if x.strip()]
    if not items:
        ET.SubElement(parent_node, 'member').text = default
        return
        
    for item in items:
        # Fortigate 'all' is 'any' in Palo Alto
        if item.lower() == 'all':
            item = 'any'
        ET.SubElement(parent_node, 'member').text = item

def convert_policies(csv_dir, xml_parent):
    policy_csv = os.path.join(csv_dir, 'firewall_policy.csv')
    
    if os.path.exists(policy_csv):
        rulebase_node = ET.SubElement(xml_parent, 'rulebase')
        security_node = ET.SubElement(rulebase_node, 'security')
        rules_node = ET.SubElement(security_node, 'rules')
        
        with open(policy_csv, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = row.get('name') or row.get('edit_id')
                if not name:
                    continue
                
                entry = ET.SubElement(rules_node, 'entry', name=name)
                
                # To / From zones
                to_node = ET.SubElement(entry, 'to')
                build_member_list(to_node, row.get('dstintf'))
                
                from_node = ET.SubElement(entry, 'from')
                build_member_list(from_node, row.get('srcintf'))
                
                # Source / Destination address
                source_node = ET.SubElement(entry, 'source')
                build_member_list(source_node, row.get('srcaddr'))
                
                dest_node = ET.SubElement(entry, 'destination')
                build_member_list(dest_node, row.get('dstaddr'))
                
                # Service
                service_node = ET.SubElement(entry, 'service')
                # Map ALL/all to any or application-default
                svc = row.get('service')
                if svc and svc.lower() == 'all':
                    svc = 'any'
                build_member_list(service_node, svc)
                
                # Action
                action = row.get('action', 'deny').lower()
                # FG 'accept' -> PA 'allow'
                if action == 'accept':
                    action = 'allow'
                ET.SubElement(entry, 'action').text = action
