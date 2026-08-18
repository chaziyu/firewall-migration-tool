import xml.etree.ElementTree as ET
import os
import xml.dom.minidom

from modules.address_converter import convert_addresses
from modules.service_converter import convert_services
from modules.interface_converter import convert_interfaces
from modules.policy_converter import convert_policies

def create_base_structure():
    config = ET.Element('config', version="11.1.0", urldb="paloaltonetworks")
    devices = ET.SubElement(config, 'devices')
    localhost = ET.SubElement(devices, 'entry', name="localhost.localdomain")
    
    vsys = ET.SubElement(localhost, 'vsys')
    vsys1 = ET.SubElement(vsys, 'entry', name="vsys1")
    
    return config, localhost, vsys1

def main():
    csv_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'csv_output')
    if not os.path.exists(csv_dir):
        print(f"Error: CSV directory '{csv_dir}' not found.")
        return
        
    print("Starting conversion...")
    config, localhost_node, vsys1_node = create_base_structure()
    
    try:
        print("Converting Interfaces...")
        convert_interfaces(csv_dir, localhost_node)
        
        print("Converting Addresses...")
        convert_addresses(csv_dir, vsys1_node)
        
        print("Converting Services...")
        convert_services(csv_dir, vsys1_node)
        
        print("Converting Policies...")
        convert_policies(csv_dir, vsys1_node)
    except Exception as e:
        print(f"Error during conversion: {e}")
        import traceback
        traceback.print_exc()
        return
        
    print("Generating XML file...")
    xml_str = ET.tostring(config, encoding='utf-8')
    # Use minidom to pretty-print
    parsed = xml.dom.minidom.parseString(xml_str)
    # Remove blank lines added by minidom by filtering out text nodes with only whitespace
    for node in parsed.getElementsByTagName('*'):
        # Filter text nodes that contain only whitespace
        new_children = []
        for child in node.childNodes:
            if child.nodeType == xml.dom.minidom.Node.TEXT_NODE and not child.data.strip():
                continue
            new_children.append(child)
        node.childNodes = new_children
        
    pretty_xml = parsed.toprettyxml(indent="  ")
    
    output_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'palo_alto_converted.xml')
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(pretty_xml)
        
    print(f"Conversion complete. Output saved to {output_file}")

if __name__ == '__main__':
    main()
