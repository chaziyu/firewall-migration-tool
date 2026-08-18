import xml.etree.ElementTree as ET
import csv
import os
import argparse

class PaloAltoExtractor:
    def __init__(self, xml_file):
        self.xml_file = xml_file
        self.tree = ET.parse(xml_file)
        self.root = self.tree.getroot()

    def _find_vsys1(self):
        # PAN-OS structure: config/devices/entry/vsys/entry[@name='vsys1']
        devices = self.root.find('devices')
        if devices is not None:
            localhost = devices.find('entry')
            if localhost is not None:
                vsys = localhost.find('vsys')
                if vsys is not None:
                    return vsys.find("entry[@name='vsys1']") or vsys.find('entry')
        return None

    def extract_all(self, output_dir):
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        vsys1 = self._find_vsys1()
        if vsys1 is None:
            # Fallback if structure is different
            vsys1 = self.root

        self._extract_addresses(vsys1, output_dir)
        self._extract_address_groups(vsys1, output_dir)
        self._extract_services(vsys1, output_dir)
        self._extract_service_groups(vsys1, output_dir)
        self._extract_policies(vsys1, output_dir)

    def _write_csv(self, filename, headers, rows):
        if not rows:
            return
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(rows)

    def _extract_addresses(self, vsys, output_dir):
        address_node = vsys.find('address')
        if address_node is None: return

        rows = []
        for entry in address_node.findall('entry'):
            name = entry.get('name')
            row = {'edit_id': name}
            
            if entry.find('ip-netmask') is not None:
                row['type'] = 'ipmask'
                val = entry.find('ip-netmask').text
                # Convert CIDR back to subnet if needed, but FortiOS 7+ supports CIDR natively in many places
                # Let's just output it and let the FG converter handle it
                row['subnet'] = val if val else ''
            elif entry.find('fqdn') is not None:
                row['type'] = 'fqdn'
                row['fqdn'] = entry.find('fqdn').text
            elif entry.find('ip-range') is not None:
                row['type'] = 'iprange'
                val = entry.find('ip-range').text
                if '-' in val:
                    row['start-ip'], row['end-ip'] = val.split('-')
            
            rows.append(row)
        
        headers = ['edit_id', 'type', 'subnet', 'fqdn', 'start-ip', 'end-ip']
        self._write_csv(os.path.join(output_dir, 'firewall_address.csv'), headers, rows)

    def _extract_address_groups(self, vsys, output_dir):
        node = vsys.find('address-group')
        if node is None: return

        rows = []
        for entry in node.findall('entry'):
            name = entry.get('name')
            members = []
            static = entry.find('static')
            if static is not None:
                for m in static.findall('member'):
                    members.append(m.text)
            
            rows.append({'edit_id': name, 'member': ','.join(members)})
        
        self._write_csv(os.path.join(output_dir, 'firewall_addrgrp.csv'), ['edit_id', 'member'], rows)

    def _extract_services(self, vsys, output_dir):
        node = vsys.find('service')
        if node is None: return

        rows = []
        for entry in node.findall('entry'):
            name = entry.get('name')
            row = {'edit_id': name}
            protocol = entry.find('protocol')
            if protocol is not None:
                if protocol.find('tcp') is not None:
                    row['protocol'] = 'TCP/UDP/SCTP'
                    row['tcp-portrange'] = protocol.find('tcp/port').text
                elif protocol.find('udp') is not None:
                    row['protocol'] = 'TCP/UDP/SCTP'
                    row['udp-portrange'] = protocol.find('udp/port').text
            rows.append(row)
        
        headers = ['edit_id', 'protocol', 'tcp-portrange', 'udp-portrange']
        self._write_csv(os.path.join(output_dir, 'firewall_service_custom.csv'), headers, rows)

    def _extract_service_groups(self, vsys, output_dir):
        node = vsys.find('service-group')
        if node is None: return

        rows = []
        for entry in node.findall('entry'):
            name = entry.get('name')
            members = [m.text for m in entry.findall('members/member')]
            rows.append({'edit_id': name, 'member': ','.join(members)})
        
        self._write_csv(os.path.join(output_dir, 'firewall_service_group.csv'), ['edit_id', 'member'], rows)

    def _extract_policies(self, vsys, output_dir):
        rulebase = vsys.find('rulebase/security/rules')
        if rulebase is None: return

        rows = []
        for entry in rulebase.findall('entry'):
            row = {'edit_id': entry.get('name')}
            row['srcintf'] = ','.join([m.text for m in entry.findall('from/member')])
            row['dstintf'] = ','.join([m.text for m in entry.findall('to/member')])
            row['srcaddr'] = ','.join([m.text for m in entry.findall('source/member')])
            row['dstaddr'] = ','.join([m.text for m in entry.findall('destination/member')])
            row['service'] = ','.join([m.text for m in entry.findall('service/member')])
            
            action = entry.find('action')
            if action is not None:
                row['action'] = 'accept' if action.text == 'allow' else 'deny'
            else:
                row['action'] = 'accept' # default in FG
            
            rows.append(row)
        
        headers = ['edit_id', 'srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'service', 'action']
        self._write_csv(os.path.join(output_dir, 'firewall_policy.csv'), headers, rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Palo Alto to CSV Extractor")
    parser.add_argument('-f', '--xml-file', required=True, help='Path to PAN-OS XML config')
    parser.add_argument('-o', '--output-dir', default='./csv_output', help='Output directory')
    args = parser.parse_args()

    extractor = PaloAltoExtractor(args.xml_file)
    extractor.extract_all(args.output_dir)
    print("PA XML Extraction complete.")
