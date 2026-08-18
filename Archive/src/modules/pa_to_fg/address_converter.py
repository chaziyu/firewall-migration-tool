import csv
import os

def cidr_to_netmask(val):
    if not val:
        return ""
    if '/' not in val:
        return val
    try:
        ip, cidr = val.split('/')
        bits = int(cidr)
        mask = (0xffffffff >> (32 - bits)) << (32 - bits)
        mask_str = f"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"
        return f"{ip} {mask_str}"
    except:
        return val

def convert_addresses(csv_dir, out_file):
    address_csv = os.path.join(csv_dir, 'firewall_address.csv')
    addrgrp_csv = os.path.join(csv_dir, 'firewall_addrgrp.csv')
    
    with open(out_file, 'a', encoding='utf-8') as f:
        if os.path.exists(address_csv):
            f.write("config firewall address\n")
            with open(address_csv, 'r', encoding='utf-8') as csv_file:
                reader = csv.DictReader(csv_file)
                for row in reader:
                    f.write(f"    edit \"{row['edit_id']}\"\n")
                    if row.get('type') == 'ipmask':
                        f.write("        set type ipmask\n")
                        subnet_val = cidr_to_netmask(row.get('subnet'))
                        if subnet_val:
                            f.write(f"        set subnet {subnet_val}\n")
                    elif row.get('type') == 'fqdn':
                        f.write("        set type fqdn\n")
                        f.write(f"        set fqdn \"{row.get('fqdn')}\"\n")
                    elif row.get('type') == 'iprange':
                        f.write("        set type iprange\n")
                        f.write(f"        set start-ip {row.get('start-ip')}\n")
                        f.write(f"        set end-ip {row.get('end-ip')}\n")
                    f.write("    next\n")
            f.write("end\n\n")

        if os.path.exists(addrgrp_csv):
            f.write("config firewall addrgrp\n")
            with open(addrgrp_csv, 'r', encoding='utf-8') as csv_file:
                reader = csv.DictReader(csv_file)
                for row in reader:
                    f.write(f"    edit \"{row['edit_id']}\"\n")
                    members = row.get('member', '')
                    if members:
                        # FortiGate members format: set member "A" "B"
                        member_str = ' '.join([f'"{m}"' for m in members.split(',') if m])
                        if member_str:
                            f.write(f"        set member {member_str}\n")
                    f.write("    next\n")
            f.write("end\n\n")
