import csv
import os

def fix_portrange(pr):
    if not pr:
        return pr
    parts = pr.split('-')
    if len(parts) == 4:
        return f"{parts[0]}-{parts[1]}:{parts[2]}-{parts[3]}"
    return pr

def convert_services(csv_dir, out_file):
    service_csv = os.path.join(csv_dir, 'firewall_service_custom.csv')
    servicegrp_csv = os.path.join(csv_dir, 'firewall_service_group.csv')
    
    with open(out_file, 'a', encoding='utf-8') as f:
        if os.path.exists(service_csv):
            f.write("config firewall service custom\n")
            with open(service_csv, 'r', encoding='utf-8') as csv_file:
                reader = csv.DictReader(csv_file)
                for row in reader:
                    f.write(f"    edit \"{row['edit_id']}\"\n")
                    # Usually protocol defaults to TCP/UDP/SCTP in FG if not specified for tcp/udp ports
                    if row.get('tcp-portrange'):
                        pr = fix_portrange(row.get('tcp-portrange'))
                        f.write(f"        set tcp-portrange {pr}\n")
                    if row.get('udp-portrange'):
                        pr = fix_portrange(row.get('udp-portrange'))
                        f.write(f"        set udp-portrange {pr}\n")
                    f.write("    next\n")
            f.write("end\n\n")

        if os.path.exists(servicegrp_csv):
            f.write("config firewall service group\n")
            with open(servicegrp_csv, 'r', encoding='utf-8') as csv_file:
                reader = csv.DictReader(csv_file)
                for row in reader:
                    f.write(f"    edit \"{row['edit_id']}\"\n")
                    members = row.get('member', '')
                    if members:
                        member_str = ' '.join([f'"{m}"' for m in members.split(',') if m])
                        if member_str:
                            f.write(f"        set member {member_str}\n")
                    f.write("    next\n")
            f.write("end\n\n")
