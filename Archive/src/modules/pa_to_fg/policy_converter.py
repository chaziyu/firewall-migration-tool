import csv
import os

def convert_policies(csv_dir, out_file):
    policy_csv = os.path.join(csv_dir, 'firewall_policy.csv')
    
    with open(out_file, 'a', encoding='utf-8') as f:
        if os.path.exists(policy_csv):
            f.write("config firewall policy\n")
            with open(policy_csv, 'r', encoding='utf-8') as csv_file:
                reader = csv.DictReader(csv_file)
                policy_id = 1
                for row in reader:
                    # In FG, policy ID is an integer. Palo uses names. 
                    # We'll use incrementing ID and set the name.
                    f.write(f"    edit {policy_id}\n")
                    if row.get('edit_id'):
                        f.write(f"        set name \"{row.get('edit_id')}\"\n")
                    
                    for field, fg_field in [('srcintf', 'srcintf'), ('dstintf', 'dstintf'), 
                                            ('srcaddr', 'srcaddr'), ('dstaddr', 'dstaddr'), 
                                            ('service', 'service')]:
                        val = row.get(field)
                        if val:
                            if val.lower() == 'any':
                                f.write(f"        set {fg_field} \"all\"\n")
                            else:
                                val_str = ' '.join([f'"{m}"' for m in val.split(',') if m])
                                f.write(f"        set {fg_field} {val_str}\n")
                    
                    action = row.get('action', 'accept')
                    f.write(f"        set action {action}\n")
                    f.write("        set schedule \"always\"\n") # default
                    f.write("    next\n")
                    policy_id += 1
            f.write("end\n\n")
