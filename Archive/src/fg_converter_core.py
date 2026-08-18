import os

from modules.pa_to_fg.address_converter import convert_addresses
from modules.pa_to_fg.service_converter import convert_services
from modules.pa_to_fg.policy_converter import convert_policies

def main():
    base_dir = os.path.dirname(os.path.dirname(__file__))
    csv_dir = os.path.join(base_dir, 'csv_output')
    out_file = os.path.join(base_dir, 'fortigate_converted.conf')

    if not os.path.exists(csv_dir):
        print(f"Error: CSV directory '{csv_dir}' not found.")
        return
        
    print("Starting Palo Alto to FortiGate conversion...")
    
    # Initialize the output file
    with open(out_file, 'w', encoding='utf-8') as f:
        f.write("# FortiGate Configuration Output\n\n")
    
    try:
        print("Converting Addresses...")
        convert_addresses(csv_dir, out_file)
        
        print("Converting Services...")
        convert_services(csv_dir, out_file)
        
        print("Converting Policies...")
        convert_policies(csv_dir, out_file)
        
        print(f"Conversion complete! Output saved to: {out_file}")

    except Exception as e:
        print(f"Error during conversion: {e}")

if __name__ == "__main__":
    main()
