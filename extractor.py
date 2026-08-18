#!/usr/bin/env python3
"""
Generic FortiGate Config to CSV Extractor
Parses FortiGate configuration files and exports each config category to its own CSV file.
"""

import sys
import os
import argparse
import csv
import shlex
import re
from collections import defaultdict
from typing import Dict, List, Any

class GenericFortiGateParser:
    """Generic Parser for FortiGate configuration"""
    
    def __init__(self, config_file: str):
        self.config_file = config_file
        # Structure: tables[config_path][edit_id] = {key: value}
        # If there's no edit_id (e.g. global config), edit_id = 'global'
        self.tables: Dict[str, Dict[str, Dict[str, str]]] = defaultdict(lambda: defaultdict(dict))
        
    def parse(self):
        """Parse the configuration file"""
        print(f"Parsing configuration from file: {self.config_file}...")
        
        try:
            with open(self.config_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            raise Exception(f"Failed to read config file: {e}")
            
        current_config_path = []
        current_edit_id = None
        
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
                
            if stripped.startswith("config "):
                config_type = stripped[7:].strip()
                # Clean the config path to avoid weird filenames
                clean_config_type = re.sub(r'[^a-zA-Z0-9_\-\s]', '', config_type)
                clean_config_type = clean_config_type.replace(' ', '_')
                current_config_path.append(clean_config_type)
                current_edit_id = "global"  # default if no edit block
                continue
                
            if stripped == "end":
                if current_config_path:
                    current_config_path.pop()
                current_edit_id = None
                continue
                
            if stripped.startswith("edit "):
                # Inside an edit block
                try:
                    parts = shlex.split(stripped)
                    if len(parts) > 1:
                        current_edit_id = parts[1]
                except ValueError:
                    parts = stripped.split(" ", 1)
                    if len(parts) > 1:
                        current_edit_id = parts[1].strip('"\'')
                continue
                
            if stripped == "next":
                current_edit_id = "global" # reset back to global scope of this config context
                continue
                
            if stripped.startswith("set "):
                if current_config_path and current_edit_id is not None:
                    path_str = "__".join(current_config_path)
                    try:
                        parts = shlex.split(stripped)
                    except ValueError:
                        parts = stripped.split()
                        
                    if len(parts) >= 3:
                        key = parts[1]
                        # join multiple values with comma and space
                        values = parts[2:]
                        values = [v.strip('"\'') for v in values]
                        value_str = ", ".join(values)
                        
                        self.tables[path_str][current_edit_id][key] = value_str

    def export_csvs(self, output_dir: str):
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        exported_count = 0
        for config_path, rows in self.tables.items():
            if not rows:
                continue
                
            # Collect all possible keys for the header
            all_keys = set()
            for edit_id, data in rows.items():
                all_keys.update(data.keys())
            
            sorted_keys = sorted(list(all_keys))
            headers = ['edit_id'] + sorted_keys
            
            filename = f"{config_path}.csv"
            filepath = os.path.join(output_dir, filename)
            
            try:
                with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(headers)
                    
                    # Sort rows by edit_id to make it somewhat deterministic
                    for edit_id in sorted(rows.keys()):
                        data = rows[edit_id]
                        row = [edit_id]
                        for key in sorted_keys:
                            row.append(data.get(key, ''))
                        writer.writerow(row)
                exported_count += 1
            except Exception as e:
                print(f"Failed to write {filepath}: {e}")
                
        print(f"Successfully generated {exported_count} CSV files in '{output_dir}'.")

def main():
    parser = argparse.ArgumentParser(
        description='Generic FortiGate Policy Extractor to CSV',
        epilog="""
Examples:
  %(prog)s -f config.conf -o ./csv_export/
        """
    )
    
    # Configuration parameters
    parser.add_argument('-f', '--config-file', required=True, help='Path to FortiGate configuration file')
    parser.add_argument('-o', '--output-dir', default='./csv_export', help='Directory to output CSV files')
    
    args = parser.parse_args()
    
    try:
        print("=" * 70)
        print("Generic FortiGate Config Extractor")
        print("=" * 70)
        print(f"\nConfiguration File: {args.config_file}")
        print()
        
        # Parse configuration from file
        print("Phase 1: Configuration Parsing")
        print("-" * 70)
        file_parser = GenericFortiGateParser(args.config_file)
        file_parser.parse()
        
        # Output to CSV files
        print("\nPhase 2: Generating CSV Outputs")
        print("-" * 70)
        file_parser.export_csvs(args.output_dir)
            
        print("\n" + "=" * 70)
        print("Extraction complete!")
        print("=" * 70)
        print()
        
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
