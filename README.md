# FortiGate Config Extractor

A generic extraction tool that parses raw FortiGate configuration files and automatically generates a directory of CSV files for every configuration category found within the config file.

## Features
- **Generic Parsing**: Dynamically understands the FortiGate configuration hierarchy without hardcoded schemas.
- **Complete Extraction**: Processes `config system global`, `config firewall policy`, `config vpn ipsec phase1-interface`, etc., converting all `set` statements into structured CSV rows.
- **Zero Dependencies**: Uses only pure Python standard library modules.

## Usage

### Extracting Configurations to CSV

Use the `extractor.py` script to parse your `.conf` file and output to a specific directory:

```bash
python extractor.py -f "deleumHQ_7-4_2878_202607131521.conf" -o "./csv_output"
```

This will create a `csv_output/` directory containing cleanly formatted CSV files for every single configuration context found, such as:
- `firewall__policy.csv`
- `system__global.csv`
- `firewall__address.csv`
- `vpn__ipsec__phase1-interface.csv`

## Configuration Schema

A full reference of the configuration hierarchy and available keys is extracted in `schema_output.json`. This JSON document maps every unique configuration block to the specific properties/settings (`set` commands) it contains.
