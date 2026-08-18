# FortiGate to Palo Alto Config Converter

A comprehensive toolset to extract FortiGate configuration files and convert them into Palo Alto Networks (PAN-OS) XML format.

## Features
- **Generic FortiGate Parsing**: Dynamically understands the FortiGate configuration hierarchy without hardcoded schemas and extracts it into CSVs.
- **Palo Alto XML Conversion**: Converts extracted CSVs into a structured PAN-OS XML format suitable for importing.
- **Modular Design**: Separate Python modules handle the conversion logic for Addresses, Interfaces, Policies, and Services.
- **Zero Dependencies**: Uses only pure Python standard library modules.

## 1. Extracting Configurations to CSV

Use the `src/extractor.py` script to parse your raw FortiGate `.conf` file and output it to a specific directory:

```bash
python src/extractor.py -f "data/deleumHQ_7-4_2878_202607131521.conf" -o "./csv_output"
```

This will create a `csv_output/` directory containing cleanly formatted CSV files for every configuration context found, such as:
- `firewall_policy.csv`
- `system_interface.csv`
- `firewall_address.csv`
- `firewall_service_custom.csv`

## 2. Converting to Palo Alto XML

Once the CSVs are extracted into the `./csv_output` directory, you can run the conversion suite:

```bash
python src/converter_core.py
```

This script will read the CSV files and generate a new file named `palo_alto_converted.xml` in the root directory. 

### Supported Conversions
- **Addresses and Address Groups** (`src/modules/address_converter.py`)
- **Services and Service Groups** (`src/modules/service_converter.py`)
- **Interfaces** (`src/modules/interface_converter.py`)
- **Security Policies** (`src/modules/policy_converter.py`)

## Schema Documentation

- `data/schema_output.json`: A full reference mapping of the FortiGate configuration hierarchy.
- `data/pa_schema.json`: A structural representation of the target Palo Alto XML tree.
- `docs/compare_format.md`: A detailed comparison document showing how FortiGate objects map to Palo Alto's schema.
