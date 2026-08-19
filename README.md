# FortiGate to Palo Alto Networks Migration Toolkit

![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10+-green.svg)

A production-quality Python toolkit for migrating firewall configurations from FortiGate to Palo Alto Networks. This toolkit converts FortiGate `.conf` files into PAN-OS XML using a vendor-neutral Intermediate Representation (IR), ensuring clean, auditable, and semantically correct migrations.

**Copyright © 2025 GSW Systems. All rights reserved.**  
**Modifications Copyright © 2026 CTC Global Malaysia (KL).**  
**License:** GNU Affero General Public License v3.0 (AGPL-3.0)  
**Original Contact:** sales@gswsystems.com 

---

## Features

### Extensible Architecture
- **Web Application:** Premium, modern web interface for seamless drag-and-drop `.conf` file migration directly in your browser.
- **Offline File-Based Processing:** Parses large FortiGate configurations securely without needing live firewall access.
- **Vendor-Neutral IR:** Models network topology and security intent independent of any single vendor, allowing easy extensions for new target platforms.
- **Dependency Graph:** Automatically orders objects correctly for PAN-OS (e.g., creating Address Objects before Address Groups).
- **Automated Audit Reporting:** Generates a detailed Markdown report identifying objects that require manual review or were partially migrated.
- **TXT Configuration Summary:** Outputs a highly readable, structured text report of all parsed addresses, services, and policies.

### Supported Features
- **Interfaces & Zones:** Interface mapping and basic zone inference.
- **Address Objects:** Subnets, IP ranges, FQDNs, and Address Groups.
- **Service Objects:** TCP/UDP ports, custom services, and Service Groups.
- **Security Policies:** Allow/Deny rules with full source/destination mapping.
- **NAT Rules:** SNAT (IP Pools) and DNAT (VIPs).
- **Routing & VPN:** Static routes and phase-1 IPsec extraction.

---

## Quickstart

### Prerequisites
- Python 3.10+
- Dependencies listed in `requirements.txt` (including `flask` for the web server)

### Installation

```bash
# Clone the repository
git clone Internal Repository
cd fortigate-palo-migration

# Install the package in editable mode
pip install -e .
```

---

## Usage

### Option 1: Web Interface (Recommended)

You can run the migration engine using the provided Windows batch script, which spins up a beautiful local web server:

1. Simply double-click `run_migration.bat` in your file explorer.
2. Open your browser and navigate to `http://localhost:5000`.
3. Drag and drop your `example_fortigate.conf` file into the UI and click "Start Migration".
4. The server will process the configuration and instantly download a `.zip` archive containing the XML, TXT summary, and Markdown audit report!

You can also start the web server manually via the CLI:
```bash
python -m fg2pan.main serve --port 5000
```

### Option 2: Command Line Interface (CLI)

If you prefer to generate the files directly in a directory via the terminal:

```bash
python -m fg2pan.main migrate \
  -i examples/example_fortigate.conf \
  -o migration_output \
  --format xml \
  --report migration_output/report.md \
  --txt-report migration_output/config_summary.txt
```

#### Output Files
After running the command (or extracting the web ZIP), you will find the following:
- `palo_alto_config.xml`: The generated PAN-OS XML snippet, ready to be imported or used via Palo Alto APIs/Panorama.
- `report.md`: A detailed breakdown of the migration confidence and required manual audits.
- `config_summary.txt`: A clean, human-readable text document summarizing all parsed settings, objects, and policies.

---

## Advanced Usage

### Zone Mapping Configuration (CLI only)
You can provide a YAML file to explicitly map FortiGate interfaces to Palo Alto zones:

```bash
python -m fg2pan.main migrate \
  -i examples/example_fortigate.conf \
  -o migration_output \
  --zone-map custom_zones.yaml \
  --format xml
```

*Example `custom_zones.yaml`:*
```yaml
zone_mapping:
  port1: untrust
  port2: trust
  dmz: dmz
```

---

## Testing

This project uses `pytest` for all unit and integration tests.

```bash
# Run all tests
python -m pytest tests/ -v
```

## Post-Migration Steps

The migration engine prioritizes an "incomplete but auditable" migration over a confidently incorrect one. Always review the generated `report.md`.

**Manual Review Required For:**
- **Dynamic/EMS Addresses:** Requires custom mapping.
- **VPN Configurations:** IPsec phase 1/2 translation to PAN-OS IKE Gateways.
- **UTM / Security Profiles:** Antivirus, IPS, URL filtering require manual assignment to PAN-OS Security Profile Groups.
- **SD-WAN:** Deep SD-WAN logic and SLA targets.
