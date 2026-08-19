# FortiGate to Palo Alto Networks Migration Toolkit

![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10+-green.svg)
![Terraform](https://img.shields.io/badge/terraform-1.0+-purple.svg)
![Tests](https://img.shields.io/badge/tests-57%20passed-brightgreen.svg)

A production-grade Python and Terraform toolkit for migrating enterprise firewall configurations from **Fortinet FortiGate** to **Palo Alto Networks (PAN-OS / Panorama)**. 

This toolkit supports **Dual Ingestion** (offline `.conf` backup files or live FortiGate REST API extraction) and **Dual Execution** (offline package download or direct live push via an automated Terraform engine with real-time streaming).

**Copyright © 2025 GSW Systems. All rights reserved.**  
**Modified in 2026 by Cha Zi Yu (23120943@siswa.um.edu.my)**  
**License:** GNU Affero General Public License v3.0 (AGPL-3.0)  

---

## 🌟 Key Capabilities

### 1. Dual Ingestion Pipeline
- 📁 **Offline File Ingestion**: Parses large FortiGate configuration files (`.conf`, `.txt`, `.cfg`) without requiring network access to the source firewall.
- 🌐 **Live FortiGate REST API Ingestion**: Pulls configuration directly from running FortiGate firewalls via `/api/v2/cmdb/` endpoints using API tokens or administrator credentials.

### 2. Vendor-Neutral Intermediate Representation (IR)
- Transforms proprietary vendor constructs into standardized **`IRConfig`** objects (`IRAddress`, `IRService`, `IRPolicy`, `IRNATRule`, `IRZone`, `IRRoute`).
- Uses topological dependency resolution (Kahn's algorithm) to guarantee correct object ordering for target systems.

### 3. Dual Target Generation Backends
- 📄 **Native PAN-OS XML**: Generates clean, hierarchically validated PAN-OS XML (`palo_alto_config.xml`) ready for GUI load or Panorama device-group imports.
- 🛠️ **Modular Terraform (HCL)**: Synthesizes modular Terraform configurations (`provider.tf`, `variables.tf`, `terraform.tfvars.example`, `main.tf`) targeting the official `PaloAltoNetworks/panos` provider (~> 1.11).

### 4. Automated Execution & Diagnostics Engine
- **Self-Healing Binary Discovery**: Automatically detects local/system Terraform or downloads the standalone binary for Windows, Linux, and macOS.
- **Pre-Flight Diagnostics**: Probes Terraform CLI health, Terraform registry reachability, TCP line-of-sight (port 443), and PAN-OS XML API authentication & hardware/OS info.
- **Dry-Run Diff Review**: Runs `terraform plan` and parses planned resource diffs (`+X to add, ~Y to change, -Z to destroy`).
- **Real-Time Live Push**: Streams `terraform apply` line-by-line via Server-Sent Events (SSE) into a built-in terminal viewer with sensitive credential masking.
- **State Safety & Rollback**: Automatically backs up timestamped `.tfstate` files and supports one-click rollback/destroy streaming.

### 5. Unified Markdown Audit Report
- Generates an interactive audit report (`migration_report.md`) detailing migration health metrics, manual engineer action items, network topology, and security policy matrices.

---

## 🚀 Quickstart

### Prerequisites
- Python 3.10+
- Dependencies listed in `requirements.txt`

### Installation

```bash
# Clone the repository
git clone <repository_url>
cd fortigate-to-palo

# Install dependencies and package in editable mode
pip install -e .
```

---

## 💻 Web Interface Usage (Recommended)

The migration toolkit includes a modern, dark-mode interactive web console:

```bash
# Start the web server
python -m fg2pan.main serve --port 5000
```
Then navigate to **`http://localhost:5000`** in your browser.

```
┌────────────────────────────────────────────────────────────────────────┐
│  [ 📄 Download Migration Package ]   [ ⚡ Direct Live Migration (TF) ]  │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Section 1: Ingestion Method       [ 📁 Upload .conf ] [ 🌐 Live API ]  │
├────────────────────────────────────────────────────────────────────────┤
│  • Drag & drop a .conf backup file OR                                  │
│  • Enter FortiGate IP, Port, API Token & Click "Pull Configuration"    │
└────────────────────────────────────────────────────────────────────────┘
```

### Modes Available:
1. **Mode A: Download Migration Package (.zip)**: Generates and downloads a ZIP containing PAN-OS XML, Terraform `.tf` files, and the Markdown audit report.
2. **Mode B: Direct Live Migration (Terraform)**: Runs pre-flight diagnostics, executes `terraform plan`, and performs a live push to your Palo Alto firewall with live log streaming.

---

## 🖥️ Command Line Interface (CLI) Usage

### 1. Offline File Migration to XML or Terraform

```bash
# Generate PAN-OS XML
fg2pan migrate \
  -i examples/example_fortigate.conf \
  -o migration_output \
  --format xml \
  --report migration_output/report.md

# Generate Terraform HCL Bundle
fg2pan migrate \
  -i examples/example_fortigate.conf \
  -o migration_output_tf \
  --format terraform \
  --report migration_output_tf/report.md
```

### 2. Live FortiGate API Ingestion via CLI

```bash
fg2pan migrate \
  --fortigate-host 192.168.1.99 \
  --fortigate-port 443 \
  --fortigate-api-key "my_secret_token" \
  --vdom "root" \
  -o live_migration_tf \
  --format terraform \
  --report live_migration_tf/report.md
```

### 3. Custom Zone Mapping

```bash
fg2pan migrate \
  -i examples/example_fortigate.conf \
  -o migration_output \
  --zone-map custom_zones.yaml \
  --format terraform
```

*Example `custom_zones.yaml`:*
```yaml
zone_mapping:
  port1: untrust
  port2: trust
  port3: dmz
```

---

## 🧪 Testing

This project includes a comprehensive test suite covering tokenizers, parsers, IR models, reports, generators, the execution engine, diagnostics, and web routes:

```bash
pytest tests/ -v
# 57 passed in 2.25s
```

---

## 📋 Manual Review & Safety Notes

The migration engine adheres to an **"auditable and transparent"** principle:
- **UTM Security Profiles**: Antivirus, IPS, URL Filtering, and SSL Decryption require manual assignment to PAN-OS Security Profile Groups.
- **Dynamic / EMS Addresses**: Identified and flagged in the Markdown report.
- **SD-WAN & Dynamic Routing**: Complex BGP/OSPF policies should be validated against target routing topologies.
