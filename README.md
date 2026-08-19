# Universal Multi-Vendor Firewall Migration Platform

![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10+-green.svg)
![Terraform](https://img.shields.io/badge/terraform-1.0+-purple.svg)
![Tests](https://img.shields.io/badge/tests-88%20passed-brightgreen.svg)

A production-grade Python and Terraform platform for migrating enterprise firewall configurations across any-to-any multi-vendor environments (**Fortinet FortiGate**, **Palo Alto Networks PAN-OS / Panorama**, **Cisco ASA / Firepower**, **Check Point R80/R81**, and **Juniper SRX / JunOS**). 

The platform adopts a decoupled $M + N$ **Vendor-Neutral Intermediate Representation (IR)** architecture, with automated rule optimization, pre-flight diagnostics, dry-run diff review, and live Terraform execution streaming.

**Copyright © 2025 GSW Systems. All rights reserved.**  
**Modified in 2026 by Cha Zi Yu (23120943@siswa.um.edu.my)**  
**License:** GNU Affero General Public License v3.0 (AGPL-3.0)  

---

## 🌟 Key Capabilities

### 1. Universal Multi-Source Ingestion ($M$)
- 🛡️ **Fortinet FortiGate**: Offline `.conf`/`.txt` configuration parser & live `/api/v2/cmdb/` REST extraction.
- 🔥 **Palo Alto Networks (PAN-OS / Panorama)**: Offline `.xml` configuration parser & live XML/REST API client adapter.
- 🌐 **Cisco ASA / Firepower (FTD)**: Offline `.cfg`/`.txt` parser for network objects, service groups, access-lists & routes + FMC API adapter.
- 🔒 **Check Point R80.x / R81.x**: Offline JSON database export parser (`mgmt_cli show-objects` / `show-access-rulebase`) + Management API adapter.
- 🌲 **Juniper SRX / JunOS**: Offline flat `set` syntax and curly-bracket parser for security zones, address books & policy sets.

### 2. Vendor-Neutral Intermediate Representation (IR) & Optimizer
- Standardizes vendor configurations into canonical **`IRConfig`** models (`IRAddress`, `IRService`, `IRPolicy`, `IRNATRule`, `IRZone`, `IRRoute`).
- **Topological Dependency Resolution**: Kahn's algorithm ordering to prevent forward-reference errors during provisioning.
- **Automated Rule Optimizer (`RuleOptimizer`)**: Identifies unused address/service objects, duplicate object definitions, and shadowed policy rules with one-click pruning.

### 3. Universal Multi-Target Generation Backends ($N$)
- 📄 **Palo Alto Networks (PAN-OS / Panorama)**: Native hierarchical XML snippets and official `PaloAltoNetworks/panos` Terraform HCL suites.
- ⚡ **Fortinet FortiGate (FortiOS)**: Native FortiOS CLI syntax configuration scripts (`.conf`) and `fortinetdev/fortios` Terraform HCL suites.
- 🌐 **Cisco ASA / Firepower (FTD)**: Native Cisco ASA CLI configuration scripts (`.cfg`) and `CiscoDevNet/ciscoasa` Terraform HCL suites.
- 🔒 **Check Point Quantum / CloudGuard**: Native `mgmt_cli` automation shell scripts (`.sh`) and `CheckPointSW/checkpoint` Terraform HCL suites.
- 🌲 **Juniper SRX / JunOS**: Native JunOS `set` syntax command scripts (`.set`) and `juniper/junos` Terraform HCL suites.
- 📊 **Audit & Diff Summaries**: Unified Markdown audit reports and JSON compliance matrices.

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

### 1. List Available Source & Target Plugins

```bash
fg2pan vendors
# or
fwmigrate vendors
```

### 2. Multi-Vendor Migration (e.g. Cisco ASA to Palo Alto)

```bash
# Migrate Cisco ASA configuration to PAN-OS Terraform with optimization
fg2pan migrate \
  -i examples/example_cisco_asa.cfg \
  --source-vendor cisco_asa \
  --target-vendor palo_alto \
  --optimize \
  -o migration_output_cisco \
  --format terraform \
  --report migration_output_cisco/report.md
```

### 3. Check Point / Juniper Migration to FortiGate

```bash
# Migrate Check Point R80/R81 JSON export to FortiOS CLI config
fg2pan migrate \
  -i examples/example_checkpoint.json \
  --source-vendor checkpoint \
  --target-vendor fortigate \
  -o migration_output_fg \
  --format cli
```

### 4. Live FortiGate API Ingestion via CLI

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

---

## 🧪 Testing

This project includes a comprehensive test suite covering tokenizers, parsers, IR models, reports, generators, the execution engine, diagnostics, web routes, and golden configuration suites across all supported vendors:

```bash
pytest tests/ -v
# 78 passed
```

---

## 📋 Manual Review & Safety Notes

The migration engine adheres to an **"auditable and transparent"** principle:
- **UTM Security Profiles**: Antivirus, IPS, URL Filtering, and SSL Decryption require manual assignment to PAN-OS Security Profile Groups.
- **Dynamic / EMS Addresses**: Identified and flagged in the Markdown report.
- **SD-WAN & Dynamic Routing**: Complex BGP/OSPF policies should be validated against target routing topologies.
