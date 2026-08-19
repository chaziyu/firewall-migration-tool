# Universal Multi-Vendor Firewall Migration Platform

![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10+-green.svg)
![Terraform](https://img.shields.io/badge/terraform-1.0+-purple.svg)
![Tests](https://img.shields.io/badge/tests-90%20passed-brightgreen.svg)
![Platform](https://img.shields.io/badge/executable-Windows%20x64%20Standalone-blue.svg)

A production-grade Python and Terraform platform for migrating enterprise firewall configurations across any-to-any multi-vendor environments (**Fortinet FortiGate**, **Palo Alto Networks PAN-OS / Panorama**, **Cisco ASA / Firepower**, **Check Point R80/R81**, and **Juniper SRX / JunOS**).

The platform adopts a decoupled $M \times N$ **Vendor-Neutral Intermediate Representation (IR)** architecture, featuring automated rule optimization, pre-flight diagnostics, dry-run diff review, and live Terraform execution streaming.

**Copyright © 2025 GSW Systems. All rights reserved.**  
**Modified in 2026 by Cha Zi Yu (23120943@siswa.um.edu.my)**  
**License:** GNU Affero General Public License v3.0 (AGPL-3.0)  

📖 **Looking for operational guides & vendor export instructions? Read the [User Manual & Operations Guide](USER_MANUAL.md).**

---

## 🚀 Quick Reference: Vendor Compatibility Matrix

The engine normalizes all vendor-specific constructs into a canonical Intermediate Representation (`IRConfig`), allowing seamless cross-vendor migration:

| Source Vendor ($M$) | Ingestion Methods | Target Vendor ($N$) | Output Formats |
|---|---|---|---|
| **Fortinet FortiGate** | `.conf` / `.txt` backup, live `/api/v2/cmdb/` REST | **Palo Alto Networks** | Native XML, `panos` Terraform HCL |
| **Palo Alto Networks** | `.xml` configuration, live XML/REST API | **Fortinet FortiGate** | Native CLI (`.conf`), `fortios` Terraform HCL |
| **Cisco ASA / Firepower** | `.cfg` / `.txt` access-lists & objects, FMC API | **Cisco ASA / FTD** | Native CLI (`.cfg`), `ciscoasa` Terraform HCL |
| **Check Point R80.x/R81.x** | `mgmt_cli` JSON export, Management API | **Check Point** | Native `mgmt_cli` shell scripts (`.sh`), `checkpoint` Terraform HCL |
| **Juniper SRX / JunOS** | Flat `set` commands, hierarchical curly syntax | **Juniper SRX** | Native JunOS `set` commands (`.set`), `junos` Terraform HCL |

> All migration paths automatically generate a **Unified Markdown Audit Report** and **JSON Parity Matrix**.

---

## ⚡ Getting Started

Choose the method that best fits your workflow:

### Option 1: Standalone Native Desktop App (No Installation)
For Windows end-users, pre-compiled standalone executable with zero dependencies:
* 📁 **Executable Path:** `dist/Firewall Migration Tool.exe` (~53 MB)
* **Highlights:** Embedded Edge WebView2 desktop window, bundled offline Terraform CLI, no Python or Node.js required.

```powershell
# Launch Desktop GUI directly:
.\dist\"Firewall Migration Tool.exe"

# Or run standalone CLI:
.\dist\"Firewall Migration Tool.exe" vendors
.\dist\"Firewall Migration Tool.exe" migrate -i examples/example_fortigate.conf -o ./output --format xml --optimize
```

---

### Option 2: One-Click Web Server (`run_migration.bat`)
To quickly start the modern web interface on Windows:
1. Double-click `run_migration.bat` in the repository root.
2. Open your browser and navigate to **`http://localhost:5000`**.

---

### Option 3: Run from Python Source

#### Prerequisites
* Python 3.10+
* Git

```bash
# 1. Clone repository
git clone <repository_url>
cd firewall-migration-tool

# 2. Install package in editable mode with dependencies
pip install -e .

# 3. Launch Web Server or Native App
python -m fwmigrate.main serve --port 5000   # Web Browser Mode
python -m fwmigrate.main app                # Native Window Mode
```

---

## 🌐 Web Interface Walkthrough

The platform features an interactive dark-mode web console designed for fast, auditable migrations:

```
┌────────────────────────────────────────────────────────────────────────┐
│  [ 📄 Download Migration Package ]   [ ⚡ Direct Live Migration (TF) ]  │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Section 1: Ingestion Method       [ 📁 Upload File ]  [ 🌐 Live API ]  │
├────────────────────────────────────────────────────────────────────────┤
│  • Select Source & Target Vendors (FortiGate, PAN-OS, Cisco, etc.)     │
│  • Upload configuration backup OR connect via Live Management API      │
└────────────────────────────────────────────────────────────────────────┘
```

### Migration Modes:
1. **Mode A: Download Migration Package (.zip)**  
   Converts source configuration into a complete archive containing native syntax files, production Terraform HCL suites, and the Markdown audit report.
2. **Mode B: Direct Live Migration (Terraform Live Engine)**  
   Executes real-time pre-flight diagnostics, runs `terraform plan` for dry-run diff inspection, and performs streamed deployment with sensitive credential masking and automatic `.tfstate` rollback backups.

---

## 💻 Command Line Interface (CLI) Usage

The CLI is available as `fwmigrate`, `fwmigrate`, or `python -m fwmigrate.main`.

### 1. View Registered Vendor Plugins
```bash
fwmigrate vendors
```

### 2. Cross-Vendor Migration (e.g. Cisco ASA ➔ Palo Alto)
```bash
fwmigrate migrate \
  -i examples/example_cisco_asa.cfg \
  --source-vendor cisco_asa \
  --target-vendor palo_alto \
  --optimize \
  -o migration_output_cisco \
  --format terraform \
  --report migration_output_cisco/report.md
```

### 3. Check Point / Juniper ➔ FortiGate Native CLI
```bash
fwmigrate migrate \
  -i examples/example_checkpoint.json \
  --source-vendor checkpoint \
  --target-vendor fortigate \
  -o migration_output_fg \
  --format cli
```

### 4. Live Device API Ingestion via CLI
```bash
fwmigrate migrate \
  --fortigate-host 192.168.1.99 \
  --fortigate-port 443 \
  --fortigate-api-key "my_secret_token" \
  --vdom "root" \
  -o live_migration_tf \
  --format terraform \
  --report live_migration_tf/report.md
```

---

## 🛠️ Architecture & Core Components

```
   ┌───────────────────────────────────────────────────────────────────┐
   │                       Source Configurations                       │
   │   FortiGate (.conf) | PAN-OS (.xml) | Cisco (.cfg) | CP (JSON)    │
   └─────────────────────────────────┬─────────────────────────────────┘
                                     │ (Ingestion & Parsing)
                                     ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │        Vendor-Neutral Intermediate Representation (IRConfig)       │
   │  IRAddress │ IRService │ IRPolicy │ IRNATRule │ IRZone │ IRRoute  │
   ├───────────────────────────────────────────────────────────────────┤
   │  • Topological Dependency Sorting (Kahn's Algorithm)              │
   │  • Automated Rule Optimizer (Deduplication, Shadowing, Pruning)   │
   └─────────────────────────────────┬─────────────────────────────────┘
                                     │ (Code Generation Backends)
                                     ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │                        Target Deliverables                        │
   │  • Native Syntax (XML / CLI / .set / .sh)                         │
   │  • Modular Terraform Suites (main.tf, variables.tf, etc.)         │
   │  • Unified Markdown Audit Report (migration_report.md)            │
   └───────────────────────────────────────────────────────────────────┘
```

1. **Ingestion Layer ($M$)**: Dedicated vendor parsers and REST/XML live API adapters.
2. **Canonical IR & Rule Optimizer**: Normalizes policies, detects orphaned/duplicate objects, flags shadowed security rules, and orders dependencies using Kahn's algorithm.
3. **Target Code Generators ($N$)**: Synthesizes vendor-native scripts, HCL Terraform suites, and audit summaries.
4. **Execution & Diagnostics Engine**: Automated Terraform binary management, reachability diagnostics, live execution streaming (SSE), and rollback safety.

---

## 🧪 Testing & Validation

The codebase includes an extensive test suite covering tokenizers, AST parsers, IR models, optimizers, report generators, diagnostics, and multi-vendor golden configurations:

```bash
pytest tests/ -v
# 90 passed
```

---

## 🔨 Building the Standalone Executable

To compile a self-contained Windows executable from source:

```powershell
pip install pywebview pyinstaller

pyinstaller --noconfirm --onefile --windowed --name "Firewall Migration Tool" `
  --icon "src/fwmigrate/static/app_icon.ico" `
  --paths "src" `
  --collect-all "fwmigrate" `
  --collect-all "webview" `
  --add-data "src/fwmigrate/templates;fwmigrate/templates" `
  --add-data "src/fwmigrate/static;fwmigrate/static" `
  --add-data "bin/terraform.exe;bin" `
  --hidden-import "clr" `
  --hidden-import "clr_loader" `
  --hidden-import "pythonnet" `
  src/fwmigrate/main.py
```

The output binary will be created at `dist/Firewall Migration Tool.exe`.

---

## 🛡️ Migration Safety & Manual Review Notes

The platform adheres to an **auditable and transparent** migration principle:
* **UTM / Security Profiles**: Antivirus, IPS, URL Filtering, and SSL Decryption policies are flagged for review and require verification against target security profile equivalents (e.g., PAN-OS Security Profile Groups or FortiOS UTM profiles).
* **Dynamic / Cloud Objects**: FQDNs, dynamic address groups, and EMS objects are clearly demarcated in the Markdown audit report.
* **Routing & NAT Topologies**: Complex NAT scenarios and dynamic routing (BGP/OSPF) should be cross-checked with the network topology summary in the audit report.
