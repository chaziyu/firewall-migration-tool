# Firewall Migration Tool — User Manual & Operations Guide

Welcome to the **Firewall Migration Tool** user manual. This guide provides comprehensive, step-by-step instructions for network administrators, security architects, and migration engineers performing firewall policy and configuration migrations across multi-vendor environments.

---

## 📑 Table of Contents
1. [Overview & Supported Platforms](#1-overview--supported-platforms)
2. [Launching the Application](#2-launching-the-application)
3. [Pre-Migration: Source Firewall Configuration Export](#3-pre-migration-source-firewall-configuration-export)
4. [Migration Mode A: File Conversion (Offline ZIP)](#4-migration-mode-a-file-conversion-offline-zip)
5. [Migration Mode B: Direct Live Migration (Terraform)](#5-migration-mode-b-direct-live-migration-terraform)
6. [Command Line Interface (CLI) Guide](#6-command-line-interface-cli-guide)
7. [Understanding Generated Output Deliverables](#7-understanding-generated-output-deliverables)
8. [Target Firewall Import & Provisioning Instructions](#8-target-firewall-import--provisioning-instructions)
9. [Interpreting the Migration Audit Report](#9-interpreting-the-migration-audit-report)
10. [Post-Migration Verification & Rollback](#10-post-migration-verification--rollback)
11. [Troubleshooting & Frequently Asked Questions](#11-troubleshooting--frequently-asked-questions)

---

## 1. Overview & Supported Platforms

The Firewall Migration Tool normalizes security policies, network objects, NAT rules, interfaces, zones, and static routes into a canonical **Intermediate Representation (`IRConfig`)**.

### Supported Multi-Vendor Matrix

| Vendor | Supported as Source ($M$) | Supported as Target ($N$) | Supported Formats |
|---|:---:|:---:|---|
| **Fortinet FortiGate** | ✅ | ✅ | `.conf`, `.txt`, Live REST API (`/api/v2/cmdb/`), Terraform (`fortinetdev/fortios`) |
| **Palo Alto Networks** | ✅ | ✅ | `.xml`, Live XML/REST API, Terraform (`PaloAltoNetworks/panos`) |
| **Cisco ASA / FTD** | ✅ | ✅ | `.cfg`, `.txt`, FMC API, Terraform (`CiscoDevNet/ciscoasa`) |
| **Check Point R80/R81** | ✅ | ✅ | `mgmt_cli` JSON dump, Management API, `.sh` scripts, Terraform (`CheckPointSW/checkpoint`) |
| **Juniper SRX / JunOS** | ✅ | ✅ | Flat `set` commands, hierarchical curly syntax, Terraform (`juniper/junos`) |

---

## 2. Launching the Application

### Method 1: Standalone Native Desktop App (Windows)
No Python, Node.js, or external browser installation is required.
1. Open the project folder in Windows Explorer.
2. Navigate to `dist/` and double-click **`Firewall Migration Tool.exe`**.
3. A dedicated desktop application window will open automatically.

### Method 2: One-Click Web Server (`run_migration.bat`)
1. Double-click **`run_migration.bat`** in the root folder.
2. Open your web browser and navigate to:
   ```
   http://localhost:5000
   ```

### Method 3: Command Line (CLI / Python)
```bash
# Start Web Server on custom port
python -m fwmigrate.main serve --port 8080

# Or launch Desktop window from source
python -m fwmigrate.main app
```

---

## 3. Pre-Migration: Source Firewall Configuration Export

Before starting migration, export the configuration file from your source firewall:

### Fortinet FortiGate
* **Via WebGUI:** Navigate to **System > Administrators > (Top right admin menu) > Configuration > Backup > Local PC**.
* **Via CLI:**
  ```fortios
  show full-configuration
  ```
  *(Save the entire output text to a `.conf` or `.txt` file)*
* **For Live REST API:**
  - Create a REST API Admin under **System > Administrators > Create New > REST API Admin**.
  - Assign Read/Write permissions to Firewall, Network, and System areas.
  - Save the generated API Token.

### Palo Alto Networks (PAN-OS / Panorama)
* **Via WebGUI:** Navigate to **Device > Setup > Operations > Export named configuration snapshot** $\rightarrow$ select `running-config.xml`.
* **Via CLI:**
  ```set
  set cli pager off
  show config running
  ```

### Cisco ASA / Firepower (FTD)
* **Via CLI:**
  ```cisco
  terminal pager 0
  show running-config
  ```
  *(Save the output as `.cfg` or `.txt`)*

### Check Point R80.x / R81.x
Export objects and rulebases using the Check Point Management CLI (`mgmt_cli`):
```bash
# Export objects and rulebase in JSON format
mgmt_cli -r true show-objects limit 500 --format json > checkpoint_objects.json
mgmt_cli -r true show-access-rulebase name "Network" limit 500 --format json > checkpoint_rules.json
```
*(Combine into a single `.json` file or use the bundled export utility)*

### Juniper SRX / JunOS
* **Flat set syntax (Recommended):**
  ```junos
  show configuration | display set | no-more
  ```
* **Hierarchical syntax:**
  ```junos
  show configuration | no-more
  ```
  *(Save output as `.set` or `.txt`)*

---

## 4. Migration Mode A: File Conversion (Offline ZIP)

Use this mode when you want to convert an offline backup file into target firewall configuration scripts, Terraform suites, and audit reports without directly touching a live network device.

```
┌────────────────────────────────────────────────────────────────────────┐
│ [Mode A: Convert Config File]          [Mode B: Direct Live Migration] │
├────────────────────────────────────────────────────────────────────────┤
│ 1. Select Source Vendor: [ Fortinet FortiGate ▼ ]                      │
│ 2. Select Target Vendor: [ Palo Alto Networks ▼ ]                      │
│ 3. Upload File:          [ Drag & Drop .conf / .xml / .cfg / .json ]   │
│ 4. Optimization Options: [x] Prune Unreferenced Objects                │
│                          [x] Deduplicate Equivalent Address Objects    │
│ 5. Click [ Start Conversion & Download Package ]                       │
└────────────────────────────────────────────────────────────────────────┘
```

### Steps:
1. Click the **Convert Config File** tab at the top.
2. Select your **Source Vendor** and **Target Platform**.
3. Drag & drop your configuration backup file into the drop zone.
4. *(Optional)* Toggle **Rule Optimizer**:
   - **Prune Unused Objects**: Removes address and service objects not referenced in any active security policy.
   - **Deduplicate Objects**: Merges identical IP definitions.
5. Click **Convert & Generate Deliverables**.
6. Download the generated **`migration_package_<timestamp>.zip`**.

---

## 5. Migration Mode B: Direct Live Migration (Terraform)

Use this mode for automated, end-to-end cutovers directly to your destination firewall with built-in pre-flight safety checks, dry-run diff review, and live log streaming.

### Step 1: Provide Target Firewall Credentials
* **Target Firewall IP / Hostname**: e.g., `192.168.1.1`
* **Target Port**: Default `443`
* **Username & Password / API Key**: Credentials for destination device
* **Target VDOM / Device Group**: (e.g., `root`, `shared`, or specific Device Group)

### Step 2: Run Pre-Flight Diagnostics
Click **Run Pre-Flight Diagnostics**. The engine will automatically test:
* ✅ Local / Embedded Terraform binary health
* ✅ TCP Port 443 line-of-sight reachability
* ✅ Target device API authentication & license validity
* ✅ Target OS version and hardware compatibility

### Step 3: Dry-Run Diff Inspection (`terraform plan`)
Click **Run Dry-Run Plan**.
* The system executes `terraform plan` inside a secure sandbox.
* The output displays exact resources to be created:
  ```diff
  + panos_address_object.db_server created
  + panos_service_object.app_port_8080 created
  + panos_security_rule_group.allow_web_traffic created
  ```
* Review resource counts (`+X to add, ~Y to change, -Z to destroy`).

### Step 4: Live Deployment (`terraform apply`)
1. Click **Deploy Configuration to Firewall**.
2. Watch the live terminal log viewer stream deployment execution line-by-line via Server-Sent Events (SSE).
3. All sensitive credentials, API keys, and passwords are automatically masked (`***`).
4. An automatic timestamped `.tfstate` backup is saved for rollback safety.

---

## 6. Command Line Interface (CLI) Guide

The CLI is available as `fwmigrate`, `fwmigrate`, or `python -m fwmigrate.main`.

### Check Available Plugins
```bash
fwmigrate vendors
```

### Convert Cisco ASA to Palo Alto Networks Terraform
```bash
fwmigrate migrate \
  --input backup/cisco_asa.cfg \
  --source-vendor cisco_asa \
  --target-vendor palo_alto \
  --optimize \
  --output ./output_palo_alto \
  --format terraform \
  --report ./output_palo_alto/migration_report.md
```

### Convert Check Point JSON to FortiGate Native CLI
```bash
fwmigrate migrate \
  --input backup/checkpoint_rules.json \
  --source-vendor checkpoint \
  --target-vendor fortigate \
  --output ./output_fortigate \
  --format cli \
  --report ./output_fortigate/migration_report.md
```

### Live Ingestion from FortiGate REST API
```bash
fwmigrate migrate \
  --fortigate-host 10.0.0.1 \
  --fortigate-port 443 \
  --fortigate-api-key "API_TOKEN_HERE" \
  --vdom "root" \
  --target-vendor palo_alto \
  --format xml \
  --output ./live_output \
  --report ./live_output/migration_report.md
```

---

## 7. Understanding Generated Output Deliverables

The generated migration package contains the following structured files:

```
migration_package/
├── native/                         # Native target configuration file
│   ├── panos_configuration.xml     # (for Palo Alto targets)
│   ├── fortigate_config.conf       # (for FortiGate targets)
│   ├── cisco_asa_config.cfg        # (for Cisco targets)
│   ├── checkpoint_rules.sh         # (for Check Point targets)
│   └── junos_config.set            # (for Juniper targets)
├── terraform/                      # Production Terraform HCL Suite
│   ├── main.tf                     # Resource definitions & security rules
│   ├── provider.tf                 # Official vendor provider configuration
│   ├── variables.tf                # Parameter declarations
│   └── terraform.tfvars            # Credentials and environment values
└── migration_report.md             # Unified Markdown Audit Report
```

---

## 8. Target Firewall Import & Provisioning Instructions

### Importing into Palo Alto Networks (PAN-OS)
#### Option 1: Native XML Import
1. Log in to PAN-OS WebGUI $\rightarrow$ **Device > Setup > Operations**.
2. Under **Configuration Management**, click **Import named configuration snapshot**.
3. Select `panos_configuration.xml`.
4. Click **Load named configuration snapshot** or **Merge with running config**.
5. Click **Commit** to activate.

#### Option 2: Standalone Terraform Execution
```bash
cd terraform/
terraform init
terraform plan
terraform apply
```

### Importing into Fortinet FortiGate (FortiOS)
1. Open the generated `fortigate_config.conf`.
2. Connect to FortiGate via SSH or open WebGUI **CLI Console**.
3. Paste the configuration blocks or upload via **System > Configuration > Restore**.

### Importing into Juniper SRX (JunOS)
1. Connect to SRX via SSH.
2. Enter configuration mode:
   ```junos
   configure
   ```
3. Load the set commands:
   ```junos
   load set junos_config.set
   commit check
   commit and-quit
   ```

### Importing into Check Point
1. Copy `checkpoint_rules.sh` to the Security Management Server.
2. Execute the shell script via `bash checkpoint_rules.sh` with administrative privileges.

---

## 9. Interpreting the Migration Audit Report

Every migration produces a detailed `migration_report.md`. Review this document prior to production cutover.

### Report Sections:
1. **Executive Migration Summary**:
   - Total address objects, service groups, NAT rules, and security policies converted.
2. **Optimization & Pruning Details**:
   - Unreferenced address objects that were safely removed.
   - Shadowed rules (rules made completely redundant by preceding rules).
3. **Manual Action Items (Engineer Review Required)**:
   - **UTM / Security Profiles**: Antivirus, IPS, and SSL Decryption require assigning target security profile groups.
   - **Dynamic / FQDN Objects**: Dynamic address feeds or cloud connectors that need target connector setup.
   - **Static Routes & Network Topology**: Verification of next-hop interfaces and default gateways.

---

## 10. Post-Migration Verification & Rollback

### Post-Migration Checklist:
- [ ] Verify address objects and service groups resolved without name collisions.
- [ ] Validate security policy ordering matches intended traffic priorities.
- [ ] Confirm NAT rules (Source NAT & Destination/VIP NAT) translate IP pools properly.
- [ ] Test bidirectional connectivity on critical application ports.
- [ ] Check security logs on destination firewall for unexpected drop counters.

### Rollback Procedures:
* **If deployed via Terraform**:
  ```bash
  terraform destroy -auto-approve
  ```
  *(Or restore from the automatically created `.tfstate.backup` snapshot)*
* **If deployed via Native Config**:
  - Revert the candidate configuration or restore the previous running configuration snapshot.

---

## 11. Troubleshooting & Frequently Asked Questions

### Q1: "SSL Certificate Verification Failed" during Live Ingestion
* **Cause**: Target/Source firewall uses a self-signed HTTPS certificate.
* **Fix**: In the Web UI, check **Disable SSL Verification (Insecure)**, or pass `--insecure` in the CLI.

### Q2: "Pre-Flight Check: Connection to Port 443 Failed"
* **Cause**: Firewall or intermediate network is blocking TCP port 443, or management interface access is restricted.
* **Fix**: Ensure your management IP is allowed in the firewall's trusted administrative host list.

### Q3: Forward-Reference Errors During Provisioning
* **Resolution**: The tool automatically applies **Kahn's Topological Sorting Algorithm** to ensure address and service objects are declared before security policies that reference them. If manual editing was performed, re-run the optimizer.

### Q4: "ModuleNotFoundError: No module named 'fwmigrate'"
* **Fix**: Run `run_migration.bat` (which sets `PYTHONPATH` automatically) or install the package in editable mode via `pip install -e .`.

---

**Copyright © 2025 GSW Systems. All rights reserved.**  
**Modified in 2026 by Cha Zi Yu (23120943@siswa.um.edu.my)**
