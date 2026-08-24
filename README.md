# Firewall Migration Tool

![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10+-green.svg)
![Terraform](https://img.shields.io/badge/terraform-1.0+-purple.svg)
![Tests](https://img.shields.io/badge/tests-126%20passed-brightgreen.svg)
![Platform](https://img.shields.io/badge/executable-Windows%20x64%20Standalone-blue.svg)

A production-grade Python and Terraform platform for migrating enterprise firewall configurations across any-to-any multi-vendor environments (**Fortinet FortiGate**, **Palo Alto Networks PAN-OS / Panorama**, **Cisco ASA / Firepower**, **Check Point R80/R81**, and **Juniper SRX / JunOS**). It also exports the pre-optimization source IR as a vendor-neutral Excel inventory, independently of any target vendor.

The platform adopts a decoupled $M \times N$ **Vendor-Neutral Intermediate Representation (IR)** architecture, featuring automated rule optimization, pre-flight diagnostics, dry-run diff review, automated UTM/Threat Prevention Profile synthesis, and live Terraform execution streaming.

**Copyright © 2025 GSW Systems. All rights reserved.**  
**Modified in 2026 by Cha Zi Yu**  
**License:** GNU Affero General Public License v3.0 (AGPL-3.0)  

> **Acknowledgments / Credits**
> This project is a derivative work adapted from the [gswsystems/fortigate-palo-migration](https://github.com/gswsystems/fortigate-palo-migration) repository by GSW Systems. We thank the original authors for their foundational work. This project is distributed under the AGPL-3.0 license.

## Documentation Reference

For deep-dive documentation on operations, architecture, and intermediate data models, please see the `documentation/` directory:
- [User Manual & Operations Guide](documentation/User%20Manual.md) — Step-by-step guides, CLI reference, and export instructions.
- [Project Detail](documentation/Project%20Detail.md) — Core engine mechanics, supported capabilities, and validation logic.
- [Intermediate Representation Data Structure](documentation/Intermediate%20Representation%20Data%20Structure.md) — Technical spec for the unified $M \times N$ IR configuration model.

---

## Table of Contents
1. [Architecture & Core Components](#architecture--core-components)
2. [Quick Reference: Any-to-Any Vendor Compatibility Matrix](#quick-reference-any-to-any-vendor-compatibility-matrix)
3. [Per-Brand Configuration Conversion Matrix](#per-brand-configuration-conversion-matrix-what-is-converted-vs-omitted)
4. [Usage Guide](#usage-guide)
   - [Getting Started](#getting-started)
   - [Web Interface Walkthrough](#web-interface-walkthrough)
   - [Command Line Interface (CLI) Usage](#command-line-interface-cli-usage)
5. [Testing & Validation](#testing--validation)
6. [Building the Standalone Executable](#building-the-standalone-executable)
7. [Migration Safety & Manual Review Notes](#migration-safety--manual-review-notes)

---

## Architecture & Core Components

```
   ┌───────────────────────────────────────────────────────────────────┐
   │                       Source Configurations                       │
   │   FortiGate (.conf) | PAN-OS (.xml) | Cisco (.cfg) | CP (JSON)    │
   └─────────────────────────────────┬─────────────────────────────────┘
                                     │ (Ingestion & Parsing)
                                     ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │        Vendor-Neutral Intermediate Representation (IRConfig)      │
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

## Quick Reference: Any-to-Any Vendor Compatibility Matrix

The engine normalizes all vendor-specific constructs into a canonical Intermediate Representation (`IRConfig`), allowing seamless cross-vendor migration between any source ($M$) and any target ($N$):

| Source Vendor ($M$) | Ingestion Methods | Target Vendor ($N$) | Output Formats & UTM Synthesis |
|---|---|---|---|
| **Fortinet FortiGate** | `.conf` / `.txt` backup, live `/api/v2/cmdb/` REST | **Palo Alto Networks** | Native XML, `panos` Terraform HCL, auto-generated `<profile-group>` |
| **Palo Alto Networks** | `.xml` configuration, live XML/REST API | **Fortinet FortiGate** | Native CLI (`.conf`), `fortios` Terraform HCL, `config firewall profile-group` |
| **Cisco ASA / Firepower** | `.cfg` / `.txt` access-lists & objects, FMC API | **Cisco ASA / FTD** | Native CLI (`.cfg`), `ciscoasa` Terraform HCL |
| **Check Point R80.x/R81.x** | `mgmt_cli` JSON export, Management API | **Check Point** | Native `mgmt_cli` shell scripts (`.sh`), Threat Prevention Layer rules |
| **Juniper SRX / JunOS** | Flat `set` commands, hierarchical curly syntax | **Juniper SRX** | Native JunOS `set` commands (`.set`), `application-services utm-policy` |

> All $M \times N$ migration paths automatically synthesize **Threat Prevention / Security Profile Groups** and generate both an **Interactive HTML Report (`.html`)** and a **Markdown Audit Report (`.md`)**.

---

## Per-Brand Configuration Conversion Matrix: What Is Converted vs. Omitted

When migrating enterprise firewalls, the platform prioritizes **active security policies, network topology, routing, and object definitions** while intentionally omitting hardware-tied or chassis-specific daemon settings:

### 1. Fortinet FortiGate (FortiOS)
* **Supported (Converted):**
  - `config firewall policy` $\to$ Security Access Rulebase + UTM Security Profile Groups
  - `config firewall address` / `addrgrp` $\to$ Host (/32), Subnet (/24), Range, FQDN address objects & groups
  - `config firewall service custom` / `group` $\to$ TCP/UDP/ICMP services & grouped definitions
  - `config firewall ippool` $\to$ Source NAT / Dynamic PAT address pools
  - `config firewall vip` / `vipgrp` $\to$ Destination NAT / Inbound Virtual IPs
  - `config system interface` / `zone` $\to$ Physical & VLAN interfaces, IP subnets, Security Zones
  - `config router static` $\to$ Virtual Router static routes, next-hop gateways, metrics
  - `config vpn ipsec phase1/phase2-interface` $\to$ IKE Gateways, IPsec Crypto Proposals, Tunnels
  - `config firewall schedule recurring` $\to$ Security policy time schedules
  - FortiGate UTM settings (Antivirus, IPS, Webfilter, Application, SSL-SSH) $\to$ Synthesized Threat Profile Groups
* **Omitted & Technical Rationale:**
  - *Hardware ASICs (`np6xlite`, `physical-switch`):* Proprietary hardware silicon unique to Fortinet chassis.
  - *Replacement Messages (`replacemsg-*`, 16 types):* Vendor-proprietary HTML block page templates.
  - *Appliance Local Users & Dashboards (`system admin`, `gui-dashboard`, `widget`):* Target firewalls configure administrative RBAC independently or via enterprise TACACS+/SAML.
  - *High Availability (`system ha`, `standalone-cluster`):* FGCP/FGSP clustering protocols; target firewalls pair HA based on new hardware serials and dedicated HA links.
  - *Edge DHCP Server (`system dhcp server`):* Enterprise networks centralize DHCP on Windows Server / Infoblox; local branch pools are enabled directly on target interfaces if required.
  - *Telemetry & Fabric (`automation-*`, `endpoint-control`):* Fortinet Security Fabric workflows not portable to non-Fortinet firewalls.

### 2. Palo Alto Networks (PAN-OS / Panorama)
* **Supported (Converted):**
  - `<security><rules>` $\to$ Security access policies with action, status, and log forwarding
  - `<nat><rules>` $\to$ Source NAT, Destination NAT, Static 1:1 NAT
  - `<address>` / `<address-group>` $\to$ IP Netmask, IP Range, FQDN objects and static/dynamic groups
  - `<service>` / `<service-group>` $\to$ TCP/UDP port ranges and service bundles
  - `<profile-group>` $\to$ Antivirus, Vulnerability (IPS), Anti-Spyware, URL, File Blocking, WildFire, Decryption
  - `<network><interface>` / `<zone>` $\to$ Layer 3 interfaces, subinterfaces, 802.1Q tags, Security Zones
  - `<virtual-router><routing-table>` $\to$ Static routes, default gateways, interface bindings, metrics
  - `<network><ike><gateway>` & `<network><tunnel><ipsec>` $\to$ IKE gateways, IPsec crypto profiles, tunnels
* **Omitted & Technical Rationale:**
  - *Panorama Device-Group Hierarchy:* Flattened into target firewall configuration or vsys.
  - *Admin RBAC & Authentication Profiles (`<mgt-config>`, `<authentication-profile>`):* Appliance-specific administrator credentials.
  - *Physical HA Link MACs (`<high-availability>`):* Hardware-specific HA1/HA2 cabling.
  - *GlobalProtect Portal/Gateway:* Client SSL VPN portals require target vendor-specific certificate and client pool setup.

### 3. Cisco ASA / Firepower (FTD)
* **Supported (Converted):**
  - `access-list ... extended permit/deny` $\to$ Security access policies
  - `object network` / `object-group network` $\to$ Host, subnet, range, and FQDN objects & groups
  - `object service` / `object-group service` $\to$ TCP/UDP/ICMP custom service definitions & groups
  - `nat (inside,outside) source/destination` $\to$ Twice NAT, Object NAT, PAT pools, Static 1:1 NAT
  - `interface`, `nameif`, `ip address` $\to$ Named interfaces, IP assignments, Security Zones
  - `route [interface] [subnet] [gateway]` $\to$ Static routes and default gateways
  - `crypto ikev2`, `crypto ipsec`, `tunnel-group` $\to$ IKEv2 gateways and Site-to-Site IPsec tunnels
* **Omitted & Technical Rationale:**
  - *Interface Security Levels (`security-level 0-100`):* Replaced by explicit zone-to-zone firewall policies.
  - *Hardware Failover (`failover`, `failover lan`):* Physical ASA Active/Standby heartbeat cabling.
  - *ASDM GUI & History (`asdm history`, `logging asdm`):* Cisco ASDM Java management tool preferences.
  - *Legacy Inspection Engines (`class-map`, `policy-map inspect`):* Replaced by target Layer 7 App-ID / Threat Prevention.

### 4. Check Point (Gaia R80.x / R81.x)
* **Supported (Converted):**
  - Access Rulebases (`show-access-rulebase`) $\to$ Security policies with source, destination, service, and action
  - Host/Network/Range/Group Objects (`show-objects`) $\to$ Normalized address objects & address groups
  - Service TCP/UDP/ICMP/Group definitions $\to$ Custom service objects and bundles
  - Automatic & Manual NAT Rulebases $\to$ Source, Destination, and Static NAT translations
  - Network Interfaces & Topology $\to$ Physical interfaces, subnets, and zone boundaries
  - Static Routes $\to$ Destination subnets, next hops, and outgoing interfaces
  - Threat Prevention Layers $\to$ Antivirus, IPS, and Threat Emulation engine profiles
* **Omitted & Technical Rationale:**
  - *SmartConsole GUI Metadata (`color`, `icon`, `comments`):* Check Point management client GUI display properties.
  - *ClusterXL & Sync Interfaces (`cphaconf`):* Check Point proprietary state-sync clustering protocols.
  - *Security Management Server (SMS) Database IDs (`uid`, `domain`):* Internal Check Point PostgreSQL schema UUIDs.

### 5. Juniper SRX (JunOS)
* **Supported (Converted):**
  - `set security policies from-zone ... to-zone ...` $\to$ Security access policies
  - `set security address-book` / `address-set` $\to$ Host, subnet, range, and DNS address objects & sets
  - `set applications application` / `application-set` $\to$ Custom protocol & port definitions
  - `set security nat source/destination/static` $\to$ NAT rule sets and translation pools
  - `set security zones security-zone` & `set interfaces` $\to$ Zones, physical interfaces, units, VLAN tags
  - `set routing-options static route` $\to$ Static routing table and next-hop forwarding
  - `set security ike` & `set security ipsec` $\to$ IKE proposals, policies, gateways, and IPsec VPNs
  - `set security utm utm-policy` $\to$ Antivirus, Web filtering, and IPS sensor policies
* **Omitted & Technical Rationale:**
  - *Chassis Cluster (`set chassis cluster`):* Hardware reth (redundant Ethernet) interfaces and control link cabling.
  - *JunOS Dynamic Routing Daemons (OSPF/BGP process options):* Converted via static routes; dynamic BGP peers configured on target routing instances.
  - *System Login & User Classes (`set system login`):* Local JunOS administrator accounts.

---

## Usage Guide

Choose the method that best fits your workflow:

### Getting Started

#### Option 1: Standalone Native Desktop App (No Installation)
For Windows end-users, pre-compiled standalone executable with zero dependencies:
* **Executable Path:** `dist/Firewall Migration Tool.exe` (~53 MB)
* **Highlights:** Embedded Edge WebView2 desktop window, bundled offline Terraform CLI, no Python or Node.js required.

```powershell
# Launch Desktop GUI directly:
.\dist\"Firewall Migration Tool.exe"

# Or run standalone CLI:
.\dist\"Firewall Migration Tool.exe" vendors
.\dist\"Firewall Migration Tool.exe" migrate -i examples/example_fortigate.conf -o ./output --format xml --optimize
```

#### Option 2: One-Click Web Server (`run_migration.bat`)
To quickly start the modern web interface on Windows:
1. Double-click `run_migration.bat` in the repository root.
2. Open your browser and navigate to **`http://localhost:5000`**.

#### Option 3: Run from Python Source

**Prerequisites**
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

### Web Interface Walkthrough

The platform features an interactive dark-mode web console designed for fast, auditable migrations:

```
┌────────────────────────────────────────────────────────────────────────┐
│  [ Download Migration Package ]   [ Direct Live Migration (TF) ]       │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Section 1: Ingestion Method       [ Upload File ]  [ Live API ]        │
├────────────────────────────────────────────────────────────────────────┤
│  • Select Source & Target Vendors (FortiGate, PAN-OS, Cisco, etc.)     │
│  • Upload configuration backup OR connect via Live Management API      │
└────────────────────────────────────────────────────────────────────────┘
```

**Migration Modes:**
1. **Mode A: Download Migration Package (.zip)**  
   Converts source configuration into a complete archive containing native syntax files, production Terraform HCL suites, and the Markdown audit report.
2. **Mode B: Direct Live Migration (Terraform Live Engine)**  
   Executes real-time pre-flight diagnostics, runs `terraform plan` for dry-run diff inspection, and performs streamed deployment with sensitive credential masking and automatic `.tfstate` rollback backups.

### Command Line Interface (CLI) Usage

The CLI is available as `fwmigrate`, `fwmigrate`, or `python -m fwmigrate.main`.

**1. View Registered Vendor Plugins**
```bash
fwmigrate vendors
```

**2. Cross-Vendor Migration (e.g. Cisco ASA to Palo Alto)**
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

**3. Check Point / Juniper to FortiGate Native CLI**
```bash
fwmigrate migrate \
  -i examples/example_checkpoint.json \
  --source-vendor checkpoint \
  --target-vendor fortigate \
  -o migration_output_fg \
  --format cli
```

**4. Live Device API Ingestion via CLI**
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

## Testing & Validation

The codebase includes an extensive test suite covering tokenizers, AST parsers, IR models, optimizers, report generators, diagnostics, and multi-vendor golden configurations:

```bash
pytest tests/ -v
# 126 passed
```

---

## Building the Standalone Executable

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

## Migration Safety & Manual Review Notes

The platform adheres to an auditable and transparent migration principle:
* **UTM / Security Profiles**: Antivirus, IPS, URL Filtering, and SSL Decryption policies are flagged for review and require verification against target security profile equivalents (e.g., PAN-OS Security Profile Groups or FortiOS UTM profiles).
* **Dynamic / Cloud Objects**: FQDNs, dynamic address groups, and EMS objects are clearly demarcated in the Markdown audit report.
* **Graceful Degradation & Security Expansion Guards**: The parser automatically quarantines malformed legacy objects (e.g., broken subnets). If filtering these broken objects reduces a security policy's source or destination to an empty list, the generator actively disables the rule to prevent a silent expansion to an "allow any" state.
* **Routing & NAT Topologies**: Complex NAT scenarios and dynamic routing (BGP/OSPF) should be cross-checked with the network topology summary in the audit report.

---

### FortiGate NAT extraction

FortiGate NAT is normalized from firewall-policy intent rather than from standalone
IP Pool/VIP objects.

Supported preservation includes:

- policy-level source NAT;
- outgoing-interface-address SNAT;
- IP Pool references;
- VIP/VIP-group DNAT;
- port translation;
- policy-to-NAT correlation;
- explicit manual-review handling for runtime-dependent translations such as SD-WAN
  and dynamically addressed interfaces.