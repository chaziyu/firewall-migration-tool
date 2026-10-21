# PAN-OS Multi-Target Migration Guide

Updated: 2026-10-21.

This guide documents the directional migration workflows taking Palo Alto PAN-OS (XML source) to five target vendors: FortiGate, Juniper SRX, Cisco ASA, Check Point, and FMC-managed Cisco FTD.

## Workflow Overview

All PAN-OS migration workflows are **offline export only**. Only FortiGate to PAN-OS retains live candidate operations.

```text
PAN-OS Source XML
  → Vendor Parser & Derived Views
  → Target Selection & Proposal
  → Target Setup (Mode, Scope, Options, Evidence)
  → Deterministic Design Session & Review
  → Signed Explicit Approval
  → Dependency-Aware Renderer
  → Offline Artifact Bundle / Downloads
```

---

## Supported Target Baselines

| Target Vendor | Target Baseline | Output Format | Files Emitted |
| :--- | :--- | :--- | :--- |
| **FortiGate** | FortiOS 7.4.6 | CLI (`.conf`) | `fortigate_config.conf`, `migration_report.json`, `migration_decisions.json`, `target_mappings.yaml` |
| **Juniper SRX** | Junos 25.2R1 standalone | Set (`.set`) | `junos_srx.set`, `migration_report.json`, `migration_decisions.json` |
| **Cisco ASA** | ASA 9.20 routed single-context | CLI (`.cfg`) | `cisco_asa.cfg`, `migration_report.json`, `migration_decisions.json` |
| **Check Point** | Management API 1.8.1 | JSON + Bash (`.json`, `.sh`) | `checkpoint_management_operations.json`, `checkpoint_bindings.json`, `checkpoint_management.sh`, `gaia_config.clish` |
| **Cisco FTD** | FMC REST API 7.7.0 | JSON + Shell (`.json`, `.sh`) | `cisco_fmc_operations.json`, `cisco_fmc_bindings.json`, `cisco_fmc_curl.sh`, `ftd_application_instructions.txt` |

---

## Target-Specific Setup Options

### 1. Palo Alto PAN-OS → FortiGate
- **Source Scope**: Select one standalone VSYS (e.g. `vsys1`).
- **Target VDOM**: Target VDOM name (default: `root`).
- **Interface Mapping**: Map PAN-OS interfaces to FortiGate physical/VLAN ports.

### 2. Palo Alto PAN-OS → Juniper SRX
- **Source Scope**: Select one standalone VSYS.
- **Target Mode**: New device (root context) or Existing target snapshot.
- **Root Context**: Must be confirmed root context on Junos 25.2R1 standalone.
- **Target Snapshot**: Optional Junos set configuration snapshot. Complete families enable exact `REUSE` classification.

### 3. Palo Alto PAN-OS → Cisco ASA
- **Source Scope**: Select one standalone VSYS.
- **Target Mode**: New device (ASA 9.20 routed single-context) or Existing target snapshot.
- **Interface / Nameif Mapping**: Map PAN-OS L3 ports to ASA physical ports, nameif identifiers, and security levels (0–100).
- **Target Snapshot**: Optional ASA CLI snapshot for address/port object reuse.

### 4. Palo Alto PAN-OS → Check Point
- **Source Scope**: Select one standalone VSYS.
- **Target Mode**: New policy package or Existing Management snapshot.
- **Management Server / Domain**: Target server hostname/IP and Management Domain.
- **Policy Package & Access Layer**: Propose names for new package and access layer.
- **Install-on**: Target gateway or cluster names for rule installation.
- **Target Snapshot**: Optional Check Point Management API 1.8.1 export bundle for object UID reuse.

### 5. Palo Alto PAN-OS → Cisco FTD (FMC-managed)
- **Source Scope**: Select one standalone VSYS.
- **Target Mode**: New Access Control Policy or Existing FMC snapshot.
- **FMC Management Server & Domain**: Hostname/IP, Domain Name, and Domain UUID (`domain_id`).
- **Access Control Policy Name**: Name of the container policy to create.
- **Target Snapshot**: Optional FMC REST export bundle (`fmc-rest-bundle`) for network, port, and security zone ID reuse.

---

## CLI Execution Examples

All pairs can be run via the `fwmigrate` command-line interface.

### PAN-OS → FortiGate
```bash
python -m fwmigrate.main migrate \
  --input "source_panos.xml" \
  --output "output_fortigate" \
  --source-vendor palo_alto \
  --target-vendor fortigate \
  --format cli
```

### PAN-OS → Juniper SRX
```bash
python -m fwmigrate.main migrate \
  --input "source_panos.xml" \
  --output "output_srx" \
  --source-vendor palo_alto \
  --target-vendor juniper_srx \
  --format set
```

### PAN-OS → Cisco ASA
```bash
python -m fwmigrate.main migrate \
  --input "source_panos.xml" \
  --output "output_asa" \
  --source-vendor palo_alto \
  --target-vendor cisco_asa \
  --format cfg
```

### PAN-OS → Check Point
```bash
python -m fwmigrate.main migrate \
  --input "source_panos.xml" \
  --output "output_checkpoint" \
  --source-vendor palo_alto \
  --target-vendor checkpoint \
  --format json
```

### PAN-OS → Cisco FTD
```bash
python -m fwmigrate.main migrate \
  --input "source_panos.xml" \
  --output "output_ftd" \
  --source-vendor palo_alto \
  --target-vendor cisco_ftd \
  --format json
```

---

## Review and Approval Security Contract

1. **Deterministic Design Draft**: The backend generates an immutable draft based on source analysis and target setup choices.
2. **Explicit Item Selection**: The operator reviews ready, blocked, and manual items. Only `CREATE` and `REUSE` items with all prerequisites satisfied can be selected.
3. **Signed Envelope**: The backend generates an HMAC-signed approval envelope that binds:
   - Source content SHA-256
   - Target configuration / snapshot SHA-256
   - Target options and parameters
   - Selected items and complete dependency closure
   - Finite expiration timestamp
4. **Invalidation**: Any modification to source text, target options, target snapshot, or prerequisite items revokes the approval and rendered artifacts immediately.
5. **Multi-File Manifest**: Every rendered file includes its content byte count and SHA-256. Tampering with any file in the artifact revokes preview and downloads.

---

## Fail-Closed Boundaries & Manual Work

The following categories remain blocked and require manual engineering review across all PAN-OS migration workflows:

- **App-ID & Content Inspection**: PAN-OS App-ID cannot be approximated to L4 ports without creating security bypasses. Threat, antivirus, vulnerability, URL filtering, and file blocking profiles fail closed.
- **Active NAT**: Dynamic IP and port (DIPP), bidirectional static NAT, and pool translations require verified return-path routing, ARP, and interface ownership proofs.
- **Named Schedules**: Non-always and recurring schedules fail closed.
- **Routing with Self-Referential Gateways**: Routes whose next-hop points to the outgoing interface's own IP address remain blocked.
- **Device Management Planes**: Check Point Gaia OS (interfaces/static routes) and FTD device physical interface assignments remain manual steps.
- **Secrets & Credentials**: Private keys, pre-shared keys (PSKs), password hashes, and tokens are redacted and never exported.
