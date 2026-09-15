# Registered Vendor Capabilities

<!-- GENERATED FILE. DO NOT EDIT DIRECTLY. -->

This file is generated from the runtime plugin registry. It reports registration, not feature-level semantic parity.

## Source parsers

| Source ID | Display name | Accepted extensions | Aliases | Status |
|---|---|---|---|---|
| `checkpoint` | Check Point R80/R81 (JSON Dump / API) | `.json`, `.txt`, `.cfg` | `check_point` | stable |
| `cisco_asa` | Cisco ASA | `.cfg`, `.txt`, `.conf` | `asa` | stable |
| `cisco_ftd` | Cisco Firepower Threat Defense | `.cfg`, `.txt`, `.conf`, `.json` | `ftd` | stable |
| `fortigate` | Fortinet FortiGate | `.conf`, `.cfg`, `.txt` | `fortinet`, `fg` | stable |
| `juniper_srx` | Juniper SRX (Junos root-level display set) | `.set`, `.txt`, `.conf` | `srx`, `junos` | stable |
| `palo_alto` | Palo Alto Networks (PAN-OS / Panorama) | `.xml`, `.json`, `.txt` | `panos`, `paloalto` | stable |

## Target generators

| Target ID | Display name | Registered formats | Aliases | Status |
|---|---|---|---|---|
| `checkpoint` | Check Point Quantum / CloudGuard | `cli`, `terraform` | `check_point` | stable |
| `cisco_asa` | Cisco ASA / Firepower | `cli`, `terraform` | `asa` | stable |
| `fortigate` | Fortinet FortiGate (FortiOS CLI / Terraform) | `cli`, `terraform` | `fortinet`, `fg` | stable |
| `juniper_srx` | Juniper SRX / JunOS | `set`, `cli`, `terraform` | `srx`, `junos` | stable |
| `palo_alto` | Palo Alto Networks (PAN-OS / Panorama) | `xml`, `terraform` | `panos`, `paloalto` | stable |

> A registered source and a registered target do not imply lossless feature parity. Review the vendor support matrix and migration report before deployment.
