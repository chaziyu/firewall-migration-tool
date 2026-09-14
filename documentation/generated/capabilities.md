# Registered Vendor Capabilities

<!-- GENERATED FILE. DO NOT EDIT DIRECTLY. -->

This file is generated from the runtime plugin registry. It reports registration, not feature-level semantic parity.

## Source parsers

| Source ID | Display name | Accepted extensions |
|---|---|---|
| `checkpoint` | Check Point R80/R81 (JSON Dump / API) | `.json`, `.txt`, `.cfg` |
| `cisco_asa` | Cisco ASA | `.cfg`, `.txt`, `.conf` |
| `cisco_ftd` | Cisco Firepower Threat Defense | `.cfg`, `.txt`, `.conf`, `.json` |
| `fortigate` | Fortinet FortiGate | `.conf`, `.cfg`, `.txt` |
| `juniper_srx` | Juniper SRX (Junos root-level display set) | `.set`, `.txt`, `.conf` |
| `palo_alto` | Palo Alto Networks (PAN-OS) | `.xml` |

## Target generators

| Target ID | Display name | Registered formats |
|---|---|---|
| `checkpoint` | Check Point Quantum / CloudGuard | `cli`, `terraform` |
| `cisco_asa` | Cisco ASA / Firepower | `cli`, `terraform` |
| `fortigate` | Fortinet FortiGate (FortiOS CLI / Terraform) | `cli`, `terraform` |
| `juniper_srx` | Juniper SRX / JunOS | `set`, `cli`, `terraform` |
| `palo_alto` | Palo Alto Networks (PAN-OS / Panorama) | `xml`, `terraform` |

**Current executable IR schema:** `1.66`

> A registered source and a registered target do not imply lossless feature parity. Review the vendor support matrix and migration report before deployment.
