# Firewall Migration Tool — Documentation Hub

Welcome to the documentation index for the Firewall Migration Tool repository.

This directory is organized into distinct categories by operational role and lifecycle:
- **Core Standard**: Authoritative cross-vendor capabilities and version boundaries.
- **Operational Guides (`guides/`)**: Pair-specific execution guides and instructions for engineers.
- **Architecture (`architecture/`)**: Core automation engines, dependency resolution DAG, and export design.
- **Official Vendor References (`official-cli-references-selected version/`)**: Pinned CLI and API syntax authorities.
- **History & Progress (`history/`)**: Multi-phase engineering plans, execution checklists, and verification logs.

---

## 1. Core Authority

| Document | Purpose |
| :--- | :--- |
| **[Migration Support Matrix](migration-support-matrix.md)** | Current directional capabilities: target versions, execution limits, supported feature subsets, and offline boundaries. Workflow metadata in `builtin.py` links to this document; code and tests implement the contracts. |

---

## 2. Operational & Migration Guides (`guides/`)

Practical instructions for running pair migrations via the web interface or CLI (`fwmigrate migrate`).

| Guide | Source Vendor | Target Vendor | Output Baseline |
| :--- | :--- | :--- | :--- |
| **[PAN-OS Multi-Target Migration](guides/PAN-OS-multi-target-migration.md)** | Palo Alto PAN-OS | FortiGate, Juniper SRX, Cisco ASA, Check Point, Cisco FTD | Comprehensive multi-target manual covering target setup, CLI commands, and security contracts. |
| **[PAN-OS to FortiGate Migration](guides/PAN-OS-to-FortiGate-migration.md)** | Palo Alto PAN-OS | FortiGate | FortiOS 7.4.6 CLI export (`.conf`). |
| **[FortiGate to Check Point Migration](guides/fortigate-to-checkpoint-migration.md)** | FortiGate | Check Point | Management API 1.8.1 JSON request templates + Gaia Clish routes. |
| **[FortiGate to Cisco ASA Migration](guides/fortigate-to-cisco-asa-migration.md)** | FortiGate | Cisco ASA | ASA 9.20 routed single-context CLI (`.cfg`). |

> **Note on Other Pairs**:
> - **FortiGate → Palo Alto PAN-OS** (the primary forward pair supporting live candidate push, validation, and explicit commit) is documented in the [root README](../README.md#overview) and candidate automation records.
> - **FortiGate → Juniper SRX** requirements and baseline settings are detailed in the [Migration Support Matrix](migration-support-matrix.md#juniper-srx).

---

## 3. Architecture & Technical Specifications (`architecture/`)

Deep-dive architecture specifications into the core engines that power source analysis and deterministic migration planning.

| Specification | Focus |
| :--- | :--- |
| **[Migration Automation Engine](architecture/migration-automation.md)** | Dependency DAG, topological sorting, render disposition (`CREATE`, `CONFIGURE`, `REUSE`, `BLOCK`), and fail-closed candidate review contracts. |
| **[Excel Export & Review Pipeline](architecture/excel-export-review.md)** | Source workbook generation architecture, fast Excel styling, and preview data transforms. |

### Active reviews and operational checkpoints

| Record | Purpose |
| :--- | :--- |
| [Code Quality Review and Refinement](code-quality-review-2026-10-23.md) | Code, import boundaries, stale policy and organization findings, implementation plan and validation. |
| [Excel Export Reliability and Efficiency](excel-export-improvements-2026-10-23.md) | Frontend cancellation and profile defaults, workbook resource cleanup, FAST memory/speed improvements and verification. |
| [PAN-OS Migration Safety Corrections](migration-safety-fixes-2026-10-23.md) | SRX policy dependencies, schedules and route preference; FMC matching, target identity and structured application. |
| [Node Runtime and Bug Review](node-runtime-and-bug-review-2026-10-23.md) | Node security baseline, dependency updates, launcher synchronization and proxy error handling. |
| [FortiGate to PAN-OS Scheduled Review](fortigate-to-panos-scheduled-review.md) | Resumable migration audit checkpoint, completed fixes and remaining engineer decisions. |
| [Offline Workflow Parity Progress](offline-workflow-parity-progress.md) | Cross-pair workflow verification and remaining limitations. |
| [Render Deployment Recovery](render-deployment-recovery-2026-10-23.md) | Failed-start investigation, cache recovery and deployment verification evidence. |

---

## 4. Official Vendor References (`official-cli-references-selected version/`)

Official vendor syntax references and command standards used as semantic authority for command parsers, transforms, and renderers:

- **[FortiGate Selected CLI References](official-cli-references-selected%20version/FortiGate%20Selected%20CLI%20References.md)** (FortiOS 7.4.6)
- **[Palo Alto Selected CLI References](official-cli-references-selected%20version/Palo_Alto_Selected_CLI_References.md)** (PAN-OS 11.1)
- **[Cisco ASA Selected Configuration References](official-cli-references-selected%20version/Cisco_ASA_Selected_Configuration_References.md)** (ASA 9.20)
- **[Cisco FTD Selected Configuration References](official-cli-references-selected%20version/Cisco_FTD_Selected_Configuration_References.md)** (FMC REST API 7.7.0)
- **[Juniper Selected CLI References](official-cli-references-selected%20version/Juniper_Selected_CLI_References.md)** (Junos 25.2R1)
- **[Check Point R81 Selected CLI and Management API References](official-cli-references-selected%20version/Check_Point_R81_Selected_CLI_and_Management_API_References.md)** (R81 Management API 1.8.1)

---

## 5. Engineering History & Project Logs (`history/`)

Archived roadmaps, phase progress tracking, and verification evidence from previous development sprints. These records describe their implementation baselines; they are not current capability or security policy. Use the support matrix, operational guides and current code for those decisions. Keep active scheduled checkpoint paths stable for subsequent runs.

### PAN-OS Expansion (`history/panos-expansion/`)
- **[PAN-OS to All Vendors Implementation Plan](history/panos-expansion/PAN-OS-to-all-vendors-implementation-plan.md)**: 10-phase roadmap for PAN-OS multi-target conversion.
- **[PAN-OS to All Vendors Implementation Progress](history/panos-expansion/PAN-OS-to-all-vendors-implementation-progress.md)**: Execution milestones and acceptance checksums.
- **[PAN-OS Migration Command Verification](history/panos-expansion/PAN-OS-migration-command-verification.md)**: Command verification across target platforms.
- **[Palo Alto to FortiGate Automation Review](history/panos-expansion/palo-alto-to-fortigate-automation-review.md)**: Review and verification logs for PA → FG pair.

### FortiGate Expansion (`history/fortigate-expansion/`)
- **[FortiGate Multi-Vendor Implementation Plan](history/fortigate-expansion/FortiGate-multi-vendor-implementation-plan.md)**: Master plan for FortiGate multi-vendor conversion.
- **[FortiGate Multi-Vendor Execution Progress](history/fortigate-expansion/FortiGate-multi-vendor-execution-progress.md)**: Execution checklists and regression logs.
- **[FortiGate Multi-Vendor Handoff](history/fortigate-expansion/FortiGate-multi-vendor-GPT-6-Luna-handoff.md)**: Sprint handoff and architectural notes.
- **[FortiGate to PAN-OS Automation Execution](history/fortigate-expansion/fortigate-to-panos-automation-execution.md)**: Execution record for candidate automation.
- **[FortiGate to PAN-OS Automation Evidence](history/fortigate-expansion/fortigate-to-panos-automation-evidence.md)**: Verification evidence and command outputs.

### Web Workflow Parity (`history/workflow-parity/`)
- **[Migration Workflow Implementation Plan](history/workflow-parity/migration-workflow-implementation-plan.md)**: Unified 4-stage UI/API workflow roadmap.
- **[Migration Workflow Verification](history/workflow-parity/migration-workflow-verification.md)**: Multi-pair web workflow verification report.
