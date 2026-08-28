# Palo Alto Networks Extraction Reference

This document describes the design and implementation of the Palo Alto Networks (PAN-OS) source configuration parser in the Firewall Migration Tool.

## Architecture

The parser implements a robust, extraction-focused design that prioritizes safety, accounting, and scoping fidelity over permissive defaults.

### 1. Scoped Parsing
PAN-OS configurations rely heavily on scoping (`shared`, `vsys`, `device-group`). The parser processes configuration sequentially:
- Pre-processes the XML to find standard scopes.
- Implements `_parse_scope()` to recursively handle elements within a specified `PANScope`.

### 2. Zero Silent Loss & Safety
Missing critical fields (such as `action`, `source`, `destination`) in Security Policies or NAT Rules are **never** silently defaulted to `allow`, `any`, or `0.0.0.0/0`.
Instead, items with missing required fields are marked as `PARTIALLY_NORMALIZED` and appended to the extraction `inventory_items` for manual review.

### 3. Residual Extraction
The `PANResidualExtractor` ensures that any configuration subtrees (e.g., `application`, `log-settings`, `reports`) that are currently unhandled are caught and logged. These subtrees are mapped as `VENDOR_EXTENSION` or `UNSUPPORTED`.

## Supported Extractions

- **Metadata**: Hostname, Vendor.
- **Topology**: Zones and Interfaces.
- **Objects**: Addresses (Host, Network, Range, FQDN), Address Groups (Static and Dynamic filters).
- **Services**: TCP/UDP services, Service Groups.
- **Policies**: Security Rules (Pre-rulebase, Rulebase, Post-rulebase), Action, Description.
- **NAT**: Source Translation, Destination Translation.
- **Routing**: Static Routes.

## Implementation Details

- **`parser.py`**: The main abstraction. Handles scope discovery and normalization.
- **`nat.py`**: Helpers for deciphering PAN-OS NAT Translation.
- **`routing.py`**: Scrapes routing-table `<virtual-router>`.
- **`residual.py`**: Implements subtree coverage discovery for `ExtractionResult`.

For generic migration semantics, refer to `IR_DATA_STRUCTURE.md` and `EXTRACTION_DATA_MODEL.md`.
