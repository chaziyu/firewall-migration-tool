# Configuration Schema Comparison: Fortigate vs Palo Alto

This document compares the fundamental schema differences between Fortigate and Palo Alto configuration structures, based on the provided XML export and CSV schema analysis.

## 1. High-Level Format Difference

- **Fortigate**: Uses a CLI-based hierarchical text format. Configurations are grouped into blocks using `config <context>` and `edit <instance>`, followed by `set <key> <value>`.
- **Palo Alto**: Uses a standardized XML format. The configuration is a single XML tree starting with the `<config>` root tag, allowing for deeply nested structured data.

## 2. Key Object Mappings

Below is a mapping of common network security elements between the two platforms:

| Feature / Object | Fortigate Schema Context | Palo Alto Schema Context (XML Path) |
| :--- | :--- | :--- |
| **Admin Users** | `system admin` | `config -> mgt-config -> users -> entry` |
| **Interfaces** | `system interface` | `config -> devices -> entry -> network -> interface -> ethernet -> entry` |
| **Address Objects** | `firewall address` | `config -> devices -> entry -> vsys -> entry -> address -> entry` |
| **Address Groups** | `firewall addrgrp` | `config -> devices -> entry -> vsys -> entry -> address-group -> entry` |
| **Services** | `firewall service custom` | `config -> devices -> entry -> vsys -> entry -> service -> entry` |
| **Security Policies** | `firewall policy` | `config -> devices -> entry -> vsys -> entry -> rulebase -> security -> rules -> entry` |
| **Security Profiles** | `firewall profile-protocol-options` | `config -> devices -> entry -> vsys -> entry -> profile-group -> entry` |

## 3. Structural Differences

### Hierarchy Depth
- **Fortigate** schemas are generally flat within their context. For instance, `firewall policy` directly contains attributes like `srcintf`, `dstintf`, `srcaddr`, and `dstaddr`.
- **Palo Alto** schemas are heavily nested. A security rule sits under `config -> devices -> entry -> vsys -> entry -> rulebase -> security -> rules -> entry`, and lists like source addresses are further nested as `<source><member>...</member></source>`.

### Global vs Virtual System (vsys / VDOM)
- **Fortigate**: Virtual Domains (VDOMs) are often handled at the top level with `config vdom` and `edit <vdom_name>`. Global settings remain under `config global`.
- **Palo Alto**: Virtual Systems (vsys) are nested inside the device configuration: `config -> devices -> entry -> vsys -> entry`. Policies, objects, and routing are strictly tied to their respective `vsys` block.

### Lists and Members
- **Fortigate**: Lists of values are space-separated strings on a single line (e.g., `set srcaddr "addr1" "addr2"`).
- **Palo Alto**: Lists are represented as repeated child XML nodes, typically inside a container element (e.g., `<source><member>addr1</member><member>addr2</member></source>`).
