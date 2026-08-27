# FortiGate Configuration Extraction Handling Reference

**Repository:** `chaziyu/firewall-migration-tool`  
**Implementation snapshot:** commit `0e1731e2816040f55919687e90c1df23a8b6eaad` (`Improve Excel workbook navigation and readability`)  
**Purpose:** implementation-level reference for how the tool handles FortiGate configuration-file extraction.  
**Scope:** current code, not a complete FortiOS CLI command encyclopedia.

> This document intentionally distinguishes **present in source**, **parsed into the FortiGate source model**, **propagated into canonical IR**, and **visible in Excel**. A field is not called “fully extracted” merely because the parser recognized it.

## 1. Source-of-truth code

This reference is derived from:

- `src/fwmigrate/parsers/fortigate/section_scanner.py`
- `src/fwmigrate/parsers/fortigate/tokenizer.py`
- `src/fwmigrate/parsers/fortigate/parser.py`
- `src/fwmigrate/parsers/fortigate/model.py`
- `src/fwmigrate/parsers/fortigate/coverage.py`
- `src/fwmigrate/parsers/fortigate/extractor.py`
- `src/fwmigrate/parsers/fortigate/transformer.py`
- `src/fwmigrate/parsers/fortigate/extraction.py`
- `src/fwmigrate/parsers/fortigate/certificates.py`
- `src/fwmigrate/parsers/fortigate/net_utils.py`
- `src/fwmigrate/parsers/fortigate/session_helper_defaults.py`
- `src/fwmigrate/report/excel_exporter.py`
- `src/fwmigrate/extraction/models.py`
- `documentation/EXTRACTION_DATA_MODEL.md`

## 2. Processing pipeline

```text
FortiGate CLI backup
    │
    ├─> independent section scanner
    │      records every config path, line range and source edit count
    │
    └─> tokenizer
           │
           v
       FortiGateParser
           │
           ├─> typed FG source models
           ├─> structured source-only trees
           └─> sanitized SourceInventoryItem commands
                  │
                  v
          FGToIRTransformer
                  │
                  v
             canonical IR
                  │
                  v
          coverage classification
                  │
                  v
            ExtractionResult
                  │
                  v
              Excel inventory
```

The scanner and parser are deliberately separate. The scanner accounts for source sections even when the typed parser does not support them. This is the basis of the project's zero-silent-loss design.

## 3. Extraction status vocabulary

| Status | Meaning in this tool |
| --- | --- |
| NORMALIZED | Source semantics are represented in canonical IR with no known section-level semantic loss. |
| PARTIALLY_NORMALIZED | Useful semantics reached IR, but some source behavior, values, or one-to-one accounting is incomplete. |
| EXTRACT_ONLY | Structured source data is retained for inventory/manual review but is not treated as portable migration intent. |
| VENDOR_EXTENSION | Reserved for structured vendor-specific data. No FortiGate path is currently assigned this status by coverage.py. |
| UNSUPPORTED | Section exists, but no typed/safe FortiGate extraction handler is registered. |
| IGNORED_BY_POLICY | Section is intentionally outside the product's current firewall-migration scope. |
| PARSE_ERROR | Reserved section-level status. Current FortiGate logic more commonly records item parse_error and marks the section PARTIALLY_NORMALIZED. |

### Important current behavior

- FortiGate coverage currently assigns `NORMALIZED`, `PARTIALLY_NORMALIZED`, `EXTRACT_ONLY`, `UNSUPPORTED`, and `IGNORED_BY_POLICY` directly.
- `VENDOR_EXTENSION` exists in the enum but no current FortiGate coverage rule assigns a section to it.
- `PARSE_ERROR` exists in the enum, but current FortiGate code normally records an object-level `parse_error` and marks the enclosing section `PARTIALLY_NORMALIZED`.

## 4. Global parsing and safety rules

### 4.1 Section discovery

- Every `config ...` block is discovered structurally before semantic parsing.
- Nested config paths are stored as full paths, for example `system dhcp server ip-range`.
- `edit` commands increment the source object count for the current section.
- `line_start` and `line_end` are recorded.
- If a matching `end` is missing, the section range is closed at EOF and a note is added.

### 4.2 Generic `set` field handling

- FortiGate keys such as `admin-sport` are normalized internally to underscore form such as `admin_sport`.
- A `set` with no value becomes boolean `True` at parser-attribute level.
- One value becomes a scalar string unless the field is declared as a list field.
- Multiple values:
  - `subnet` and `ip` are stored as `address netmask`.
  - `tcp-portrange` and `udp-portrange` are joined with commas.
  - generic multi-value fields are joined with spaces unless explicitly registered as list fields.
- Explicit list fields preserve source ordering as lists.

### 4.3 `unset` and `append`

- `unset` removes the normalized parser attribute and records the source operation.
- `append` extends an existing list; for scalar fields it joins the existing value and appended values.
- Items containing `unset` or `append` are retained in source inventory even when the main section is otherwise normalized, because those operations can carry source-only semantics.

### 4.4 Unknown fields / Additional Settings

For source models that support `extra_settings`, unknown parsed keys are moved into a sanitized dictionary and later shown as `Additional Settings` in Excel.

Secret-like key names containing any of the following are redacted before retention:

`password`, `passwd`, `secret`, `psk`, `psksecret`, `private_key`, `seed`, `activation_code`, `community`, `auth_key`, `token`, `api_key`.

### 4.5 Strict network safety

- IPv4 address/netmask and route networks are normalized with Python `ipaddress`.
- Invalid network syntax is **not repaired**.
- The tool does not invent `/0`, `/32`, `any`, or another usable fallback merely to keep conversion running.
- Invalid values are preserved as raw evidence where the IR model supports it, with `parse_error`, `requires_manual_review`, and an audit entry.

### 4.6 FortiOS enable/disable conversion

Many typed booleans use the helper:

```python
None -> None
'enable' -> True
any other non-None value -> False
```

Therefore unexpected nonstandard values can become `False` unless the transformer explicitly preserves them in `source_attributes`. Sections that need stronger validation are called out below.

## 5. Master section coverage matrix

| FortiGate config path | Coverage behavior | Typed/IR path | Excel output | Important note |
| --- | --- | --- | --- | --- |
| system global | Typed; count-based | FGSystemGlobal → IRSystemSettings | System Settings | Singleton scanner counts can cause PARTIALLY_NORMALIZED even when fields are represented. |
| system dns | Typed; count-based | FGDns → IRDNSSettings | DNS Settings | Singleton scanner counts can cause PARTIALLY_NORMALIZED. |
| system interface | NORMALIZED / PARTIALLY_NORMALIZED | FGInterface → IRInterface | Interfaces; Interface Source Settings | Invalid IP/remote-IP makes section partial; all explicit interface set values are also preserved as sanitized source_attributes. |
| system interface secondaryip | NORMALIZED / PARTIALLY_NORMALIZED | FGInterfaceSecondaryIP → IRInterfaceSecondaryIP | Interface Secondary IPs | Nested secondary interface IPs extracted into typed child collection; invalid/missing IP or unmodeled child settings make section partial. |
| system zone | Typed; count-based | FGSystemZone → IRZone | Zones | Name/interfaces propagate; parsed tag/description do not currently propagate. |
| system dhcp server | Typed; count-based | FGDHCPServer → IRDHCPServer | DHCP Servers | IR object is source-oriented EXTRACT_ONLY/manual-review even if section coverage counts align. |
| system dhcp server ip-range | Typed; count-based | FGDHCPIPRange → IRDHCPIPRange | DHCP IP Ranges | Nested child collection. |
| system dhcp server reserved-address | Typed; count-based | FGDHCPReservation → IRDHCPReservation | DHCP Reservations | Nested child collection. |
| firewall address | NORMALIZED / PARTIALLY_NORMALIZED | FGAddress → IRAddress or IRAddressGroup | Addresses / Address Groups | Strict network/MAC validation; dynamic objects become dynamic groups; invalid values are preserved without fake replacement. |
| firewall address6 | NORMALIZED / PARTIALLY_NORMALIZED | FGAddress(is_ipv6=True) → IRAddress | Addresses | Explicit reserved objects are retained as special source inventory without fabricated networks. |
| firewall multicast-address | NORMALIZED / PARTIALLY_NORMALIZED | FGAddress(is_multicast=True) → IRAddress | Addresses | Shares address transformation logic. |
| firewall multicast-address6 | NORMALIZED / PARTIALLY_NORMALIZED | FGAddress(is_ipv6=True,is_multicast=True) → IRAddress | Addresses | Shares address transformation logic. |
| firewall addrgrp | Count-based; often PARTIALLY_NORMALIZED | FGAddressGroup → IRAddressGroup | Address Groups | IR address_groups also contains dynamic groups derived from firewall address, so normalized count can exceed source addrgrp count. |
| firewall wildcard-fqdn custom | Count-based; may report PARTIALLY_NORMALIZED | FGWildcardFQDN → IRAddress(WILDCARD_FQDN) | Addresses | Coverage maps into shared IR addresses collection, so normalized count is not one-to-one. |
| firewall service category | EXTRACT_ONLY | FGServiceCategory → IRServiceCategory | Service Categories | Retained as source inventory/category metadata. |
| firewall service custom | Count-based | FGService → IRService/IRServicePort | Services | Individual services can be PARTIALLY_NORMALIZED/manual-review even if section object counts match. |
| firewall service group | Typed; count-based | FGServiceGroup → IRServiceGroup | Service Groups | Direct member preservation. |
| firewall schedule recurring | Typed; count-based | FGSchedule(type=recurring) → IRSchedule | Schedules | Counts filtered by schedule type. |
| firewall schedule onetime | Typed; count-based | FGSchedule(type=onetime) → IRSchedule | Schedules | Counts filtered by schedule type. |
| firewall shaper traffic-shaper | PARTIALLY_NORMALIZED | FGTrafficShaper → IRTrafficShaper | Traffic Shapers | Exact target QoS semantics are vendor-specific. |
| firewall proxy-address | EXTRACT_ONLY | FGProxyAddress → IRProxyAddress | Proxy Addresses | Manual review; not converted into ordinary firewall address semantics. |
| web-proxy global | EXTRACT_ONLY | FGWebProxyGlobal → IRWebProxySettings | Web Proxy Settings | Source-only/manual-review. |
| firewall policy | Typed; count-based | FGPolicy → IRPolicy | Policies | Normalizes action/schedule/address/service keywords; unresolved zones are audited and never guessed. |
| firewall ippool | Typed; count-based | FGIPPool → IRIPPool | IP Pools | Advanced IR fields exist beyond visible Excel columns; unknown IP-pool fields are not generically preserved. |
| firewall vip | Typed; count-based | FGVIP → IRVirtualIP | Virtual IPs | Unknown VIP fields preserved in extra_settings. |
| firewall vip realservers | Typed; count-based | FGVIPRealServer → IRVirtualIPRealServer | VIP Real Servers | Nested fields preserved; unknown real-server fields are not generically retained. |
| firewall vipgrp | EXTRACT_ONLY | FGVIPGroup → IRVirtualIPGroup | VIP Groups | Manual review. |
| firewall internet-service-name | Typed; count-based | FGInternetService → IRInternetService | Internet Services | internet-service-id is explicitly converted to integer source_id; sanitized unknown settings remain source-only Additional Settings. |
| vpn ipsec phase1-interface | Typed; count-based | FGPhase1Interface → IRVPNTunnel | VPN Tunnels | PSK contents are discarded/redacted; proposal/peertype/net-device are parsed but not propagated to IR. |
| vpn ipsec phase2-interface | PARTIALLY_NORMALIZED | FGPhase2Interface → IRVPNPhase2 | VPN Phase 2 | Typed selectors/settings retained, but full cross-vendor IPsec model is incomplete. |
| vpn certificate remote | EXTRACT_ONLY | FGCertificate → IRCertificate | Certificates | Safe X.509 metadata only; secrets are discarded. |
| vpn certificate local | EXTRACT_ONLY | FGCertificate → IRCertificate | Certificates | Safe X.509 metadata only; secrets are discarded. |
| vpn certificate ca | EXTRACT_ONLY | FGCertificate → IRCertificate | Certificates | Safe X.509 metadata only; secrets are discarded. |
| firewall ssh local-key | EXTRACT_ONLY | FGSSHKey → IRSSHKey | SSH Keys | Public-key presence only in Excel; private/password contents discarded. |
| firewall ssh local-ca | EXTRACT_ONLY | FGSSHKey → IRSSHKey | SSH Keys | Public-key presence only in Excel; private/password contents discarded. |
| router static | NORMALIZED / PARTIALLY_NORMALIZED | FGStaticRoute → IRRoute | Routes | Invalid network syntax or retained unmodeled settings makes section partial. |
| system session-helper | EXTRACT_ONLY | FGSessionHelper → IRSessionHelper | Session Helpers | Classified DEFAULT/CUSTOM/CUSTOMIZED/UNKNOWN against built-in baseline. |
| system session-ttl | PARTIALLY_NORMALIZED (current implementation) | Global commands retained as source inventory; no dedicated typed global model | Extraction Coverage only for global settings | Registry calls it typed/extract-only, but there is no _COLLECTIONS mapping; parent global fields do not have a dedicated Excel detail sheet. |
| system session-ttl port | EXTRACT_ONLY | FGSessionTTLOverride → IRSessionTTLOverride | Session TTL Overrides | Manual review. |
| endpoint-control fctems | Count-based coverage; IR item EXTRACT_ONLY | FGFCTEMS → IRZTNAProvider | ZTNA Providers | Empty placeholder edits are intentionally omitted from IR; meaningful connectors require manual review. |
| system sdwan | EXTRACT_ONLY | FGSDWan → IRSDWAN | SD-WAN | Source-only but its zone/member data is used for policy/interface zone resolution. |
| system sdwan zone | EXTRACT_ONLY | FGSDWanZone → IRSDWANZone | SD-WAN | Source-only/manual-review. |
| system sdwan members | EXTRACT_ONLY | FGSDWanMember → IRSDWANMember | SD-WAN Members | Numeric normalization for weight/priority. |
| system sdwan health-check | EXTRACT_ONLY | FGSDWanHealthCheck → IRSDWANHealthCheck | SD-WAN Health Checks | members converted to integer IDs; interval integer-normalized. |
| system sdwan health-check sla | EXTRACT_ONLY | FGSDWanSLA → IRSDWANSLA | SD-WAN SLAs | Only ID is typed; all other SLA settings are retained in Additional Settings. |
| system sdwan service | EXTRACT_ONLY | FGSDWanService → IRSDWANRule | SD-WAN Rules | Priority-member and app-control IDs converted to integers where possible. |
| user ldap | EXTRACT_ONLY | FGUserLDAP → IRUserLDAP | LDAP Servers | Password value is discarded; only has_password is retained. |
| user saml | EXTRACT_ONLY | FGUserSAML → IRUserSAML | SAML Servers | Source-only/manual-review. |
| user local | EXTRACT_ONLY | FGLocalUser → IRLocalUser | Local Users | Password value is discarded; only has_password is retained. |
| user group | EXTRACT_ONLY | FGUserGroup → IRUserGroup | User Groups | Nested match entries extracted. |
| user group match | EXTRACT_ONLY | FGUserGroupMatch → IRUserGroupMatch | User Group Matches | Nested unknown match fields are not generically retained. |
| vpn ssl web portal | EXTRACT_ONLY | FGSSLVPNPortal → IRSSLVPNPortal | SSL VPN Portals | Manual review. |
| vpn ssl web portal host-check-software | EXTRACT_ONLY | FGSSLVPNHostCheckSoftware → IRSSLVPNHostCheck | SSL VPN Host Checks | Only nested portal host-check-software is typed. |
| vpn ssl settings | EXTRACT_ONLY | FGSSLVPNSettings → IRSSLVPNSettings | SSL VPN Settings | Global source-only settings. |
| vpn ssl settings authentication-rule | EXTRACT_ONLY | FGSSLVPNAuthenticationRule → IRSSLVPNAuthenticationRule | SSL VPN Authentication Rules | Nested rule collection. |
| firewall DoS-policy | EXTRACT_ONLY | FGDoSPolicy → IRDoSPolicy | DoS Policies | Manual review. |
| firewall DoS-policy anomaly | EXTRACT_ONLY | FGDoSAnomaly → IRDoSAnomaly | DoS Anomalies | Threshold converted to int when possible. |
| firewall sniffer | EXTRACT_ONLY | FGFirewallSniffer → IRFirewallSniffer | Firewall Sniffer | Source-only/manual-review. |
| authentication scheme | EXTRACT_ONLY | FGAuthenticationScheme → IRAuthenticationScheme | Authentication Schemes | Source-only/manual-review. |
| authentication rule | EXTRACT_ONLY | FGAuthenticationRule → IRAuthenticationRule | Authentication Rules | Source-only/manual-review. |
| ips sensor | EXTRACT_ONLY | FGIPSSensor → IRIPSSensor | IPS Sensors | Source signature semantics are not translated. |
| ips sensor entries | EXTRACT_ONLY | FGIPSSensorEntry → IRIPSSensorEntry | IPS Sensor Entries | Nested rule IDs/rate values integer-normalized where possible. |

## 6. Detailed typed section handling

### `config system global`

**Coverage:** Typed, count-based coverage; singleton source-count accounting can make the coverage row PARTIALLY_NORMALIZED.  
**Parser/source model:** `FGSystemGlobal → IRSystemSettings`  
**Excel:** `System Settings`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| hostname | IR `hostname` → Excel `Hostname` | Direct. |
| timezone | IR `timezone` → Excel `Timezone` | Direct. |
| admin-sport | IR `admin_https_port` → Excel `Admin HTTPS Port` | Converted to integer by the global parser. |
| other `set` keys | `source_attributes` → `Additional Settings` | Sanitized before retention. |

**Rules / considerations**

- `unset hostname` resets the parser value to `unknown`; `unset admin-sport`/`timezone` becomes `None`.
- Global source sections have no `edit` records, while the coverage counter treats the parsed singleton as one object. This can make the section appear PARTIALLY_NORMALIZED even though the typed fields are present.

### `config system dns`

**Coverage:** Typed, count-based coverage; singleton count caveat applies.  
**Parser/source model:** `FGDns → IRDNSSettings`  
**Excel:** `DNS Settings`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| primary | IR/Excel `Primary DNS` | Direct string preservation. |
| secondary | IR/Excel `Secondary DNS` | Direct string preservation. |
| other settings | `source_attributes` → `Additional Settings` | Sanitized source preservation. |

**Rules / considerations**

- `unset primary` or `unset secondary` clears the corresponding field.
- No DNS address normalization is applied here; values are retained as source strings.

### `config system interface`

**Coverage:** NORMALIZED when counts align and no interface network parse errors; otherwise PARTIALLY_NORMALIZED.  
**Parser/source model:** `FGInterface → IRInterface`  
**Excel:** `Interfaces` and `Interface Source Settings`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| edit name | `Name` | Direct. |
| vdom | `Source VDOM` | Default parser value is `root` if absent. |
| ip | `IP / Prefix` | Strict IPv4 prefix normalization; `0.0.0.0/0` means no usable configured IP and becomes blank. |
| remote-ip | `Remote IP / Prefix` | Same strict normalization as `ip`. |
| allowaccess | `Management Access` | List preserved. |
| type | `Interface Type` | Default `physical`. |
| role | `Role` | `undefined` becomes blank/None in IR. |
| alias | `Alias` | Direct. |
| description | `Description` | Direct. |
| vlanid | `VLAN ID`; also assigned to IR `tag` | Integer/Pydantic coercion. |
| interface | `Parent / Underlay Interface` | Direct parent reference. |
| status | `Enabled` | Anything except literal `down` becomes enabled. |
| mode | `Addressing Mode`; may also set `DHCP Client` / `PPPoE Mode` | `dhcp` => DHCP client True; `pppoe` => PPPoE mode. |
| username | `PPPoE Username` | Direct. |
| every explicitly configured set key | `Interface Source Settings` | A sanitized copy is retained even when the value is also normalized. |

**Rules / considerations**

- Zone resolution uses explicit `system zone`, optional caller-provided zone mapping, or the source SD-WAN member zone.
- The transformer does **not** infer `trust`/`untrust` from interface role, alias, name, or description.
- Invalid `ip` or `remote-ip` is not repaired; the normalized field is blank, source evidence remains in Interface Source Settings, and an audit/manual-review entry is emitted.

**Not fully extracted / current limitation**

- Excel has a `Management Profile` column, but the current FortiGate transformer does not populate an IR management-profile field from interface config. If such a FortiGate setting exists, it is visible only in `Interface Source Settings`.

### `config system zone`

**Coverage:** Typed/count-based.  
**Parser/source model:** `FGSystemZone → IRZone`  
**Excel:** `Zones`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| edit name | IR/Excel `Name` | Direct. |
| interface | IR/Excel `Interfaces` | Explicit list. |
| tag | Parsed in FGSystemZone only | Typed parser field. |
| description | Parsed in FGSystemZone only | Typed parser field. |

**Rules / considerations**

- Zone membership is also used by policy zone resolution.

**Not fully extracted / current limitation**

- `tag` and `description` are currently parsed but not propagated by `_transform_interfaces_and_zones()` into IRZone, so they are not reliably visible in Excel.
- FGSystemZone has no `extra_settings`; unknown zone keys are not generically preserved in the typed object.

### `config system dhcp server`

**Coverage:** Typed/count-based coverage; IR object is treated as EXTRACT_ONLY/manual-review.  
**Parser/source model:** `FGDHCPServer → IRDHCPServer`  
**Excel:** `DHCP Servers`; nested data in `DHCP IP Ranges` and `DHCP Reservations`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| edit numeric ID | `Server ID` | Numeric edit name is used as `id`; synthetic string name is removed. |
| status | `Enabled` | False only for literal `disable`; otherwise True. |
| interface | `Interface` | Direct. |
| default-gateway | `Default Gateway` | Direct source string. |
| netmask | `Netmask` | Direct source string. |
| lease-time | `Lease Time (Seconds)` | Typed numeric field. |
| dns-service | `DNS Service` | Direct. |
| dns-server1/2/3 | `DNS Servers` | Non-empty values are combined into one ordered list. |
| timezone-option | `Timezone Option` | Direct. |
| other server keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- DHCP is preserved for migration review but no cross-vendor target behavior is assumed.
- Nested range and reservation records are retained separately.

### `config system dhcp server > config ip-range`

**Coverage:** Typed child collection.  
**Parser/source model:** `FGDHCPIPRange → IRDHCPIPRange`  
**Excel:** `DHCP IP Ranges`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| edit ID | `Range ID` | Numeric. |
| start-ip | `Start IP` | Direct. |
| end-ip | `End IP` | Direct. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- No pool-size calculation or CIDR conversion is performed; start/end values remain source values.

### `config system dhcp server > config reserved-address`

**Coverage:** Typed child collection.  
**Parser/source model:** `FGDHCPReservation → IRDHCPReservation`  
**Excel:** `DHCP Reservations`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| edit ID | `Reservation ID` | Numeric. |
| ip | `IP Address` | Direct. |
| mac | `MAC Address` | Direct. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- DHCP reservation MAC values are retained as source strings; the stricter MAC regex used for firewall address objects is not applied here.

### `config firewall address`, `address6`, `multicast-address`, `multicast-address6`

**Coverage:** NORMALIZED or PARTIALLY_NORMALIZED depending strict validation and section-count behavior.  
**Parser/source model:** `FGAddress → IRAddress; dynamic addresses can become IRAddressGroup`  
**Excel:** `Addresses`; dynamic objects may appear in `Address Groups`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| edit name | `Name` | Direct, except selected built-in names are withheld from ordinary IR. |
| uuid | `Source UUID` | Direct. |
| type | `Type` | Controls address transformation. |
| subnet | `Value` / IR subnet | Strict IPv4 prefix normalization for `ipmask`. |
| ip6 | `Value` / IPv6 network | Used for IPv6 address sections. |
| fqdn | `Value` / FQDN | Used when type is `fqdn`. |
| start-ip / end-ip | Host or range value | Equal start/end => HOST `/32`; otherwise RANGE. |
| country | GEO code | Used when type is `geography`. |
| macaddr / mac | MAC value | Must match six colon-separated octets; no fake IP fallback. |
| comment | `Description` | Direct. |
| associated-interface | `Associated Interface` | Direct. |
| allow-routing | `Allow Routing` | `enable` => True; other non-None values => False. |
| color | `Source Color` | Direct. |
| sub-type | `EMS Sub-Type` | Direct. |
| obj-tag | `EMS Object Tag` | Direct; also participates in dynamic-tag selection. |
| tag-type | `EMS Tag Type` | Direct. |
| obj-type | `EMS Object Type` | Direct. |
| dirty | `EMS Dirty` | Direct. |
| unmodeled keys | `Additional Settings` | Sanitized, when not already declared as an FGAddress model field. |

**Rules / considerations**

- `address6` sets `is_ipv6=True`; multicast sections set `is_multicast=True`.
- Explicit objects named `all`, `none`, `FABRIC_DEVICE`, and `FIREWALL_AUTH_PORTAL_ADDRESS` are emitted as special address inventory with exact source names, source metadata, and IPv6/multicast context. They are not converted into ordinary or artificial networks; policy references to `all` still normalize independently to canonical any.
- Empty VPN helper objects whose name contains `remote_subnet` can be inferred from a static route whose device matches the tunnel name. This inference is explicitly audited as PARTIAL.
- Empty objects whose name contains `local_subnet` can be inferred from the first local LAN/trust subnet when available; this is also audited as PARTIAL.
- MAC objects are preserved as MAC. Invalid/missing MAC values produce raw evidence + manual review; the tool no longer creates RFC2544 IPv4 placeholders.
- Dynamic/EMS-tag addresses are converted to dynamic address groups. Tag selection order is `obj_tag`, then `ems_tag_name`, then object name. The dynamic filter is stored as the quoted tag name.
- If strict IR validation fails, typed destination fields are removed, `raw_value` and `parse_error` are retained, and an audit entry is created.

**Not fully extracted / current limitation**

- `sdn` and `filter` are declared FGAddress model fields but are not currently propagated by the transformer and are excluded from `extra_settings`; they can therefore disappear from IR/Excel.
- `ems_tag_name` is used for dynamic objects but is not separately exposed for ordinary objects.
- Coverage counting for address groups/wildcard FQDN can be non-one-to-one because several source families share IR collections.

### `config firewall addrgrp`

**Coverage:** Typed/count-based; can report PARTIALLY_NORMALIZED because the IR address-group collection also contains dynamic groups derived from addresses.  
**Parser/source model:** `FGAddressGroup → IRAddressGroup`  
**Excel:** `Address Groups`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| name | `Name` | Direct. |
| uuid | `Source UUID` | Direct. |
| member | `Members` | List preserved. |
| comment | `Description` | Direct. |
| allow-routing | `Allow Routing` | FortiOS enable conversion. |
| color | `Source Color` | Direct. |
| category | `Source Category` | Direct. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- No membership expansion is performed; references remain names.

### `config firewall wildcard-fqdn custom`

**Coverage:** Typed; coverage may be PARTIALLY_NORMALIZED because normalized objects share the global IR address collection.  
**Parser/source model:** `FGWildcardFQDN → IRAddress(type=WILDCARD_FQDN)`  
**Excel:** `Addresses`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| name | `Name` | Direct. |
| wildcard-fqdn | `Value` / IR fqdn | Stored as wildcard FQDN. |
| comment | `Description` | Direct. |
| uuid | `Source UUID` | Direct. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- IR validation rules still apply to the wildcard-FQDN value.

### `config firewall service category`

**Coverage:** EXTRACT_ONLY.  
**Parser/source model:** `FGServiceCategory → IRServiceCategory`  
**Excel:** `Service Categories`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| name | `Name` | Direct. |
| comment | `Description` | Direct. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- Category metadata is retained but is not treated as portable traffic-matching semantics.

### `config firewall service custom`

**Coverage:** Typed/count-based. Each IR service carries its own NORMALIZED/PARTIALLY_NORMALIZED migration status.  
**Parser/source model:** `FGService → IRService + IRServicePort`  
**Excel:** `Services`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| name | `Name` | Direct. |
| uuid | `Source UUID` | Direct. |
| category | `Category` | Direct source category. |
| protocol | `Source Protocol` and normalized port protocol | Upper-cased for branch selection. |
| tcp-portrange | `Protocol / Destination Port`; `Source Port Constraint` | Split on comma/space. `destination:source` is preserved as destination port + source_port + raw_source_value. |
| udp-portrange | Same as TCP using UDP protocol | Same parsing. |
| protocol-number | `Source Protocol Number`; IP service port representation | IP protocol number is retained. |
| icmptype / icmpcode | IR service-port ICMP metadata | Used for ICMP/ICMP6. |
| proxy | `Proxy` | `enable`/`disable` converted to bool. |
| comment | `Description` | Direct. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- `protocol=IP` + protocol-number creates an IP-protocol service.
- `protocol=IP` without protocol-number becomes ANY only for service named `ALL`; otherwise it remains IP/ANY.
- ICMP6 maps to ICMPv6; ICMP maps to ICMP.
- Proxy semantics force manual review.
- Destination ports `0` or ranges beginning `0-` force manual review.
- If no safe normalized port representation is produced, the service is PARTIALLY_NORMALIZED/manual-review.

**Not fully extracted / current limitation**

- `sctp-portrange` is not a typed FGService field. It can survive in Additional Settings, but the transformer does not currently build SCTP IR service ports from it.

### `config firewall service group`

**Coverage:** Typed/count-based.  
**Parser/source model:** `FGServiceGroup → IRServiceGroup`  
**Excel:** `Service Groups`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| name | `Name` | Direct. |
| uuid | `Source UUID` | Direct. |
| member | `Members` | List preserved. |
| comment | `Description` | Direct. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- No recursive group expansion is performed.

### `config firewall schedule recurring` / `onetime`

**Coverage:** Typed/count-based.  
**Parser/source model:** `FGSchedule → IRSchedule`  
**Excel:** `Schedules`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| name | `Name` | Direct. |
| start | `Start` | Direct string. |
| end | `End` | Direct string. |
| day | `Days` | List. |
| color | `Color` | Direct. |
| expiration-days | `Expiration Days` | Typed numeric field. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- The parser sets `schedule_type` from the config path rather than trusting a separate source field.
- No timezone conversion or calendar expansion is performed.

### `config firewall shaper traffic-shaper`

**Coverage:** Always PARTIALLY_NORMALIZED at section coverage level.  
**Parser/source model:** `FGTrafficShaper → IRTrafficShaper`  
**Excel:** `Traffic Shapers`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| name | `Name` | Direct. |
| guaranteed-bandwidth | `Guaranteed Bandwidth` | Typed numeric value. |
| maximum-bandwidth | `Maximum Bandwidth` | Typed numeric value. |
| bandwidth-unit | `Source Bandwidth Unit` | Preserved; no unit conversion. |
| priority | `Priority` | Direct. |
| per-policy | `Per Policy` | enable=>True, disable=>False; unexpected value retained in Additional Settings. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- Target QoS behavior is vendor-specific, so exact behavior is not claimed.

### `config firewall proxy-address`

**Coverage:** EXTRACT_ONLY/manual-review.  
**Parser/source model:** `FGProxyAddress → IRProxyAddress`  
**Excel:** `Proxy Addresses`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| name | `Name` | Direct. |
| uuid | `Source UUID` | Direct. |
| type | `Type` | Direct. |
| host | `Host` | Direct. |
| host-regex | `Host Regex` | Direct. |
| path | `Path` | Direct. |
| query | `Query` | Direct. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- Proxy-address semantics are not converted into normal L3/L4 firewall address objects.

### `config web-proxy global`

**Coverage:** EXTRACT_ONLY/manual-review.  
**Parser/source model:** `FGWebProxyGlobal → IRWebProxySettings`  
**Excel:** `Web Proxy Settings`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| proxy-fqdn | `Proxy FQDN` | Direct. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- Global `unset` is handled for typed and extra fields.

### `config firewall policy`

**Coverage:** Typed/count-based.  
**Parser/source model:** `FGPolicy → IRPolicy`  
**Excel:** `Policies`; related derived output in `Security Profiles`, `NAT Rules`, `ZTNA Providers`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| edit policy ID | `Source Policy ID`; generated `Rule #` is workbook sequence | Source ID retained as string. |
| uuid | `Source UUID` | Direct. |
| name | `Name` | If absent, generated as `Rule_<id>`. |
| srcintf | `Source Interface` + derived `From Zone` | Source list preserved; zones resolved separately. |
| dstintf | `Destination Interface` + derived `To Zone` | Source list preserved; zones resolved separately. |
| srcaddr | `Source` | Each name normalized through FortiGate vendor map. |
| dstaddr | `Destination` | Each name normalized through FortiGate vendor map. |
| groups | `User Groups` | Source list preserved. |
| users | `Users` | Source list preserved. |
| service | `Service` | Each name normalized through FortiGate vendor map. |
| action | `Action` | Only literal `accept` becomes ALLOW; all other values become DENY. |
| schedule | `Schedule` | `always` becomes blank/None; other values preserved. |
| logtraffic | `Log Setting`, plus derived `Log Start`/`Log End` | `all` or `utm` => both log flags True. |
| nat | `NAT Enabled` | `enable` => True. |
| ippool | `IP Pool Enabled` | `enable` => True. |
| poolname | `NAT Pool` | List preserved. |
| comments | `Description` | Direct. |
| status | `Disabled` | `disable` => True. |
| utm-status | Controls derived Security Profile Group | Not exposed as a dedicated Excel column. |
| ssl-ssh-profile | `SSL/SSH Profile` when UTM enabled | Used in synthetic security-profile group. |
| av-profile | `Antivirus` when UTM enabled | Used in synthetic security-profile group. |
| webfilter-profile | `Web Filter` when UTM enabled | Used in synthetic security-profile group. |
| ips-sensor | `IPS Sensor` when UTM enabled | Used in synthetic security-profile group. |
| application-list | `Application List` when UTM enabled | Used in synthetic security-profile group. |
| internet-service | Used by NAT review logic | Enable flag itself is not a dedicated Excel field. |
| internet-service-name | `Internet Services` | List preserved. |
| inspection-mode | `Inspection Mode` | Direct. |
| ztna-status | `ZTNA Status` | Direct. |
| ztna-ems-tag | `ZTNA EMS Tags` | List preserved. |
| unknown policy keys | `Additional Settings` | Sanitized; e.g. timeout-send-rst, auto-asic-offload, np-acceleration, port-preserve. |

**Rules / considerations**

- Policy zones are resolved only from explicit system-zone membership, explicit external zone mapping, or source SD-WAN zone names. Unresolved interfaces are preserved and audited; the transformer does not invent trust/untrust.
- Source object/service keywords are normalized through the FortiGate vendor map. For example source `ALL`/`all` may become the canonical IR any keyword.
- UTM enabled: the transformer synthesizes a security-profile-group name from active profile references: `AV_<name>`, `IPS_<name>`, `WF_<name>`, `APP_<name>`, prefixed with `SPG_`, sanitized to `[A-Za-z0-9_-]`, and truncated to 63 characters.
- If no UTM component name exists, the synthetic group name is `Migrated_Profiles`.
- Synthetic defaults can be inserted into the generated security profile group: antivirus/IPS/webfilter default values, anti-spyware `default`, file blocking `basic-file-blocking`, WildFire `default`.
- NAT correlation is performed after policy transformation; see the derived NAT section below.

**Not fully extracted / current limitation**

- Raw source `action=accept`, `schedule=always`, `service=ALL`, and address keyword spelling are normalized and are not currently exposed in dedicated parallel `Source Action`/`Source Schedule`/`Source Service` columns.
- `utm-status` is parsed but not separately displayed; its effect is reflected in security-profile fields/group generation.
- `internet-service` enable/disable is parsed but Excel primarily exposes `internet-service-name` values.
- Coverage only compares policy counts; unresolved zone audits do not automatically make the section coverage status partial.

### `config firewall ippool`

**Coverage:** Typed/count-based.  
**Parser/source model:** `FGIPPool → IRIPPool`  
**Excel:** `IP Pools`; references also affect derived `NAT Rules`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| name | `Name` | Direct. |
| type | `Type` | Default `overload`. |
| startip / endip | `Start IP` / `End IP` | Direct. |
| source-startip / source-endip | `Source Start IP` / `Source End IP` | Direct. |
| source-prefix6 | IR `source_prefix6` | Extracted to IR but not currently a dedicated Excel IP Pools column. |
| startport / endport | `Start Port` / `End Port` | Direct. |
| associated-interface | `Associated Interface` | Direct. |
| arp-reply | `ARP Reply` | FortiOS enable conversion. |
| arp-intf | `ARP Interface` | Direct. |
| permit-any-host | `Permit Any Host` | FortiOS enable conversion. |
| exclude-ip | `Excluded IPs` | List preserved. |
| block-size | `Block Size` | Direct. |
| num-blocks-per-user | `Blocks Per User` | Direct. |
| pba-timeout | `PBA Timeout` | Direct. |
| pba-interim-log | IR only | Extracted to IR; no dedicated Excel column. |
| port-per-user | `Ports Per User` | Direct. |
| privileged-port-use-pba | IR only | Bool in IR; no dedicated Excel column. |
| nat64 | `NAT64` | Bool. |
| add-nat64-route | IR only | Bool; no dedicated Excel column. |
| client-prefix-length | IR only | No dedicated Excel column. |
| subnet-broadcast-in-ippool | IR `include_subnet_broadcast` | No dedicated Excel column. |
| tcp-session-quota | `TCP Session Quota` | Direct. |
| udp-session-quota | `UDP Session Quota` | Direct. |
| icmp-session-quota | `ICMP Session Quota` | Direct. |
| comments | `Description` | Direct. |

**Rules / considerations**

- Policy NAT correlation resolves pool names against this inventory.
- If start=end during NAT correlation, translated source is one IP; otherwise it becomes a textual `start-end` range.
- Advanced pool types other than `overload`/`one-to-one`, or NAT64 pools, trigger NAT manual review when referenced by a policy.

**Not fully extracted / current limitation**

- FGIPPool currently has no `extra_settings`; FortiGate IP-pool keys not declared in FGIPPool are not generically preserved in the typed/IR output.
- Several fields reach IR but are not currently shown as dedicated columns in `IP Pools`, as marked above.

### `config firewall vip`

**Coverage:** Typed/count-based.  
**Parser/source model:** `FGVIP → IRVirtualIP`  
**Excel:** `Virtual IPs`; nested servers in `VIP Real Servers`; policy references create derived NAT rules

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| name / id / uuid | `Name`, `Source ID`, `Source UUID` | Direct. |
| type | `Type` | Default `static-nat`. |
| status | `Enabled` | Anything except `disable` => True. |
| extip | `External IP` | Direct. |
| extaddr | `External Address Objects` | List. |
| mappedip | `Mapped IPs` | List. |
| mapped-addr | `Mapped Address` | Direct. |
| extintf | `External Interface` | Default `any`. |
| arp-reply | `ARP Reply` | FortiOS enable conversion. |
| portforward | `Port Forward` | enable=>True. |
| protocol | `Protocol` | Direct. |
| extport | `External Port` | Direct source string. |
| mappedport | `Mapped Port` | Direct source string. |
| portmapping-type | `Port Mapping Type` | Direct. |
| nat-source-vip | `NAT Source VIP` | Bool. |
| src-filter | `Source Filters` | List. |
| srcintf-filter | `Source Interface Filters` | List. |
| service | `Services` | List. |
| gratuitous-arp-interval | `Gratuitous ARP Interval` | Direct. |
| ldb-method | `Load Balance Method` | Direct. |
| server-type | `Server Type` | Direct. |
| persistence | `Persistence` | Direct. |
| http-redirect | `HTTP Redirect` | Bool. |
| monitor | `Monitors` | List. |
| max-embryonic-connections | `Max Embryonic Connections` | Direct. |
| comment | `Description` | Direct. |
| color | `Color` | Direct. |
| other VIP keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- Port-forward VIP correlation can generate a synthetic pre-NAT TCP/UDP service object named `svc_nat_<protocol>_<external_port>` if one does not already exist.
- VIPs with multiple mapped destinations are preserved but force NAT manual review.
- Unresolved `extintf` also forces NAT manual review.

### `config firewall vip > config realservers`

**Coverage:** Typed child collection/count-based.  
**Parser/source model:** `FGVIPRealServer → IRVirtualIPRealServer`  
**Excel:** `VIP Real Servers`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| edit ID | `Server ID` | Numeric. |
| ip | `IP` | Direct. |
| port | `Port` | Direct. |
| status | `Status` | Direct source value. |
| weight | `Weight` | Direct. |
| holddown-interval | `Holddown Interval` | Direct. |

**Rules / considerations**

- Rows retain the parent VIP name.

**Not fully extracted / current limitation**

- FGVIPRealServer has no `extra_settings`; unknown real-server fields are not generically retained.

### `config firewall vipgrp`

**Coverage:** EXTRACT_ONLY/manual-review.  
**Parser/source model:** `FGVIPGroup → IRVirtualIPGroup`  
**Excel:** `VIP Groups`; member references are also expanded during derived NAT correlation

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| name | `Name` | Direct. |
| uuid | `Source UUID` | Direct. |
| interface | `Interface` | Direct. |
| member | `Members` | List. |
| color | `Source Color` | Direct. |
| comment | `Description` | Direct. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- When a policy destination references a VIP group, NAT correlation iterates each member VIP.
- Missing member VIPs are preserved as audit/manual-review errors rather than silently ignored.

### `config firewall internet-service-name`

**Coverage:** Typed/count-based.  
**Parser/source model:** `FGInternetService → IRInternetService`  
**Excel:** `Internet Services`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| name | `Name` | Direct. |
| internet-service-id | `Source ID` | Explicitly remapped to integer `id`; invalid representation becomes None and the original safe value remains in Additional Settings. |
| comment | `Description` | Direct. |
| other keys | `Additional Settings` | Sanitized source/vendor-specific settings; not portable migration semantics. |

**Rules / considerations**

- Source vendor is added in the Excel row for traceability.
- Unknown safe settings flow through `FGInternetService.extra_settings` and
  `IRInternetService.source_attributes`; secret-like values remain redacted.

### `config vpn ipsec phase1-interface`

**Coverage:** Typed/count-based coverage.  
**Parser/source model:** `FGPhase1Interface → IRVPNTunnel`  
**Excel:** `VPN Tunnels`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| name | `Name` | Direct. |
| interface | `Local Interface` | Direct. |
| ike-version | `IKE Version` | `1` => `v1`; anything else => `v2`. |
| remote-gw | `Peer Address` | If absent, IR uses literal `dynamic`. |
| comments | `Description` | Direct. |
| psksecret | Credential presence only | Parser immediately stores `[REDACTED]` and `has_psk=True`; usable secret is never retained. |
| proposal | Parsed FG field only | List retained in FG model but not currently propagated to IRVPN tunnel crypto profile. |
| peertype | Parsed FG field only | Not currently propagated. |
| net-device | Parsed FG field only | Not currently propagated. |

**Rules / considerations**

- Every Phase 1 emits a PARTIAL audit note explaining that a usable PSK must be retrieved securely from the source environment.
- Excel shows `Configured / Redacted` or `Not configured`; it does not show the PSK.

**Not fully extracted / current limitation**

- Coverage can still report the section NORMALIZED when object counts match even though proposal/peertype/net-device are not propagated. Treat this as a current coverage-model limitation.
- FGPhase1Interface has no `extra_settings`; other unmodeled Phase 1 keys are not generically preserved in the typed output.

### `config vpn ipsec phase2-interface`

**Coverage:** Always PARTIALLY_NORMALIZED by coverage policy.  
**Parser/source model:** `FGPhase2Interface → IRVPNPhase2`  
**Excel:** `VPN Phase 2`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| name | `Name` | Direct. |
| phase1name | `Phase 1` | Reference preserved. |
| proposal | `Proposal` | List preserved. |
| src-addr-type | `Source Address Type` | Direct. |
| dst-addr-type | `Destination Address Type` | Direct. |
| src-name | `Source Selector` | List preserved. |
| dst-name | `Destination Selector` | List preserved. |
| src-subnet | `Source Subnet` | Direct source value. |
| dst-subnet | `Destination Subnet` | Direct source value. |
| auto-negotiate | `Auto Negotiate` | FortiOS enable conversion. |
| dhgrp | `DH / PFS Groups` | List of ints where parsing succeeds. |
| keepalive | `Keepalive` | FortiOS enable conversion. |
| comments | `Description` | Direct. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- A missing Phase 1 reference makes the record manual-review and emits an audit warning.
- Any nonempty Additional Settings also makes Phase 2 manual-review.
- Coverage explicitly states that the complete cross-vendor IPsec model is not implemented.

### `config vpn certificate remote/local/ca`

**Coverage:** EXTRACT_ONLY.  
**Parser/source model:** `FGCertificate → IRCertificate`  
**Excel:** `Certificates`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| name | `Name` | Direct. |
| section type | `Certificate Type` | Derived from config path: remote/local/ca. |
| range | `Range` | Direct. |
| source | `Source` | Direct. |
| comment | `Description` | Mapped to comments. |
| last-updated | `Last Updated` | Integer epoch converted to UTC datetime; invalid value is retained in Additional Settings. |
| certificate / remote / ca PEM | Parsed public certificate metadata | PEM is retained in IR but the Excel sheet intentionally does not output raw PEM. |
| private-key | `Has Private Key`; `Private Key Encrypted` | Private-key content is discarded immediately; encrypted marker is detected. |
| password/passwd | `Has Password` | Value discarded immediately. |
| other safe keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- X.509 parser derives subject, issuer, serial number, validity range, public-key algorithm/size, signature algorithm, SHA-256 fingerprint, self-signed status and CA BasicConstraints.
- SHA-256 fingerprint is upper-case hex with colon-separated octets.
- Self-signed status is cryptographically verified where supported, not determined only by subject==issuer.
- Certificate parse errors intentionally do not include exception text because a crypto parser error could echo sensitive source input.
- Excel computes `Expired` by comparing `valid_until` against the extraction timestamp.
- Manual review is required when certificate parsing failed, the certificate is not a factory local certificate, or certificate material is missing.

### `config firewall ssh local-key/local-ca`

**Coverage:** EXTRACT_ONLY/manual-review.  
**Parser/source model:** `FGSSHKey → IRSSHKey`  
**Excel:** `SSH Keys`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| name | `Name` | Direct. |
| section type | `Type` | Derived from path: local-key/local-ca. |
| public-key | IR public key; Excel `Has Public Key` only | Public key contents are not written into the normal Excel cell. |
| source | `Source` | Direct. |
| private-key | `Has Private Key` | Content discarded immediately. |
| password/passwd | `Has Password` | Content discarded immediately. |
| other safe keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- Excel intentionally exposes presence flags instead of private/password content.

### `config router static`

**Coverage:** NORMALIZED when all routes are safe; PARTIALLY_NORMALIZED if any route has parse error/manual review/unmodeled semantics.  
**Parser/source model:** `FGStaticRoute → IRRoute`  
**Excel:** `Routes`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| edit ID | `Source Route ID`; IR name=`route_<id>` | Numeric. |
| dst | `Source Destination` + normalized `Destination` | Missing destination defaults to source `0.0.0.0 0.0.0.0`; strict network normalization uses `strict=False` for host bits. |
| gateway | `Next Hop` | Direct. |
| device | `Interface` | Direct. |
| distance | `Administrative Distance` | Explicit integer normalization; invalid text is moved to Additional Settings. |
| priority | `Priority` | Explicit integer normalization; invalid text is moved to Additional Settings. |
| comment | `Description` | Direct. |
| sdwan-zone | `SD-WAN Zone` | Direct. |
| blackhole | `Blackhole` | `enable` => True; unexpected values preserved in Additional Settings. |
| status | `Enabled` | If set: disable=>False, other=>True; unexpected value also retained in Additional Settings. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- IR `metric` is deliberately left `None`; FortiGate administrative distance is not mislabeled as metric.
- Invalid destination/netmask leaves normalized `Destination` blank while preserving `Source Destination` and `Parse Error`.
- Any retained unmodeled source setting makes the route PARTIALLY_NORMALIZED/manual-review.

### `config system session-helper`

**Coverage:** EXTRACT_ONLY.  
**Parser/source model:** `FGSessionHelper → IRSessionHelper`  
**Excel:** `Session Helpers`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| edit ID | `Source ID` | Numeric. |
| name | `Name` | If absent, generated `session-helper-<id>`. |
| protocol | `Protocol Number` + derived protocol name | 6=>TCP, 17=>UDP, other=>`IP-<n>`. |
| port | `Port` | Direct. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- Entries are compared against a hard-coded common FortiOS baseline (IDs 1-20).
- Classification: exact baseline => DEFAULT; unknown ID => CUSTOM; known ID with changed tuple => CUSTOMIZED; missing name/protocol/port => UNKNOWN.
- Manual review is required for every classification except DEFAULT.
- The baseline is not yet version-specific, so FortiOS release differences must be considered.

### `config system session-ttl`

**Coverage:** Current coverage behavior: PARTIALLY_NORMALIZED.  
**Parser/source model:** `No dedicated typed global model; source commands can be retained as SourceInventoryItem`  
**Excel:** `Extraction Coverage`; no dedicated global Session TTL detail sheet

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| global set/unset/append commands | Sanitized source inventory | Parser records operations, but `apply_global_set()` does not create a typed system-session-ttl model. |

**Rules / considerations**

- The coverage registry lists `system session-ttl` as typed/extract-only, but `_COLLECTIONS` has no mapping for the parent section. The classifier therefore stops earlier and marks it PARTIALLY_NORMALIZED.
- The nested `port` entries are handled separately and do have a typed/Excel representation.

**Not fully extracted / current limitation**

- Global session-TTL field values are not currently rendered in a dedicated Excel detail sheet.

### `config system session-ttl > config port`

**Coverage:** EXTRACT_ONLY/manual-review.  
**Parser/source model:** `FGSessionTTLOverride → IRSessionTTLOverride`  
**Excel:** `Session TTL Overrides`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| edit ID | `Source ID` | Numeric. |
| protocol | `Protocol Number` + derived protocol name | 6=>TCP, 17=>UDP, other=>IP-n. |
| timeout | `Timeout (Seconds)` | Direct typed value. |
| start-port | `Start Port` | Direct. |
| end-port | `End Port` | Direct. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- Session lifetime behavior is target-platform dependent, therefore always manual-review.

### `config endpoint-control fctems`

**Coverage:** Coverage is count-based; generated IRZTNAProvider records are EXTRACT_ONLY/manual-review.  
**Parser/source model:** `FGFCTEMS → IRZTNAProvider`  
**Excel:** `ZTNA Providers`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| edit ID | `Source ID` | Stringified in IR. |
| name | `Name` | If absent, generated `FCTEMS_<id>`. |
| status | `Enabled` | enable=>True. |
| fortinetone-cloud-authentication | `Cloud Authentication` | enable=>True, disable=>False, absent=>None. |
| serial-number | `Source Serial` | Direct. |
| tenant-id | `Tenant ID` | Direct. |
| capabilities | `Capabilities` | List. |
| verifying-ca | `Verifying CA` | Direct. |
| verified-cn | `Verified CN` | Direct. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- An empty placeholder such as `edit 2` / `next` is intentionally not emitted as a ZTNA provider.
- Excel also shows policy IDs and EMS tags **observed elsewhere in the same source config**. Those are correlation hints only; the exporter does not claim that each observed tag belongs to a specific connector.
- A migration instruction is emitted telling the operator to recreate equivalent endpoint-posture/ZTNA intent on the target platform.

### `config system sdwan` and nested SD-WAN sections

**Coverage:** EXTRACT_ONLY/manual-review.  
**Parser/source model:** `FGSDWan tree → IRSDWAN tree`  
**Excel:** `SD-WAN`, `SD-WAN Members`, `SD-WAN Health Checks`, `SD-WAN SLAs`, `SD-WAN Rules`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| root status | `SD-WAN Status` | Direct. |
| root load-balance-mode | `Load Balance Mode` | Direct. |
| zone edit name | `SD-WAN zone name` | Direct; other zone settings go to Additional Settings. |
| member interface | `Interface` | Required typed field. |
| member zone | `Zone` | Defaults to `virtual-wan-link` if absent. |
| member gateway | `Gateway` | Direct. |
| member weight / priority | `Weight` / `Priority` | Explicit integer normalization; unparsed values retained in Additional Settings. |
| health-check server | `Server` | Direct. |
| health-check members | `Members` | Converted to integer IDs; unparsed values retained. |
| health-check interval | `Interval` | Integer-normalized. |
| SLA edit ID | `SLA ID` | Only typed SLA field; all detailed SLA criteria remain Additional Settings. |
| service/rule src,dst | `Source` / `Destination` | Lists. |
| service health-check | `Health Check` | Direct. |
| priority-members | `Priority Members` | Integer list. |
| internet-service | `Internet Service` | Direct. |
| internet-service-name | `Internet Service Names` | List. |
| internet-service-app-ctrl | `Internet Service App Control` | Integer list where possible. |
| use-shortcut-sla | `Use Shortcut SLA` | Direct. |
| unmodeled settings | `Additional Settings` | Sanitized at each tree level. |

**Rules / considerations**

- Although SD-WAN is EXTRACT_ONLY, SD-WAN zones and members participate in interface/policy zone resolution.
- Interface-address SNAT through an SD-WAN zone is deliberately not resolved statically, because the runtime member determines the source address; NAT requires manual review.

### `config user ldap`

**Coverage:** EXTRACT_ONLY/manual-review.  
**Parser/source model:** `FGUserLDAP → IRUserLDAP`  
**Excel:** `LDAP Servers`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| name | `Name` | Direct. |
| server | `Server` | Direct. |
| cnid | `CNID` | Direct. |
| dn | `DN` | Direct. |
| type | `Type` | Direct. |
| username | `Username` | Direct. |
| password/passwd | `Password Configured` | Value discarded; only `has_password=True` retained. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- Identity secrets are intentionally never placed in normal IR/Excel.

### `config user saml`

**Coverage:** EXTRACT_ONLY/manual-review.  
**Parser/source model:** `FGUserSAML → IRUserSAML`  
**Excel:** `SAML Servers`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| entity-id | `Entity ID` | Direct. |
| single-sign-on-url | `SSO URL` | Direct. |
| single-logout-url | `SLO URL` | Direct. |
| idp-entity-id | `IdP Entity ID` | Direct. |
| idp-single-sign-on-url | `IdP SSO URL` | Direct. |
| idp-single-logout-url | `IdP SLO URL` | Direct. |
| idp-cert | `IdP Certificate` | Reference preserved. |
| user-name | `User Name` | Direct. |
| group-name | `Group Name` | Direct. |
| digest-method | `Digest Method` | Direct. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- No SAML metadata download, certificate validation, or target-provider conversion is performed.

### `config user local`

**Coverage:** EXTRACT_ONLY/manual-review.  
**Parser/source model:** `FGLocalUser → IRLocalUser`  
**Excel:** `Local Users`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| name | `Name` | Direct. |
| status | `Status` | Direct source value. |
| type | `Type` | Direct. |
| passwd/password | `Password Configured` | Value discarded; only presence retained. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- Other secret-like identity fields such as seed/activation_code/private_key are ignored rather than retained.

### `config user group` and nested `config match`

**Coverage:** EXTRACT_ONLY.  
**Parser/source model:** `FGUserGroup / FGUserGroupMatch → IRUserGroup / IRUserGroupMatch`  
**Excel:** `User Groups`; `User Group Matches`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| group name | `Name` | Direct. |
| type | `Type` | Parser renames source `type` to `group_type`. |
| member | `Members` | List. |
| match edit ID | `ID` | Numeric. |
| match server-name | `Server Name` | Direct. |
| match group-name | `Group Name` | Direct. |
| other group keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- Group match count is calculated from the number of nested matches.

**Not fully extracted / current limitation**

- FGUserGroupMatch has no `extra_settings`; unknown nested match fields are not generically retained.

### `config vpn ssl web portal` and nested `host-check-software`

**Coverage:** EXTRACT_ONLY/manual-review.  
**Parser/source model:** `FGSSLVPNPortal / FGSSLVPNHostCheckSoftware → IRSSLVPNPortal / IRSSLVPNHostCheck`  
**Excel:** `SSL VPN Portals`; `SSL VPN Host Checks`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| portal tunnel-mode | `Tunnel Mode` | Direct. |
| ipv6-tunnel-mode | `IPv6 Tunnel Mode` | Direct. |
| ip-pools | `IP Pools` | List. |
| ipv6-pools | `IPv6 Pools` | List. |
| split-tunneling | `Split Tunneling` | Direct source value. |
| limit-user-logins | `Limit User Logins` | Direct source value. |
| forticlient-download | `FortiClient Download` | Direct source value. |
| host check name/type/guid/version | `SSL VPN Host Checks` fields | Direct. |
| other portal/check keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- The typed host-check path is the nested `vpn ssl web portal host-check-software` path.
- A separate top-level `config vpn ssl web host-check-software` is not in the typed registry and is therefore UNSUPPORTED unless support is added.

### `config vpn ssl settings` and nested `authentication-rule`

**Coverage:** EXTRACT_ONLY.  
**Parser/source model:** `FGSSLVPNSettings / FGSSLVPNAuthenticationRule → IRSSLVPNSettings / IRSSLVPNAuthenticationRule`  
**Excel:** `SSL VPN Settings`; `SSL VPN Authentication Rules`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| status | `Status` | Direct. |
| ssl-min-proto-ver | `Minimum Protocol` | Direct. |
| banned-cipher | `Banned Ciphers` | List. |
| servercert | `Server Certificate` | Reference preserved. |
| source-interface | `Source Interfaces` | List. |
| source-address | `Source Addresses` | List. |
| tunnel-ip-pools | `Tunnel IP Pools` | List. |
| default-portal | `Default Portal` | Direct. |
| auth rule edit ID | `ID` | Numeric. |
| auth rule groups | `Groups` | List. |
| auth rule portal | `Portal` | Direct. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- No target SSL-VPN configuration is asserted; all settings remain source-oriented.

### `config firewall DoS-policy` and nested `anomaly`

**Coverage:** EXTRACT_ONLY/manual-review.  
**Parser/source model:** `FGDoSPolicy / FGDoSAnomaly → IRDoSPolicy / IRDoSAnomaly`  
**Excel:** `DoS Policies`; `DoS Anomalies`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| policy ID | `Policy ID` | Numeric. |
| status | `Status` | Direct. |
| interface | `Interface` | Direct. |
| srcaddr | `Source Addresses` | List. |
| dstaddr | `Destination Addresses` | List. |
| service | `Services` | List. |
| comments | `Description` | Direct. |
| anomaly name | `Name` | Direct. |
| anomaly status/log/action | Corresponding anomaly columns | Direct. |
| anomaly threshold | `Threshold` | Explicit integer normalization; invalid raw value retained in Additional Settings. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- No target DoS profile translation is performed.

### `config firewall sniffer`

**Coverage:** EXTRACT_ONLY/manual-review.  
**Parser/source model:** `FGFirewallSniffer → IRFirewallSniffer`  
**Excel:** `Firewall Sniffer`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| edit ID | `ID` | Numeric. |
| uuid | `Source UUID` | Direct. |
| logtraffic | `Log Traffic` | Direct. |
| ipv6 | `IPv6` | Direct. |
| non-ip | `Non-IP` | Direct. |
| application-list-status / application-list | Application columns | Direct. |
| ips-sensor-status / ips-sensor | IPS columns | Direct. |
| av-profile-status / av-profile | AV columns | Direct. |
| webfilter-profile-status / webfilter-profile | Web Filter columns | Direct. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- This is traffic-processing/source inventory, not a portable policy object.

### `config authentication scheme`

**Coverage:** EXTRACT_ONLY/manual-review.  
**Parser/source model:** `FGAuthenticationScheme → IRAuthenticationScheme`  
**Excel:** `Authentication Schemes`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| name | `Name` | Direct. |
| method | `Method` | Direct. |
| user-database | `User Database` | Direct. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- No target authentication design is inferred.

### `config authentication rule`

**Coverage:** EXTRACT_ONLY/manual-review.  
**Parser/source model:** `FGAuthenticationRule → IRAuthenticationRule`  
**Excel:** `Authentication Rules`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| name | `Name` | Direct. |
| srcintf | `Source Interfaces` | List. |
| srcaddr | `Source Addresses` | List. |
| active-auth-method | `Active Auth Method` | Direct. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- Source references are preserved; no rule broadening is performed.

### `config ips sensor` and nested `entries`

**Coverage:** EXTRACT_ONLY/manual-review.  
**Parser/source model:** `FGIPSSensor / FGIPSSensorEntry → IRIPSSensor / IRIPSSensorEntry`  
**Excel:** `IPS Sensors`; `IPS Sensor Entries`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| sensor name | `Name` | Direct. |
| comment | `Description` | Direct. |
| block-malicious-url | `Block Malicious URL` | enable=>True, disable=>False; unexpected raw value is retained in Additional Settings and bool becomes None. |
| scan-botnet-connections | `Scan Botnet Connections` | Direct source value. |
| entry edit ID | `Entry ID` | Numeric. |
| rule | `Signature IDs` | Each value converted to int; unparsed values retained as `unparsed_rule_values` in Additional Settings. |
| severity | `Severities` | List. |
| location | `Location` | Direct. |
| protocol | `Protocols` | List. |
| status | `Enabled` | enable=>True, disable=>False; unexpected raw value retained. |
| action | `Action` | Direct. |
| rate-count / rate-duration | Rate columns | Integer-normalized; invalid raw values retained. |
| quarantine / quarantine-expiry | Quarantine columns | Direct. |
| other keys | `Additional Settings` | Sanitized. |

**Rules / considerations**

- Source signature IDs are preserved but not translated to another vendor's signature database.

## 7. Structured source-only security sections

These sections are **not forced into canonical cross-vendor security-profile semantics**. Instead the parser recursively preserves the source command tree.

| Config path | Status | Excel |
| --- | --- | --- |
| application custom | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| application list | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| dlp data-type | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| dlp dictionary | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| dlp sensor | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| dlp filepattern | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| dlp profile | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| webfilter urlfilter | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| webfilter profile | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| webfilter ftgd-local-cat | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| webfilter ftgd-local-rating | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| dnsfilter profile | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| antivirus profile | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| antivirus settings | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| file-filter profile | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| emailfilter profile | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| icap profile | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| voip profile | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| virtual-patch profile | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| firewall profile-protocol-options | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| firewall ssl-ssh-profile | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| waf profile | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| casb profile | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| casb saas-application | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| casb user-activity | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |
| ips settings | EXTRACT_ONLY | Source Security Profiles / Source Security Profile Setting |

For every structured security section:

- `set`, `unset`, and `append` operations are preserved.
- Nested `config` and `edit` hierarchy is preserved recursively.
- Secret-like values are sanitized before storage.
- Excel detail rows contain: `Profile Type`, `Profile Name`, `Subsection`, `Entry`, `Operation`, `Setting`, `Value`.
- Manual review is required.
- Policy-reference correlation in the Excel summary currently checks names used by policy antivirus, IPS sensor, web filter, application list, and SSL/SSH profile fields. Other profile families are not automatically correlated to policies.

This mechanism is intentionally preferred over inventing a target-neutral schema for vendor-specific profile internals.

## 8. Structured source-only routing sections

| Config path | Status | Excel |
| --- | --- | --- |
| router rip | EXTRACT_ONLY | Routing Protocols / Routing Protocol Settings |
| router ripng | EXTRACT_ONLY | Routing Protocols / Routing Protocol Settings |
| router ospf | EXTRACT_ONLY | Routing Protocols / Routing Protocol Settings |
| router ospf6 | EXTRACT_ONLY | Routing Protocols / Routing Protocol Settings |
| router bgp | EXTRACT_ONLY | Routing Protocols / Routing Protocol Settings |
| router isis | EXTRACT_ONLY | Routing Protocols / Routing Protocol Settings |
| router multicast | EXTRACT_ONLY | Routing Protocols / Routing Protocol Settings |

Handling is recursive and loss-resistant at the command-tree level:

- Source `set`, `unset`, `append`, `config`, and `edit` structure is preserved.
- Values are sanitized.
- No BGP/OSPF/RIP/etc. canonical routing model is currently asserted.
- Nested paths below these roots are also classified EXTRACT_ONLY.
- Manual review is required.

Static routes are separate and have their own typed `router static` handling described above.

## 9. Other source-inventory-only section

### `config user fsso`

`user fsso` is explicitly classified `EXTRACT_ONLY` by the coverage registry, but it does not have a dedicated typed FG model.

- The generic parser still records sanitized source commands in `ExtractionResult.inventory_items`.
- It is not normalized into canonical identity IR.
- There is currently no dedicated generic Excel source-inventory sheet that renders these command values, so the field-level values are primarily programmatic extraction data plus coverage evidence.
- This is different from `user group`, which has a typed Excel representation.

## 10. Intentionally ignored sections

| Prefix | Status | Reason |
| --- | --- | --- |
| system replacemsg | IGNORED_BY_POLICY | FortiGate replacement-message configuration is outside current firewall migration scope. |
| switch-controller | IGNORED_BY_POLICY | FortiSwitch configuration is outside firewall migration scope. |
| wireless-controller | IGNORED_BY_POLICY | FortiAP/wireless-controller configuration is outside firewall migration scope. |

All nested sections under these prefixes inherit the ignored classification. They remain visible in `Extraction Coverage` with the policy reason, but are not treated as migration inventory.

## 11. Unsupported section catch-all

Any discovered FortiGate config path that is not:

1. in the typed section registry,
2. in the structured security/routing registry,
3. explicitly source-inventory-only, or
4. under an ignored prefix,

is classified `UNSUPPORTED` with:

`No typed FortiGate extraction handler is registered.`

Current behavior:

- The independent scanner still records section path, source edit count, and source line range.
- Generic parser commands can exist in `ExtractionResult.inventory_items` with sanitized values.
- `UnsupportedItem` is created at section level with manual review required.
- The current `Unsupported` Excel sheet primarily shows section/reason/manual-review. `raw_capture` is currently not populated by the FortiGate extractor, so unsupported field values are not fully reproduced there.

Common FortiGate areas that therefore remain unsupported unless a handler is added include management-plane, HA, token, logging, and other feature families not listed in the registries above. The exact result is determined by the source path, not by a broad assumption.

### Important known unsupported identity example

`config user adgrp` is not in the current typed or source-only registry. It is therefore `UNSUPPORTED`. This matters for FSSO/AD-group migrations because policies may reference identity groups whose source AD-group metadata is not yet represented as typed Excel inventory.

### Important SSL-VPN example

The tool types **nested** `vpn ssl web portal host-check-software`, but a separate top-level `vpn ssl web host-check-software` path is not registered and will be `UNSUPPORTED`.

## 12. Derived data and calculations

The following outputs are calculated from source objects; they are not standalone FortiGate config sections.

### 12.1 Zone derivation

For each interface/policy interface reference:

1. explicit caller-provided `zone_mapping` wins;
2. explicit FortiGate `system zone` membership is used;
3. SD-WAN member zone can be used;
4. otherwise the zone stays unresolved.

No trust/untrust inference is made from interface role/name/alias/description.

### 12.2 Policy security profile groups

When `utm-status enable`:

- active source profiles are gathered;
- names are prefixed (`AV_`, `IPS_`, `WF_`, `APP_`);
- a synthetic `SPG_...` name is created, sanitized, and truncated to 63 characters;
- a corresponding IR security-profile group is created once;
- an audit entry records the mapping.

This is a derived migration convenience, not raw FortiGate source fidelity.

### 12.3 NAT correlation

NAT Rules are derived by correlating `firewall policy`, `firewall ippool`, `firewall vip`, `firewall vipgrp`, interfaces and resolved zones.

#### Source NAT

- `policy nat enable` + `ippool enable` => pool translation mode.
- Each `poolname` is resolved against extracted IP pools.
- Missing pool references do not fall back to interface NAT; they are preserved and marked manual-review.
- Pool start=end => one translated source IP.
- Pool start!=end => textual translated range `start-end`.
- Multiple pool types can result in source pool type `mixed`.
- Advanced pool types or NAT64 force target-specific review.
- `policy nat enable` without IP pool => interface-address mode.
- Interface-address SNAT is resolved only when exactly one destination interface exists, it is not `any`, not an SD-WAN zone, exists in the source, uses static addressing, and has a usable primary IP.
- Dynamic/DHCP/PPPoE/SD-WAN/ambiguous egress cases remain unresolved/manual-review.

#### Destination / twice NAT

- Policy destination names are checked against VIPs and VIP groups.
- VIP-group members are expanded to individual VIP correlations.
- Missing group members produce manual-review audits.
- External destination uses VIP `extip`, otherwise `extaddr` list.
- Translated destination uses `mappedip`, otherwise `mapped-addr`.
- Port-forward VIPs preserve external and mapped ports.
- TCP/UDP port-forward VIPs can create a synthetic pre-NAT service object.
- Unsupported port-forward protocols require manual review.
- Policy using both source NAT and VIP destination becomes TWICE NAT.
- Missing policy match fields are never replaced with `any` merely to create a valid NAT rule.

## 13. Excel export safety and visibility

Excel is an inventory/reporting layer. It does not make source parsing more complete.

Current workbook safety behavior includes:

- every source-derived cell passes through shared redaction again;
- lists are displayed as newline-separated values;
- booleans are rendered as Yes/No or explicit TRUE/FALSE depending the exporter helper used by the sheet;
- illegal XML control characters are removed;
- cell text is capped at Excel's 32,767-character limit with a truncation marker;
- values beginning with `=`, `+`, `-`, or `@` are prefixed with an apostrophe to prevent formula injection;
- certificate/private-key/password/PSK handling intentionally avoids exposing usable credentials.

### Excel is not the full ExtractionResult

Some data can exist in `ExtractionResult.inventory_items` but have no dedicated workbook detail sheet. Notable current examples are generic `user fsso` commands and parent `system session-ttl` global commands.

## 14. Current implementation gaps / fields that deserve follow-up

| Area | Current limitation |
| --- | --- |
| System zone | `tag` and `description` are parsed but not propagated to IRZone/Excel. |
| Address | `sdn` and `filter` are typed FG fields but not propagated and not placed into extra_settings. |
| Phase 1 IPsec | `proposal`, `peertype`, `net-device` are parsed but not propagated; unknown Phase 1 keys have no extra_settings safety net. |
| IP Pools | Unknown keys have no extra_settings safety net; several advanced IR fields are not visible as dedicated Excel columns. |
| VIP real servers | Unknown nested real-server fields have no extra_settings safety net. |
| Internet Service Name | Unknown fields have no extra_settings safety net. |
| User group match | Unknown nested match fields have no extra_settings safety net. |
| Firewall policy source fidelity | Raw `accept`/`always`/`ALL` and other normalized source values do not have dedicated parallel source-value columns. |
| Generic EXTRACT_ONLY inventory | `user fsso` field values are retained programmatically but not rendered in a generic source-detail Excel sheet. |
| Unsupported inventory | Unsupported source commands can be parsed/sanitized, but the Excel Unsupported sheet does not currently render a complete safe command tree/raw capture. |
| Coverage counting | Shared IR collections and singleton global sections can make section counts misleading; count equality is not a universal proof of semantic completeness. |
| Service coverage | Section counts can match even when individual service objects are PARTIALLY_NORMALIZED/manual-review. |
| Policy coverage | Section counts can match even when policy zone resolution emitted manual-review audits. |
| Phase 1 coverage | Section counts can match despite known parsed-but-not-propagated Phase 1 fields. |

## 15. How to interpret 'extracted'

Use these definitions when reviewing the tool:

- **Source accounted for:** the section appears in `Extraction Coverage`.
- **Parsed:** a typed FG model or sanitized source inventory command exists.
- **Normalized:** portable semantics reached canonical IR.
- **Excel-visible:** the current workbook has a sheet/column for the value.
- **Target-migratable:** a target generator safely consumes the semantics. This is a separate question from extraction.

A section can therefore be:

```text
present -> parsed -> EXTRACT_ONLY -> Excel-visible -> not target-migratable
```

or:

```text
present -> parsed -> IR field -> not currently exposed as a dedicated Excel column
```

or:

```text
present -> unsupported -> coverage/audit only
```

This distinction is required to avoid claiming full extraction merely because an object count matches.

## 16. Maintenance rule for future FortiGate changes

When adding support for a FortiGate config section or field, update all applicable layers:

1. `coverage.py` section registry/status.
2. `model.py` source model fields.
3. `parser.py` list/numeric/nested-field handling and safe `extra_settings` behavior.
4. `transformer.py` normalization/source-only mapping.
5. IR model if portable/source-inventory representation is required.
6. `excel_exporter.py` visibility.
7. extraction/Excel tests.
8. this document.

For every new field, explicitly decide one of:

`NORMALIZE | EXTRACT_ONLY | VENDOR_EXTENSION | UNSUPPORTED | IGNORED_BY_POLICY | PARSE_ERROR`

and never allow a migration-relevant source value to disappear without an explicit reason.
