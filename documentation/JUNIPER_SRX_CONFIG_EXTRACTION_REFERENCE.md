# Juniper SRX Configuration Extraction Reference

**Vendor identifier:** `juniper_srx`  
**Display name:** Juniper SRX (Junos root-level display set)  
**Supported file extensions:** `.set`, `.txt`, `.conf`  
**Authoritative contract:** `ExtractionResult` via `JuniperSRXSourceParser.extract()`  

---

## 1. Supported Input Format

- **Format:** Junos root-level `show configuration | display set` output.
- **Root hierarchy validation:** The parser expects root-level set statements. Relative display set configurations (such as outputs starting with `set unit ...` or `set policy ...` from within an `edit` hierarchy) are detected and rejected with a descriptive `ValueError`.
- **Comment handling:** 
  - Single-line comments starting with `#` are skipped.
  - Multi-line block comments enclosed in `/* ... */` are parsed and skipped.
- **Junos command operations:**
  - `set` — creates or modifies configuration elements.
  - `deactivate` — marks individual configuration nodes or entire subtrees as inactive; accounted in source extraction.
  - `activate` — restores active state for previously deactivated paths.

---

## 2. Extraction Accounting and Zero Silent Loss

Every non-comment input statement is classified into one of the repository canonical extraction statuses:

1. **`NORMALIZED`**: Feature fully parsed and translated into portable `IRConfig` data models.
2. **`PARTIALLY_NORMALIZED`**: Feature mapped with source caveats; flagged with `requires_manual_review=True` in both IR and ExtractionResult.
3. **`EXTRACT_ONLY`**: Structured configuration retained in `ExtractionResult.inventory_items` for inventory/audit/Excel export, but not emitted into canonical IR.
4. **`VENDOR_EXTENSION`**: Feature explicitly specific to Junos.
5. **`UNSUPPORTED`**: Recognized Junos construct without safe migration representation; preserved with sanitized raw capture in `ExtractionResult.unsupported_items`.
6. **`PARSE_ERROR`**: Syntactically invalid line or lexical failure.

---

## 3. Supported Junos Hierarchy

### 3.1 System & Version
- `set version <version>` -> `IRMetadata.source_version`
- `set system host-name <name>` -> `IRMetadata.hostname`
- `set system time-zone <tz>` -> normalized
- `set system name-server <ip>` -> normalized

### 3.2 Interfaces & VLANs
- `set interfaces <intf> description <desc>`
- `set interfaces <intf> disable` -> `status=False`
- `set interfaces <intf> unit <unit> vlan-id <id>` -> `IRInterface.vlanid`
- `set interfaces <intf> unit <unit> family inet address <ip>` -> `IRInterface.ip` (or `IRInterfaceSecondaryIP`)
- `set interfaces <intf> unit <unit> family inet6 address <ip>` -> `IRInterface.secondary_ips`

### 3.3 Security Zones
- `set security zones security-zone <zone> interfaces <intf>` -> `IRZone.interfaces`
- `set security zones security-zone <zone> description <desc>` -> `IRZone.description`
- `set security zones security-zone <zone> screen <screen>` -> `EXTRACT_ONLY`
- `set security zones security-zone <zone> host-inbound-traffic ...` -> `EXTRACT_ONLY`

### 3.4 Address Books & Address Sets
- **Global address book:** `set security address-book global ...`
- **Named address books:** `set security address-book <book> attach zone <zone>`
- **Legacy zone address books:** `set security zones security-zone <zone> address-book ...`
- **Address types:**
  - `ip-prefix` (IPv4 / IPv6) -> `AddressType.NETWORK` / `AddressType.HOST`
  - `dns-name` / `dns-address` -> `AddressType.FQDN`
  - `range-address <start> to <end>` -> `AddressType.RANGE`
  - `wildcard-address <ip/mask>` -> `AddressType.WILDCARD_MASK`
- **Address sets:** nested sets supported with cycle detection.

### 3.5 Applications & Application Sets
- `set applications application <name> protocol <proto>` (or protocol number)
- `set applications application <name> destination-port <port>` / `source-port <port>`
- `set applications application <name> icmp-type <type>` / `icmp-code <code>`
- `set applications application <name> term <term> ...` (multi-term support)
- `set applications application-set <name> application <member>` -> `IRServiceGroup`

### 3.6 Security Policies
- **Zone policies:** `set security policies from-zone <from> to-zone <to> policy <name> ...`
- **Global policies:** `set security policies global policy <name> ...`
- **Actions:**
  - `then permit` -> `PolicyAction.ALLOW`
  - `then deny` -> `PolicyAction.DENY`
  - `then reject` -> `PolicyAction.DENY` (`source_action="reject"`, `requires_manual_review=True`)
- **Logging & Counting:**
  - `then log session-init` -> `log_start=True`
  - `then log session-close` -> `log_end=True`
  - `then count` -> `source_extra_settings["junos_count"]=True`
- **Match exclusions:** `source-address-excluded`, `destination-address-excluded` -> `requires_manual_review=True`

### 3.7 Static Routes
- `set routing-options static route <dst> next-hop <gw>` -> `IRRoute`
- `set routing-options static route <dst> qualified-next-hop <gw> preference/metric/tag`
- `set routing-options static route <dst> discard|reject` -> `blackhole=True`
- `set routing-instances <inst> routing-options static route ...` -> `source_attributes["junos_routing_instance"]`

### 3.8 NAT
- **Source NAT:** pools, rule-sets (from/to zone/interface/routing-instance), interface/pool/off translation.
- **Destination NAT:** pools, rule-sets, translation to pool IP.
- **Static NAT:** rule-sets, prefix translation.

### 3.9 VPN
- **IKE:** proposals, policies, gateways.
- **IPsec:** proposals, policies, VPNs bound to `st0.x` tunnel interfaces.

---

## 4. Secret Sanitization Rules

In accordance with platform security invariants, sensitive values are redacted before any source command or attribute is preserved in memory or stored in `ExtractionResult`:
- Keywords triggering redaction: `pre-shared-key`, `encrypted-password`, `plain-text-password`, `authentication-key`, `secret`, `password`, `community`, `private-key`, `token`, `api-key`.
- Token-aware sanitization prevents accidental redaction of object names containing substrings (e.g. `community-web`).

---

## 5. ACCESS-DENIED Handling

If Junos configuration contains `ACCESS-DENIED` placeholders due to operator permission restrictions:
- The command is structurally identified.
- Classified as `UNSUPPORTED` / `PARTIALLY_NORMALIZED` with `requires_manual_review=True`.
- The extraction audit notes that source configuration was hidden by Junos permissions.

---

## 6. Zone Mapping Specification

When `zone_mapping` dictionary is supplied to `extract()` or `parse()`:
- **Applied to:** `IRZone.name`, `IRInterface.zone`, `IRPolicy.from_zone`, `IRPolicy.to_zone`, global policy zone match criteria, NAT from/to zone contexts.
- **Not applied to:** routing instances, VRFs, interface names, address book names, VPN bind interfaces.
