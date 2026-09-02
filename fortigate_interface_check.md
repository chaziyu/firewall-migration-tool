## Result

For the uploaded sample, the **interface extraction coverage is strong**:

- **63/63 interfaces** in `config system interface` are present in Excel. The workbook summary also reports 63 interfaces.  
- The raw interface block contains **333 explicit `set` statements across 21 distinct sub-config keys**. All 21 key types are represented in the Excel output.
- **329/333 values are preserved with their actual value.** The remaining 4 are PPPoE `password` values, intentionally exported as `[REDACTED]`. For example, `unifi_port1` retains the PPPoE mode, username, VLAN, parent interface, DNS override, etc., while redacting the password. 
- There is **no `config secondaryip` in this sample**, and Excel correctly reports `Interface Secondary IPs = 0`. 
- There are also no nested interface blocks in this particular sample, so positive-case nested parsing cannot be verified from these two files.

### 1. Original config → Excel cross-check

| Interface sub-config | Raw count | Excel extraction | Result |
|---|---:|---|---|
| `vdom` | 63 | Source VDOM + source settings | ✅ Correct |
| `snmp-index` | 63 | Source settings | ✅ Correct |
| `type` | 57 | Interface Type | ✅ Correct |
| `interface` | 29 | Parent interface | ✅ Correct |
| `role` | 17 | Role | ✅ Correct |
| `speed` | 17 | Source settings only | ⚠️ Extracted, not normalized |
| `allowaccess` | 15 | Management Access | ✅ Correct |
| `ip` | 11 | Converted to CIDR, e.g. `/24` | ✅ Correct |
| `alias` | 11 | Alias | ✅ Correct |
| `device-identification` | 8 | Source settings only | ⚠️ Extracted, not normalized |
| `mediatype` | 8 | Source settings only | ⚠️ Extracted, not normalized |
| `vlanid` | 6 | Tag / VLAN ID | ✅ Correct |
| `monitor-bandwidth` | 5 | Source settings only | ⚠️ Extracted, not normalized |
| `mode` | 5 | Addressing Mode / PPPoE Mode | ✅ Correct |
| `status` | 4 | `down` → Enabled=`No` | ✅ Correct |
| `username` | 4 | PPPoE Username | ✅ Correct |
| `password` | 4 | `[REDACTED]` | ⚠️ Intentionally not preserved verbatim |
| `dns-server-override` | 3 | Source settings only | ⚠️ Extracted, not normalized |
| `dedicated-to` | 1 | Source settings only | ⚠️ Extracted, not normalized |
| `ike-saml-server` | 1 | Source settings only | ⚠️ Extracted, not normalized |
| `src-check` | 1 | Source settings only | ⚠️ Extracted, not normalized |

Examples confirm the behavior: `HQ_Vlan20` becomes a VLAN interface with `10.10.2.1/24`, parent `port3`, VLAN 20 and management access `ping`; `unifi_port1` becomes PPPoE/VLAN with parent `port1` and VLAN 500; `naf.root` retains `src-check=disable`; and the `x*` interfaces retain `mediatype` and `speed` as source settings.  

**Data-extraction verdict: `PASS`, with one intentional fidelity exception: PPPoE passwords are redacted.**

---

## 2. Code logic vs FortiOS 7.4.6

The repository's design explicitly has two levels: common interface properties are normalized into `FGInterface → IRInterface`, while **all explicit top-level `set` commands are additionally retained as sanitized `source_attributes`**. Unknown nested configurations are retained recursively. 

The FortiGate model correctly establishes FortiOS defaults such as `role="undefined"`, `status="up"` and `mode="static"`, while defining typed fields for IP, `allowaccess`, type, VLAN ID, parent interface, VRF, username, secondary IPs and common IPv6 settings.  The transformer maps parent=`interface`, VLAN/tag=`vlanid`, `status != down`, role, addressing mode and management access into the portable interface representation.  

| Sub-config | Code handling | Against FortiOS 7.4.6 | Logic verdict |
|---|---|---|---|
| `vdom` | Typed → Source VDOM | FortiOS defines interface ownership by VDOM | ✅ Correct |
| `snmp-index` | Source-only | Permanent SNMP interface index | ✅ Correct for inventory |
| `type` | Typed; explicit type used; parent+VLAN ID can infer `vlan` | Official types include physical, VLAN, tunnel, aggregate, etc. | ✅ Correct |
| `interface` | Typed → parent/underlay | Valid interface reference | ✅ Correct |
| `role` | `lan/wan/dmz`; `undefined` → no portable role | Exact FortiOS roles/default | ✅ Correct |
| `speed` | Source-only | Controls physical interface speed/duplex | ⚠️ **Incomplete semantic mapping** |
| `allowaccess` | List → Management Access | FortiOS defines ping/HTTPS/SSH/SNMP/HTTP/etc. | ✅ Correct |
| `ip` | Netmask form → CIDR | FortiOS uses IPv4 address + mask | ✅ Correct |
| `alias` | Typed alias | Interface display alias | ✅ Correct |
| `device-identification` | Source-only + manual review | Passive device identity gathering | ⚠️ Preserved, not modeled |
| `mediatype` | Source-only | Selects SFP media interface type | ⚠️ **Incomplete semantic mapping** |
| `vlanid` | Integer → VLAN ID/tag | Official range/meaning is VLAN ID | ✅ Correct |
| `monitor-bandwidth` | Source-only + manual review | Enables bandwidth monitoring | ⚠️ Preserved; review classification is overly conservative |
| `mode` | Default `static`; supports DHCP/PPPoE | Exact FortiOS addressing modes | ✅ Correct |
| `status` | Default `up`; `down` → disabled | Official values are `up/down` | ✅ Correct |
| `username` | PPPoE Username | Officially PPPoE account username | ✅ Correct |
| `password` | Sanitized/redacted | Officially PPPoE account password | ⚠️ Correct security treatment, but not full-fidelity extraction |
| `dns-server-override` | Source-only | Valid system-interface setting | ⚠️ Preserved, semantics not modeled |
| `dedicated-to` | Source-only + review | `management` means management-purpose-only interface | ⚠️ **Important semantic gap** |
| `ike-saml-server` | Source-only + review | IKE authentication SAML server | ⚠️ Preserved, semantics not modeled |
| `src-check` | Source-only + review | Enables/disables source-IP checking | ⚠️ **Important semantic gap** |

Fortinet confirms, among other things, that `dedicated-to management` makes the interface management-only and that `device-identification` performs passive identity gathering.  It defines `mode` as static/DHCP/PPPoE and `monitor-bandwidth` strictly as bandwidth monitoring.  It defines interface speed, source-IP checking, and administrative `up/down` status explicitly.  Interface roles are `lan`, `wan`, `dmz`, and `undefined`.  Types include physical, VLAN, aggregate, redundant and tunnel, while `username` is specifically the PPPoE account username.  VLAN IDs are explicitly defined as `vlanid`.  `ike-saml-server` is specifically the interface's IKE authentication SAML server. 

### Final assessment

| Area | Verdict |
|---|---|
| Interface object count | ✅ **63/63 correct** |
| 21 sub-config types present in sample | ✅ **21/21 captured** |
| Raw explicit setting coverage | ✅ **333/333 represented** |
| Exact value preservation | ⚠️ **329/333** — four passwords intentionally redacted |
| Common interface semantic mapping | ✅ **Correct** |
| Source-only preservation mechanism | ✅ **Good design** |
| Full FortiOS interface semantic coverage | ⚠️ **Not complete** |
| Main gaps | `speed`, `mediatype`, `dedicated-to`, `src-check`, `ike-saml-server`, `dns-server-override`, plus some monitoring/identification settings remain source-only |

So, **for this uploaded config the extractor is not losing ordinary interface configuration**. The bigger issue is not parsing; it is that several successfully extracted FortiGate-specific settings remain only in `Additional Settings`/`Interface Source Settings` rather than being semantically modeled. The highest-priority interface improvements are **`dedicated-to`, `src-check`, `speed`, and `mediatype`**.