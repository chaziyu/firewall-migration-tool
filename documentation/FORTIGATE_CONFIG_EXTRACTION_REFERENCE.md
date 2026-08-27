# FortiGate Configuration Extraction Handling Reference

## Firewall policy

**Coverage:** `NORMALIZED` for safely portable IPv4 allow/deny policies and
`PARTIALLY_NORMALIZED` when retained source semantics require manual review.
**Flow:** `FGPolicy -> IRPolicy -> Policies`, plus sanitized `SourceCommand`
inventory in `Firewall Policy Source Settings`.

- Canonical fields: policy ID/name, interfaces/zones, IPv4 source and
  destination, services, allow/deny action, schedule, status, logging, basic
  NAT, explicit profile references, and Internet Service names.
- Typed source preservation: UUID, separate IPv6 references and IPv4/IPv6
  negate settings, service negation, `logtraffic-start`, IPv6 pool names,
  profile type/group/protocol options, policy-based IPsec tunnel, Internet
  Service status, inspection mode, and ZTNA state/tags.
- Fallback preservation: sanitized `source_extra_settings` and exact ordered
  source commands.
- Manual review: IPsec action, any enabled negation, IPv6 family-specific match
  semantics, FortiGate profile-group semantics, and other source-only traffic
  behavior that cannot be represented safely by the canonical policy model.

An unnamed numeric `edit` key is the policy ID, not a synthetic policy name.
`logtraffic` does not imply session-start logging. Explicit security profiles
remain visible regardless of `utm-status`. A source `profile-group` remains
distinct from any generated migration security profile group. Unsafe policies
are withheld from target policy generators rather than broadened or coerced to
allow/deny.

## FortiGate NAT resources and correlation

| Source path | Coverage | Typed/report path | Safety rule |
| --- | --- | --- | --- |
| `firewall ippool` | `NORMALIZED` for safe basic pools; `PARTIALLY_NORMALIZED` for exclusions, full-cone, PBA/CGN/NAT64 or other advanced semantics | `FGIPPool -> IRIPPool -> IP Pools` | Advanced semantics are preserved and withheld when correlated. |
| `firewall ippool6` | `EXTRACT_ONLY` | `FGIPPool6 -> IRIPPool -> IP Pools` | No IPv4 NAT is invented. |
| `firewall vip` | `NORMALIZED` for basic static IPv4 VIPs; `PARTIALLY_NORMALIZED` for advanced types, restrictions, cross-family, or load-balancing semantics | `FGVIP -> IRVirtualIP -> Virtual IPs` | Only straightforward static DNAT/port forwarding is automatically eligible. |
| `firewall vip realservers` | `NORMALIZED` for simple IP backends; `PARTIALLY_NORMALIZED` for address references, health/monitor/client restrictions, or other advanced fields | `FGVIPRealServer -> IRVirtualIPRealServer -> VIP Real Servers` | Address objects remain references, never fake IPs. |
| `firewall vip6` / `firewall vip6 realservers` | `EXTRACT_ONLY` | IPv6 typed source inventory | No IPv4 DNAT is invented. |
| `firewall vipgrp` | `EXTRACT_ONLY` source inventory | `FGVIPGroup -> IRVirtualIPGroup -> VIP Groups` | Existing safe IPv4 correlation may expand members. |
| `firewall vipgrp6` | `EXTRACT_ONLY` | IPv6 group inventory | No automatic NAT correlation. |

Policy/resource correlation remains in `_transform_nat()` and produces derived
`IRNATRule` rows. Pool exclusions are not converted into guessed sub-ranges;
VIP restrictions remain separate from policy source/service matches; disabled
VIPs produce disabled manual-review rules. A target may emit a NAT rule only
when it is `NORMALIZED`, has no review reasons, and does not require review.

## Nested `config system interface` update

This file contains the documentation changes required for the nested-interface extraction implementation. Merge these sections into `documentation/FORTIGATE_CONFIG_EXTRACTION_REFERENCE.md`.

---

## 1. Master section coverage matrix

Replace the existing `system interface` and `system interface secondaryip` rows with:

| FortiGate config path | Coverage behavior | Typed/IR path | Excel output | Important note |
| --- | --- | --- | --- | --- |
| system interface | NORMALIZED / PARTIALLY_NORMALIZED | FGInterface → IRInterface | Interfaces; Interface Source Settings; Interface Nested Configuration | Portable interface fields are normalized. All explicit top-level `set` values are retained as sanitized `source_attributes`. Unmodeled nested interface blocks are recursively preserved under the owning interface as `nested_source_configs`; their presence makes the parent section PARTIALLY_NORMALIZED because those nested semantics are extraction-only. |
| system interface secondaryip | NORMALIZED / PARTIALLY_NORMALIZED | FGInterfaceSecondaryIP → IRInterfaceSecondaryIP | Interface Secondary IPs | `config secondaryip` remains a dedicated typed child collection. Invalid/missing IP values or unmodeled child settings make the child section partial. It must not also be duplicated into generic nested interface configuration. |
| system interface <nested path> | EXTRACT_ONLY | FGSourceNode → IRSourceConfigNode attached to IRInterface | Interface Nested Configuration | Any nested interface block without a dedicated typed model is retained recursively under its parent interface. Parent ownership, `config`/`edit` hierarchy, `set`/`unset`/`append` operations, source order, and sanitized values are preserved. Target generators must ignore these source-only nodes. |

The `<nested path>` row is conceptual coverage for paths such as:

```text
system interface ipv6
system interface ipv6 ip6-extra-addr
system interface ipv6 ip6-prefix-list
system interface ipv6 ip6-delegated-prefix-list
system interface ipv6 dhcp6-iapd-list
system interface ipv6 vrrp6
system interface client-options
system interface dhcp-snooping-server-list
system interface egress-queues
system interface l2tp-client-settings
system interface tagging
system interface vrrp
system interface vrrp proxy-arp
system interface wifi-mac-list
system interface wifi-networks
```

Do not enumerate every possible FortiOS nested interface path in code. Coverage should classify any `system interface ...` path as `EXTRACT_ONLY` unless that exact path already has a dedicated typed handler such as `system interface secondaryip`.

---

## 2. Replace the detailed `config system interface` section

### `config system interface`

**Coverage:** `NORMALIZED` only when the main interface objects are represented without network parse errors and there are no unmodeled nested interface blocks. `PARTIALLY_NORMALIZED` when an interface contains invalid `ip`/`remote-ip` syntax or one or more nested source configuration blocks that are retained as extraction-only data.  
**Parser/source model:** `FGInterface → IRInterface`  
**Excel:** `Interfaces`, `Interface Source Settings`, `Interface Secondary IPs`, and `Interface Nested Configuration`

| FortiGate source field | Destination / visibility | Handling |
| --- | --- | --- |
| edit name | `Name` | Direct. |
| vdom | `Source VDOM` | Parser compatibility default remains `root` when absent. |
| ip | `IP / Prefix` | Strict IPv4 prefix normalization; invalid syntax is not repaired. |
| remote-ip | `Remote IP / Prefix` | Same strict normalization as `ip`. |
| allowaccess | `Management Access` | Explicit list preserved in source order. |
| type | `Interface Type` | Explicit source value is retained. If `type` is omitted, the source model leaves it unset. The transformer may resolve `vlan` only when the interface has both an explicit parent interface and VLAN ID. It must not globally invent `physical` or `vlan` for otherwise ambiguous interfaces. |
| role | `Role` | `undefined` becomes blank/None in normalized IR. |
| alias | `Alias` | Direct. |
| description | `Description` | Direct. |
| vlanid | `VLAN ID`; also compatibility IR `tag` | Numeric value retained. |
| interface | `Parent / Underlay Interface` | Direct parent reference. |
| status | `Enabled` | Literal `down` becomes disabled; other supported source values follow current compatibility behavior. |
| mode | `Addressing Mode`; may also set `DHCP Client` / `PPPoE Mode` | `dhcp` => DHCP client; `pppoe` => PPPoE mode. |
| username | `PPPoE Username` | Direct. |
| every explicitly configured top-level `set` key | `Interface Source Settings` | Sanitized copy retained even when the same value is also normalized. |
| unmodeled nested `config ...` blocks | `nested_configs` → `nested_source_configs` → `Interface Nested Configuration` | Recursively preserved as extraction-only source hierarchy attached to the owning interface. |

### Interface type rule

`FGInterface.type` must not use a synthetic `"physical"` default.

Expected source behavior:

```text
set type physical
    -> FGInterface.type = "physical"

set type tunnel
    -> FGInterface.type = "tunnel"

no set type
    -> FGInterface.type = None
```

The transformer may resolve:

```text
set interface "port3"
set vlanid 20
```

with no explicit `set type` to effective normalized interface type:

```text
vlan
```

This inference affects the normalized interface field only. It must not create a synthetic `type` entry in `source_attributes` or `Interface Source Settings`.

### Top-level interface source preservation

All explicitly configured top-level interface `set` values are retained in sanitized:

```text
FGInterface.source_attributes
    -> IRInterface.source_attributes
    -> Interface Source Settings
```

`nested_configs` must be excluded from `source_attributes`; otherwise recursive Pydantic/source-tree data would be duplicated and serialized into a flat settings map.

### Nested interface configuration

FortiOS permits recursive configuration inside each interface. Examples include:

```text
config client-options
config dhcp-snooping-server-list
config egress-queues
config ipv6
config l2tp-client-settings
config secondaryip
config tagging
config vrrp
config wifi-mac-list
config wifi-networks
```

The extraction implementation must preserve every unmodeled nested block using the existing recursive source tree:

```text
FGSourceNode
    node_type
    name
    commands[]
    children[]
```

The parent interface owns the top-level nodes:

```text
FGInterface.nested_configs[]
```

and the transformer propagates them into extraction-only IR compatibility nodes:

```text
IRInterface.nested_source_configs[]
```

The recursive representation must preserve:

```text
parent interface
config/edit hierarchy
node name / edit identity
set/unset/append operation
setting key
ordered values
source ordering
sanitized secret handling
empty config/edit nodes where practical
```

Do not write one parser for every FortiOS nested interface subsection. Unknown future nested blocks under `config system interface` must be retained automatically.

### Dedicated `secondaryip` exception

`config secondaryip` already has dedicated typed extraction:

```text
FGInterfaceSecondaryIP
    -> IRInterfaceSecondaryIP
    -> Interface Secondary IPs
```

Therefore:

```text
secondaryip
```

must not also be added to `FGInterface.nested_configs`.

Other fields inside a secondary-IP edit that do not have dedicated typed fields remain in that child object's sanitized `extra_settings` / `source_attributes`.

### Secret handling

Nested source nodes must use the same source-command sanitization path as all other FortiGate extraction.

For example:

```text
config l2tp-client-settings
    set user "example"
    set password ENC ...
end
```

may retain the non-secret username but the password value must be represented only as redacted source evidence. Plaintext, encrypted credential material, private keys, PSKs, API tokens, communities, or equivalent secrets must not be copied into IR or Excel.

### Audit behavior

An interface containing unmodeled nested source configuration is not a parse failure. It is a partially normalized interface whose source semantics are preserved for review.

Emit one manual-review audit entry per affected interface, listing its top-level nested blocks, for example:

```text
Interface 'port1' contains nested FortiGate configuration preserved
as extraction-only source data: ipv6, vrrp, tagging.
Review these settings before target migration.
```

Do not emit one audit entry for every recursive child node.

### Coverage behavior

For the parent:

```text
system interface
```

mark `PARTIALLY_NORMALIZED` if either:

```text
one or more interface IP parse errors exist
OR
one or more interfaces contain nested_source_configs
```

For a nested path such as:

```text
system interface ipv6
system interface vrrp
system interface tagging
```

mark:

```text
EXTRACT_ONLY
```

with parser handler:

```text
FortiGateParser.parse_source_node
```

The coverage note should state that the nested source hierarchy is retained under the owning interface and is not yet portable target semantics.

### Excel representation

`Interface Nested Configuration` should contain:

```text
Interface
Config Path
Node Type
Object / Edit
Operation
Setting
Value
Extraction Status
Manual Review
```

Example:

| Interface | Config Path | Node Type | Object / Edit | Operation | Setting | Value | Extraction Status | Manual Review |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| port1 | ipv6 | config | | set | ip6-address | 2001:db8:1::1/64 | EXTRACT_ONLY | Yes |
| port1 | ipv6 / ip6-prefix-list | edit | 2001:db8:1::/64 | set | autonomous-flag | enable | EXTRACT_ONLY | Yes |
| port1 | vrrp | edit | 1 | set | priority | 150 | EXTRACT_ONLY | Yes |
| port1 | vrrp / 1 / proxy-arp | edit | 1 | set | ip | 10.0.0.10 | EXTRACT_ONLY | Yes |

This sheet is source inventory only. Target generators must not consume it.

### Definition of complete handling for this phase

Nested interface preservation is complete when:

1. parent-interface ownership is retained;
2. arbitrary recursion is retained;
3. source ordering is retained;
4. `set`, `unset`, and `append` are retained;
5. secret values remain sanitized;
6. `secondaryip` remains on its existing typed path;
7. nested nodes reach `IRInterface.nested_source_configs`;
8. affected parent interfaces require manual review;
9. nested section coverage reports `EXTRACT_ONLY`, not `UNSUPPORTED`;
10. Excel displays the hierarchy in `Interface Nested Configuration`;
11. target generators ignore the source-only structure; and
12. all existing interface and secondary-IP regression tests continue passing.

---

## 3. Current phase limitation

This change does not claim that nested FortiGate interface features are portable.

In this phase:

```text
IPv6 interface hierarchy     -> EXTRACT_ONLY
VRRP / VRRP6                 -> EXTRACT_ONLY
L2TP client settings         -> EXTRACT_ONLY
DHCP client options          -> EXTRACT_ONLY
interface object tagging     -> EXTRACT_ONLY
Wi-Fi nested configuration   -> EXTRACT_ONLY
unknown future nested blocks -> EXTRACT_ONLY
```

Future tasks may promote individual families such as IPv6 and VRRP into dedicated typed/partially normalized models. The recursive source hierarchy remains the lossless fallback and must not be removed when that happens.
