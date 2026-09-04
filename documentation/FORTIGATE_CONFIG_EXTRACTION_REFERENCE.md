# FortiGate Configuration Extraction Handling Reference

## Semantic support matrix

Coverage reports extraction status and semantic support separately. A present
source block is not treated as fully supported merely because it was parsed.

| Source area | Semantic level | Truthful handling |
| --- | --- | --- |
| Local-user status, password presence, and `passwd-time` | `TYPED_EXTRACT_ONLY` | Typed inventory; actual password is secret and never exported. |
| RADIUS/TACACS+ server fields | `TYPED_EXTRACT_ONLY` | Typed source inventory; obscure fields remain sanitized Additional Settings. |
| IPS sensor action and nested fields | `TYPED_EXTRACT_ONLY` | Typed source inventory; signature behavior remains source-only. |
| Webfilter and other unmodeled profile features | `STRUCTURED_EXTRACT_ONLY` | Recursive source tree and settings remain visible for review. |
| Profile-group references | `TYPED_EXTRACT_ONLY` | Typed group inventory with policy reference validation. |

## Firewall objects and groups

Typed extraction covers `firewall address`, nested `firewall address list` and
address tagging, `firewall address6`, IPv4/IPv6 multicast addresses and their
tagging, `firewall addrgrp`, `firewall addrgrp6`, `firewall wildcard-fqdn
custom`, `firewall service category`, `firewall service custom`, and `firewall
service group`. Unknown settings remain sanitized in `extra_settings` and the
Excel Additional Settings columns.

| Address type | Handling |
| --- | --- |
| `ipmask`, `iprange`, `fqdn` | Normalized when explicit values are valid. |
| `geography` | Normalized only with an explicit country. |
| `wildcard` | Normalized as a wildcard mask. |
| `mac` | Normalized only when valid. |
| `dynamic` + `ems-tag` | Normalized to generic dynamic address-group semantics. |
| other `dynamic` | Source-preserved; manual review. |
| `interface-subnet`, `route-tag` | Source-preserved; manual review. |
| missing value | Source-preserved with blank value; never inferred. |

All address and group rows retain exact source-section and address-family
provenance. IPv6 `exclude-member` values remain distinct ordered references.
Nested address list and tagging data survives parser to IR to Excel.

FortiGate `interface-subnet` addresses preserve the exact `interface` reference
in `IRAddress.source_interface`. When the same-context primary static interface
IP is usable, its network is retained in `resolved_interface_subnet` as an
extraction-time snapshot and `interface_reference_resolved` is true. Missing,
dynamic, unaddressed, or invalid interfaces remain source-only with manual
review; secondary IPs are not inferred into this snapshot.

FortiGate dynamic addresses preserve `fsso-group`, `hw-model`, and `hw-vendor`
as typed source semantics in `IRAddress.source_fsso_group`,
`IRAddress.source_hw_model`, and `IRAddress.source_hw_vendor`. The values are
also retained in `source_attributes` for audit. `fsso-group` is an identity
association; hardware fields are dynamic device-attribute criteria. None is
automatically translated to a target address primitive. The documented limits
are 511 characters for `fsso-group` and 35 characters each for `hw-model` and
`hw-vendor`; invalid values are preserved and require manual review.

FortiGate address `cache-ttl` is preserved as `IRAddress.source_cache_ttl` and
in `source_attributes` for extraction and audit only. The documented range is
0-86400 seconds; `None` means it was not explicitly configured, while `0`
means it was explicitly configured as zero. Out-of-range values are retained
and require manual review.

Dynamic ClearPass addresses preserve `clearpass-spt` in
`IRAddress.source_clearpass_spt`; valid values are `unknown`, `healthy`,
`quarantine`, `checkup`, `transient`, and `infected`, with `type dynamic` and
`sub-type clearpass-spt` as the expected source context. `epg-name` is
preserved in `IRAddress.source_epg_name` for IPv4 and IPv6 addresses; names up
to 255 characters are valid. `fabric-object` is preserved in
`IRAddress.source_fabric_object_setting`; `enable` and `disable` are the
documented values, and unknown values remain available for manual review.
These fields are extraction metadata only and are not generated for targets
automatically.

FortiGate `node-ip-only` is preserved as `IRAddress.source_node_ip_only` for
Kubernetes node-address-only collection behavior. `None` means unset and
`False` means explicitly disabled; unknown values and non-dynamic usage require
manual review. FortiGate `obj-id` is preserved separately as
`IRAddress.source_obj_id` for the NSX object identifier and is never merged
with the FortiGate address UUID. Values longer than 255 characters require
manual review without truncation.

FortiGate dynamic address metadata is preserved independently in
`source_organization` (maximum 35), `source_os` (maximum 35), and
`source_policy_group` (maximum 15). SDN criteria remain separate in
`source_sdn`, `source_sdn_addr_type` (`private`, `public`, or `all`), and
`source_sdn_tag` (maximum 15); an absent address type remains `None`.
`route-tag` remains an integer source criterion in `source_route_tag`, valid
from 1 through 4294967295. Context or range violations are retained and marked
for manual review, never converted into a broader address value.

SCTP custom-service ranges and exact source-port constraints are preserved in
IR. FortiGate round-trip generation reproduces `sctp-portrange`; unsupported
targets withhold the service rather than broadening it.

### Custom services and service groups

FortiOS custom services retain both configured and effective protocol. When
`set protocol` is omitted, configured protocol is blank while effective
protocol is the FortiOS default `tcp/udp/sctp`. An explicit
`set protocol TCP/UDP/SCTP` remains explicit. For `protocol IP`, an omitted or
zero `protocol-number` normalizes to canonical any-IP semantics based solely
on the fields, not a service name such as `ALL`; explicit zero remains visible
as zero.

Destination/source constraints retain FortiOS `destination:source` syntax and
raw ordering. Exact destination port `0` requires review and is never rewritten
to an any-port range. `0-65535` is a range, not exact port zero; proxy services
using that range remain partial because proxy semantics require review.

Typed source metadata includes UUID, category, color, and `fabric-object`.
Other explicit service settings are preserved under `source_attributes`.
Traffic-affecting settings without canonical semantics—including helpers,
FQDN/IP-range matching, session TTL/timers, and application constraints—are
listed in `source_unmodeled_semantic_settings` and force partial/manual-review
status without dropping the safe canonical protocol/port subset. Modeled
`unset` provenance, such as unset ICMP type/code, does not itself create an
unknown semantic.

Service groups retain exact ordered membership and expose `unsafe_members` for
partial services, unsafe nested groups, and unresolved references. Review state
propagates through nested groups. Target generators withhold unsafe services
and groups rather than generating a broader object or a group referencing a
withheld member. Coverage count equality measures object flow only; service or
group manual-review state keeps the section `PARTIALLY_NORMALIZED`.

## Static routing

`router static` and `router static6` share one typed source collection and are
distinguished by address family. `IRRoute.destination` contains only a strict
portable network prefix. `IRRoute.source_destination_reference` contains a
FortiGate `dstaddr` firewall address/address-group reference.

```text
set dstaddr "REMOTE_NET"
    -> destination = null
    -> source_destination_reference = "REMOTE_NET"
    -> manual review
```

It must never become `0.0.0.0/0` because `set dst` is absent. A genuinely
omitted destination with no `dstaddr` retains the FortiGate default route for
its family. Unsafe routes are withheld from all target route generators.

## SD-WAN source inventory

FortiGate SD-WAN remains typed `EXTRACT_ONLY` source inventory with mandatory
manual review. Members, health checks, nested health-check SLAs, service rules,
multi-health-check cardinality, nested service SLAs, duplication rules, and
neighbors retain their source hierarchy without deriving target selection or
failover behavior. Any future unmodeled `system sdwan` child remains visible in
`FortiGate Source Configuration`.

## VPN extraction

| FortiGate config path | Status | Typed/IR path | Notes |
| --- | --- | --- | --- |
| `vpn ipsec phase1-interface` | `PARTIALLY_NORMALIZED` | `FGPhase1Interface -> IRVPNTunnel` | Portable tunnel fields and exact FortiGate proposal/source fields are retained. PSK content is discarded before model construction; only `has_psk` is retained. |
| `vpn ipsec phase2-interface` | `PARTIALLY_NORMALIZED` | `FGPhase2Interface -> IRVPNPhase2` | `phase1name` is the only Phase 1 relationship. Phase 1 and Phase 2 names remain independent. Every row requires migration review. |
| `vpn ssl web host-check-software` | `EXTRACT_ONLY` | `FGSSLVPNHostCheckSoftware -> IRSSLVPNHostCheck` | Host-check definitions are top-level inventory and are extracted even when unused or SSL VPN is disabled. |
| `vpn ssl web host-check-software check-item-list` | `EXTRACT_ONLY` | `FGSSLVPNHostCheckItem -> IRSSLVPNHostCheckItem` | Ordered nested actions, hashes, targets, types, versions, and sanitized unknown settings are retained. |
| `vpn ssl web portal` | `EXTRACT_ONLY` | `FGSSLVPNPortal -> IRSSLVPNPortal` | Portals retain host-check policy names as references; definitions are not embedded into portals. |
| `vpn ssl settings` | `EXTRACT_ONLY` | `FGSSLVPNSettings -> IRSSLVPNSettings` | Disabled state, explicit empty server-certificate state, selected security settings, and sanitized unknown fields remain visible. |
| `vpn ssl settings authentication-rule` | `EXTRACT_ONLY` | `FGSSLVPNAuthenticationRule -> IRSSLVPNAuthenticationRule` | Access-control source fields remain separate extraction inventory. |

Missing host-check, portal, user-group, address, or pool references remain
unchanged and produce manual-review audit entries. No default object or target
VPN policy is substituted. Unknown non-secret VPN fields remain in
`source_attributes`; target crypto profiles are never inferred from FortiGate
proposal strings. Encrypted or plaintext PSK values never enter source models,
IR, reports, coverage, warnings, or source-detail output.

## Routing dependencies

Dynamic protocols remain `EXTRACT_ONLY`. Route maps, IPv4/IPv6 prefix and
access lists, AS-path/community lists, and BFD/BFD6 are shown separately as
routing dependencies. Reports distinguish a source block that is present but
empty from one that contains configuration commands.

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
| `firewall ippool6` | `NORMALIZED` | `FGIPPool6 -> IRIPPool -> IP Pools` | Address family remains explicit. |
| `firewall vip` | `NORMALIZED` for basic static IPv4 VIPs; `PARTIALLY_NORMALIZED` for advanced types, restrictions, cross-family, or load-balancing semantics | `FGVIP -> IRVirtualIP -> Virtual IPs` | Only straightforward static DNAT/port forwarding is automatically eligible. |
| `firewall vip realservers` | `NORMALIZED` for simple IP backends; `PARTIALLY_NORMALIZED` for address references, health/monitor/client restrictions, or other advanced fields | `FGVIPRealServer -> IRVirtualIPRealServer -> VIP Real Servers` | Address objects remain references, never fake IPs. |
| `firewall vip6` / `firewall vip6 realservers` | `NORMALIZED` | `FGVIP6 -> IRVirtualIP -> Virtual IPs` | IPv6 and cross-family flags remain explicit. |
| `firewall vipgrp` | `EXTRACT_ONLY` source inventory | `FGVIPGroup -> IRVirtualIPGroup -> VIP Groups` | Existing safe IPv4 correlation may expand members. |
| `firewall vipgrp6` | `NORMALIZED` | `FGVIPGroup6 -> IRVirtualIPGroup -> VIP Groups` | No interface is synthesized. |

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
| password | `PPPoE Password Configured`; `PPPoE Password Format` | Only safe presence and format metadata are retained. The credential is always redacted. |
| speed | `Speed`; `Duplex` | Recognized combined FortiOS tokens are decomposed while the exact token remains in source attributes. Unknown hardware-dependent values require manual review. |
| mediatype | `Media Type` | Exact hardware-dependent FortiOS token retained as structured source inventory and in source attributes; no portable optic semantics are inferred. |
| monitor-bandwidth | `Bandwidth Monitoring` | Valid `enable`/`disable` values become low-risk structured monitoring metadata while the exact source value remains in source attributes. |
| device-identification | `Device Identification` | Recognized `enable`/`disable` values are retained as structured source inventory. The exact value remains in source attributes. |
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

### Interface speed

`set speed` is parsed as a typed FortiGate interface field. Recognized tokens
are decomposed into `IRInterface.source_speed` and `source_duplex`, while the
exact FortiGate token remains in `source_attributes` for audit fidelity.

- `100full` -> speed `100`, duplex `full`
- `1000auto` -> speed `1000`, duplex `auto`
- `5000auto` -> speed `5000`, duplex `auto`
- `10000full` -> speed `10000`, duplex `full`

Unrecognized hardware-dependent values are preserved without coercion and
require manual review.

### Interface media type

FortiGate `system interface -> mediatype` is retained as the typed
`IRInterface.source_media_type` source-interface property and in
`source_attributes["mediatype"]` for source fidelity. For example,
`set mediatype sr-lr` becomes `source_media_type = "sr-lr"`.

Available media-type values are hardware-dependent, so the configured token is
preserved without inferring optic type, wavelength, reach, connector type, or
equivalent target-vendor media configuration.

### Interface bandwidth monitoring

FortiGate `monitor-bandwidth` is represented as
`IRInterface.source_monitor_bandwidth`: `enable` becomes `True`, `disable`
becomes `False`, and absence remains `None`. The exact FortiGate value remains
in `source_attributes`.

This setting is source-oriented monitoring/observability metadata, not portable
packet-forwarding semantics. A valid value does not require manual review by
itself; unknown values remain preserved and require review.

### DNS server override

FortiGate `system interface -> dns-server-override` is represented as
`IRInterface.source_dns_server_override`:

- `enable` -> `True`
- `disable` -> `False`

The exact configured FortiGate value remains in
`source_attributes["dns_server_override"]`. This is source-side interface DNS
behavior and must not be assumed to have a direct target-vendor equivalent.

### IKE SAML server

FortiGate `ike-saml-server` is retained as the structured source reference
`IRInterface.source_ike_saml_server`. Resolution against the extracted SAML
server inventory is tracked in `source_ike_saml_server_resolved`, but target
platform compatibility still requires manual review.

### Source IP checking

FortiGate `src-check` is represented as `IRInterface.source_src_check`:
`enable` maps to `True` and `disable` maps to `False`. The exact source value
remains in `source_attributes`; invalid values map to `None` and require
review. This affects source-IP validation/security behavior and remains
migration-review relevant.

### Dedicated interface purpose

FortiGate `system interface -> dedicated-to` is retained in
`IRInterface.source_dedicated_to`. The value `management` identifies an
interface dedicated to management use. It is structured source intent but still
requires manual migration review because equivalent target-platform behavior
is vendor-specific; unexpected values remain preserved and reviewed.

### Device identification

FortiGate `system interface` device identification is stored in
`IRInterface.source_device_identification` for structured source inventory.
Supported values are `enable` and `disable`; the exact FortiGate setting also
remains in `source_attributes`. Unknown values are preserved without coercion
and require manual review. This field does not imply a portable equivalent to
another vendor's device-identification technology.

### Top-level interface source preservation

All explicitly configured top-level interface `set` values are retained in sanitized:

```text
FGInterface.source_attributes
    -> IRInterface.source_attributes
    -> Interface Source Settings
```

`nested_configs` must be excluded from `source_attributes`; otherwise recursive Pydantic/source-tree data would be duplicated and serialized into a flat settings map.

### PPPoE password handling

PPPoE passwords are never serialized in plaintext or FortiGate encrypted form.
The parser records only `has_pppoe_password` and `pppoe_password_format`, where
the format is `encrypted`, `plaintext`, `unknown`, or `None`. Current parsing
uses `True` when a password command is present and `False` when no password
evidence is present. Older IR is migrated with `None` because historical data
cannot prove absence. The actual credential must never appear in IR, Excel,
logs, exceptions, source inventory, or target configuration; it must be
supplied securely to the target device.

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

An interface containing unmodeled nested source configuration is not a parse failure. It is a partially normalized interface whose source semantics are preserved for review. Phase 7 also types the primary `config ipv6` settings (`ip6-address`, `ip6-allowaccess`, `ip6-mode`, `ip6-send-adv`, `ip6-manage-flag`, and `ip6-other-flag`). A `config ipv6` node containing only those settings remains source-preserved but does not by itself require review; nested IPv6 children or untyped IPv6 commands still do.

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
one or more interfaces contain nested/source-specific semantics requiring review
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

## Management-plane inventory

`system admin` is retained as typed, `EXTRACT_ONLY` source inventory. This
includes access-profile and VDOM assignments, every explicitly configured
IPv4/IPv6 trusted-host slot, two-factor/token references, guest user groups,
and relevant remote/peer/SSH metadata. Multi-value guest groups remain ordered
lists. Passwords, token seeds, private keys, and other credential material are
never retained.

`system accprofile` retains its parent profile and the nested FortiGate-only
permission groups (`fwgrp-permission`, `loggrp-permission`,
`netgrp-permission`, `sysgrp-permission`, and `utmgrp-permission`). They are
shown in the `Admin Profile Permissions` worksheet and require manual review;
they are not target administrator roles.

`system ha` and logging configuration remain structured/generic source
inventory with `EXTRACT_ONLY` status. The API client extracts `system admin`
and `system accprofile`; HA and logging API parity remains endpoint/version
dependent and is not claimed unless returned source inventory is available.

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

The primary IPv6 interface settings are now typed when safely understood;
remaining complex families such as VRRP/VRRP6 may be promoted into dedicated
typed or partially normalized models in future phases. The recursive source
hierarchy remains the lossless fallback and must not be removed when that
happens.

## Security and Identity dependency fidelity

The following FortiGate sections have typed `EXTRACT_ONLY` inventory:

- `config user ldap`, `user radius`, `user tacacs+`, `user saml`, `user fsso`, `user adgrp`, `user fortitoken`,
  `user local`, and `user group`, including nested group matches;

`config user radius` also exposes typed accounting-server children. Their
server, status, port, source/interface settings, and secret-presence flag are
exported to `RADIUS Accounting Servers`; interim accounting intervals remain
on the parent RADIUS object. Other FortiOS RADIUS settings remain in sanitized
additional source attributes.

`config user tacacs+` is also typed through the parser, IR, and dedicated
`TACACS+ Servers` worksheet. Primary, secondary, and tertiary server fields,
authentication, authorization, source/interface settings, and `status-ttl`
are retained; all TACACS+ keys are reduced to secret-presence flags.

LDAP behavior-affecting bind/search, group-identification, source-port, TLS,
and client-certificate fields are typed and exported. SAML claim mappings,
certificate references, relay-state, reauthentication, and digest settings
are typed and exported. Optional fields remain unset when the source does not
configure them; FortiOS defaults are not presented as explicit source values.
- `config user setting` and `config user quarantine` singleton settings;
- `config authentication scheme` and `config authentication rule`; and
- `config system admin` and `config system accprofile`.

Dependencies resolve by exact, case-sensitive FortiGate source names. User
group members are classified by compatible source object type, including
RADIUS and TACACS+ providers. FSSO AD groups resolve FSSO providers; LDAP and
SAML servers resolve certificate names; authentication
schemes resolve user databases; authentication rules resolve scheme names;
administrators resolve FortiTokens and custom or known built-in access
profiles. `user setting` certificate references and `user quarantine`
address-group references are also validated. An LDAP match `server-name` is a
local FortiGate dependency, while its external directory `group-name` is not.

Resolution only proves that the source object exists. It does not prove
portable target semantics. Firewall policies containing source `groups` or
`users` are always `PARTIALLY_NORMALIZED`, require manual review, and are
withheld by targets that do not implement equivalent identity enforcement.
Missing identity dependencies are additionally preserved and audited. The same
reference-integrity result propagates to IPsec authentication groups and SSL
VPN authentication-rule groups.

FortiGate antivirus, IPS, web-filter, application-control, SSL/SSH, protocol
options, and source profile-group names are validated against the actual source
profile inventory. Auto-correlated IR Security Profile Groups are inventory
objects, not translated target profiles. Policies that enforce source UTM
semantics require target-specific review even when every source profile name
resolves, and target generators do not create profiles based on name equality.

LDAP/FSSO/local-user/administrator passwords, FortiToken seeds and activation
codes, VPN PSKs, certificate private keys, and equivalent credential material
are discarded or redacted before IR and Excel serialization.

`webfilter search-engine`, `webfilter ips-urlfilter-setting`, and
`webfilter ips-urlfilter-setting6` are retained as recursive structured
security-profile source inventory with `EXTRACT_ONLY` status, including empty
sections. No portable search-engine or URL-filter semantics are inferred.

## FortiOS execution context and interpretation-changing modes

FortiGate parsing uses `ExtractionResult` as the authoritative path. The public
`parse()` result is `extract().canonical_ir`; scanning, inventory, coverage and
unsupported detection therefore cannot be bypassed by ordinary parser calls.

`config vdom` is a structural wrapper. Nested paths use their logical section
name plus a separate `source_context` VDOM. Migration-relevant objects retain
this context, so duplicate names in different VDOMs remain distinct source
identities.
Interface, zone, address, service, schedule, IP-pool, VIP, policy, NAT and VPN
dependency resolution uses the VDOM plus object name. Multi-VDOM canonical data
is retained for audit, but target generation is blocked until source VDOMs have
an explicit target-scope mapping.

`config system settings` produces an execution-context record containing
`central-nat`, `ngfw-mode`, and `opmode`. With central NAT enabled, firewall
policy NAT is not emitted as authoritative NAT. `firewall central-snat-map` is
typed, ordered source inventory and remains `PARTIALLY_NORMALIZED` until an
exact target mapping is available. Policy-based NGFW mode likewise blocks
completeness; `firewall security-policy` remains a distinct source-only family.

The complete Internet Service source/destination and IPv4/IPv6 selector
families are retained. Custom Internet Service definitions and groups retain
nested structure. Such policies require review and cannot be generated by
combining Internet Service matching with ordinary address/service conditions.

Policy routing, local-in, explicit proxy, shaping, DHCPv6, policy-mode/manual-key
IPsec, multicast, TTL, IP translation, load-balancer monitor, SSL server,
traffic-class, and wildcard-FQDN-group sections use distinct source-only
collections. Schedule groups retain ordered membership and unresolved members.
The presence of any nonportable source-only traffic rule makes migration
incomplete and generation unsafe; successful inventory retention is not treated
as successful semantic migration.

`router policy` and `router policy6` use dedicated typed extraction for their
input interfaces, direct source/destination selectors, address-object
selectors, action/status, protocol and source/destination ports, gateway,
output interface, Internet Service custom/ID selectors, comments, negate
flags, and TOS values. Multi-value fields preserve source order, while raw
commands, malformed numeric values, and unknown fields remain available for
audit. These sections remain `TYPED_EXTRACT_ONLY`, require manual review, and
continue to block target generation; this is not automatic PBR migration.
Nested interface IPv6 settings are retained recursively and in sanitized typed
source settings without fabricating addresses. Global session TTL `default` is
separate from per-port overrides.

Unknown traffic-affecting policy settings force `PARTIALLY_NORMALIZED` and
manual review. Only approved cosmetic metadata may remain without changing
policy safety.

SSL VPN settings, portal scalars, authentication rules, and portal child
structures are typed source extraction and remain `EXTRACT_ONLY`. Bookmark
passwords and arbitrary form-data values are reduced to configured markers.
## Security profile support tiers

FortiGate security-profile coverage reports an explicit support level for each
family. `firewall profile-group` is currently `TYPED_EXTRACT_ONLY`; the
remaining profile families listed below remain authoritative recursive
`STRUCTURED_EXTRACT_ONLY` fallback until their semantics are modeled:

| Family group | Support level |
| --- | --- |
| firewall profile-group | TYPED_EXTRACT_ONLY |
| ssl-ssh, antivirus, webfilter, dnsfilter, application, dlp, file-filter, emailfilter, icap, voip, WAF, CASB, virtual-patch | STRUCTURED_EXTRACT_ONLY |
| Unrecognized profile sections | UNSUPPORTED |
