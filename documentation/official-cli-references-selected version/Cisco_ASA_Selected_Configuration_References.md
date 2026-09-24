# Cisco Secure Firewall ASA Selected Configuration References

> **Purpose:** Source-configuration extraction reference for the firewall migration/extraction project.
>
> **Baseline:** The 20 selected FortiGate configuration areas used by this project.
>
> **Source rule:** This document uses Cisco's official **Cisco Secure Firewall ASA Series Command Reference** PDF books as the primary source. It keeps ASA configuration in its native source architecture rather than manufacturing FortiGate-shaped ASA objects.
>
> **Extraction date:** 2026-09-23.
>
> **Security rule:** Never export, log, persist, or report actual passwords, password hashes, pre-shared keys, private keys, AAA shared secrets, certificate private-key material, or equivalent authentication secrets. Safe presence metadata such as `Password Configured = Yes` and `Pre-Shared Key Configured = Yes` is allowed.

---

# 1. Official Cisco PDF Sources

Cisco publishes the ASA CLI command reference as four official PDF books.

1. **A-H Commands**  
   https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/A-H/asa-command-ref-A-H.pdf

2. **I-R Commands**  
   https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/I-R/asa-command-ref-I-R.pdf

3. **S Commands**  
   https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/S/asa-command-ref-S.pdf

4. **T-Z Commands and IOS Commands for ASASM**  
   https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/T-Z/asa-command-ref-T-Z.pdf

Official command-reference index:

https://www.cisco.com/c/en/us/support/security/adaptive-security-appliance-asa-software/products-command-reference-list.html

Useful official chapter PDFs referenced below include:

- A-H `aa-ac`: https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/A-H/asa-command-ref-A-H/aa-ac-commands.pdf
- A-H `ca-cld`: https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/A-H/asa-command-ref-A-H/ca-cld-commands.pdf
- A-H `crypto a-ir`: https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/A-H/asa-command-ref-A-H/crypto-a-to-crypto-ir-commands.pdf
- A-H `crypto is-cz`: https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/A-H/asa-command-ref-A-H/crypto-is-cz-commands.pdf
- A-H `dh-dm`: https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/A-H/asa-command-ref-A-H/m_dh-dm.pdf
- A-H `g-h`: https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/A-H/asa-command-ref-A-H/m_g-h.pdf
- I-R `int-ipu`: https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/I-R/asa-command-ref-I-R/int-ipu-commands.pdf
- I-R `n`: https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/I-R/asa-command-ref-I-R/n-commands.pdf
- I-R `o`: https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/I-R/asa-command-ref-I-R/o-commands.pdf
- I-R `pa-pn`: https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/I-R/asa-command-ref-I-R/pa-pn-commands.pdf
- I-R `po-pq`: https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/I-R/asa-command-ref-I-R/po-pq-commands.pdf
- I-R `pr-pz`: https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/I-R/asa-command-ref-I-R/pr-pz-commands.pdf
- I-R `ret-rz`: https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/I-R/asa-command-ref-I-R/ret-rz-commands.pdf

## 1.1 Source-model principles

Keep these states distinct:

```text
explicit ASA source
resolved relationship
runtime / operational state
derived migration view
effective/default behavior
unknown / unsupported source
```

Rules:

- A missing command means **not explicitly configured** in the extracted source.
- Do not populate source fields using documented ASA defaults unless the actual extracted source contains the value.
- If `show running-config all` is used, retain enough provenance to distinguish explicit configuration from default-expanded output.
- Preserve command ordering when ordering changes behavior, especially ACLs, NAT, route maps, crypto maps, policy maps, and other ordered rules.
- Preserve `inactive`, disabled, and inherited state when the source exposes it.
- Preserve references first. Resolve relationships later.
- Preserve safe unsupported subcommands as source-only/raw configuration.
- Secret-bearing unknown fields must be redacted or dropped rather than copied into `raw_extra`.

## 1.2 ASA concepts that must not be synthesized

Do **not** create these as explicit ASA source objects merely to resemble FortiGate:

```text
IPPool
VIP
VIPGroup
SecurityProfileGroup
SDWAN
Phase1
Phase2
```

Migration/reporting views for those concepts can be derived later from ASA-native objects and relationships.

---

# 2. Mapping Index

| # | FortiGate selected config | Cisco ASA source configuration to extract | Mapping |
|---|---|---|---|
| 1 | `config firewall address` | `object network` | Direct |
| 2 | `config firewall addrgrp` | `object-group network` | Direct |
| 3 | `config firewall ippool` | network objects/groups + object NAT / twice NAT source translation | Different model |
| 4 | `config firewall policy` | `access-list ... extended` + `access-group` | Direct policy behavior, split rule/binding model |
| 5 | `config firewall profile-group` | `class-map` + `policy-map` / `policy-map type inspect` + feature actions + `service-policy` | No single equivalent |
| 6 | `config firewall schedule group/onetime/recurring` | `time-range` + `absolute` + `periodic` | Mostly direct; no schedule-group object |
| 7 | `config firewall service category/custom/group` | `object service` + `object-group service` | Direct except category |
| 8 | `config firewall vip` | static object NAT and/or twice NAT destination/service translation | Different NAT model |
| 9 | `config firewall vipgrp` | NAT rules + network objects/groups | No direct VIP-group object |
| 10 | `config ips sensor` | MPF `ips` action and AIP SSM sensor reference | Closest equivalent; separate IPS architecture |
| 11 | `config router static` | `route` + `ipv6 route` | Direct |
| 12 | `config system accprofile` | `privilege` + `aaa authorization command` + assigned user privilege | Split authorization model |
| 13 | `config system admin` | `username` + management AAA / authorization configuration | Direct-ish / shared local-user database |
| 14 | `config system dhcp server` | `dhcpd ...` command family | Direct |
| 15 | `config system sdwan` | `policy-route`, route maps, path monitoring and/or SLA/track configuration | No direct ASA SD-WAN object |
| 16 | `config system zone` | `zone` + interface `zone-member` | Direct |
| 17 | `config user group` | Identity Firewall `object-group user`; VPN `group-policy` where applicable | Split by use case |
| 18 | `config user local` | `username` + authentication relationships | Direct-ish / shared local-user database |
| 19 | `config vpn ipsec phase1/phase2` | IKE policy + IPsec proposal/transform + crypto map or VTI + tunnel-group | Split architecture |
| 20 | `config vpn ssl ...` | `webvpn` + remote-access `tunnel-group` + `group-policy` + address pool + user/AAA settings | Different architecture |

---

# 3. Selected ASA Configuration References

## 3.1 Address Objects

### Mapping

```text
FortiGate:
config firewall address

ASA:
object network <name>
```

### Source hierarchy to recognize

```text
object network <name>
    description ...
    host <ip>
    subnet <network> <mask>
    range <first-ip> <last-ip>
    fqdn ...
    nat ...                 # object-owned NAT, if configured
```

The exact address-definition subcommand depends on the configured representation.

### Extraction rules

- Preserve the object name.
- Preserve exactly which address representation is configured: host, subnet, range, or FQDN.
- A network object contains one address definition. Reconfiguration of another address form replaces the prior address definition rather than creating multiple independent addresses in the same object.
- Do not normalize range/FQDN/subnet/host into a single generic subnet source field.
- Keep an object's `nat` statement as NAT source state related to the object; do not convert it into an address-object field.
- Network objects and object groups participate in a shared naming/reference environment. Preserve references by name.
- Preserve descriptions and safe unrecognized object subcommands.

### Relationship rules

A network object can be referenced by:

```text
object-group network
access-list
nat
crypto / VPN ACLs
route-map match ACLs indirectly
other feature-specific commands
```

### Official PDF reference

- I-R Commands, `o` chapter, **object network**, approximately PDF pages 11-14.

---

## 3.2 Address Groups

### Mapping

```text
FortiGate:
config firewall addrgrp

ASA:
object-group network <name>
```

### Source hierarchy to recognize

```text
object-group network <name>
    description ...
    network-object ...
    network-object object <network-object-name>
    group-object <nested-group-name>
```

### Extraction rules

- Preserve direct members and nested group references separately.
- Members are references or inline network specifications; do not copy referenced child objects into the group source object.
- Nested object groups are supported and must remain references.
- An ASA network object group can contain IPv4 and IPv6 members, but a **mixed IPv4/IPv6 group cannot be used for NAT**.
- Preserve membership order if present in the source even where runtime matching is set-like.
- Do not materialize a group into a flattened list of IP ranges as explicit source state.
- A resolved/flattened member view is derived state only.

### Official PDF reference

- I-R Commands, `o` chapter, **object-group**, approximately PDF pages 2-8.

---

## 3.3 Source NAT / FortiGate IP Pool Equivalent

### Mapping

```text
FortiGate:
config firewall ippool

ASA:
object network / object-group network
+ object NAT and/or twice NAT
```

### Important model rule

ASA does not require a FortiGate-style standalone IP-pool source object.

Keep these ASA source areas separate:

```text
NetworkObject / NetworkObjectGroup
ObjectNAT
TwiceNATRule
```

A migration-oriented source NAT pool view may be derived from translated network objects and NAT rules, but must remain traceable to its source rule/object.

### A. Object NAT

Recognize NAT nested under a network object:

```text
object network <real-object>
    ...address definition...
    nat (<real-if>,<mapped-if>) dynamic ...
```

and static forms:

```text
object network <real-object>
    nat (<real-if>,<mapped-if>) static ...
```

Object NAT supports source translation tied to the owning network object. Static object NAT can also perform inline TCP/UDP/SCTP port translation.

### B. Twice NAT / manual NAT

Recognize global NAT rules containing explicit source and optional destination/service terms:

```text
nat (<real-if>,<mapped-if>) ... source static ...
nat (<real-if>,<mapped-if>) ... source dynamic ...
```

Optional branches can include:

```text
destination static ...
service ...
pat-pool ...
interface / interface ipv6
net-to-net
dns
unidirectional
no-proxy-arp
route-lookup
inactive
description
```

### NAT ordering rules

Preserve which NAT section the rule belongs to:

```text
Section 1: twice NAT / manual NAT before object NAT
Section 2: network object NAT
Section 3: twice NAT configured after-auto
```

Rules:

- A global/twice NAT rule is added to Section 1 by default.
- `after-auto` places a global/twice NAT rule in Section 3.
- `line` can control position inside the applicable manual-NAT section.
- NAT rule order is source-significant. Do not sort rules alphabetically.
- Network object NAT is Section 2.
- A network object supports one NAT rule for that object. If the same address needs multiple object-NAT rules, ASA configuration uses separate objects.

### Address/reference rules

- Preserve real and mapped interface names.
- Preserve source real object/reference.
- Preserve mapped source object/reference or interface translation.
- Preserve destination real/mapped objects when configured.
- Preserve service translation objects/ports when configured.
- Network object groups used by NAT must not mix IPv4 and IPv6 members.
- Destination mapping inside twice NAT is static.
- Preserve interface PAT vs explicit translated-address/PAT-pool semantics.
- Do not detach a translated address from its NAT rule and store it as an explicit standalone ASA pool.

### Mapped-address constraints to preserve/validate

The Cisco reference documents restrictions around translated pools, including conflicts with interface addresses and existing VPN address pools. Validation should report such constraints; it must not mutate the source.

### Runtime rule

Changing NAT configuration does not turn the current translation table into source configuration. Existing xlate/runtime state must stay separate from explicit NAT source state.

### Official PDF reference

- I-R Commands, `n` chapter, **nat (global)** and **nat (object)**.
- I-R full PDF is the authoritative parent reference.

---

## 3.4 Access Control Policy

### Mapping

```text
FortiGate:
config firewall policy

ASA:
access-list <acl-name> ... extended ...
access-group <acl-name> ...
```

ASA separates a rule list from the interface/global binding. Do not combine them into one explicit ASA source object.

### A. Extended ACE source

Recognize ordered entries such as:

```text
access-list <name> [line <n>] extended permit ...
access-list <name> [line <n>] extended deny ...
access-list <name> [line <n>] remark ...
```

An extended ACE can explicitly contain, depending on traffic type:

```text
action: permit | deny
protocol or service/object-group
source user selector
security-group selector
source address/object/group
source port
Destination address/object/group
destination port
ICMP/ICMPv6 type/code
logging configuration
time-range reference
inactive state
```

### B. ACL binding

Recognize:

```text
access-group <acl-name> in interface <interface>
access-group <acl-name> out interface <interface>
access-group <acl-name> global
```

Preserve binding direction and interface/global scope independently from the ACL itself.

### Ordering and behavior rules

- ACE order is mandatory source state.
- Preserve explicit `line` numbers when present.
- Preserve `inactive`; inactive is different from absent.
- Preserve remarks as ACL structure, but do not treat a remark as a permit/deny rule.
- An `access-group` cannot reference an empty ACL or an ACL containing only remarks.
- If all functional permit/deny entries are removed from a bound ACL, ASA removes the associated access-group binding.
- For overlapping interface/global access rules, the interface-specific rule is processed before the global rule.
- A time-range reference remains a reference to a separate `time-range` object.
- Object/object-group references remain references.

### VPN interaction

Remote-access VPN traffic has special ACL behavior. Cisco documents that VPN traffic can bypass interface ACL checking by default, with behavior changing when `no sysopt connection permit-vpn`, `vpn-filter`, and `per-user-override` are used. Preserve these commands independently; do not infer a firewall rule rewrite.

### Official PDF reference

- A-H Commands, `aa-ac` chapter:
  - **access-group**, approximately PDF pages 75-78.
  - **access-list extended**, approximately PDF pages 88-96.
  - **access-list remark**, approximately PDF pages 97-98.

---

## 3.5 FortiGate Security Profile Group Equivalent / Modular Policy Framework

### Mapping

```text
FortiGate:
config firewall profile-group

ASA:
class-map
policy-map
policy-map type inspect
feature action commands
service-policy
```

### Important model rule

There is no single ASA object equivalent to a FortiGate `profile-group`.

Keep these source objects distinct:

```text
ClassMap
InspectionClassMap
PolicyMap
InspectionPolicyMap
PolicyClassAction
ServicePolicyBinding
```

### MPF relationship chain

```text
class-map
    -> matched traffic

policy-map
    -> class <class-map>
        -> feature action(s)

policy-map type inspect
    -> application-specific match/action logic

service-policy
    -> activates Layer3/4 policy-map globally or on an interface
```

### Source hierarchy to recognize

Layer 3/4 class maps:

```text
class-map <name>
    match ...
```

Application inspection class maps:

```text
class-map type inspect <application> [match-all|match-any] <name>
    match ...
```

Policy maps:

```text
policy-map <name>
    class <class-name>
        inspect ...
        set connection ...
        ips ...
        other feature actions...
```

Inspection policy maps:

```text
policy-map type inspect <application> <name>
    match ...
    class ...
    parameters
    application-specific action commands
```

Activation:

```text
service-policy <policy-map> global
service-policy <policy-map> interface <interface>
```

### MPF rules

- A Layer 3/4 class map identifies traffic; application-specific inspection matching belongs in `class-map type inspect` or an inspection policy map.
- Preserve default class maps when they are explicitly present in the extracted source; do not invent them from documentation defaults.
- `class-default` is a distinct built-in/default matching construct.
- Preserve class order inside a policy map.
- Preserve feature actions independently. Do not turn multiple actions into a synthetic security-profile bundle.
- `service-policy` can activate a Layer 3/4 policy map globally or on an interface.
- Interface service-policy behavior takes precedence over the global policy for the same feature area, while non-conflicting features can coexist.
- Only one global service policy can be active.
- Inspection policy maps are referenced by inspection actions; they are not directly applied as global/interface `service-policy` targets.
- An “effective security stack” may be a derived relationship view, but must remain traceable to class-map/policy-map/service-policy source.

### Official PDF reference

- A-H Commands, `ca-cld` chapter, **class-map**, **class-map type inspect**, and MPF relationship discussion, approximately PDF pages 73-83.
- S Commands, **service-policy (global)**.

---

## 3.6 Schedules / Time Ranges

### Mapping

```text
FortiGate:
config firewall schedule onetime
config firewall schedule recurring
config firewall schedule group

ASA:
time-range <name>
    absolute ...
    periodic ...
```

### Time-range root

```text
time-range <name>
```

Creating a time range only defines the schedule. The schedule has an effect when another configuration element references it.

### One-time / absolute form

```text
absolute [end <time> <date>] [start <time> <date>]
```

Rules:

- Preserve explicit start and end independently.
- A missing start/end must not be stored as an explicit value merely because Cisco documents resulting behavior.
- Date/time semantics are local to the ASA system clock.

### Recurring form

```text
periodic <days> <start-time> to [<days>] <end-time>
```

Supported day selectors include specific weekdays and aggregate selectors such as daily, weekdays, and weekend.

Rules:

- Multiple periodic entries may belong to one time-range.
- Preserve each periodic entry separately.
- If an absolute boundary and periodic entries coexist, preserve both source structures. Do not collapse them into precomputed effective intervals.
- The time range relies on the ASA system clock; Cisco recommends accurate time synchronization.

### Policy reference

A typical ACL reference is:

```text
access-list <name> ... time-range <time-range-name>
```

### Schedule-group rule

No FortiGate-style standalone ASA schedule-group source object is identified in this command model. Do not fabricate one.

### Official PDF reference

- T-Z Commands, **time-range**, approximately PDF pages 82-83.
- A-H Commands, `aa-ac`, **absolute**, approximately PDF pages 71-72.
- I-R Commands, `pa-pn`, **periodic**.

---

## 3.7 Service Objects and Service Groups

### Mapping

```text
FortiGate:
config firewall service custom
config firewall service group
config firewall service category

ASA:
object service <name>
object-group service <name>
```

### A. Service object

Recognize:

```text
object service <name>
    description ...
    service ...
```

The service definition can represent protocol-oriented services and TCP/UDP/SCTP port semantics. Preserve source and destination port roles separately.

### B. Service object-group

Preferred modern form:

```text
object-group service <name>
    service-object ...
    group-object <service-group-name>
```

Older/protocol-qualified group syntax can also appear:

```text
object-group service <name> tcp
object-group service <name> udp
object-group service <name> tcp-udp
```

Cisco documents the mixed `service-object` form as the preferred approach; the extractor must nevertheless preserve whichever valid source form is actually configured.

### Extraction rules

- Preserve protocol.
- Preserve source-port and destination-port semantics separately.
- Preserve ICMP/ICMPv6 type semantics when represented by a service.
- Preserve nested `group-object` references.
- Do not flatten groups into copied service definitions.
- An ASA service object contains one service specification; replacing it is not equivalent to adding a second service entry.
- Preserve references to service groups in ACL/NAT/MPF where supported.
- Do not invent a standalone ASA equivalent for FortiGate **service category**.

### Official PDF reference

- I-R Commands, `o` chapter:
  - **object service**, approximately PDF pages 15-17.
  - **object-group**, approximately PDF pages 2-8.

---

## 3.8 Destination NAT / FortiGate VIP Equivalent

### Mapping

```text
FortiGate:
config firewall vip

ASA:
static object NAT
and/or
twice NAT with destination/static translation
```

### Important model rule

ASA destination translation is NAT source state, not a standalone VIP object.

### Source forms to recognize

Static object NAT:

```text
object network <real-object>
    nat (<real-if>,<mapped-if>) static <mapped-address-or-object> ...
```

Static port translation can be configured inline for supported transport protocols.

Twice NAT can include destination translation:

```text
nat (...) source ... destination static <mapped-destination> <real-destination> ...
```

and optional service translation.

### Extraction rules

- Keep original match/source context together with destination translation.
- Preserve real and mapped interfaces.
- Preserve translated destination reference/value.
- Preserve real destination reference/value.
- Preserve translated and real service/port semantics.
- Preserve NAT section/order.
- Preserve `inactive`, `unidirectional`, `dns`, `no-proxy-arp`, and `route-lookup` only when explicitly configured.
- Do not create an explicit ASA `VIP` object.
- A derived VIP report row can be produced later from the NAT rule, but must reference the original NAT source identity.

### Official PDF reference

- I-R Commands, `n` chapter, **nat (object)** and **nat (global)**.

---

## 3.9 FortiGate VIP Group Equivalent

### Mapping

```text
FortiGate:
config firewall vipgrp

ASA:
no direct VIP-group object
```

### Source configuration to collect

```text
object network
object-group network
nat (object)
nat (global / twice NAT)
access-list references associated with the published service, where relevant
```

### Rules

- Do not create an explicit ASA `VIPGroup` source object.
- Preserve every NAT rule independently.
- Preserve address/object-group references used by those NAT rules.
- Any grouping of related published mappings for reporting or migration is derived state only.

### Official PDF reference

- I-R Commands, `n` and `o` chapters.

---

## 3.10 IPS / FortiGate IPS Sensor Equivalent

### Mapping

```text
FortiGate:
config ips sensor

ASA legacy AIP SSM integration:
class-map
policy-map
class
ips inline|promiscuous ... [sensor ...]
service-policy
```

### IPS action

Recognize the policy-class action:

```text
ips inline {fail-close|fail-open} [sensor <name>]
ips promiscuous {fail-close|fail-open} [sensor <name>]
```

### Semantics to preserve

```text
inline
    traffic traverses the IPS module; IPS can block/drop it

promiscuous
    a copy is sent to the IPS module; the original traffic is not blocked by that IPS copy path

fail-close
    block traffic when the AIP SSM fails

fail-open
    permit traffic when the AIP SSM fails

sensor <name>
    reference to the selected IPS virtual sensor
```

### Extraction rules

- Preserve the class-map defining which traffic is sent to IPS.
- Preserve policy-map/class ownership.
- Preserve inline vs promiscuous.
- Preserve fail-open vs fail-close.
- Preserve sensor name/reference.
- Preserve service-policy activation.
- Do **not** treat the referenced sensor's internal signature policy as if it were native ASA base configuration unless that separate IPS module configuration is also explicitly collected from an authoritative source.
- Do not expand a vendor signature database into explicit source configuration.
- This is a legacy/separate IPS architecture; model it as such rather than pretending it is a FortiGate sensor object.

### Official PDF reference

- I-R Commands, `int-ipu` chapter, **ips**, approximately PDF pages 69-71.
- A-H `ca-cld` and S `service-policy` for the MPF relationship.

---

## 3.11 Static Routes

### Mapping

```text
FortiGate:
config router static

ASA IPv4:
route ...

ASA IPv6:
ipv6 route ...
```

### A. IPv4 static route

Recognize:

```text
route <interface> <destination> <netmask> <gateway> [<metric>] [track <id>]
route <interface> <destination> <netmask> <gateway> ... tunneled
```

Retain:

```text
interface
destination
netmask
next-hop gateway
administrative distance / metric
track reference
tunneled marker
```

Rules:

- Gateway can be optional in specific transparent-mode cases; preserve absence rather than inventing one.
- `null0` is an explicit black-hole next-hop/interface semantic in routed mode. Preserve it.
- `track` is a relationship to a separate tracking object.
- `tunneled` is a distinct static-route semantic for VPN traffic.

### B. IPv6 static route

Recognize:

```text
ipv6 route <interface> <prefix>/<length> <next-hop> [<administrative-distance>|tunneled]
```

Retain IPv6 prefix/length, interface, next hop, administrative distance, and tunneled state.

### Extraction rules

- Keep IPv4 and IPv6 routes distinct.
- Do not infer a next hop from an interface or vice versa.
- Do not store documented default administrative distance as explicit source unless it appears in the extracted configuration.
- Preserve multiple routes to the same prefix as independent explicit entries.
- Tracking/runtime reachability is operational state; the `track` reference itself is source state.

### Official PDF reference

- I-R Commands, `ret-rz`, **route**.
- I-R Commands, `ipv-ir`, **ipv6 route**.

---

## 3.12 Administrator Access Profiles / Command Authorization

### Mapping

```text
FortiGate:
config system accprofile

ASA:
privilege ...
aaa authorization command ...
username ... privilege ...
```

### Important model rule

ASA does not expose a FortiGate-style named reusable `accprofile` object for command authorization.

Keep separate:

```text
CommandPrivilegeOverride
CommandAuthorizationMethod
LocalUserPrivilegeAssignment
Remote AAA authorization source
```

### Command privilege source

Recognize `privilege` commands that assign a command/form/mode to privilege level 0-15, including forms similar to:

```text
privilege cmd level <n> ... command <command>
privilege show level <n> ... command <command>
privilege clear level <n> ... command <command>
```

The source may distinguish command form and CLI mode.

### Authorization activation

Recognize management authorization such as:

```text
aaa authorization command LOCAL
```

or a TACACS+ server-group form, optionally with local fallback where configured.

### User assignment

```text
username <name> ... privilege <0-15>
```

### Rules

- Preserve command-level privilege overrides exactly; do not collapse them into synthetic read/write flags.
- Preserve privilege level as an integer 0-15.
- Preserve command form (`cmd`, `show`, `clear`, configuration form) and CLI mode when explicitly scoped.
- Preserve AAA authorization method separately from privilege definitions.
- A privilege definition does not by itself prove that local command authorization is active.
- Preserve TACACS+/LOCAL fallback semantics where explicitly configured.
- Command authorization can vary by security context; do not flatten different contexts into one global role model.
- Do not invent a named ASA role object unless the source actually defines one through a different feature.

### Official PDF reference

- I-R Commands, `pr-pz`, **privilege**, approximately PDF pages 25-27.
- A-H Commands / AAA command-reference sections for `aaa authorization command`.

---

## 3.13 Administrators / Management Login Users

### Mapping

```text
FortiGate:
config system admin

ASA:
username <name> ...
+ management authentication / authorization commands
```

### Local username source

Recognize:

```text
username <name> [password ... | nopassword] [privilege <level>]
username <name> attributes
    ...per-user attributes...
```

### Secret rule

If password/authentication material is present:

```text
Password Configured = Yes
```

Do not store:

```text
plaintext password
encrypted password representation
PBKDF2 hash
MSCHAP/NT password material
other credential material
```

### Management-role relationships

A local `username` is stored in the ASA local user database and can participate in different authentication contexts. Therefore:

- Extract the username once as explicit source.
- Preserve its explicit privilege level.
- Resolve whether it is used for SSH/ASDM/console/VPN/other AAA through relationships with management authentication and VPN configuration.
- Do not duplicate the same `username` into separate synthetic `AdminUser` and `FirewallUser` source records solely because FortiGate has separate tables.

### External administrators

AAA-authenticated administrators might not have a corresponding local `username` object. Preserve AAA server groups, authentication methods, and authorization configuration as independent source areas when they are part of the selected extraction scope.

### Official PDF reference

- T-Z Commands, **username**, approximately PDF pages 259-263.
- A-H Commands, AAA sections for management authentication/authorization.

---

## 3.14 DHCP Server

### Mapping

```text
FortiGate:
config system dhcp server

ASA:
dhcpd ...
```

### Core source commands to recognize

```text
dhcpd address <first>[-<last>] <interface>
dhcpd enable <interface>
dhcpd dns ...
dhcpd wins ...
dhcpd domain ...
dhcpd lease ...
dhcpd ping_timeout ...
dhcpd option ...
dhcpd reserve-address <ip> <mac> <interface>
dhcpd auto_config ...
dhcpd update dns ...
```

Retain additional safe `dhcpd` subcommands if explicitly present.

### Pool rules

- `dhcpd address` associates an address pool with an interface.
- DHCP clients must be directly connected to the ASA DHCP-server interface according to the command reference.
- In routed mode, preserve whether the pool belongs to a routed interface or BVI.
- In transparent mode, preserve bridge-group member interface ownership.
- Cisco documents a parsing restriction for `dhcpd address`: an interface name containing `-` conflicts with the address-range separator. Validation may report it; do not rewrite the interface name.

### Enablement rules

- `dhcpd enable <interface>` is explicit enablement for that interface.
- In multiple-context mode, DHCP server enablement is restricted on interfaces shared by more than one context.
- The interface address/subnet participates in DHCP gateway behavior; do not copy that effective value into explicit DHCP source fields unless separately configured.

### Options

Preserve DNS, WINS, domain, lease, ping timeout, custom options, auto-config source, and DDNS update settings only when explicitly configured.

For `dhcpd option`:

- Preserve option code.
- Preserve value encoding/type such as ASCII or IP where represented.
- Do not assume Cisco has validated arbitrary option code/value semantic correctness; the reference notes that the ASA does not validate every arbitrary option's RFC type/value pairing.

### Reservations

```text
dhcpd reserve-address <ip> <mac> <interface>
```

Keep reservation address, MAC address, and interface ownership together.

### Official PDF reference

- A-H Commands, `dh-dm` chapter, **dhcpd address**, **dhcpd enable**, **dhcpd option**, **dhcpd reserve-address**, and related `dhcpd` commands, approximately PDF pages 16-35.

---

## 3.15 SD-WAN Equivalent / Policy-Based Routing and Path Monitoring

### Mapping

```text
FortiGate:
config system sdwan

ASA:
no direct FortiGate-style SD-WAN object
```

Potentially relevant ASA source areas are:

```text
interface ... policy-route route-map <name>
interface ... policy-route cost <value>
interface ... policy-route path-monitoring ...
route-map ...
match ...
set ...
sla monitor ...
sla monitor schedule ...
track ...
static routes with track references
```

Not every deployment uses every area.

### A. Interface policy-route binding

Recognize:

```text
interface <interface>
    policy-route route-map <route-map-name>
```

### B. Interface path cost

```text
interface <interface>
    policy-route cost <value>
```

Cisco documents lower cost as higher preference. Equal cost can participate in load-sharing behavior where supported.

### C. Path monitoring

Recognize interface path-monitoring configuration such as:

```text
policy-route path-monitoring auto
policy-route path-monitoring auto4
policy-route path-monitoring auto6
policy-route path-monitoring <peer-ip>
```

Preserve the exact configured monitor type/peer.

### D. Route map

Preserve route-map source independently:

```text
route-map <name> permit|deny <sequence>
    match ...
    set ...
```

For PBR, important relationships can include ACL matches and next-hop/set actions. Preserve sequence/order.

### E. Classic SLA + track

Where used, preserve independently:

```text
sla monitor <id>
    type echo protocol ipIcmpEcho <target> interface <interface>
    timeout ...
    frequency ...

sla monitor schedule <id> ...
track <track-id> rtr <sla-id> reachability
```

and the route/feature that references the track object.

### Extraction rules

- Do not create one explicit `SDWAN` ASA source object.
- Preserve interfaces, route maps, path-monitoring configuration, SLA operations, schedules, tracks, and static routes independently.
- Resolve references in the relationship layer.
- Preserve route-map sequence/order.
- Preserve path-monitor type and peer exactly.
- Runtime RTT/jitter/loss/reachability measurements are operational state, not explicit source configuration.
- `policy-route path-monitoring` and classic `sla monitor`/`track` are separate source mechanisms; do not merge them unless a derived relationship explicitly justifies it.

### Official PDF reference

- I-R Commands, `po-pq`, **policy-route**, approximately PDF pages 16-18.
- S Commands, **sla monitor** and **sla monitor schedule**.
- I-R/T-Z command families for route-map/track relationships.

---

## 3.16 Security / Traffic Zones

### Mapping

```text
FortiGate:
config system zone

ASA:
zone <name>
interface <interface>
    zone-member <name>
```

### Zone source

```text
zone <name>
```

### Membership source

```text
interface <interface>
    zone-member <zone-name>
```

### Rules

- Preserve the zone object and interface membership relationship separately.
- An interface can be a member of only one traffic zone.
- Cisco documents up to eight interfaces per zone.
- The first interface added determines the zone security level; additional interfaces must use the same security level.
- Security level remains interface source configuration; do not invent a separate zone security-level field unless the extracted source explicitly has one.
- Changing/removing zone membership can affect existing connections at runtime; runtime connection deletion is not source configuration.
- Supported zone members include physical, VLAN, EtherChannel, and redundant interfaces.
- Cisco documents interface types that cannot be zone members, including management-only, management-access, failover/state, cluster-control-link, and member interfaces that belong inside EtherChannel/redundant bundles.
- Interface topology must come from interface/zone relationships, not parser inference.

### Official PDF reference

- T-Z Commands, **zone**, approximately PDF pages 408-409.
- T-Z Commands, **zone-member**, approximately PDF pages 426-427.

---

## 3.17 User Groups / Identity and VPN Group Policy

### Mapping

```text
FortiGate:
config user group

ASA has at least two distinct source concepts:
1. Identity Firewall user object groups
2. VPN group policies
```

Do not merge them into one source type.

### A. Identity Firewall user object-group

```text
object-group user <name>
    description ...
    user <domain-user>
    user-group <directory-group>
    group-object <nested-user-group>
```

Rules:

- Preserve explicit individual-user references.
- Preserve external/directory group references.
- Preserve nested object-group references.
- Do not materialize runtime directory membership into the explicit group.

### B. VPN group policy

Creation:

```text
group-policy <name> internal [from <other-policy>]
```

or an external group-policy form backed by a AAA server group.

Attributes:

```text
group-policy <name> attributes
    ...attributes...
    webvpn
        ...WebVPN/Secure Client attributes...
```

Important attribute families include, when explicitly configured:

```text
DNS/WINS/default domain
VPN access hours
VPN filter
idle/session timeouts
simultaneous login limits
split-tunnel policy/list
VPN tunnel protocols
address pools
client access/firewall attributes
webvpn/Secure Client attributes
```

### Group-policy inheritance rules

- `no <attribute>` removes the local override and allows inheritance from another policy/default source.
- `none` on attributes that support it represents an explicit null value that prevents inheritance.
- Boolean attributes preserve explicit enabled/disabled state.
- `DefaultGroupPolicy` exists as a default ASA group policy, but documented defaults must not be written into explicit source unless present in the extracted source or intentionally collected as effective/default data.
- Keep `internal`, `external`, and `internal from <policy>` source semantics distinct.
- External group-policy passwords are secrets and must never be exported.

### Official PDF reference

- I-R Commands, `o`, **object-group user**.
- A-H Commands, `g-h`, **group-policy** and **group-policy attributes**, approximately PDF pages 19-23.

---

## 3.18 Local Authentication Users

### Mapping

```text
FortiGate:
config user local

ASA:
username <name> ...
```

### Source hierarchy

```text
username <name> [password ... | nopassword] [privilege <level>]
username <name> attributes
    ...
```

### Rules

- Preserve username.
- Preserve explicit privilege level.
- Preserve safe non-secret per-user attributes.
- Never export password/hash/encrypted password material.
- If a credential field exists, record only safe presence metadata.
- Keep authentication role/use as relationships: VPN user, management administrator, or another AAA use can reference/use the same local database entry.
- Do not create duplicate source users simply to satisfy separate FortiGate `system admin` and `user local` categories.

### Official PDF reference

- T-Z Commands, **username**, approximately PDF pages 259-263.

---

## 3.19 Site-to-Site IPsec VPN

### Mapping

```text
FortiGate:
config vpn ipsec phase1
config vpn ipsec phase1-interface
config vpn ipsec phase2
config vpn ipsec phase2-interface

ASA:
IKE policy
IPsec proposal / transform-set
crypto map OR VTI/IPsec profile
tunnel-group
optional crypto ACL / traffic selector policy
```

### Important model rule

Do not collapse ASA VPN configuration into synthetic `Phase1` and `Phase2` source objects.

Keep the native source structures independent and resolve references later.

### A. IKEv1 policy

```text
crypto ikev1 policy <priority>
    authentication ...
    encryption ...
    hash ...
    group ...
    lifetime ...
```

Rules:

- Preserve policy priority; lower numeric priority is higher precedence.
- Preserve only algorithms/settings explicitly configured.
- Deprecated/insecure algorithms present in old source are still source state; preserve safe non-secret values and let validation report incompatibility/deprecation rather than silently replacing them.

### B. IKEv2 policy

```text
crypto ikev2 policy <index>
    encryption ...
    integrity ...
    prf ...
    group ...
    lifetime ...
    additional-key-exchange ...
```

Preserve the configured proposal parameters and ordering/priority semantics.

### C. IPsec transform/proposal

IKEv1 commonly references a transform set:

```text
crypto ipsec ikev1 transform-set <name> ...
```

IKEv2 uses IPsec proposals:

```text
crypto ipsec ikev2 ipsec-proposal <name>
    protocol esp encryption ...
    protocol esp integrity ...
```

Preserve proposal name and explicitly configured transforms.

### D. Policy-based VPN / crypto map

Preserve crypto map entry identity and sequence:

```text
crypto map <map-name> <seq> match address <acl>
crypto map <map-name> <seq> set peer ...
crypto map <map-name> <seq> set transform-set ...
crypto map <map-name> <seq> set ikev2 ipsec-proposal ...
crypto map <map-name> <seq> set pfs ...
crypto map <map-name> <seq> set security-association lifetime ...
crypto map <map-name> interface <interface>
```

Only the commands actually present should be stored.

Rules:

- Preserve sequence number/order.
- Preserve peer list/order.
- Preserve crypto ACL reference; do not copy ACEs into the crypto map source object.
- Preserve transform/proposal references.
- Preserve PFS and SA lifetime overrides where explicit.
- Preserve interface binding separately.

### E. Tunnel group / IPsec peer attributes

Site-to-site peers commonly use:

```text
tunnel-group <peer-name-or-address> type ipsec-l2l
tunnel-group <peer-name-or-address> general-attributes
    ...
tunnel-group <peer-name-or-address> ipsec-attributes
    ...
```

Preserve peer identity and non-secret IPsec attributes.

### Secret handling

Never export:

```text
IKE pre-shared-key value
IKEv2 pre-shared-key value
private keys
certificate private-key material
AAA shared secret used by a VPN dependency
```

Safe metadata:

```text
Pre-Shared Key Configured = Yes
Certificate Authentication Configured = Yes
```

### F. Route-based VPN / VTI

Preserve tunnel-interface source separately:

```text
interface Tunnel<id>
    tunnel source interface ...
    tunnel destination ...
    tunnel protection ipsec profile <profile>
    tunnel protection ipsec policy <acl>     # when explicitly configured
    ...interface addressing/routing...
```

IPsec profile:

```text
crypto ipsec profile <name>
    set ikev1 transform-set ...
    set ikev2 ipsec-proposal ...
    set pfs ...
    set security-association lifetime ...
    set trustpoint ...
```

Only retain subcommands actually present.

Rules:

- Keep VTI interface, IPsec profile, IKE policy, proposal/transform, tunnel-group/peer, and routes as distinct source objects/sections.
- `tunnel protection ipsec policy <acl>` is an explicit selector relationship when configured.
- If no selector ACL is configured, do not manufacture an explicit any-any source selector merely because the command reference documents the effective behavior.

### Official PDF reference

- A-H Commands, `crypto a-ir`:
  - **crypto ikev1 policy**, approximately PDF pages 82-83.
  - **crypto ikev2 policy**, approximately PDF pages 97-99.
  - **crypto ipsec profile**, approximately PDF pages 119-120.
- A-H Commands, `crypto is-cz`, crypto-map command family.
- T-Z Commands, **tunnel-group**, **tunnel-group ipsec-attributes**, and **tunnel protection ipsec**.

---

## 3.20 Remote Access SSL VPN / Secure Client / WebVPN

### Mapping

```text
FortiGate:
config vpn ssl ...

ASA:
webvpn
remote-access tunnel-group
group-policy
local/AAA users
local/DHCP/AAA address assignment
Secure Client / WebVPN attributes
certificate / trustpoint dependencies
ACL / vpn-filter / split-tunnel dependencies
```

### Important model rule

ASA remote access is not one SSL-VPN source object.

Keep separate:

```text
WebVPNGlobalConfig
TunnelGroup
TunnelGroupGeneralAttributes
TunnelGroupWebVPNAttributes
GroupPolicy
GroupPolicyAttributes
GroupPolicyWebVPNAttributes
Username
UsernameAttributes
LocalAddressPool
AAAAddressAssignment
VPNFilterACL
SplitTunnelACL
Certificate/TrustpointReference
```

### A. Global WebVPN

```text
webvpn
    ...global WebVPN/Secure Client configuration...
```

Preserve explicit global subcommands such as interface enablement, client image/profile references, certificate/trustpoint-related references, tunnel-group-list behavior, and other safe WebVPN configuration when present.

Do not fill missing global WebVPN leaves with documented defaults.

### B. Remote-access connection profile / tunnel group

Recognize:

```text
tunnel-group <name> type remote-access
```

and, where present:

```text
tunnel-group <name> general-attributes
    ...

tunnel-group <name> webvpn-attributes
    ...

tunnel-group <name> ipsec-attributes
    ...
```

Older/clientless configurations may use a WebVPN tunnel-group type where explicitly present. Preserve the actual source type.

### C. Group policy

```text
group-policy <name> internal [from <other-policy>]
group-policy <name> attributes
    ...
```

Common relevant attributes include:

```text
vpn-tunnel-protocol
vpn-access-hours
vpn-filter
vpn-idle-timeout
vpn-session-timeout
vpn-simultaneous-logins
split-tunnel-policy
split-tunnel-network-list
dns-server
wins-server
default-domain
address-pools
webvpn ...
```

Preserve only what is explicitly configured.

### D. Group-policy / username WebVPN mode

From group-policy attributes or username attributes:

```text
webvpn
    ...per-group or per-user WebVPN/Secure Client attributes...
```

Inheritance rules:

```text
global/default settings
    <- overridden by named group-policy WebVPN attributes
        <- overridden by per-user WebVPN attributes
```

This precedence is a relationship/effective behavior. Keep each explicit source layer independently.

### E. Local IPv4 address pool

Recognize:

```text
ip local pool <name> <first>-<last> [mask <mask>]
```

Rules:

- Preserve pool name, range, and explicit mask.
- If a non-standard network requires an explicit mask for correct client routing, validation may report its absence; do not invent the mask in source state.
- Local address pools can be referenced by VPN group/tunnel configuration.

### F. Address assignment method

Recognize:

```text
vpn-addr-assign aaa
vpn-addr-assign dhcp
vpn-addr-assign local [reuse-delay ...]
```

Keep the selected assignment mechanisms as explicit source.

DHCP-based assignment has separate dependencies such as DHCP scope/server configuration. Local assignment has local pool dependencies.

### G. User/AAA relationships

Remote-access authentication can use local `username` entries or external AAA. Preserve:

```text
username source
AAA server-group reference
authentication-server-group settings
group-policy relationships
tunnel-group relationships
```

Never export AAA server shared secrets or user passwords.

### H. VPN authorization filters and split tunneling

ACL references such as `vpn-filter` and split-tunnel network lists remain references to ACL source. Do not copy ACEs into the group-policy object.

### Extraction rules

- Preserve tunnel-group, group-policy, webvpn, pool, username/AAA, ACL, and certificate dependencies as separate source configuration.
- Resolve relationships later.
- Preserve inheritance/null semantics in group-policy attributes.
- Preserve connection-profile type.
- Preserve disabled or absent protocol settings without inventing effective defaults.
- Never export credential, private-key, pre-shared-key, or AAA-secret values.
- A migration-oriented “SSL VPN portal/profile” view may be derived, but must remain traceable to all contributing ASA source objects.

### Official PDF reference

- T-Z Commands:
  - **tunnel-group**, approximately PDF pages 139-143.
  - **tunnel-group general-attributes**, approximately PDF pages 144-145.
  - **tunnel-group ipsec-attributes**, approximately PDF pages 146+.
  - **vpn-addr-assign**, approximately PDF page 315.
  - **webvpn (global)**, approximately PDF pages 380-381.
  - **webvpn (group-policy attributes, username attributes)**, approximately PDF pages 382-384.
  - **username**, approximately PDF pages 259-263.
- A-H Commands, `g-h`, **group-policy** / **group-policy attributes**.
- I-R Commands for `ip local pool`.

---

# 4. Cross-Section Relationships to Build

The relationship layer should resolve references without overwriting explicit source.

```text
NetworkObjectGroup
    -> NetworkObject / nested NetworkObjectGroup

ServiceObjectGroup
    -> ServiceObject / nested ServiceObjectGroup

ACL
    -> NetworkObject / NetworkObjectGroup
    -> ServiceObject / ServiceObjectGroup
    -> TimeRange
    -> Identity user/group selectors

AccessGroup
    -> ACL
    -> Interface / global scope

ObjectNAT
    -> owning NetworkObject
    -> mapped NetworkObject / interface

TwiceNATRule
    -> real/mapped NetworkObject or NetworkObjectGroup
    -> optional destination objects
    -> optional ServiceObject(s)

ClassMap
    -> ACL or other match source

PolicyMap
    -> ClassMap
    -> feature actions
    -> optional InspectionPolicyMap

ServicePolicy
    -> PolicyMap
    -> interface/global scope

StaticRoute
    -> Interface
    -> optional Track

PolicyRoute
    -> RouteMap
    -> Interface

RouteMap
    -> ACL / prefix/match objects
    -> next-hop/set actions

Track
    -> SLA Monitor

Zone
    <- Interface.zone-member

Username
    -> privilege / management auth relationship
    -> VPN group-policy / tunnel-group relationship where applicable

GroupPolicy
    -> TimeRange through vpn-access-hours
    -> VPN-filter ACL
    -> split-tunnel ACL
    -> local address pool
    -> WebVPN/Secure Client attributes

TunnelGroup
    -> GroupPolicy
    -> AAA server group
    -> IPsec attributes / WebVPN attributes

CryptoMapEntry
    -> crypto ACL
    -> IKE/IPsec proposal/transform
    -> peer / TunnelGroup
    -> interface binding

VTI
    -> IPsecProfile
    -> tunnel source/destination
    -> routing
```

---

# 5. Recommended Extraction Ordering

A deterministic extraction/report pipeline should preserve source first, then resolve dependencies.

```text
1. interfaces / nameif / security level / zones
2. network objects
3. network object groups
4. service objects
5. service groups
6. time ranges
7. users / user groups / group policies
8. ACLs
9. ACL bindings
10. NAT rules
11. MPF class maps
12. MPF policy maps / inspection maps
13. service-policy bindings
14. DHCP
15. routes / route maps / policy-route / SLA / track
16. IKE/IPsec objects
17. crypto maps / VTI / tunnel groups
18. WebVPN / remote access
19. relationship resolution
20. validation
21. derived migration/report views
```

This is an extraction dependency order, not a claim that ASA internally stores the configuration in exactly this sequence.

---

# 6. Validation Rules

Validation detects and reports only. It must not mutate or silently repair ASA source configuration.

Useful validations for these selected areas include:

- unresolved object/object-group/service/time-range references;
- ACL binding referencing an unavailable ACL;
- mixed IPv4/IPv6 network object-group used for NAT;
- NAT ordering conflicts or unsupported address-family combinations;
- duplicate/conflicting NAT relationships that require review;
- object NAT ownership/reference inconsistencies;
- invalid zone membership or security-level mismatch across zone members;
- missing route-map/track/SLA references;
- VPN crypto map references to missing transform/proposal/ACL/peer;
- group-policy references to missing pools/ACLs/time ranges;
- remote-access tunnel groups referencing missing policies/AAA sources;
- secret-bearing values accidentally captured in parsed/raw output;
- unsupported/deprecated crypto algorithms detected in explicit old configurations;
- command families that are valid only in a firewall mode/context different from the extracted deployment.

Do not automatically replace deprecated algorithms, fill missing masks, reorder NAT/ACL rules, create missing objects, or expand defaults.

---

# 7. Secret Redaction Rules

The extractor must detect secret-bearing configuration before storing `raw_extra` or logs.

At minimum redact/drop actual values from source areas such as:

```text
username ... password ...
AAA server shared secrets / keys
LDAP bind passwords
RADIUS/TACACS+ secrets
IKEv1/IKEv2 pre-shared keys
crypto-map or tunnel-group pre-shared key material
certificate/private-key material
VPN external group-policy password
WebVPN/Secure Client authentication secrets
```

Allowed safe metadata examples:

```text
Password Configured = Yes
AAA Shared Secret Configured = Yes
Pre-Shared Key Configured = Yes
Certificate Authentication Configured = Yes
Private Key Present = Yes
```

Never place actual secret values into:

```text
raw_extra
Additional Settings
Source Inventory
JSON debug output
logs
Markdown reports
Excel
web preview
```

---

# 8. Source-Fidelity Rules for the Project

For Cisco ASA, use the following architecture boundary:

```text
Tokenizer / parser
    -> parse ASA syntax and hierarchy only

Command evaluator / source builder
    -> explicit ASA configuration objects

Relationships
    -> named references, interface bindings, NAT ownership, VPN dependencies

Transforms / DerivedViews
    -> FortiGate-comparison or migration-friendly views

Validation
    -> detect/report only

Excel
    -> presentation only
```

A FortiGate comparison view can contain derived concepts such as:

```text
DerivedSourceNATPool
DerivedVIP
DerivedFirewallPolicy
DerivedSecurityStack
DerivedSDWANPathPolicy
DerivedSSLVPNProfile
```

but those must never replace the native ASA source model.

---

# 9. Compact Source Inventory Checklist

For the 20-area baseline, collect at least these ASA source families when present:

```text
object network
object service
object-group network
object-group service
object-group user

time-range
absolute
periodic

access-list
access-group

nat (object)
nat (global / twice NAT)

class-map
class-map type inspect
policy-map
policy-map type inspect
service-policy
ips

route
ipv6 route
route-map
policy-route
sla monitor
sla monitor schedule
track

privilege
aaa authorization command
username

dhcpd address
dhcpd enable
dhcpd dns
dhcpd wins
dhcpd domain
dhcpd lease
dhcpd ping_timeout
dhcpd option
dhcpd reserve-address
dhcpd auto_config
dhcpd update dns

zone
interface ... zone-member

crypto ikev1 policy
crypto ikev2 policy
crypto ipsec ikev1 transform-set
crypto ipsec ikev2 ipsec-proposal
crypto ipsec profile
crypto map
interface Tunnel
tunnel protection ipsec
tunnel-group

group-policy
group-policy ... attributes
ip local pool
vpn-addr-assign
webvpn
```

If a recognized selected-area hierarchy contains additional safe subcommands in the source, preserve them instead of dropping them merely because they are not enumerated in this checklist.

---

# 10. Final Modeling Summary

```text
Cisco ASA source configuration
    -> stay ASA-shaped

No synthetic source:
    IPPool
    VIP
    VIPGroup
    ProfileGroup
    SDWAN
    Phase1
    Phase2

Instead:
    preserve explicit ASA objects/rules
    -> resolve references
    -> derive FortiGate-comparison views only when useful
```

Priority:

```text
correctness
-> source preservation
-> clear semantics
-> traceability
-> maintainability
```
