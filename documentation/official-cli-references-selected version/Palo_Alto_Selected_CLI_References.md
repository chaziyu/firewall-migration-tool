# Palo Alto PAN-OS Selected CLI References

> **Purpose:** Source-configuration extraction reference for the firewall migration/extraction project.
>
> **Official source:** Palo Alto Networks, *PAN-OS CLI Quick Start — Version 11.1 & later*  
> https://docs.paloaltonetworks.com/content/dam/techdocs/en_US/pdf/ngfw/ngfw-cli.pdf
>
> **Document scope used:** PAN-OS configuration-mode command hierarchy, with the standalone firewall / targeted-vsys hierarchy as the primary extraction model. Panorama `device-group`, `template`, and `template-stack` wrappers are deployment scopes and must be preserved when they are present.
>
> **Mapping baseline:** The 20 FortiGate selected configuration areas supplied for this project.
>
> **Security rule:** Never export, log, or write actual passwords, password hashes, pre-shared keys, private keys, API keys, tokens, GlobalProtect passcodes, IPsec manual keys, or equivalent authentication secrets. Record only safe metadata such as `Password Configured = Yes` or `Pre-Shared Key Configured = Yes`.

---

## 1. Extraction Principles

### 1.1 Prefer set-format configuration output

The PAN-OS guide documents this workflow:

```text
set cli config-output-format set
configure
show <configuration-section>
```

For example, the guide shows:

```text
admin@fw1> set cli config-output-format set
admin@fw1# show deviceconfig system snmp-setting
```

This produces full `set ...` commands and is the preferred source form for deterministic parsing.

### 1.2 Preserve source scope

PAN-OS configuration is hierarchical.

Keep these scopes distinct:

```text
firewall/device scope
vsys scope
shared scope
Panorama device-group scope
Panorama template scope
Panorama template-stack scope
```

Do not silently flatten a Panorama-managed configuration into a local firewall configuration.

For a specific virtual system, the guide documents:

```text
set system setting target-vsys <vsys-name>
```

After targeting a vsys, vsys-scoped objects can appear with roots such as:

```text
set address ...
set address-group ...
set rulebase ...
set profiles ...
set zone ...
```

Return to firewall scope with:

```text
set system target-vsys none
```

### 1.3 Preserve explicit source only

A missing PAN-OS leaf means:

```text
not explicitly present in the extracted source
```

Do not infer a PAN-OS default and store it as explicit source configuration.

Keep these separate:

```text
explicit source
derived relationship
effective/default value
unknown/unparsed source
```

Unknown or newly introduced PAN-OS leaves should be retained as raw source rather than dropped.

### 1.4 Preserve references instead of expanding them

PAN-OS policies and profiles contain references to other source objects.

Examples:

```text
security rule -> address/address-group
security rule -> service/service-group
security rule -> schedule
security rule -> profile-group or individual profiles
NAT rule -> address/address-group
SD-WAN rule -> SD-WAN profiles
IPsec tunnel -> IKE gateway / IPsec crypto profile
```

Store the reference in the source object and resolve relationships separately.

### 1.5 Dependency/order rule recorded by Palo Alto Networks

The guide notes that configuration sections should be applied in logical dependency order. It gives security rules as an example: objects that rules depend on, such as zones, security profiles, and address groups, should exist first.

The guide also states that CLI deletion does **not** perform the same dependency checking as the web interface. References must therefore be searched and handled explicitly.

### 1.6 Secret handling

The official hierarchy contains secret-bearing leaves in several selected areas.

Examples include:

```text
local-user-database user ... phash
IKE / IPsec pre-shared-key or manual key material
IKEv2 post-quantum pre-shared key material
GlobalProtect passcodes / uninstall passwords
proxy or authentication passwords
```

Extractor rule:

```text
detect presence
-> record safe configured/not-configured metadata if useful
-> redact/drop the actual value
-> never place the value in logs, raw_extra, reports, or Excel
```

---

# 2. Mapping Index

| # | FortiGate selected config | PAN-OS source configuration to extract | Mapping |
|---|---|---|---|
| 1 | `config firewall address` | `address` | Direct |
| 2 | `config firewall addrgrp` | `address-group`; `tag` for dynamic filters/tags | Direct |
| 3 | `config firewall ippool` | `rulebase nat rules ... source-translation` | Different model |
| 4 | `config firewall policy` | `rulebase security rules` | Direct |
| 5 | `config firewall profile-group` | `profile-group` | Direct |
| 6 | `config firewall schedule group/onetime/recurring` | `schedule` | Mostly direct |
| 7 | `config firewall service category/custom/group` | `service`; `service-group` | Direct except category |
| 8 | `config firewall vip` | `rulebase nat rules ... destination-translation` / `dynamic-destination-translation` | Different model |
| 9 | `config firewall vipgrp` | NAT rules plus referenced `address` / `address-group` | No direct VIP-group object |
| 10 | `config ips sensor` | `profiles vulnerability` | Closest equivalent |
| 11 | `config router static` | `network virtual-router ... static-route`; `network logical-router ... static-route` | Direct |
| 12 | `config system accprofile` | `shared admin-role` | Direct |
| 13 | `config system admin` | `mgt-config users` | Direct |
| 14 | `config system dhcp server` | `network dhcp interface ... server` | Direct |
| 15 | `config system sdwan` | `sdwan-interface-profile`; interface SD-WAN link settings; SD-WAN profiles; `rulebase sdwan rules` | Split model |
| 16 | `config system zone` | `zone` | Direct |
| 17 | `config user group` | `local-user-database user-group`; `group-mapping` | Depends on local/external group |
| 18 | `config user local` | `local-user-database user` | Direct |
| 19 | `config vpn ipsec phase1/phase2` | IKE gateway, IKE crypto, IPsec crypto, IPsec tunnel, Proxy IDs | Split model |
| 20 | `config vpn ssl ...` | GlobalProtect portal, gateway, client settings, clientless VPN | Different architecture |

---

# 3. Selected PAN-OS Configuration References

## 3.1 Address Objects

### Mapping

```text
FortiGate:
config firewall address

PAN-OS:
set address ...
```

### Extraction root

```text
show address
```

### Recorded hierarchy

```text
set address
set address <name>
set address <name> description <value>

set address <name> ip-netmask <ip/netmask>
set address <name> ip-range <ip-range>
set address <name> ip-wildcard <ipdiscontmask>
set address <name> fqdn <value>

set address <name> tag [ <tag1> <tag2>... ]
```

### Extraction rules

- Preserve the configured address representation. Do not normalize every address into an IP/netmask.
- `ip-netmask`, `ip-range`, `ip-wildcard`, and `fqdn` represent different source semantics.
- Preserve tags as references.
- Do not invent a value when none of the address-type leaves is explicitly present.
- Preserve unrecognized leaves as source-only/raw fields.

---

## 3.2 Address Groups and Tags

### Mapping

```text
FortiGate:
config firewall addrgrp

PAN-OS:
set address-group ...
set tag ...
```

### Extraction roots

```text
show address-group
show tag
```

### Recorded hierarchy

```text
set address-group
set address-group <name>
set address-group <name> description <value>

set address-group <name> static [ <static1> <static2>... ]

set address-group <name> dynamic
set address-group <name> dynamic filter <value>

set address-group <name> tag [ <tag1> <tag2>... ]
```

Tags:

```text
set tag
set tag <name>
set tag <name> color <color1|color2|...|color42>
set tag <name> comments <value>
```

### Extraction rules

- Keep **static** and **dynamic** address groups distinct.
- Static group members are object references.
- A dynamic address group stores a filter expression; do not resolve it into a static member list and replace the source.
- Extract tags because dynamic filters and policy/object tagging can depend on them.
- Resolved dynamic membership, if calculated later, is derived state and must not overwrite the source filter.

---

## 3.3 Source NAT / FortiGate IP Pool Equivalent

### Mapping

```text
FortiGate:
config firewall ippool

PAN-OS:
set rulebase nat rules <name> source-translation ...
```

### Important model rule

PAN-OS does **not** represent the FortiGate IP-pool concept as an equivalent standalone source object in this hierarchy.

Source NAT translation is configuration **inside a NAT rule**.

Do not create a synthetic PAN-OS `IPPool` source object merely to resemble FortiGate.

### Extraction root

```text
show rulebase nat
```

### NAT rule match fields

```text
set rulebase nat rules <name> from [ ... ]
set rulebase nat rules <name> to [ ... ]
set rulebase nat rules <name> source [ ... ]
set rulebase nat rules <name> destination [ ... ]
set rulebase nat rules <name> service <value>
set rulebase nat rules <name> nat-type <ipv4|nat64|nptv6>
set rulebase nat rules <name> to-interface <value>|<any>
```

### Source translation branches

```text
set rulebase nat rules <name> source-translation dynamic-ip-and-port
set rulebase nat rules <name> source-translation dynamic-ip-and-port translated-address [ ... ]
set rulebase nat rules <name> source-translation dynamic-ip-and-port interface-address ...

set rulebase nat rules <name> source-translation persistent-dynamic-ip-and-port
set rulebase nat rules <name> source-translation persistent-dynamic-ip-and-port translated-address [ ... ]
set rulebase nat rules <name> source-translation persistent-dynamic-ip-and-port interface-address ...

set rulebase nat rules <name> source-translation dynamic-ip
set rulebase nat rules <name> source-translation dynamic-ip translated-address [ ... ]
set rulebase nat rules <name> source-translation dynamic-ip interface-address ...
set rulebase nat rules <name> source-translation dynamic-ip fallback ...

set rulebase nat rules <name> source-translation static-ip
set rulebase nat rules <name> source-translation static-ip translated-address <value>|<ip/netmask>|<ip-range>
set rulebase nat rules <name> source-translation static-ip bi-directional <yes|no>
```

### Extraction rules

- Extract the whole NAT rule, not only the translated addresses.
- A translated address/pool is scoped by the NAT rule and translation mode.
- Preserve interface-address source NAT separately from explicit translated-address source NAT.
- Preserve the source translation type exactly.
- Any derived “IP pool” view must remain derived and traceable to its NAT rule.

---

## 3.4 Security Policy

### Mapping

```text
FortiGate:
config firewall policy

PAN-OS:
set rulebase security rules ...
```

### Extraction root

```text
show rulebase security
```

### Core recorded hierarchy

```text
set rulebase security rules <name>

set rulebase security rules <name> from [ ... ]
set rulebase security rules <name> to [ ... ]

set rulebase security rules <name> source [ ... ]
set rulebase security rules <name> source-user [ ... ]
set rulebase security rules <name> destination [ ... ]

set rulebase security rules <name> application [ ... ]
set rulebase security rules <name> service [ ... ]
set rulebase security rules <name> category [ ... ]

set rulebase security rules <name> source-hip [ ... ]
set rulebase security rules <name> destination-hip [ ... ]

set rulebase security rules <name> schedule <value>
set rulebase security rules <name> tag [ ... ]

set rulebase security rules <name> negate-source <yes|no>
set rulebase security rules <name> negate-destination <yes|no>
set rulebase security rules <name> disabled <yes|no>

set rulebase security rules <name> description <value>
set rulebase security rules <name> group-tag <value>

set rulebase security rules <name> saas-user-list [ ... ]
set rulebase security rules <name> saas-tenant-list [ ... ]

set rulebase security rules <name> action <deny|allow|drop|reset-client|reset-server|reset-both>
set rulebase security rules <name> icmp-unreachable <yes|no>
set rulebase security rules <name> disable-inspect <yes|no>

set rulebase security rules <name> rule-type <universal|intrazone|interzone>
```

Profile/logging branches include:

```text
set rulebase security rules <name> option ...
set rulebase security rules <name> log-setting <value>
set rulebase security rules <name> log-start <yes|no>
set rulebase security rules <name> log-end <yes|no>

set rulebase security rules <name> profile-setting profiles ...
set rulebase security rules <name> profile-setting group ...
```

Individual profile references can include:

```text
url-filtering
data-filtering
file-blocking
wildfire-analysis
virus
spyware
vulnerability
```

### Extraction rules

- Rule order is significant. Preserve configuration ordering/sequence.
- Preserve `rule-type`; do not infer it from zones.
- Preserve object names as references.
- Do not replace a referenced profile group with expanded profile members in the source model.
- Preserve disabled rules.
- Keep rule match criteria and action/settings distinct.
- Extract referenced address, service, schedule, zone, and profile objects separately.

---

## 3.5 Security Profile Groups

### Mapping

```text
FortiGate:
config firewall profile-group

PAN-OS:
set profile-group ...
```

### Extraction root

```text
show profile-group
```

### Recorded hierarchy

```text
set profile-group
set profile-group <name>

set profile-group <name> virus [ ... ]
set profile-group <name> spyware [ ... ]
set profile-group <name> vulnerability [ ... ]
set profile-group <name> url-filtering [ ... ]
set profile-group <name> file-blocking [ ... ]
set profile-group <name> wildfire-analysis [ ... ]
set profile-group <name> data-filtering [ ... ]
```

Panorama/device-group variants can include additional leaves such as `gtp`, `sctp`, `ai-security`, and `disable-override`.

### Extraction rules

- Preserve each referenced profile by type.
- Do not manufacture an “effective” profile stack unless a later transform explicitly calculates one.
- Preserve deployment-scope-only fields such as Panorama override controls when present.

---

## 3.6 Schedules

### Mapping

```text
FortiGate:
config firewall schedule group
config firewall schedule onetime
config firewall schedule recurring

PAN-OS:
set schedule ...
```

### Extraction root

```text
show schedule
```

### Recorded hierarchy

```text
set schedule <name> schedule-type recurring

set schedule <name> schedule-type recurring weekly
set schedule <name> schedule-type recurring weekly sunday [ ... ]
set schedule <name> schedule-type recurring weekly monday [ ... ]
set schedule <name> schedule-type recurring weekly tuesday [ ... ]
set schedule <name> schedule-type recurring weekly wednesday [ ... ]
set schedule <name> schedule-type recurring weekly thursday [ ... ]
set schedule <name> schedule-type recurring weekly friday [ ... ]
set schedule <name> schedule-type recurring weekly saturday [ ... ]

set schedule <name> schedule-type recurring daily [ ... ]

set schedule <name> schedule-type non-recurring [ ... ]
```

### Extraction rules

- Preserve the schedule type.
- Weekly, daily, and non-recurring entries are not interchangeable.
- PAN-OS does not expose a FortiGate-style schedule-group object in this selected hierarchy; do not invent one.
- A policy schedule reference remains a reference to a PAN-OS schedule object.

---

## 3.7 Service Objects and Service Groups

### Mapping

```text
FortiGate:
config firewall service custom
config firewall service group
config firewall service category

PAN-OS:
set service ...
set service-group ...
```

### Extraction roots

```text
show service
show service-group
```

### Service hierarchy

```text
set service <name>
set service <name> description <value>

set service <name> protocol tcp
set service <name> protocol tcp port <0-65535,...>
set service <name> protocol tcp source-port <0-65535,...>
set service <name> protocol tcp override no
set service <name> protocol tcp override yes
set service <name> protocol tcp override yes timeout <1-604800>
set service <name> protocol tcp override yes halfclose-timeout <1-604800>
set service <name> protocol tcp override yes timewait-timeout <1-600>

set service <name> protocol udp
set service <name> protocol udp port <0-65535,...>
set service <name> protocol udp source-port <0-65535,...>
set service <name> protocol udp override no
set service <name> protocol udp override yes
set service <name> protocol udp override yes timeout <1-604800>

set service <name> tag [ ... ]
```

### Service-group hierarchy

```text
set service-group <name>
set service-group <name> members [ <members1> <members2>... ]
set service-group <name> tag [ <tag1> <tag2>... ]
```

Panorama/device-group scope can additionally expose `disable-override`.

### Extraction rules

- Preserve TCP and UDP service definitions separately.
- Preserve source port and destination port semantics.
- Preserve protocol override/timeouts only when explicitly configured.
- Service-group members are references.
- No direct selected PAN-OS equivalent was identified for FortiGate **service category** as a standalone migration object. Do not fabricate one.

---

## 3.8 Destination NAT / FortiGate VIP Equivalent

### Mapping

```text
FortiGate:
config firewall vip

PAN-OS:
set rulebase nat rules <name> destination-translation ...
set rulebase nat rules <name> dynamic-destination-translation ...
```

### Important model rule

PAN-OS destination translation is source state inside a NAT rule. It is not a standalone VIP object equivalent.

### Recorded destination translation hierarchy

```text
set rulebase nat rules <name> destination-translation
set rulebase nat rules <name> destination-translation translated-address <value>|<ip/netmask>|<ip-range>
set rulebase nat rules <name> destination-translation translated-port <1-65535>

set rulebase nat rules <name> destination-translation dns-rewrite
set rulebase nat rules <name> destination-translation dns-rewrite direction <reverse|forward>
```

Dynamic destination translation can include:

```text
set rulebase nat rules <name> dynamic-destination-translation
set rulebase nat rules <name> dynamic-destination-translation translated-address <value>
set rulebase nat rules <name> dynamic-destination-translation translated-port <1-65535>
set rulebase nat rules <name> dynamic-destination-translation distribution <round-robin|source-ip-hash|ip-modulo|ip-hash|least-sessions>
```

### Extraction rules

- Keep original NAT match criteria together with translation configuration.
- A derived “VIP” representation may be useful for migration, but it must remain derived.
- Do not detach translated destination data from the NAT rule in the explicit PAN-OS source model.

---

## 3.9 FortiGate VIP Group Equivalent

### Mapping

```text
FortiGate:
config firewall vipgrp

PAN-OS:
no direct VIP-group object
```

### Source configuration to collect

```text
rulebase nat rules
address
address-group
```

### Extraction rules

- Do not create a fake PAN-OS VIP-group source object.
- Preserve NAT rules independently.
- Preserve address/address-group references used by NAT rules.
- Any grouping of NAT mappings for migration/reporting is derived state.

---

## 3.10 Vulnerability Protection / FortiGate IPS Sensor Equivalent

### Mapping

```text
FortiGate:
config ips sensor

PAN-OS:
set profiles vulnerability ...
```

### Extraction root

```text
show profiles vulnerability
```

### Selected recorded hierarchy

```text
set profiles vulnerability <name>

set profiles vulnerability <name> rules <name>
set profiles vulnerability <name> rules <name> threat-name <value>
set profiles vulnerability <name> rules <name> host <value>
set profiles vulnerability <name> rules <name> vendor-id [ ... ]
set profiles vulnerability <name> rules <name> severity [ ... ]
set profiles vulnerability <name> rules <name> category <value>|<any>

set profiles vulnerability <name> rules <name> action default
set profiles vulnerability <name> rules <name> action allow
set profiles vulnerability <name> rules <name> action alert
set profiles vulnerability <name> rules <name> action drop
set profiles vulnerability <name> rules <name> action reset-client
set profiles vulnerability <name> rules <name> action reset-server
set profiles vulnerability <name> rules <name> action reset-both
set profiles vulnerability <name> rules <name> action block-ip
set profiles vulnerability <name> rules <name> action block-ip track-by <source|source-and-destination>
set profiles vulnerability <name> rules <name> action block-ip duration <1-3600>

set profiles vulnerability <name> rules <name> packet-capture <disable|single-packet|extended-capture>
```

Threat exceptions include:

```text
set profiles vulnerability <name> threat-exception <name>
set profiles vulnerability <name> threat-exception <name> packet-capture <disable|single-packet|extended-capture>

set profiles vulnerability <name> threat-exception <name> action default
set profiles vulnerability <name> threat-exception <name> action allow
set profiles vulnerability <name> threat-exception <name> action alert
set profiles vulnerability <name> threat-exception <name> action drop
set profiles vulnerability <name> threat-exception <name> action reset-client
set profiles vulnerability <name> threat-exception <name> action reset-server
set profiles vulnerability <name> threat-exception <name> action reset-both
set profiles vulnerability <name> threat-exception <name> action block-ip
set profiles vulnerability <name> threat-exception <name> action block-ip track-by <source|source-and-destination>
set profiles vulnerability <name> threat-exception <name> action block-ip duration <1-3600>

set profiles vulnerability <name> threat-exception <name> time-attribute interval <1-3600>
set profiles vulnerability <name> threat-exception <name> time-attribute threshold <1-65535>
set profiles vulnerability <name> threat-exception <name> time-attribute track-by <source|destination|source-and-destination>
set profiles vulnerability <name> threat-exception <name> exempt-ip ...
```

Newer hierarchy entries also include cloud inline analysis / MICA-related leaves.

### Extraction rules

- Use `profiles vulnerability` as the primary equivalent for a FortiGate IPS sensor.
- Do **not** confuse this with `threats vulnerability`, which is a different hierarchy for custom vulnerability threat definitions.
- Preserve rule selection criteria, actions, packet capture settings, and exceptions.
- Preserve new/unrecognized profile leaves as source-only configuration.

---

## 3.11 Static Routes

### Mapping

```text
FortiGate:
config router static

PAN-OS:
set network virtual-router ...
set network logical-router ...
```

### Extraction roots

Legacy/virtual-router model:

```text
show network virtual-router
```

Logical-router model:

```text
show network logical-router
```

### Virtual Router IPv4 route root

```text
set network virtual-router <name> routing-table ip static-route <name> ...
```

### Logical Router IPv4 route root

```text
set network logical-router <name> vrf <name> routing-table ip static-route <name> ...
```

### Route properties to retain

Depending on router model and address family, the hierarchy includes:

```text
destination
interface
nexthop
admin-dist
metric
route-table
bfd profile
path-monitor
```

Nexthop variants include model-specific branches such as:

```text
ip-address
fqdn
discard
next-vr
next-lr
```

Path monitoring includes:

```text
path-monitor enable <yes|no>
path-monitor failure-condition <any|all>
path-monitor hold-time <0-1440>

path-monitor monitor-destinations <name> enable <yes|no>
path-monitor monitor-destinations <name> source ...
path-monitor monitor-destinations <name> destination <value>
path-monitor monitor-destinations <name> destination-fqdn <value>    # where supported
path-monitor monitor-destinations <name> interval <1-60>
path-monitor monitor-destinations <name> count <3-10>
```

### Extraction rules

- Keep **Virtual Router** and **Logical Router / VRF** source models distinct.
- Preserve router/VRF ownership for every route.
- Preserve next-hop type, not only next-hop value.
- Preserve path-monitor and BFD references.
- Do not silently convert one routing architecture into the other.

---

## 3.12 Administrator Roles

### Mapping

```text
FortiGate:
config system accprofile

PAN-OS:
set shared admin-role ...
```

### Extraction root

```text
show shared admin-role
```

### Primary firewall role scope

```text
set shared admin-role <name> role device ...
```

The hierarchy contains granular permissions for areas such as:

```text
webui
xmlapi
restapi
cli
```

and nested product areas including policies, objects, network, device, reports, logs, administrators, admin roles, local user database, certificates, server profiles, and others.

Permission leaves commonly use:

```text
<enable|read-only|disable>
```

Some action-oriented privileges use:

```text
<enable|disable>
```

### Extraction rules

- Capture the complete role subtree.
- Do not collapse granular permissions into a single synthetic “read/write” flag.
- Preserve permission channel separately: Web UI, XML API, REST API, CLI.
- Panorama role scopes (`panorama`, `device-group`) are distinct from a firewall `device` role and must not be silently merged.

---

## 3.13 Administrators

### Mapping

```text
FortiGate:
config system admin

PAN-OS:
set mgt-config users ...
```

### Extraction root

```text
show mgt-config users
```

### Role configuration

```text
set mgt-config users <name> permissions
set mgt-config users <name> permissions role-based

set mgt-config users <name> permissions role-based devicereader [ ... ]
set mgt-config users <name> permissions role-based deviceadmin [ ... ]
set mgt-config users <name> permissions role-based superreader <yes>
set mgt-config users <name> permissions role-based superuser <yes>
set mgt-config users <name> permissions role-based custom ...
```

The account subtree can also contain user preferences and authentication-related configuration.

### Extraction rules

- Preserve administrator name and explicit role assignment.
- Preserve custom Admin Role Profile reference when configured.
- Authentication Profile / external authentication is distinct from a locally stored password.
- **Never export password/hash values.**
- If a password/hash leaf exists, record safe metadata only:

```text
Password Configured = Yes
```

- User-interface preferences and saved log queries are source configuration but are usually migration-nonessential. Preserve them as source-only/raw if the project wants full source fidelity rather than deleting them.

---

## 3.14 DHCP Server

### Mapping

```text
FortiGate:
config system dhcp server

PAN-OS:
set network dhcp interface <name> server ...
```

### Extraction root

```text
show network dhcp
```

### Recorded hierarchy

```text
set network dhcp
set network dhcp interface
set network dhcp interface <name>
set network dhcp interface <name> server

set network dhcp interface <name> server mode <enabled|disabled|auto>
set network dhcp interface <name> server probe-ip <yes|no>
```

Lease:

```text
set network dhcp interface <name> server option lease unlimited
set network dhcp interface <name> server option lease timeout <0-1000000>
```

Inheritance and common options:

```text
set network dhcp interface <name> server option inheritance source <value>
set network dhcp interface <name> server option gateway <ip/netmask>
set network dhcp interface <name> server option subnet-mask <value>

set network dhcp interface <name> server option dns primary <ip/netmask>|<inherited>
set network dhcp interface <name> server option dns secondary <ip/netmask>|<inherited>

set network dhcp interface <name> server option wins ...
set network dhcp interface <name> server option ntp ...
set network dhcp interface <name> server option pop3-server ...
set network dhcp interface <name> server option smtp-server ...
set network dhcp interface <name> server option dns-suffix <value>|<inherited>
```

Custom DHCP options:

```text
set network dhcp interface <name> server option user-defined <name> code <1-254>
set network dhcp interface <name> server option user-defined <name> vendor-class-identifier <value>
set network dhcp interface <name> server option user-defined <name> inherited <yes|no>
set network dhcp interface <name> server option user-defined <name> ip [ ... ]
set network dhcp interface <name> server option user-defined <name> ascii [ ... ]
set network dhcp interface <name> server option user-defined <name> hex [ ... ]
```

Pools and reservations:

```text
set network dhcp interface <name> server ip-pool [ ... ]

set network dhcp interface <name> server reserved
set network dhcp interface <name> server reserved <name>
set network dhcp interface <name> server reserved <name> mac <value>
set network dhcp interface <name> server reserved <name> description <value>
```

### Extraction rules

- DHCP server is interface-scoped.
- Preserve mode exactly (`enabled`, `disabled`, `auto`).
- Preserve inherited option state rather than replacing it with an inferred effective value.
- Keep pools and reservations as explicit source entries.

---

## 3.15 SD-WAN

### Mapping

```text
FortiGate:
config system sdwan

PAN-OS:
split across multiple configuration areas
```

### Required extraction roots

```text
show sdwan-interface-profile
show network interface ethernet
show profiles sdwan-path-quality
show profiles sdwan-traffic-distribution
show profiles sdwan-saas-quality
show profiles sdwan-error-correction
show rulebase sdwan
```

Not every deployment uses every profile type.

### A. SD-WAN Interface Profile

Vsys-scoped root:

```text
set sdwan-interface-profile <name> ...
```

Recorded fields include:

```text
set sdwan-interface-profile <name> link-tag <value>
set sdwan-interface-profile <name> link-type <ADSL/DSL|Cablemodem|Ethernet|Fiber|LTE/3G/4G/5G|MPLS|Microwave/Radio|Satellite|WiFi|Private1|Private2|Private3|Private4|Other>
set sdwan-interface-profile <name> vpn-data-tunnel-support <yes|no>
set sdwan-interface-profile <name> maximum-download <float>
set sdwan-interface-profile <name> maximum-upload <float>
set sdwan-interface-profile <name> error-correction <yes|no>
set sdwan-interface-profile <name> path-monitoring <Aggressive|Relaxed>
set sdwan-interface-profile <name> vpn-failover-metric <1-65535>
set sdwan-interface-profile <name> probe-frequency <1-5>
set sdwan-interface-profile <name> probe-idle-time <1-86400>
set sdwan-interface-profile <name> failback-hold-time <20-120>
set sdwan-interface-profile <name> comment <value>
```

Panorama template/template-stack paths wrap this under the managed device/vsys context.

### B. Interface SD-WAN Link Settings

Example hierarchy:

```text
set network interface ethernet <name> layer3 sdwan-link-settings enable <yes|no>
```

Subinterface/unit hierarchy includes:

```text
set network interface ethernet <name> layer3 units <name> sdwan-link-settings enable <yes|no>
set network interface ethernet <name> layer3 units <name> sdwan-link-settings ipv6-enable <yes|no>
set network interface ethernet <name> layer3 units <name> sdwan-link-settings sdwan-interface-profile <value>
set network interface ethernet <name> layer3 units <name> sdwan-link-settings upstream-nat ...
```

### C. Path Quality Profile

```text
set profiles sdwan-path-quality <name> metric latency threshold <10-3000>
set profiles sdwan-path-quality <name> metric latency sensitivity <low|medium|high>

set profiles sdwan-path-quality <name> metric pkt-loss threshold <1-100>
set profiles sdwan-path-quality <name> metric pkt-loss sensitivity <low|medium|high>

set profiles sdwan-path-quality <name> metric jitter threshold <10-2000>
set profiles sdwan-path-quality <name> metric jitter sensitivity <low|medium|high>
```

### D. Traffic Distribution Profile

```text
set profiles sdwan-traffic-distribution <name> traffic-distribution <Best Available Path|Top Down Priority|Weighted Session Distribution>

set profiles sdwan-traffic-distribution <name> link-tags <name> weight <0-100>
```

### E. SaaS Quality Profile

The hierarchy supports monitor modes including:

```text
adaptive
static-ip
http-https
```

Examples include probe intervals and monitored URL/FQDN/IP fields.

### F. Error Correction Profile

```text
set profiles sdwan-error-correction <name> activation-threshold <1-99>
set profiles sdwan-error-correction <name> mode forward-error-correction ...
set profiles sdwan-error-correction <name> mode packet-duplication ...
```

### G. SD-WAN Policy Rules

```text
set rulebase sdwan rules <name> from [ ... ]
set rulebase sdwan rules <name> to [ ... ]
set rulebase sdwan rules <name> source [ ... ]
set rulebase sdwan rules <name> source-user [ ... ]
set rulebase sdwan rules <name> destination [ ... ]
set rulebase sdwan rules <name> application [ ... ]
set rulebase sdwan rules <name> service [ ... ]
set rulebase sdwan rules <name> tag [ ... ]

set rulebase sdwan rules <name> negate-source <yes|no>
set rulebase sdwan rules <name> negate-destination <yes|no>
set rulebase sdwan rules <name> disabled <yes|no>
set rulebase sdwan rules <name> description <value>
set rulebase sdwan rules <name> group-tag <value>

set rulebase sdwan rules <name> path-quality-profile <value>
set rulebase sdwan rules <name> saas-quality-profile <value>
set rulebase sdwan rules <name> error-correction-profile <value>

set rulebase sdwan rules <name> action traffic-distribution-profile <value>
set rulebase sdwan rules <name> action app-failover-for-nat-sessions <keep-existing-link|failover-to-better-path>
```

### Extraction rules

- Do not force PAN-OS SD-WAN into a single FortiGate-like object.
- Preserve interface profile, interface binding, quality profiles, distribution profiles, and policy rules independently.
- Resolve their references in the relationship layer.
- Preserve rule order.
- Preserve unsupported/new SD-WAN profile types as source-only data.

---

## 3.16 Zones

### Mapping

```text
FortiGate:
config system zone

PAN-OS:
set zone ...
```

### Extraction root

```text
show zone
```

### Recorded hierarchy

```text
set zone <name>
set zone <name> enable-user-identification <yes|no>
set zone <name> enable-device-identification <yes|no>

set zone <name> network
set zone <name> network zone-protection-profile <value>
set zone <name> network enable-packet-buffer-protection <yes|no>
set zone <name> network net-inspection <yes|no>

set zone <name> network prenat-identification enable-prenat-user-identification <yes|no>
set zone <name> network prenat-identification enable-prenat-device-identification <yes|no>
set zone <name> network prenat-identification enable-prenat-source-policy-lookup <yes|no>
set zone <name> network prenat-identification enable-prenat-source-ip-downstream <yes|no>

set zone <name> network log-setting <value>

set zone <name> network tap [ ... ]
set zone <name> network virtual-wire [ ... ]
set zone <name> network layer2 [ ... ]
set zone <name> network layer3 [ ... ]
set zone <name> network tunnel

set zone <name> user-acl include-list [ ... ]
set zone <name> user-acl exclude-list [ ... ]
set zone <name> device-acl include-list [ ... ]
set zone <name> device-acl exclude-list [ ... ]
```

### Extraction rules

- Zone membership comes from the zone source configuration and referenced interfaces.
- Preserve zone network type and member list.
- Do not infer interface hierarchy by parser heuristics.
- Zone protection and log-setting are references.

---

## 3.17 User Groups

### Mapping

Local PAN-OS group:

```text
FortiGate:
config user group

PAN-OS:
set local-user-database user-group ...
```

External/directory-backed group discovery:

```text
set group-mapping ...
```

### Local user-group hierarchy

```text
set local-user-database user-group
set local-user-database user-group <name>
set local-user-database user-group <name> user [ <user1> <user2>... ]
```

### Group Mapping hierarchy

```text
set group-mapping
set group-mapping <name>
set group-mapping <name> server-profile <value>
set group-mapping <name> disabled <yes|no>
set group-mapping <name> use-ldap-for-serialno-check <yes|no>
set group-mapping <name> use-modify-timestamp <yes|no>
set group-mapping <name> limited-group-search <yes|no>
set group-mapping <name> nested-group-level <1-20>
```

Additional mapping attributes include:

```text
group-object [ ... ]
group-member [ ... ]
group-name [ ... ]
user-object [ ... ]
user-name [ ... ]
user-email [ ... ]
group-email [ ... ]
alternate-user-name-1 [ ... ]
alternate-user-name-2 [ ... ]
alternate-user-name-3 [ ... ]
container-object [ ... ]
last-modify-attr [ ... ]
group-include-list [ ... ]
```

### Extraction rules

- Local user groups and directory group mapping are different source concepts.
- A Group Mapping configuration is not itself a static local user group.
- Preserve directory attribute mappings and server-profile reference.
- If later logic resolves external groups/users, that resolved membership is derived data.

---

## 3.18 Local Users

### Mapping

```text
FortiGate:
config user local

PAN-OS:
set local-user-database user ...
```

### Extraction root

```text
show local-user-database
```

### Recorded hierarchy

```text
set local-user-database user
set local-user-database user <name>
set local-user-database user <name> phash <value>
set local-user-database user <name> disabled <yes|no>
```

### Extraction rules

- Preserve username and disabled state.
- **Never export `phash` content.**
- Safe representation:

```text
Password Configured = Yes|No
```

- Local users and management administrators are separate models:
  - `local-user-database user` = authentication user
  - `mgt-config users` = PAN-OS administrator

---

## 3.19 IPsec VPN

### Mapping

```text
FortiGate:
config vpn ipsec phase1-interface / phase1
config vpn ipsec phase2-interface / phase2

PAN-OS:
network ike gateway
network ike crypto-profiles ike-crypto-profiles
network ike crypto-profiles ipsec-crypto-profiles
network tunnel ipsec
auto-key proxy-id / proxy-id-v6
```

### Required extraction roots

```text
show network ike
show network tunnel ipsec
```

### A. IKE Gateway

```text
set network ike gateway <name> ...
```

Important subtrees include:

```text
local-address
peer-address
local-id
peer-id
authentication
protocol
protocol-common
```

Protocol version:

```text
set network ike gateway <name> protocol version <ikev1|ikev2|ikev2-preferred>
```

IKEv1:

```text
set network ike gateway <name> protocol ikev1 exchange-mode <auto|main|aggressive>
set network ike gateway <name> protocol ikev1 ike-crypto-profile <value>
set network ike gateway <name> protocol ikev1 dpd enable <yes|no>
set network ike gateway <name> protocol ikev1 dpd interval <2-100>
set network ike gateway <name> protocol ikev1 dpd retry <2-100>
```

IKEv2:

```text
set network ike gateway <name> protocol ikev2 ike-crypto-profile <value>
set network ike gateway <name> protocol ikev2 require-cookie <yes|no>
set network ike gateway <name> protocol ikev2 dpd enable <yes|no>
set network ike gateway <name> protocol ikev2 dpd interval <2-100>
```

Common settings:

```text
set network ike gateway <name> protocol-common nat-traversal enable <yes|no>
set network ike gateway <name> protocol-common nat-traversal keep-alive-interval <10-3600>
set network ike gateway <name> protocol-common nat-traversal udp-checksum-enable <yes|no>
set network ike gateway <name> protocol-common passive-mode <yes|no>
set network ike gateway <name> protocol-common fragmentation enable <yes|no>
```

Newer IKEv2 hierarchy can include PQ-PPK/PQ-KEM settings.

**Secret rule:** PQ pre-shared key values and traditional pre-shared key values are secret and must never be exported.

### B. IKE Crypto Profile

```text
set network ike crypto-profiles ike-crypto-profiles <name> ...
```

Retain:

```text
encryption algorithms
authentication algorithms
DH / AKE groups
lifetime
authentication-multiple
```

Lifetime constraints recorded by the hierarchy include:

```text
seconds <180-65535>
minutes <3-65535>
hours <1-65535>
days <1-365>
```

### C. IPsec Crypto Profile

```text
set network ike crypto-profiles ipsec-crypto-profiles <name> ...
```

Selected hierarchy:

```text
set network ike crypto-profiles ipsec-crypto-profiles <name> esp encryption [ ... ]
set network ike crypto-profiles ipsec-crypto-profiles <name> esp authentication [ ... ]
set network ike crypto-profiles ipsec-crypto-profiles <name> ah authentication [ ... ]
set network ike crypto-profiles ipsec-crypto-profiles <name> dh-group <...>
```

Retain lifetime and newer AKE/PQ leaves when present.

### D. IPsec Tunnel

```text
set network tunnel ipsec <name> ...
```

Important subtrees:

```text
tunnel-interface
auto-key
manual-key
global-protect-satellite
```

For ordinary site-to-site auto-key tunnels, retain:

```text
IKE gateway reference(s)
IPsec crypto profile reference
Proxy IDs
tunnel interface
tunnel monitor / related explicit settings
```

Proxy IDs include IPv4 and IPv6 variants:

```text
set network tunnel ipsec <name> auto-key proxy-id <name> ...
set network tunnel ipsec <name> auto-key proxy-id-v6 <name> ...
```

Protocol selectors can include:

```text
number <1-254>
any
tcp
tcp local-port <0-65535>
tcp remote-port <0-65535>
udp
udp local-port <0-65535>
udp remote-port <0-65535>
```

### E. Manual-key tunnel secret rule

The hierarchy contains manual ESP/AH authentication/encryption keys.

Examples of secret-bearing leaves:

```text
manual-key esp authentication ... key <value>
manual-key esp encryption key <value>
manual-key ah ... key <value>
```

Never export these values.

### Extraction rules

- Do not collapse IKE Gateway, IKE Crypto Profile, IPsec Crypto Profile, Tunnel, and Proxy ID into one source object.
- Keep references explicit and resolve them separately.
- Preserve IKE version and negotiation mode.
- Preserve tunnel selector/proxy-ID semantics.
- Preserve secret-presence metadata but not secret material.

---

## 3.20 SSL VPN / GlobalProtect

### Mapping

```text
FortiGate:
config vpn ssl ...

PAN-OS:
GlobalProtect architecture
```

PAN-OS GlobalProtect is not a direct object-for-object equivalent of FortiGate SSL VPN.

### Required extraction roots

```text
show global-protect global-protect-portal
show global-protect global-protect-gateway
```

Related referenced configuration may also be required, including authentication profiles, certificate profiles, SSL/TLS service profiles, zones, tunnel interfaces, addresses, and local users/groups.

### A. GlobalProtect Portal

```text
set global-protect global-protect-portal <name> ...
```

Important subtrees include:

```text
clientless-vpn
client-config
client-config root-ca
client-config configs
client-config configs <name> gateways
client-config configs <name> internal-host-detection
client-config configs <name> agent-ui
client-config configs <name> hip-collection
client-config configs <name> agent-config
client-config configs <name> gp-app-config
client-config configs <name> authentication-override
```

Examples:

```text
set global-protect global-protect-portal <name> client-config configs <name> gateways internal ...
set global-protect global-protect-portal <name> client-config configs <name> gateways external ...

set global-protect global-protect-portal <name> client-config configs <name> internal-host-detection ip-address <ip/netmask>
set global-protect global-protect-portal <name> client-config configs <name> internal-host-detection hostname <value>
```

Clientless VPN includes:

```text
set global-protect global-protect-portal <name> clientless-vpn hostname <value>
set global-protect global-protect-portal <name> clientless-vpn security-zone <value>

set global-protect global-protect-portal <name> clientless-vpn login-lifetime minutes <60-1440>
set global-protect global-protect-portal <name> clientless-vpn login-lifetime hours <1-24>

set global-protect global-protect-portal <name> clientless-vpn inactivity-logout minutes <5-1440>
set global-protect global-protect-portal <name> clientless-vpn inactivity-logout hours <1-24>

set global-protect global-protect-portal <name> clientless-vpn max-user <1-30000>
set global-protect global-protect-portal <name> clientless-vpn dns-proxy <value>
```

### B. GlobalProtect Gateway

```text
set global-protect global-protect-gateway <name> ...
```

Important subtrees include:

```text
remote-user-tunnel-configs
client-auth
ssl-tls-service-profile
certificate-profile
tunnel-mode
local-address
```

Remote-user tunnel settings include:

```text
IP pools
split tunneling
authentication server IP pools
local-network access controls
```

Examples from the hierarchy:

```text
set global-protect global-protect-gateway <name> remote-user-tunnel-configs <name> split-tunneling ...
set global-protect global-protect-gateway <name> remote-user-tunnel-configs <name> no-direct-access-to-local-network <yes|no>
set global-protect global-protect-gateway <name> remote-user-tunnel-configs <name> retrieve-framed-ip-address <yes|no>
set global-protect global-protect-gateway <name> remote-user-tunnel-configs <name> authentication-server-ip-pool [ ... ]

set global-protect global-protect-gateway <name> ssl-tls-service-profile <value>

set global-protect global-protect-gateway <name> client-auth <name> os <value>|<Any|Satellite|X-Auth>
set global-protect global-protect-gateway <name> client-auth <name> authentication-profile <value>
set global-protect global-protect-gateway <name> client-auth <name> auto-retrieve-passcode <yes|no>

set global-protect global-protect-gateway <name> tunnel-mode <yes|no>
set global-protect global-protect-gateway <name> local-address ip-address-family <ipv4|ipv6|ipv4_ipv6>
set global-protect global-protect-gateway <name> local-address interface <value>
```

### Secret handling

Portal/client configuration can contain sensitive leaves such as:

```text
agent-ui passcode
agent-ui uninstall-password
proxy password
authentication secret material
```

Do not export their values.

### Extraction rules

- Keep Portal and Gateway as separate source objects.
- Preserve each named client configuration / remote-user tunnel configuration.
- Preserve authentication and certificate references rather than expanding them.
- Preserve split-tunnel source semantics.
- Clientless VPN configuration is separate from tunnel-mode remote access.
- Do not create a synthetic FortiGate-style SSL-VPN source object. Any cross-vendor normalized view is derived only.

---

# 4. Recommended Extraction Order

This order follows source dependencies and the Palo Alto Networks warning that dependent policy configuration should not be handled before the objects it references.

```text
1. Tags
2. Address objects
3. Address groups
4. Service objects
5. Service groups
6. Schedules
7. Zones
8. Local users
9. Local user groups
10. Group mappings
11. Vulnerability profiles
12. Security profile groups
13. Admin roles
14. Administrators
15. DHCP
16. Virtual Router / Logical Router static routes
17. IKE crypto profiles
18. IPsec crypto profiles
19. IKE gateways
20. IPsec tunnels / Proxy IDs
21. SD-WAN interface profiles
22. Interface SD-WAN settings
23. SD-WAN quality/distribution/error-correction profiles
24. NAT rules
25. Security policy rules
26. SD-WAN policy rules
27. GlobalProtect portals
28. GlobalProtect gateways
```

This is an extraction/reporting dependency order, not a claim that the source configuration itself is stored in this sequence.

---

# 5. Parser / Source-Model Guidance

## 5.1 Suggested primary source sections

For a standalone firewall or a targeted vsys, recognize at least:

```text
address
address-group
tag

service
service-group
schedule

profiles vulnerability
profile-group

rulebase security
rulebase nat
rulebase sdwan

zone
local-user-database
group-mapping
sdwan-interface-profile
global-protect

network dhcp
network virtual-router
network logical-router
network interface
network ike
network tunnel ipsec

shared admin-role
mgt-config users
```

## 5.2 Panorama wrappers

When extracting Panorama-managed configuration, preserve wrappers such as:

```text
device-group <name> ...
template <name> config ...
template-stack <name> config devices <name> ...
```

Do not strip the wrapper before the source model has recorded ownership/scope.

## 5.3 Unsupported / future leaves

The official PDF is labeled **Version 11.1 & later** and includes CLI change sections in addition to complete command hierarchies.

PAN-OS evolves over time. Therefore:

```text
recognized selected field
    -> structured source field

recognized selected object + unknown leaf
    -> preserve in raw_extra / source appendix

unknown object outside selected scope
    -> Source Inventory / unsupported source section
```

Do not silently discard a leaf only because this selected reference does not list it.

---

# 6. Cross-Vendor Modeling Rules for These 20 Areas

## 6.1 Do not restore a vendor-neutral IR

Keep PAN-OS explicit source state as PAN-OS source state.

Cross-vendor comparison belongs in relationships/transforms/derived views.

## 6.2 Different-model mappings

The following must **not** be forced into fake PAN-OS source objects:

```text
FortiGate IP pool
    -> PAN-OS NAT source translation

FortiGate VIP
    -> PAN-OS NAT destination translation

FortiGate VIP group
    -> no direct PAN-OS object

FortiGate SD-WAN
    -> PAN-OS interface settings + profiles + rules

FortiGate phase1/phase2
    -> PAN-OS IKE gateway + crypto profiles + IPsec tunnel + Proxy IDs

FortiGate SSL VPN
    -> PAN-OS GlobalProtect portal/gateway architecture
```

## 6.3 Source vs derived examples

Correct:

```text
PAN-OS source:
NAT rule "snat-web"
  source-translation = dynamic-ip-and-port
  translated-address = [203.0.113.10-203.0.113.20]

Derived view:
Source NAT pool candidate
  owner = NAT rule "snat-web"
  range = 203.0.113.10-203.0.113.20
```

Incorrect:

```text
PAN-OS source:
IPPool(name="snat-web", ...)
```

when PAN-OS did not explicitly configure such an object.

---

# 7. Verification Checklist

For each extracted configuration:

- [ ] Preserve configuration scope (device/vsys/shared/Panorama).
- [ ] Preserve object/rule names exactly.
- [ ] Preserve explicit source values.
- [ ] Do not fill missing fields with assumed PAN-OS defaults.
- [ ] Preserve rule ordering for policy/NAT/SD-WAN rules.
- [ ] Preserve reference names.
- [ ] Resolve references only in relationships/transforms.
- [ ] Preserve dynamic address-group filter expression.
- [ ] Preserve NAT translation mode.
- [ ] Keep Virtual Router and Logical Router models distinct.
- [ ] Keep local users separate from administrators.
- [ ] Keep local groups separate from directory group mapping.
- [ ] Keep IKE Gateway, crypto profiles, tunnel, and Proxy IDs distinct.
- [ ] Keep GlobalProtect Portal and Gateway distinct.
- [ ] Redact all secret values.
- [ ] Preserve unknown selected-object leaves in `raw_extra`.
- [ ] Preserve unsupported objects in Source Inventory/source appendices.

---

# 8. Official PDF Locations Used

The following areas in the official PDF were used to construct this selected reference:

```text
Get Started with the CLI
- Configuration mode
- Find / show hierarchy
- Modify Configuration
- set system setting target-vsys
- set cli config-output-format set
- dependency/order warning when copying configuration

Configure CLI hierarchy
- address
- address-group
- tag
- service / service-group
- schedule
- profiles vulnerability
- profile-group
- rulebase security
- rulebase nat
- rulebase sdwan
- zone
- group-mapping
- local-user-database
- sdwan-interface-profile
- network interface ... sdwan-link-settings
- network dhcp
- network virtual-router
- network logical-router
- shared admin-role
- mgt-config users
- network ike
- network tunnel ipsec
- global-protect global-protect-portal
- global-protect global-protect-gateway
```

---

# 9. Compact Extraction Root List

```text
# vsys/shared object and policy configuration
show tag
show address
show address-group
show service
show service-group
show schedule
show profiles vulnerability
show profile-group
show rulebase security
show rulebase nat
show rulebase sdwan
show zone
show local-user-database
show group-mapping
show sdwan-interface-profile
show global-protect global-protect-portal
show global-protect global-protect-gateway

# device/network configuration
show network dhcp
show network interface ethernet
show network virtual-router
show network logical-router
show network ike
show network tunnel ipsec

# administrator configuration
show shared admin-role
show mgt-config users
```

Before using vsys-scoped roots, target the intended virtual system where required:

```text
set system setting target-vsys <vsys-name>
```

Then restore firewall scope:

```text
set system target-vsys none
```

---

## End of selected reference
