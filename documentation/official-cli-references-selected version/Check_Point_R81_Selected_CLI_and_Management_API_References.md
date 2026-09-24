# Check Point R81 Selected CLI and Management API References

> **Purpose:** Source-configuration extraction reference for the firewall migration/extraction project.
>
> **Primary source requested:** Check Point, *R81 CLI Reference Guide*  
> https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_CLI_ReferenceGuide/CP_R81_CLI_ReferenceGuide.pdf
>
> **Management object schema source required by the R81 CLI guide:** Check Point Management API Reference **v1.8.1** / the management server's local API documentation at `https://<Management-Server>/api_docs`.
>
> **Gaia configuration source required by the R81 CLI guide:** Check Point *R81 Gaia Administration Guide*.
>
> **Mapping baseline:** The 20 FortiGate selected configuration areas supplied for this project.
>
> **Security rule:** Never export, log, persist, or report actual passwords, password hashes, shared secrets, pre-shared keys, private keys, API session identifiers, tokens, or equivalent authentication secret material. Safe metadata such as `Password Configured = Yes` or `Pre-Shared Key Configured = Yes` is allowed.

---

# 1. Source and Extraction Principles

## 1.1 Important source boundary in the official R81 CLI PDF

The R81 CLI Reference Guide documents the generic Management API CLI entry point:

```text
mgmt_cli <Command Name> <Command Parameters> <Optional Switches>
```

The guide explicitly directs the reader to the **Check Point Management API Reference** for the complete Management API commands and parameters. It also identifies the local API documentation endpoint:

```text
https://<Management-Server-IP>/api_docs
```

Therefore:

```text
R81 CLI Reference PDF
    -> authoritative for mgmt_cli invocation and Check Point CLI tooling

Management API Reference v1.8.1
    -> authoritative for host/network/rule/NAT/VPN/etc. management object schemas

R81 Gaia Administration Guide
    -> authoritative for Gaia Clish objects such as routes, DHCP, users, RBA, and VTI
```

Do **not** claim that a per-object Management API schema came from the CLI PDF when the PDF only points to the Management API Reference.

## 1.2 Preserve Check Point's split source architecture

Keep these source domains separate:

```text
Management API / management database
    objects
    policy packages
    Access Control layers and rules
    NAT Rule Base
    Threat Prevention policy and profiles
    administrators and permission profiles
    gateway / cluster management objects
    VPN communities

Gaia Clish / appliance operating-system configuration
    static routes
    DHCP server
    Gaia local users
    Gaia RBA roles
    VTI configuration
```

Do not flatten management objects and Gaia configuration into one synthetic Check Point source object.

## 1.3 Preserve Management Domain / policy-package ownership

For every Management API object or rule, preserve its owning management Domain when applicable.

For policy data, also preserve:

```text
policy package
layer
section
inline layer relationship
rule position / ordering
rule UID
object references / UIDs
```

Do not silently merge objects from different Domains or policy packages.

## 1.4 Preserve explicit source only

A missing Check Point field means:

```text
not explicitly present in the extracted source
```

Do not turn a documented Check Point default into explicit source state unless the source actually returned that value and the API semantics make it explicit.

Keep distinct:

```text
explicit source
resolved reference / relationship
derived migration view
effective/default behavior
unknown / unsupported source
```

## 1.5 Preserve references instead of replacing them

Examples:

```text
Access Rule -> host/network/group/service/time/access-role
NAT Rule -> original and translated objects
Threat Rule -> Threat Prevention profile
VPN Community -> gateway / cluster / interoperable-device members
Gateway interface -> Security Zone
Access Role -> users/groups/networks/machines/remote-access clients
```

Store the source references first. Resolve object relationships separately.

## 1.6 Pagination and full-detail retrieval

Most `show-*` Management API collection commands are paginated.

Extractor rule:

```text
request collection
-> preserve total/from/to if useful
-> continue offset/limit until all objects are collected
-> fetch full details where the list response does not contain the required source fields
```

Do not assume the first page is complete.

When `details-level full` expands referenced objects, keep the original UID/name reference relationship rather than copying expanded objects into the owner as independent source objects.

## 1.7 API permissions and session rules recorded by the R81 CLI guide

The R81 CLI guide records these Management API rules:

- The API Server must allow the connecting client according to its configured accessibility setting.
- The administrator's Permission Profile must permit **Management API Login**.
- Management changes are session based and must be published to become part of the published management database.
- Multi-Domain environments require the correct Domain context.

For a read-only extractor, do not publish or change configuration.

## 1.8 Gaia persistence rule

R81 Gaia documentation repeatedly records this rule after configuration changes:

```text
save config
```

A read-only extractor must never issue mutating `add`, `set`, `delete`, or `save config` operations. Use only the documented `show` commands.

## 1.9 Secret handling

Never persist actual values from fields containing authentication secret material.

Examples include:

```text
administrator passwords or password hashes
Gaia user passwords or password hashes
VPN pre-shared keys
private keys
API session IDs / tokens
RADIUS / TACACS shared secrets
LDAP bind passwords
certificate private-key material
```

Safe source metadata can be represented as:

```text
Password Configured = Yes|No
Pre-Shared Key Configured = Yes|No
Private Key Present = Yes|No
```

Never place secret values in `raw_extra`, logs, JSON debug dumps, Markdown reports, or Excel.

---

# 2. Mapping Index

| # | FortiGate selected config | Check Point R81 source configuration to extract | Scope | Mapping |
|---|---|---|---|---|
| 1 | `config firewall address` | `host`, `network`, `address-range`; DNS/domain, wildcard, dynamic, and updatable objects when referenced | Management API | Direct / split object types |
| 2 | `config firewall addrgrp` | `group`, `group-with-exclusion` | Management API | Direct |
| 3 | `config firewall ippool` | NAT Rule Base source translation + automatic NAT settings attached to eligible network objects | Management API | Different model |
| 4 | `config firewall policy` | Policy packages, Access Control layers, Access Rule Base, sections, inline layers | Management API | Direct |
| 5 | `config firewall profile-group` | Threat Prevention profiles/rules + Access Control security settings + HTTPS Inspection policy/settings where relevant | Management API | No single equivalent |
| 6 | `config firewall schedule group/onetime/recurring` | Time objects + Time Groups | Management API | Mostly direct |
| 7 | `config firewall service category/custom/group` | TCP, UDP, ICMP, ICMPv6, Other and other supported service objects + Service Groups | Management API | Direct except category |
| 8 | `config firewall vip` | NAT Rule Base destination translation + applicable automatic NAT settings | Management API | Different model |
| 9 | `config firewall vipgrp` | NAT rules + referenced address/group objects | Management API | No direct VIP-group object |
| 10 | `config ips sensor` | Threat Prevention profiles/rules + IPS protections, profile activation and overrides/exceptions | Management API | Closest equivalent |
| 11 | `config router static` | IPv4 and IPv6 static routes | Gaia Clish | Direct |
| 12 | `config system accprofile` | Management Permission Profiles + optional Gaia RBA roles | Management API + Gaia | Split model |
| 13 | `config system admin` | Management administrators + Gaia local administrative users/RBA assignment | Management API + Gaia | Split model |
| 14 | `config system dhcp server` | Gaia DHCP server process, subnets, address pools, leases, default gateway, domain and DNS parameters | Gaia Clish | Direct |
| 15 | `config system sdwan` | **No direct R81.00 equivalent** | — | No R81.00 equivalent |
| 16 | `config system zone` | Security Zone objects + Security Gateway/Cluster interface topology and zone assignment | Management API | Direct but split |
| 17 | `config user group` | Internal user groups + LDAP/directory-backed identities + Access Roles when used for policy identity matching | Management API | Split model |
| 18 | `config user local` | Internal Check Point user objects and authentication-related configuration | Management API | Direct-ish |
| 19 | `config vpn ipsec phase1/phase2` | Star/Meshed VPN Communities + Gateway/Cluster VPN settings + Interoperable Devices + VPN domains + Gaia VTI configuration | Management API + Gaia | Split architecture |
| 20 | `config vpn ssl ...` | Remote Access VPN / Mobile Access gateway settings + `RemoteAccess` community + Access Roles + relevant users/groups/authentication | Management API | Different architecture |

---

# 3. Common Management API Extraction Roots

Use R81 Management API v1.8.1 as the authority for exact request/response fields.

Typical read form through `mgmt_cli`:

```text
mgmt_cli <show-command> <parameters> --format json
```

Do not hard-code a newer Management API schema into the R81 source model. The management server's local `/api_docs` is the best source for the exact API version actually running.

Common collection commands used by these selected areas include:

```text
show-hosts
show-networks
show-address-ranges
show-dns-domains
show-dynamic-objects
show-updatable-objects
show-groups
show-groups-with-exclusion

show-services-tcp
show-services-udp
show-services-icmp
show-services-icmp6
show-services-other
show-service-groups

show-times
show-time-groups

show-packages
show-access-layers
show-access-rulebase
show-nat-rulebase

show-threat-profiles
show-threat-rulebase
show-threat-rule-exception-rulebase

show-permission-profiles
show-administrators

show-security-zones
show-simple-gateways
show-simple-clusters
show-gateways-and-servers

show-user-groups
show-users
show-access-roles

show-vpn-communities-star
show-vpn-communities-meshed
show-interoperable-devices
```

Some list/singular command names and fields are API-version dependent. Treat the R81 v1.8.1 `api_docs` response as authoritative if it differs from later documentation.

---

# 4. Selected Check Point R81 Configuration References

## 4.1 Address Objects

### Mapping

```text
FortiGate:
config firewall address

Check Point R81:
host
network
address-range
DNS/domain object
dynamic-object
updatable-object
wildcard object where present/referenced
```

### Management API roots

```text
show-hosts
show-networks
show-address-ranges
show-dns-domains
show-dynamic-objects
show-updatable-objects
```

Use `show-objects` only as a supplementary inventory/fallback when an object type cannot be retrieved through its dedicated command in the running R81 API version.

### Source fields to retain

Common metadata:

```text
uid
name
type
domain
tags
comments
color
groups / membership references when returned
```

Address semantics by type:

```text
host
    IPv4 address
    IPv6 address when supported/configured

network
    subnet/network address
    mask / mask length
    IPv4 / IPv6 semantics as returned

address-range
    first address
    last address
    IPv4 / IPv6 range semantics as returned

DNS/domain
    domain name
    FQDN/sub-domain matching semantics returned by source

wildcard
    address
    wildcard mask

dynamic-object
    object identity
    management object metadata
    gateway-resolved ranges only if explicitly collected as separate runtime state

updatable-object
    object identity
    provider / category metadata returned by source
    do not copy the cloud-maintained IP membership into explicit user configuration
```

### Recorded R81 rules

- Address Range represents the interval between a lowest and highest IP address and is used when a network-mask representation is unsuitable.
- Domain objects identify DNS domains by name rather than by a fixed IP address.
- FQDN-style domain matching and non-FQDN/sub-domain matching have different resolution semantics; preserve the configured source form.
- Dynamic Objects are logical management objects whose concrete IP ranges can be resolved differently on different Security Gateways.
- Updatable Objects represent external services/geographies/providers and are updated on the Security Gateway independently of normal policy installation.
- Wildcard objects use an IP address plus wildcard mask and must stay a distinct address representation.

### Extraction rules

- Do not normalize every address-like object into a generic subnet.
- Preserve object `type` as first-class source state.
- Do not replace an Updatable Object with its currently resolved IP list.
- Do not replace a Dynamic Object with one gateway's current resolved ranges.
- If runtime-resolved Dynamic Object ranges are collected, store them as gateway-scoped runtime/derived state.
- Preserve automatic NAT settings attached to eligible objects separately because they are required by sections 4.3 and 4.8.

---

## 4.2 Address Groups and Groups with Exclusion

### Mapping

```text
FortiGate:
config firewall addrgrp

Check Point R81:
group
group-with-exclusion
```

### Management API roots

```text
show-groups
show-groups-with-exclusion
```

### Source fields to retain

For ordinary groups:

```text
uid
name
members[]
comments
tags
color
groups / parent membership if returned
```

For Group with Exclusion:

```text
uid
name
include reference
except reference
comments/tags/color where returned
```

### Recorded rules

- A normal Network Group can contain hosts, networks and other applicable network objects/groups.
- Group membership is reusable by policy and other objects.
- A Group with Exclusion is semantically an included group minus an excluded group.

### Extraction rules

- Preserve member references; do not copy child objects into the group source object.
- Preserve `include` and `except` separately for Group with Exclusion.
- Do not replace Group with Exclusion with a materialized IP range list in explicit source state.
- A materialized range view can be derived for comparison/migration, but must remain traceable to the original include/except references.

---

## 4.3 Source NAT / FortiGate IP Pool Equivalent

### Mapping

```text
FortiGate:
config firewall ippool

Check Point R81:
NAT Rule Base source translation
automatic NAT settings on eligible network objects
```

### Important model rule

Check Point does **not** require a FortiGate-style standalone IP-pool source object.

Keep two Check Point NAT sources distinct:

```text
Manual NAT Rule Base
Automatic NAT generated from object NAT settings
```

Do not create a synthetic Check Point `IPPool` source object just to resemble FortiGate.

### Management API roots

```text
show-packages
show-nat-rulebase

plus full details for NAT-capable objects such as:
show-hosts
show-networks
show-address-ranges
show-simple-gateways
show-simple-clusters
```

### NAT rule fields to retain

Preserve the complete NAT rule, including:

```text
uid
rule number / order
enabled
comments
install-on

original-source
original-destination
original-service

translated-source
translated-destination
translated-service

method / translation metadata returned by the R81 API
```

For automatic NAT-capable objects retain the full explicit `nat-settings` subtree returned by R81, including the configured method and translated/hide address choices.

### Recorded R81 rules

- NAT can translate source IP, destination IP, and TCP/UDP service ports.
- Check Point supports **Automatic NAT** and **Manual NAT**.
- Automatic NAT rules are generated from NAT properties on objects and are not edited like ordinary manual NAT rules.
- Manual NAT rules are evaluated sequentially; the first matching manual rule determines the manual translation behavior.
- Automatic NAT supports **Static** and **Hide** methods.
- Check Point documents an ordering for automatically generated NAT rules: gateway/host static, gateway/host hide, network/range static, network/range hide.
- NAT occurs after anti-spoofing; anti-spoofing therefore evaluates the original source address.

### Extraction rules

- Preserve manual rule order exactly.
- Preserve original and translated columns as object references.
- Preserve automatic NAT object settings as object-owned source state.
- Do not merge automatic and manual NAT into one fake source object type.
- Any derived “source NAT pool” must remain derived and traceable to its owning NAT rule or object's automatic NAT settings.

---

## 4.4 Access Control Policy

### Mapping

```text
FortiGate:
config firewall policy

Check Point R81:
Policy Package
Access Control Layer
Access Rule Base
Section
Inline Layer
```

### Management API roots

```text
show-packages
show-access-layers
show-access-rulebase
```

For inline layers, recurse into the referenced inline layer/rulebase as returned by the API.

### Core rule source fields to retain

```text
uid
rule-number / position
name
enabled
comments

source
destination
vpn
services-and-applications / service references
content where present

source-negate / destination-negate where returned
action
track
install-on
time

inline-layer reference / Apply Layer action
```

Also retain structural nodes:

```text
layer identity
section identity and position
nested inline-rulebase ownership
```

### Recorded R81 rules

- Ordered Access Control Layers are evaluated in order.
- Within a layer, rules are matched top-to-bottom.
- An inline layer is an independent sub-policy entered through a parent rule whose action applies that layer.
- A Drop in an ordered layer stops enforcement of later ordered layers; an Accept can continue to the next ordered layer.
- Each ordered layer has an implicit cleanup behavior; Check Point recommends an explicit cleanup rule where appropriate so the intended action is visible.
- Sections are organizational/visual structure in the Rule Base and must not be treated as firewall rules.
- Shared layers can be reused in multiple policies.

### Extraction rules

- Rule ordering is mandatory source state.
- Keep section nodes rather than flattening all rules into a single numbered list.
- Keep inline-layer ownership and parent-rule relationship.
- Do not infer an inline layer from rule contents.
- Preserve disabled rules.
- Preserve object references instead of expanding them into embedded copies.
- Keep Access Control fields separate from NAT and Threat Prevention configuration.

---

## 4.5 FortiGate Profile Group Equivalent

### Mapping

```text
FortiGate:
config firewall profile-group

Check Point R81:
Threat Prevention profiles
Threat Prevention rules
Access Control security settings
HTTPS Inspection policy/settings where relevant
```

### Important model rule

There is no single Check Point object that should be forced into a FortiGate `profile-group` source model.

### Management API roots

```text
show-threat-profiles
show-threat-rulebase
show-threat-rule-exception-rulebase
show-access-rulebase
```

Also collect HTTPS Inspection policy/settings through the R81 Management API surfaces available in the running v1.8.1 API and gateway objects when required by the selected policy.

### Source state to retain

Threat Prevention profile:

```text
profile identity
enabled Software Blades returned by source
activation thresholds / activation settings
actions by confidence/severity/performance criteria
overrides
tracking / packet capture overrides where present
```

Threat Prevention rule:

```text
rule order
protected scope
profile/action reference
install-on
exceptions
comments / enabled state
```

Access Control:

```text
rule security-related references and settings
inspection-relevant service/application matches
```

HTTPS Inspection:

```text
policy/layer ownership
source/destination/service/category match as returned
action / inspection behavior
certificate/profile references
install-on / gateway relationship
```

### Recorded rules

- Threat Prevention profiles determine which protections and Threat Prevention Software Blades are activated for traffic matched by Threat Prevention rules.
- Threat Prevention rules and exceptions are distinct structural policy elements.
- HTTPS traffic must be inspected when inspection is required for IPS/Threat Prevention to inspect encrypted content.
- HTTPS Inspection policy is layered and can be shared across policy packages.

### Extraction rules

- Do not manufacture a single `SecurityProfileGroup` source object.
- Keep Threat Prevention profile, Threat Rule, Access Rule, and HTTPS Inspection source objects distinct.
- Preserve references between them.
- An “effective security stack” is derived state only if a transform explicitly calculates it.
- Never export private keys or certificate secret material.

---

## 4.6 Time Objects and Time Groups

### Mapping

```text
FortiGate:
config firewall schedule onetime
config firewall schedule recurring
config firewall schedule group

Check Point R81:
Time
Time Group
```

### Management API roots

```text
show-times
show-time-groups
```

### Source fields to retain

```text
uid
name
type
start / end dates where configured
day/month/week-day selection
hour ranges
comments/tags/color
group members for Time Group
```

### Recorded rules

- A Time object can define active hours and/or activation/expiration dates.
- A rule is not enforced when its Time condition has expired or is outside its active interval.
- Check Point documents up to three specific hour ranges in a Time object.
- Time is evaluated using the Security Gateway's local time.
- A Time Group combines multiple Time objects; when a member time condition applies, the rule can be active.

### Extraction rules

- Preserve Time and Time Group as separate object types.
- Preserve member references in a Time Group.
- Do not convert all schedules to UTC unless the source explicitly stores UTC.
- Do not invent an effective schedule outside the explicit source.

---

## 4.7 Service Objects and Service Groups

### Mapping

```text
FortiGate:
config firewall service custom
config firewall service group
config firewall service category

Check Point R81:
service-tcp
service-udp
service-icmp
service-icmp6
service-other
other supported service object types
service-group
```

### Management API roots

```text
show-services-tcp
show-services-udp
show-services-icmp
show-services-icmp6
show-services-other
show-service-groups
```

If a selected policy references additional R81 service object types, retrieve them with the matching R81 v1.8.1 service API rather than coercing them into TCP/UDP.

### Source fields to retain

Common:

```text
uid
name
type
comments
tags
color
```

Protocol-specific:

```text
TCP / UDP
    destination port / port expression
    source port where configured
    session timeout / advanced matching when explicitly configured

ICMP / ICMPv6
    ICMP type
    ICMP code where exposed/configured

Other
    IP protocol number
    match expression / advanced protocol matching if explicitly configured

Service Group
    member references
```

### Recorded rules

- Service matching can be based on IP protocol and TCP/UDP destination port.
- TCP/UDP service objects can also match source ports.
- Protocol signatures/advanced matching may exist for supported service types.

### Extraction rules

- Preserve service object `type`.
- Preserve source-port and destination-port semantics separately.
- Service Group members are references.
- No direct selected Check Point R81 source equivalent should be invented for a FortiGate **service category** object.
- A reporting category can be derived later if justified, but is not Check Point explicit source.

---

## 4.8 Destination NAT / FortiGate VIP Equivalent

### Mapping

```text
FortiGate:
config firewall vip

Check Point R81:
NAT Rule Base destination translation
automatic Static NAT settings where applicable
```

### Management API roots

```text
show-nat-rulebase

plus full details for NAT-capable network objects
```

### Source fields to retain

From the NAT rule:

```text
original-source
original-destination
original-service
translated-source
translated-destination
translated-service
rule order
enabled
install-on
comments
```

From automatic NAT object settings:

```text
auto-rule / automatic NAT enablement
method
translated IPv4/IPv6 address data returned by R81
install-on
hide/static-specific settings
```

### Recorded rules

- Destination translation is part of Check Point NAT policy, not a standalone VIP object.
- Automatic Static NAT can be generated from a network object's NAT properties.
- Manual NAT is required for cases that need more specific source/destination combinations, service translation, one-way static NAT, or dynamic-object participation.

### Extraction rules

- Do not create a Check Point `VIP` source object.
- Keep NAT match criteria and translation together.
- A derived VIP view may be useful for migration but must be traceable to the NAT rule/object NAT settings.

---

## 4.9 FortiGate VIP Group Equivalent

### Mapping

```text
FortiGate:
config firewall vipgrp

Check Point R81:
no direct VIP-group object
```

### Source configuration to collect

```text
show-nat-rulebase
show-hosts
show-networks
show-address-ranges
show-groups
show-groups-with-exclusion
```

### Extraction rules

- Preserve NAT rules independently.
- Preserve network/group references used in original and translated NAT fields.
- Do not create a fake Check Point `VIPGroup` source object.
- Any migration/reporting grouping of related DNAT rules is derived state only.

---

## 4.10 IPS / Threat Prevention

### Mapping

```text
FortiGate:
config ips sensor

Check Point R81:
Threat Prevention profile
Threat Prevention Rule Base
IPS protections
profile activation
protection overrides
Threat Prevention rule exceptions
```

### Management API roots

```text
show-threat-profiles
show-threat-rulebase
show-threat-rule-exception-rulebase
```

Retrieve IPS/protection catalogue information through the R81 Management API protection commands supported by v1.8.1 where required for the selected profile's explicit overrides.

### Source fields to retain

Threat profile:

```text
name / uid
IPS enabled state
activation criteria
severity criteria
confidence criteria
performance-impact criteria
overrides[]
```

Protection override:

```text
protection reference
action
track
capture-packets
other explicit override fields returned by R81
```

Threat rule:

```text
position
protected scope
profile/action reference
install-on
enabled/comments
exceptions
```

### Recorded rules

- Check Point IPS contains protections with attributes such as severity, confidence level and performance impact.
- Profile actions include prevention/detection/inactive behavior according to the profile and explicit overrides.
- Overrides can change protection action, tracking and packet capture behavior.
- Removing an override restores profile-controlled behavior; therefore override presence itself is important source state.
- Threat Prevention rules associate protected scope with a Threat Prevention profile.
- HTTPS Inspection is required when IPS must inspect relevant encrypted HTTPS traffic.

### Extraction rules

- Preserve profile activation criteria and explicit per-protection overrides separately.
- Do not materialize all vendor-default protections as explicit source configuration.
- Only store protections explicitly overridden/configured if the goal is explicit source fidelity; catalogue/default state belongs to effective/reference data.
- Preserve rule exceptions as separate nested policy structure.

---

## 4.11 Static Routes

### Mapping

```text
FortiGate:
config router static

Check Point R81:
Gaia IPv4 static routes
Gaia IPv6 static routes
```

### Gaia Clish extraction roots

IPv4:

```text
show route static all
```

IPv6:

```text
show ipv6 route static all
```

The R81 Gaia feature list records the configuration families:

```text
set static-route ...
show route static ...

set ipv6 static-route ...
show ipv6 route static ...
```

### IPv4 route properties to retain

```text
destination / default
comment
next-hop type:
    gateway address
    logical interface
    blackhole
    reject
next-hop priority
ping
rank
scopelocal
```

### IPv6 route properties to retain

```text
destination / default
comment
next-hop type:
    IPv6 gateway
    interface
    blackhole
    reject
priority
ping6
rank
```

### Recorded rules

- R81 Gaia documents **no `add` command** for static-route configuration; `set static-route` / `set ipv6 static-route` are used to configure them.
- IPv6 support must be enabled before IPv6 static routes are operational.
- Route rank is explicit routing preference source state.

### Extraction rules

- Keep IPv4 and IPv6 routes separate.
- Preserve next-hop type, not just next-hop value.
- Preserve multiple next hops/priorities if returned.
- Do not infer a gateway from the interface or vice versa.
- Extract with `show`; never mutate routes.

---

## 4.12 Management Permission Profiles and Gaia RBA Roles

### Mapping

```text
FortiGate:
config system accprofile

Check Point R81:
Management Permission Profile
Gaia RBA Role (appliance administration, when relevant)
```

### Management API root

```text
show-permission-profiles
```

Retain the complete permission profile returned by the R81 v1.8.1 API, including granular management permissions and Access Control layer delegation where present.

### Gaia Clish roots

```text
show rba all
show rba roles
show rba role <Role Name>
```

For user assignments:

```text
show rba users
show rba user <User Name>
```

### RBA source fields to retain

```text
role name
domain-type
all-features if explicitly represented
read-only feature list
read-write feature list
virtual-system-access
```

### Recorded rules

Management Permission Profiles:

- A Permission Profile is a reusable set of Security Management / SmartConsole administrator permissions.
- Multiple administrators can use the same Permission Profile.
- The **Management API Login** permission controls API login permission.
- Default permission profiles cannot be modified/deleted; they can be cloned.
- Layer permissions can delegate ownership of Access Control layers.

Gaia RBA:

- Roles have read-only and/or read-write Gaia feature permissions.
- `all-features` is equivalent to full Gaia feature permission.
- RBA roles can restrict VSX Virtual System access.
- The same Gaia user can be assigned one or more RBA roles.

### Extraction rules

- Do not collapse Management Permission Profile and Gaia RBA Role into one source type.
- Preserve granular permissions rather than synthesizing only `read`/`write`.
- Preserve VSX access restrictions.
- Preserve user-to-role assignment separately from role definition.

---

## 4.13 Administrators

### Mapping

```text
FortiGate:
config system admin

Check Point R81:
Management administrator
Gaia local user + RBA assignment where the account administers the appliance
```

### Management API root

```text
show-administrators
```

Retain the administrator identity, authentication method metadata and Permission Profile reference(s) exposed by R81.

### Gaia Clish roots

```text
show users
show user <UserName>
show rba user <UserName>
```

### Gaia local user source fields to retain

```text
username
uid
gid
home directory
real name
shell
lock-out state
force-password-change state
RBA roles
access mechanisms
```

### Recorded Gaia rules

R81 Gaia documents:

```text
add user <UserName> uid <User ID> homedir <Path>
set user <UserName> ...
show users
show user <UserName> ...
```

Important semantics:

- UID `0` is used for administrator/RADIUS-style accounts; non-administrator local users use non-zero IDs in the documented range.
- A newly added Gaia local user needs a password before login is possible.
- Default `admin` and `monitor` accounts have restrictions on what can be changed/deleted.

### Extraction rules

- Keep Management administrators separate from Gaia OS users.
- Preserve Permission Profile references for management administrators.
- Preserve Gaia RBA role/access-mechanism relationships for Gaia users.
- Never export password or password-hash content.
- If source indicates password material exists, record only safe configured/not-configured metadata.

---

## 4.14 Gaia DHCP Server

### Mapping

```text
FortiGate:
config system dhcp server

Check Point R81:
Gaia DHCP Server
```

### Gaia Clish extraction roots

```text
show dhcp server all
show dhcp server status
show dhcp server subnets
show dhcp server subnet <Subnet Entry> ip-pools
```

### Recorded configuration syntax

```text
add dhcp server subnet <Subnet Entry>
    netmask <Mask>
    include-ip-pool start <First IPv4 Address> end <Last IPv4 Address>
    exclude-ip-pool start <First IPv4 Address> end <Last IPv4 Address>

set dhcp server subnet <Subnet Entry>
    enable | disable
    include-ip-pool <First-Last> enable|disable
    exclude-ip-pool <First-Last> enable|disable
    default-lease <Seconds>
    max-lease <Seconds>
    default-gateway <IPv4 Address>
    domain <Domain Name>
    dns <DNS Server IPv4 Address[, ...]>

set dhcp server enable|disable
```

### Source fields to retain

```text
server process enabled state
subnet
netmask / prefix
subnet enabled state
included address pools and enabled states
excluded address pools and enabled states
default lease
maximum lease
default gateway
domain name
DNS server list
```

### Recorded rules

- DHCP subnet entries are associated with Gaia interfaces/networks.
- Multiple DNS server addresses can be supplied in order.
- Included and excluded pools are explicit source ranges.
- R81 documentation requires `save config` after modifications; extraction remains read-only.

### Extraction rules

- Preserve disabled subnets and disabled pools.
- Do not synthesize reservations if R81 source did not configure them.
- Do not infer DHCP defaults as explicit source values if not returned by the source.
- This R81 Gaia DHCP model is IPv4-oriented in the documented selected command family.

---

## 4.15 SD-WAN

### Mapping

```text
FortiGate:
config system sdwan

Check Point R81.00:
NO DIRECT EQUIVALENT IN THIS SELECTED R81 SOURCE MODEL
```

### Extraction root

```text
None for an R81.00 SD-WAN equivalent.
```

### Rule

Do not map later Check Point Quantum SD-WAN / Infinity Portal models backward into R81.00.

### Extraction rules

- Record the source area as unsupported/no-equivalent for Check Point R81.00.
- Do not create a fake `sdwan` object.
- Do not use policy-based routing, static routes, ISP redundancy, or VPN topology as a substitute unless a separate project requirement explicitly asks for those features.
- Later Check Point releases/products have separate SD-WAN architecture; that is outside this R81.00 reference.

---

## 4.16 Security Zones and Interface Topology

### Mapping

```text
FortiGate:
config system zone

Check Point R81:
Security Zone object
Gateway / Cluster interfaces
interface topology
zone assignment
```

### Management API roots

```text
show-security-zones
show-simple-gateways
show-simple-clusters
```

Use `show-gateways-and-servers` / the applicable R81 gateway API when the simple object APIs do not expose the required gateway/interface source fields.

### Source fields to retain

Security Zone object:

```text
uid
name
comments
tags
color
```

Gateway/cluster interface:

```text
interface name
IP/subnet metadata required to identify topology
interface topology / leads-to information returned by source
security-zone enabled/assignment state
specific zone reference when explicitly assigned
auto-calculated state when exposed
```

### Recorded R81 rules

- A Security Zone object represents a part of the network.
- A Gateway interface is assigned to a Security Zone.
- Security Zone objects can be used in Access Control Rule Base Source/Destination fields.
- By default, a zone can be calculated from where the interface **Leads To**; administrators can instead explicitly specify a Security Zone.
- NAT policy and Threat Prevention policy support Security Zones on R81 Security Gateways.

### Extraction rules

- The zone object alone is insufficient to reconstruct membership.
- Interface-to-zone relationship must come from the managed Gateway/Cluster interface topology source.
- Preserve whether the zone was explicitly specified versus auto-calculated when the API exposes that distinction.
- Do not infer interface hierarchy in the parser.
- For VSX or object types not completely represented by the R81 simple APIs, preserve the limitation/unknown source state instead of guessing.

---

## 4.17 User Groups, Directory Identities, and Access Roles

### Mapping

```text
FortiGate:
config user group

Check Point R81:
internal user-group
LDAP / Active Directory identities and groups
Access Role for identity-aware policy matching
```

### Management API roots

```text
show-user-groups
show-access-roles
```

Also collect the LDAP / directory configuration and object references required by the returned access roles/user groups through the R81 API surfaces available in v1.8.1.

### Internal User Group source fields

```text
uid
name
members[]
email where present
comments/tags/color
group memberships where returned
```

### Access Role source fields

Preserve the explicit selectors returned by R81, including:

```text
uid
name
networks
users / user groups
machines
remote-access clients
comments/tags/color
```

### Recorded R81 rules

- Access Roles can match network location, users/groups, machines, and Remote Access client types.
- Specific users/groups can include internal users and directory identities.
- Before using Active Directory users/machines/groups in an Access Role, LDAP connectivity to the directory must exist.
- Identity Awareness automatically updates identity information when LDAP group membership changes.
- Access Roles can be used as Source and, where applicable, Destination in Access Control rules.

### Extraction rules

- Keep a static internal `user-group` separate from directory-backed identity state.
- Keep Access Role separate from User Group.
- Preserve directory references/DNs returned by the source; do not replace them with a static resolved member list.
- Runtime LDAP membership is derived/external state unless explicitly stored in Check Point management source.

---

## 4.18 Internal Users

### Mapping

```text
FortiGate:
config user local

Check Point R81:
internal Check Point user objects
```

### Management API root

```text
show-users
```

Use the exact R81 v1.8.1 API user schema returned by the server.

### Source fields to retain

Retain non-secret source metadata such as:

```text
uid
name
user type / authentication method metadata
expiration / validity metadata when explicitly configured
group memberships
comments/tags/color
other non-secret authentication policy fields explicitly returned
```

### Extraction rules

- Internal authentication users are not the same as Management administrators.
- Preserve user-to-group relationships.
- Preserve authentication method metadata without exporting credentials.
- Never export passwords, hashes, challenge/response secrets, shared secrets, tokens, or private keys.
- Unknown authentication leaves should be preserved only if they are non-secret; secret-bearing unknown leaves must be redacted/dropped.

---

## 4.19 Site-to-Site IPsec VPN

### Mapping

```text
FortiGate:
config vpn ipsec phase1
config vpn ipsec phase1-interface
config vpn ipsec phase2
config vpn ipsec phase2-interface

Check Point R81:
Star VPN Community
Meshed VPN Community
Security Gateway / Cluster VPN settings
Interoperable Device
VPN domain
Gaia VTI
```

### Management API roots

```text
show-vpn-communities-star
show-vpn-communities-meshed
show-simple-gateways
show-simple-clusters
show-interoperable-devices
```

Use the applicable full Gateway/Cluster API object when the simple API does not expose a required VPN property in R81 v1.8.1.

### Community source fields to retain

```text
uid
name
community type: star | meshed
member gateways/clusters/interoperable devices
center / satellite role for Star communities
IKE / IPsec encryption and authentication settings returned by source
Perfect Forward Secrecy / DH settings returned by source
shared-secret configured metadata only, never value
routing / tunnel-sharing settings returned by source
comments/tags/color
```

### Gateway / Interoperable Device fields to retain

```text
VPN participation
VPN domain type
VPN domain object/reference
interface/topology data relevant to VPN
identity / IP addresses
VPN-related source settings returned by R81
```

Interoperable Devices are separate managed objects and can have their own interfaces and VPN-domain configuration.

### Gaia VTI extraction roots

```text
show vpn tunnels
show vpn tunnel <Tunnel ID>
```

R81 Gaia documents VTI configuration families such as:

```text
add vpn tunnel <Tunnel ID> type numbered local <Local IP> remote <Remote IP> peer <Peer Name>

add vpn tunnel <Tunnel ID> type unnumbered peer <Peer Name> dev <Local Interface>
```

### Recorded VTI rules

- VTI is used for route-based VPN.
- The VPN Community and member Gateways must exist before the VTI is configured.
- VTI names use `vpnt<VPN Tunnel ID>` and the documented tunnel ID range is 1-99.
- Numbered and unnumbered VTIs are distinct.

### Extraction rules

- Do not collapse community, gateway VPN properties, VPN domain, interoperable device, and VTI into one Check Point source object.
- Preserve Star versus Meshed architecture.
- Preserve member roles and references.
- Preserve VPN domain as explicit source ownership/reference.
- Keep VTI as Gaia source state and relate it to management VPN objects later.
- Never export pre-shared-key content or private key material.

---

## 4.20 Remote Access VPN / Mobile Access

### Mapping

```text
FortiGate:
config vpn ssl ...

Check Point R81:
Remote Access VPN gateway settings
Mobile Access gateway settings
RemoteAccess VPN Community
Access Roles
users / user groups / directory identities
authentication and certificate references
Access Control policy
```

### Required source areas

Management objects/policy:

```text
RemoteAccess community
participating Security Gateways
participating user groups
Gateway / Cluster VPN settings
Access Roles
internal users and user groups
LDAP/directory references
Access Control Rule Base
Mobile Access inline/ordered layers where configured
```

Gateway settings to preserve where exposed by the R81 Management API include, as applicable:

```text
Remote Access blade / Mobile Access blade enablement
VPN domain
Visitor Mode
Office Mode / address assignment
authentication method/profile references
certificate references
client / portal settings returned by source
Mobile Access application/resource policy settings
```

### Recorded R81 rules

- All Remote Access Gateways must participate in a Remote Access VPN Community.
- The default `RemoteAccess` community is the central community used by Remote Access configuration.
- The Remote Access Community contains participating Gateways and participating user groups.
- A VPN community by itself does **not** grant network access; Access Control rules still determine permitted services/resources.
- R81 allows Remote Access / VPN clients to be represented through Access Roles in Access Control policy.
- Identity Awareness must support identity-based Access Role enforcement.
- When Mobile Access or IPsec VPN is enabled, the gateway participates in Remote Access architecture and Mobile Access rules can be integrated into Unified Access Policy / inline layers.
- Remote Access supports VPN domain configuration, Visitor Mode and Office Mode as separate gateway settings.

### Extraction rules

- Do not create a synthetic FortiGate-style SSL-VPN source object.
- Keep `RemoteAccess` community, gateway settings, access roles, users/groups, and Access Control rules separate.
- Preserve Office Mode address allocation separately from ordinary network/NAT address objects.
- Preserve authentication/certificate/profile references rather than embedding them.
- Never export authentication secrets or private-key material.

---

# 5. Recommended Extraction Order

This is a dependency-aware extraction order for reporting/migration. It is not a claim that Check Point internally stores source configuration in this sequence.

```text
1. Management Domain / session context
2. Policy packages and layer inventory

3. Host objects
4. Network objects
5. Address ranges
6. DNS/domain objects
7. Wildcard / Dynamic / Updatable objects when referenced
8. Network Groups
9. Groups with Exclusion

10. Service objects by type
11. Service Groups
12. Time objects
13. Time Groups
14. Security Zone objects

15. Internal users
16. Internal user groups
17. Directory/LDAP references needed by selected identities
18. Access Roles

19. Management Permission Profiles
20. Management administrators
21. Gaia users and RBA roles

22. Gateway objects / Cluster objects / interfaces / topology
23. Interoperable Devices
24. VPN Communities
25. Gateway/Cluster VPN settings and VPN domains
26. Gaia VTIs

27. Threat Prevention profiles
28. Threat Prevention protections/explicit overrides
29. Threat Prevention Rule Base and exceptions
30. HTTPS Inspection source needed by selected policy

31. NAT Rule Base
32. Access Control Rule Bases, sections and inline layers

33. Gaia IPv4 static routes
34. Gaia IPv6 static routes
35. Gaia DHCP server

36. Record SD-WAN as no R81.00 equivalent
```

Why object-first:

```text
rules reference objects
NAT references address/service objects
Access Rules reference zones/services/times/identities
VPN communities reference gateways/devices
Threat Rules reference profiles
```

Relationships are resolved after source extraction.

---

# 6. Parser / Source-Model Guidance

## 6.1 Suggested primary Check Point source sections

Recognize at least:

```text
Management domain

host
network
address-range
dns-domain
wildcard
dynamic-object
updatable-object

group
group-with-exclusion

service-tcp
service-udp
service-icmp
service-icmp6
service-other
service-group

time
time-group

security-zone
user
user-group
access-role

permission-profile
administrator

gateway
cluster
interoperable-device
vpn-community-star
vpn-community-meshed

policy-package
access-layer
access-section
access-rule
nat-section
nat-rule
threat-layer
threat-section
threat-rule
threat-rule-exception
threat-profile
https-inspection source section(s)
```

Gaia sections:

```text
static-route-ipv4
static-route-ipv6
dhcp-server
gaia-user
gaia-rba-role
gaia-rba-user-assignment
vpn-tunnel-vti
```

## 6.2 Preserve object identity

Check Point heavily uses object UIDs.

For managed objects retain:

```text
uid
name
type
domain
```

References should preferentially retain UID plus display name/type when returned.

Do not use only object names as globally unique keys across Domains.

## 6.3 Preserve policy structure

Correct:

```text
Policy Package
  Access Layer A
    Section 1
      Rule 1
      Rule 2 -> Apply Inline Layer B
        Inline Layer B
          Rule B1
          Rule B2
```

Incorrect:

```text
flat_rules = [Rule1, Rule2, RuleB1, RuleB2]
```

The flattened representation loses source ownership and enforcement semantics.

## 6.4 Keep automatic NAT attached to its source object

Correct:

```text
Network object "Web-Net"
  nat-settings.auto-rule = true
  nat-settings.method = static
  ...
```

plus the generated/effective NAT Rule Base view if separately returned.

Incorrect:

```text
IPPool(name="Web-Net", ...)
```

when no such Check Point source object exists.

## 6.5 Keep Gaia state separate

Correct:

```text
Gateway Management Object
  uid/name/interfaces/VPN properties

Gaia Device State
  static routes
  DHCP
  local users
  RBA
  VTI
```

Relate them by the managed device/gateway identity in the relationship layer.

## 6.6 Unknown fields

For a recognized selected object with a non-secret field not yet modeled:

```text
preserve in raw_extra / source appendix
```

For an unknown object outside selected scope:

```text
Source Inventory / unsupported source section
```

For an unknown secret-bearing field:

```text
detect
-> redact/drop value
-> optionally record safe presence metadata
```

Never preserve an unknown field blindly if it can contain credentials or key material.

---

# 7. Cross-Vendor Modeling Rules for These 20 Areas

## 7.1 Do not restore a vendor-neutral IR

Keep Check Point explicit source state as Check Point source state.

Cross-vendor comparison belongs in relationships/transforms/derived views.

## 7.2 Different-model mappings

Do not force these into fake Check Point source objects:

```text
FortiGate IP pool
    -> Check Point NAT source translation / object automatic NAT

FortiGate VIP
    -> Check Point NAT destination translation / object automatic NAT

FortiGate VIP group
    -> no direct Check Point object

FortiGate profile-group
    -> Threat Prevention + Access Control + HTTPS Inspection source areas

FortiGate phase1/phase2
    -> VPN Community + Gateway/Cluster/Interoperable Device + VPN domain + VTI

FortiGate SSL VPN
    -> Remote Access / Mobile Access architecture

FortiGate SD-WAN
    -> no direct Check Point R81.00 equivalent in this selected source model
```

## 7.3 Source versus derived examples

Correct:

```text
Check Point source:
NAT rule #12
  original-source = "Internal-Net"
  translated-source = "203.0.113.10"
  ...

Derived view:
Source NAT mapping candidate
  owner = NAT rule #12
  translated address = 203.0.113.10
```

Incorrect:

```text
Check Point source:
IPPool(name="NAT-rule-12", ...)
```

Correct:

```text
Check Point source:
Security Zone "DMZZone"
Gateway interface eth2
  zone assignment = DMZZone
```

Incorrect:

```text
SecurityZone.members = [eth2]
```

if the member relationship actually comes from gateway interface topology rather than the zone object.

---

# 8. Verification Checklist

For every extraction run:

- [ ] Use the R81 Management API version exposed by the actual management server; do not silently apply a later schema.
- [ ] Preserve Management Domain ownership.
- [ ] Preserve object UID, name and type.
- [ ] Preserve policy package and layer ownership.
- [ ] Preserve Access/NAT/Threat rule ordering.
- [ ] Preserve sections and inline-layer structure.
- [ ] Preserve disabled objects/rules where returned.
- [ ] Preserve references instead of replacing them with expanded copies.
- [ ] Preserve Group-with-Exclusion `include` and `except` semantics.
- [ ] Preserve Dynamic Object source separately from gateway-resolved runtime ranges.
- [ ] Preserve Updatable Object identity instead of materializing cloud IP contents as explicit source.
- [ ] Preserve automatic NAT object settings separately from manual NAT rules.
- [ ] Preserve original versus translated NAT fields.
- [ ] Keep Threat Profile, Threat Rule, exception and HTTPS Inspection source distinct.
- [ ] Keep Management Permission Profiles separate from Gaia RBA roles.
- [ ] Keep Management administrators separate from Gaia local users.
- [ ] Keep internal users/groups separate from LDAP/directory identities and Access Roles.
- [ ] Preserve Security Zone object separately from interface topology/zone assignment.
- [ ] Keep IPv4 and IPv6 static routes distinct.
- [ ] Preserve static-route next-hop type and priority/rank.
- [ ] Preserve DHCP server status, subnet status, pools, leases, gateway, domain and DNS.
- [ ] Keep VPN Community, gateway VPN settings, interoperable devices, VPN domains and VTIs distinct.
- [ ] Keep Remote Access community/gateway settings/Access Roles/policy distinct.
- [ ] Record SD-WAN as **no direct R81.00 equivalent**; do not invent one.
- [ ] Never export passwords, hashes, PSKs, shared secrets, private keys, API session IDs or tokens.
- [ ] Preserve non-secret unknown selected-object fields in `raw_extra`.
- [ ] Preserve unsupported selected-scope objects in Source Inventory/source appendices.

---

# 9. Official R81 Sources Used

## 9.1 Primary requested CLI reference

**Check Point R81 CLI Reference Guide**  
https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_CLI_ReferenceGuide/CP_R81_CLI_ReferenceGuide.pdf

Relevant source areas:

```text
Managing Security through API
API Server configuration/status
mgmt_cli
CLI syntax conventions
```

The CLI guide explicitly directs per-object API work to the Management API Reference and Gaia command work to the Gaia Administration Guide.

## 9.2 Management API reference required by the CLI guide

**Check Point Management API Reference**  
https://sc1.checkpoint.com/documents/latest/APIs/index.html

For an R81 Management Server, use the R81 API version identified by the CLI guide (**v1.8.1**) / local version-specific documentation:

```text
https://<Management-Server-IP>/api_docs
```

This is the authority for exact `show-*` request parameters and response fields.

## 9.3 R81 Gaia Administration Guide

**R81 Gaia Administration Guide**  
https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_Gaia_AdminGuide/CP_R81_Gaia_AdminGuide.pdf

Selected topics used:

```text
Configuring IPv4 Static Routes in Gaia Clish
IPv6 Static Routes
Configuring a DHCP Server in Gaia Clish
Managing User Accounts in Gaia Clish
Configuring Roles in Gaia Clish
List of Available Features in Roles
VPN Tunnel Interfaces / route-based VPN
```

## 9.4 R81 Security Management Administration Guide

**R81 Quantum Security Management Administration Guide**  
https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_SecurityManagement_AdminGuide/CP_R81_Quantum_SecurityManagement_AdminGuide.pdf

Selected topics used:

```text
Object Categories
Hosts / Networks / Address Ranges
DNS Domains
Wildcard Objects
Dynamic Objects
Updatable Objects
Network Groups
Security Zones
Access Roles
Access Control Layers / Ordered Layers / Inline Layers / Sections
NAT Policy / Automatic NAT / Manual NAT
Threat Prevention Profiles and Rules
IPS Protections and overrides
HTTPS Inspection
Administrators and Permission Profiles
```

## 9.5 R81 Remote Access VPN Administration Guide

https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_RemoteAccessVPN_AdminGuide/CP_R81_RemoteAccessVPN_AdminGuide.pdf

Selected topics used:

```text
RemoteAccess VPN Community
Participating Gateways
Participating User Groups
VPN Domain
Visitor Mode
Office Mode
Access Control rules for Remote Access
Access Roles for Remote Access
```

## 9.6 R81 Mobile Access Administration Guide

https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_MobileAccess_AdminGuide/CP_R81_MobileAccess_AdminGuide.pdf

Selected topics used:

```text
Mobile Access in Unified Access Policy
RemoteAccess community relationship
Mobile Access rules / inline layers
Mobile Access gateway and application access behavior
```

---

# 10. Compact Extraction Root List

```text
# Management API — address-like objects
show-hosts
show-networks
show-address-ranges
show-dns-domains
show-dynamic-objects
show-updatable-objects
show-groups
show-groups-with-exclusion

# Management API — services / schedules
show-services-tcp
show-services-udp
show-services-icmp
show-services-icmp6
show-services-other
show-service-groups
show-times
show-time-groups

# Management API — policy
show-packages
show-access-layers
show-access-rulebase
show-nat-rulebase
show-threat-profiles
show-threat-rulebase
show-threat-rule-exception-rulebase

# Management API — administration
show-permission-profiles
show-administrators

# Management API — topology / identity / VPN
show-security-zones
show-simple-gateways
show-simple-clusters
show-gateways-and-servers
show-users
show-user-groups
show-access-roles
show-vpn-communities-star
show-vpn-communities-meshed
show-interoperable-devices

# Gaia — routing
show route static all
show ipv6 route static all

# Gaia — DHCP
show dhcp server all
show dhcp server status
show dhcp server subnets
show dhcp server subnet <Subnet Entry> ip-pools

# Gaia — users / RBA
show users
show user <UserName>
show rba all
show rba roles
show rba role <Role Name>
show rba users
show rba user <User Name>

# Gaia — route-based VPN
show vpn tunnels
show vpn tunnel <Tunnel ID>
```

### R81 version rule

Before coding a Management API parser against these command families:

```text
1. Open the target R81 Management Server's /api_docs.
2. Confirm the command exists in its exposed API version.
3. Confirm exact field names and nesting.
4. Preserve unknown non-secret fields.
5. Do not silently import fields only documented in later API versions.
```

---

## End of selected reference
