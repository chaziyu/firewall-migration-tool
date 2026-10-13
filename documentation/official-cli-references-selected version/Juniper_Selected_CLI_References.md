# Juniper Junos Selected CLI References

> **Purpose:** Source-configuration extraction reference for the firewall migration/extraction project.
>
> **Baseline:** The 20 FortiGate selected configuration areas used by this project.
>
> **Source rule:** This file is derived only from official Juniper Networks PDF documentation listed in **Official PDF Sources**. It does not use third-party syntax references.
>
> **Modeling rule:** Keep Junos explicit source state as Junos source state. Do not manufacture FortiGate-shaped Junos source objects where Junos uses a different architecture.
>
> **Security rule:** Never export, log, persist, or report actual passwords, encrypted password strings, pre-shared keys, shared secrets, LDAP bind passwords, private keys, certificate private-key material, or equivalent authentication secret values. Safe metadata such as `Password Configured = Yes` or `Pre-Shared Key Configured = Yes` is allowed.

---

# 1. Extraction Principles

## 1.1 Preferred source form: Junos `set` format

The Junos OS CLI User Guide documents `display set` as the way to display configuration as the `set` commands that create it.

Preferred extraction form from configuration mode:

```text
[edit]
show | display set
```

The guide also shows that inactive configuration is retained in this representation:

```text
set ...
deactivate ...
```

Therefore the extractor should preserve both the configuration statement and its active/inactive state.

### Rule

```text
explicit set statement
deactivate statement
configuration-group statement
apply-groups reference
apply-groups-except reference
```

are source configuration and must remain distinguishable.

Do not silently convert an inactive statement into an absent statement.

**Official PDF:** *CLI User Guide for Junos OS*, viewer pages 180–183.

---

## 1.2 Configuration groups and inheritance

Junos supports reusable configuration groups with `groups`, `apply-groups`, and `apply-groups-except`.

The CLI guide documents:

```text
groups {
    <group-name> {
        ...
    }
}

apply-groups <group-name>;
apply-groups-except [ <group-names> ];
```

`display inheritance` shows inherited configuration and identifies the group from which a value was inherited:

```text
show | display inheritance
```

The guide also documents:

```text
show | display inheritance no-comments
```

for an expanded view without the inheritance comments.

### Source-model rule

Keep these separate:

```text
explicit local statement
configuration-group statement
apply-groups relationship
inherited/effective statement
```

Do not replace explicit source state with the expanded inherited configuration.

If a later transform calculates effective Junos configuration, that output is derived/effective state.

`apply-groups-except` is explicit source state and must be preserved because it changes inheritance behavior.

**Official PDF:** *CLI User Guide for Junos OS*, viewer pages 143–146.

---

## 1.3 Missing configuration

A missing Junos statement means:

```text
not explicitly configured in the extracted source
```

Do not populate source-model fields with documented or assumed Junos defaults.

Keep distinct:

```text
explicit source
inherited source
derived relationship
effective/default behavior
unknown/unparsed source
```

---

## 1.4 Configuration validation

The CLI guide documents:

```text
commit check
```

as the configuration-mode syntax/consistency validation step.

For this extraction project:

```text
Validation detects and reports.
Validation does not mutate or repair source configuration.
```

The extractor itself should remain read-only.

**Official PDF:** *CLI User Guide for Junos OS*, viewer pages 183–186.

---

## 1.5 Scope ownership

Junos configuration can be scoped by architecture such as:

```text
default system/device scope
logical-systems <name>
routing-instances <name>
security zones
address books attached to zones
global address book
```

Preserve the owning scope instead of flattening objects with the same name into one namespace.

Routing-instance ownership is especially important for:

```text
static routes
NAT
DHCP address assignment where configured in an instance
APBR/AppQoE paths
```

---

## 1.6 References are relationships

Examples:

```text
security policy -> address/address-set
security policy -> application/application-set
security policy -> scheduler
security policy -> UTM policy
security policy -> IDP policy

source NAT rule -> source NAT pool
destination NAT rule -> destination NAT pool

IKE gateway -> IKE policy
IKE policy -> IKE proposal
IPsec VPN -> IKE gateway
IPsec VPN -> IPsec policy
IPsec policy -> IPsec proposal

Secure Connect remote-access profile -> access profile
Secure Connect remote-access profile -> client-config
Secure Connect remote-access profile -> IPsec VPN
```

Store the source reference first.

Resolve the relationship separately.

Do not expand referenced objects into the owner and overwrite the original source representation.

---

## 1.7 Secret handling

Secret-bearing Junos hierarchies documented by the selected PDFs include, among others:

```text
system login user ... authentication ...
access profile ... client ... firewall-user password ...
access profile ... radius-server ... secret ...
access profile ... ldap-options ... password ...
security ike policy ... pre-shared-key ...
certificate/private-key related configuration
```

Extractor behavior:

```text
secret leaf detected
    -> do not store its value
    -> do not place value in raw_extra
    -> do not log value
    -> optionally record safe presence metadata
```

Safe examples:

```text
Password Configured = Yes
Pre-Shared Key Configured = Yes
LDAP Bind Password Configured = Yes
Private Key Present = Yes
```

The official Junos User Access PDF explicitly identifies several access-profile password/secret hierarchy locations, and the IPsec/Secure Connect PDFs contain pre-shared-key and authentication-secret configuration examples.

---

# 2. Mapping Index

| # | FortiGate selected config | Junos source configuration to extract | Mapping |
|---|---|---|---|
| 1 | `config firewall address` | `security address-book ... address ...` | Direct |
| 2 | `config firewall addrgrp` | `security address-book ... address-set ...` | Direct |
| 3 | `config firewall ippool` | `security nat source pool ...` plus source NAT rule sets/rules | Direct pool + split rule model |
| 4 | `config firewall policy` | `security policies from-zone ... to-zone ... policy ...`; global policies where present | Direct |
| 5 | `config firewall profile-group` | `security utm utm-policy ...`, `security idp idp-policy ...`, and security-policy application-services references | No single equivalent |
| 6 | `config firewall schedule group/onetime/recurring` | `schedulers scheduler ...` | Mostly direct; no FortiGate-style schedule-group source object identified |
| 7 | `config firewall service category/custom/group` | `applications application ...`, `applications application-set ...` | Direct except service category |
| 8 | `config firewall vip` | destination NAT pools/rules and static NAT rules | Different NAT model |
| 9 | `config firewall vipgrp` | NAT rules/pools plus address/address-set references | No direct VIP-group object |
| 10 | `config ips sensor` | `security idp idp-policy ...` | Closest direct equivalent |
| 11 | `config router static` | `routing-options static route ...`; routing-instance static routes where present | Direct |
| 12 | `config system accprofile` | `system login class ...` | Direct |
| 13 | `config system admin` | `system login user ...` | Direct |
| 14 | `config system dhcp server` | `system services dhcp-local-server ...` + `access address-assignment ...` | Split model |
| 15 | `config system sdwan` | `security advance-policy-based-routing ...` plus AppQoE path/SLA configuration and referenced interfaces/routing instances | Split model |
| 16 | `config system zone` | `security zones security-zone ...` | Direct |
| 17 | `config user group` | access-profile client-group / identity-role relationships and external AAA group configuration where present | Different model |
| 18 | `config user local` | `access profile ... client ... firewall-user ...` | Closest equivalent for local firewall-auth users |
| 19 | `config vpn ipsec phase1/phase2` | `security ike ...` + `security ipsec ...` | Split model |
| 20 | `config vpn ssl ...` | `security remote-access ...` plus IKE/IPsec/access-profile/address pool/`st0`/zone/policy dependencies | Different architecture: Juniper Secure Connect |

---

# 3. Selected Junos Configuration References

## 3.1 Address Objects

### Mapping

```text
FortiGate:
config firewall address

Junos:
security address-book <book-name> address <address-name> ...
```

### Official PDF

*Security Policies User Guide for Security Devices*

Relevant viewer pages: 41–44, 61, 136.

### Source hierarchy to recognize

The official PDF demonstrates address objects under:

```text
security address-book <book-name> address <name> <prefix>
security address-book <book-name> address <name> range-address <start> to <end>
security address-book <book-name> address <name> dns-name <name>
security address-book <book-name> address <name> wildcard-address <address/wildcard-mask>
```

Examples in the PDF include IPv4, IPv6, range-address, DNS-name, and wildcard-address forms.

Address books can be associated with zones:

```text
security address-book <book-name> attach zone <zone-name>
```

Junos also supports a global address book used in contexts such as global policies and NAT.

### Rules

- Preserve the configured address representation.
- Do not normalize a range, DNS name, wildcard address, IPv4 prefix, and IPv6 prefix into one generic subnet field.
- Preserve address-book ownership.
- Preserve zone attachment as a relationship.
- Preserve global-address-book ownership as distinct from zone-attached address books.
- Reserved policy address keywords such as `any`, `any-ipv4`, and `any-ipv6` are not user address objects.
- NAT can reference global address-book objects; do not duplicate those objects into a NAT-specific source model.
- Unknown non-secret leaves under a recognized address object should be preserved as source-only/raw data.

---

## 3.2 Address Sets

### Mapping

```text
FortiGate:
config firewall addrgrp

Junos:
security address-book <book-name> address-set <set-name> ...
```

### Official PDF

*Security Policies User Guide for Security Devices*

Relevant viewer pages: 44, 61.

### Source hierarchy

The PDF demonstrates:

```text
security address-book <book-name> address-set <set-name> address <address-name>
```

Address sets may reference address objects in the same address-book/zone context supported by the source configuration.

### Rules

- Members are references.
- Do not copy the child address object into the address-set source object.
- Preserve address-set name, address-book ownership, and member names.
- Preserve nested address-set references if present in source.
- Do not materialize a set into a flattened IP list in explicit source state.
- A resolved member list is derived state only.

---

## 3.3 Source NAT and FortiGate IP Pool Equivalent

### Mapping

```text
FortiGate:
config firewall ippool

Junos:
security nat source pool <pool-name> ...
security nat source rule-set <rule-set-name> ...
```

### Official PDF

*Network Address Translation User Guide*

Relevant viewer pages: 16–24, 61, 116–124.

### Source NAT pool hierarchy

The PDF documents named source NAT pools:

```text
security nat source pool <pool-name> address ...
```

Source NAT pool capabilities documented in the guide include address ranges and pool/port behaviors such as:

```text
port no-translation
port translation
address-pooling behavior
PAT-related behavior
pool utilization alarms
```

Model only leaves explicitly found in source.

### Source NAT rule hierarchy

The PDF demonstrates:

```text
security nat source rule-set <rule-set-name> from zone <zone>
security nat source rule-set <rule-set-name> to zone <zone>

security nat source rule-set <rule-set-name> rule <rule-name> match source-address ...
security nat source rule-set <rule-set-name> rule <rule-name> match destination-address ...

security nat source rule-set <rule-set-name> rule <rule-name> then source-nat pool <pool-name>
security nat source rule-set <rule-set-name> rule <rule-name> then source-nat off
```

Other supported rule-set ownership/match forms present in source should be preserved rather than coerced to zones.

### NAT processing rules documented by Juniper

The NAT guide documents an order in which NAT stages interact with route and security-policy processing.

Important high-level behavior:

```text
static NAT and destination NAT:
    processed before route/security-policy lookup

static NAT:
    higher precedence than destination NAT when both apply

source NAT:
    processed after route/security-policy lookup in the forward flow
```

Do not turn these processing semantics into explicit source fields unless the configuration actually contains corresponding statements.

### Extraction rules

Keep separate:

```text
SourceNATPool
SourceNATRuleSet
SourceNATRule
```

Do not make a single synthetic `IPPool` object containing rule match behavior.

A FortiGate-like "IP pool usage" report can be derived:

```text
pool
    <- referenced by
source NAT rule
    <- owned by
source NAT rule-set
```

Preserve rule order/position where the Junos source or operational configuration exposes ordering.

---

## 3.4 Security Policies

### Mapping

```text
FortiGate:
config firewall policy

Junos:
security policies from-zone <source-zone> to-zone <destination-zone> policy <name> ...
security policies global policy <name> ...
```

### Official PDF

*Security Policies User Guide for Security Devices*

Relevant viewer pages: 111–120, 202–204, 245–246.

### Zone policy hierarchy

The documented model is:

```text
security policies
    from-zone <source-zone>
        to-zone <destination-zone>
            policy <policy-name>
                match ...
                then ...
                scheduler-name ...
```

Core match concepts documented throughout the guide include:

```text
source-address
destination-address
application
source-identity where identity policy is used
```

Actions include permit/deny behavior and optional application services.

### Global policies

The guide documents:

```text
security policies global policy <name> ...
```

Global policies can match traffic across zones and use global address-book objects.

The guide states that regular policies have priority over global policies; global policy lookup occurs when no matching regular policy is found in the applicable context.

### Rule order

Security policy order is meaningful.

Preserve source ordering.

Do not sort policies alphabetically.

### Dependencies

The security-policy guide's configuration examples build dependencies before rules, including:

```text
zones
address-book objects
applications/application sets
policies
schedulers where used
```

### Extraction rules

Preserve at least:

```text
policy scope
source zone
destination zone
policy name
policy ordering
match subtree
action subtree
logging/action settings
application-services references
scheduler reference
inactive/deactivated state
```

Keep references by name.

Do not expand address sets, application sets, schedulers, UTM policies, or IDP policies into the policy source object.

---

## 3.5 FortiGate Profile-Group Equivalent

### Mapping

```text
FortiGate:
config firewall profile-group

Junos:
security utm utm-policy <name> ...
security idp idp-policy <name> ...
security policy ... then permit application-services ...
```

### Official PDFs

- *Content Security User Guide*
- *Intrusion Detection and Prevention User Guide*
- *Security Policies User Guide for Security Devices*

### Important model rule

The selected official PDFs do not define one Junos source object that corresponds to a FortiGate security `profile-group`.

Keep the source areas separate.

### A. UTM policy

The Content Security PDF demonstrates:

```text
security utm utm-policy <name> anti-virus http-profile <profile>
security utm utm-policy <name> anti-virus ftp upload-profile <profile>
security utm utm-policy <name> anti-virus ftp download-profile <profile>
security utm utm-policy <name> anti-virus smtp-profile <profile>
security utm utm-policy <name> anti-virus pop3-profile <profile>
```

Other UTM examples in the PDF use policy references for features such as anti-spam and web filtering.

A security policy attaches a UTM policy through its permit/application-services subtree.

### B. IDP policy

IDP is a separate source model:

```text
security idp idp-policy <name> ...
```

A security policy can directly reference the IDP policy under its permit/application-services configuration.

### Rules

- Preserve UTM policy and IDP policy separately.
- Preserve the individual feature-profile references inside a UTM policy.
- Preserve IDP rulebase configuration separately from UTM.
- Do not create a source `SecurityProfileGroup` merely to resemble FortiGate.
- If a report needs "effective security stack", calculate it as a derived view from the security-policy references.
- The Content Security guide notes deprecated configuration in some feature-profile hierarchies. If deprecated statements are actually present in source, preserve them as source rather than silently converting them.

---

## 3.6 Schedulers

### Mapping

```text
FortiGate:
config firewall schedule onetime
config firewall schedule recurring
config firewall schedule group

Junos:
schedulers scheduler <name> ...
```

### Official PDF

*Security Policies User Guide for Security Devices*

Relevant viewer pages: 243–248.

### Recurring schedule

The PDF demonstrates:

```text
schedulers
    scheduler <name>
        daily {
            start-time <time>
            stop-time <time>
        }
```

It also documents per-weekday schedule configuration and `exclude`.

A per-day time slot takes priority over a daily time slot when both apply.

### Nonrecurring schedule

The PDF documents start/stop date-time style scheduling for a one-time interval.

### Policy reference

```text
security policies ... policy <name> scheduler-name <scheduler>
```

### Rules

- Preserve one-time and recurring semantics.
- Preserve daily and weekday-specific definitions separately.
- Preserve `exclude` when explicitly configured.
- Do not materialize a calculated "currently active" value as explicit source state.
- The selected Junos scheduler hierarchy does not expose a FortiGate-style standalone schedule-group object. Do not invent one.
- Policy scheduler references remain references.

---

## 3.7 Service Objects and Groups

### Mapping

```text
FortiGate:
config firewall service custom
config firewall service group
config firewall service category

Junos:
applications application <name> ...
applications application-set <name> ...
```

### Official PDF

*Security Policies User Guide for Security Devices*

Relevant viewer pages: 71–75.

### Application hierarchy

The PDF demonstrates custom application definitions such as:

```text
applications application <name> protocol <protocol>
applications application <name> source-port <range>
applications application <name> destination-port <range>
applications application <name> inactivity-timeout <seconds>
```

It also demonstrates term-based application configuration:

```text
applications application <name> term <term-name> protocol <protocol>
applications application <name> term <term-name> source-port <range>
applications application <name> term <term-name> destination-port <range>
```

### Application set

The PDF demonstrates:

```text
applications application-set <set-name> application <application-name>
```

### Rules

- Preserve the application definition exactly.
- Preserve source-port and destination-port semantics separately.
- Preserve top-level vs term-based application structure.
- Preserve inactivity timeout only when explicitly configured.
- Application-set members are references.
- Preserve references to predefined `junos-*` applications without creating fake local application objects unless the project intentionally inventories built-ins as reference data.
- No standalone FortiGate-style service-category object is identified in this selected Junos source mapping. Do not fabricate one.

---

## 3.8 Destination NAT / FortiGate VIP Equivalent

### Mapping

```text
FortiGate:
config firewall vip

Junos:
security nat destination ...
security nat static ...
```

### Official PDF

*Network Address Translation User Guide*

Relevant viewer pages: 23–24, 181–224.

### Destination NAT

The PDF demonstrates:

```text
security nat destination pool <pool-name> address ...
security nat destination pool <pool-name> address port <port>

security nat destination rule-set <rule-set> from routing-instance <instance>
security nat destination rule-set <rule-set> rule <rule> match destination-address ...
security nat destination rule-set <rule-set> rule <rule> match destination-port ...
security nat destination rule-set <rule-set> rule <rule> then destination-nat pool <pool-name>
```

Other valid source scope/match forms should be preserved if present.

### Static NAT

The PDF demonstrates:

```text
security nat static rule-set <rule-set> from zone <zone>

security nat static rule-set <rule-set> rule <rule> match destination-address ...
security nat static rule-set <rule-set> rule <rule> match destination-port ...

security nat static rule-set <rule-set> rule <rule> then static-nat prefix ...
security nat static rule-set <rule-set> rule <rule> then static-nat prefix mapped-port ...
```

### Rules

- Destination/static NAT is not a standalone Junos `VIP` object.
- Keep NAT pool, rule set, and rule separate.
- Preserve match criteria together with the translation action.
- Preserve routing-instance/zone ownership.
- Preserve translated/mapped ports only when explicitly configured.
- A FortiGate-like VIP view may be derived, but must be traceable to the original NAT rule and pool/static mapping.
- NAT stage/order semantics belong to documented effective behavior, not explicit source.

---

## 3.9 FortiGate VIP Group Equivalent

### Mapping

```text
FortiGate:
config firewall vipgrp

Junos:
no direct VIP-group source object identified
```

### Source configuration to collect

```text
security nat destination
security nat static
security address-book
security policies
```

### Rules

- Do not create a Junos `VIPGroup`.
- Preserve each NAT rule independently.
- Preserve address/address-set references used by the associated policies/NAT configuration.
- Any grouping of related destination/static NAT mappings for migration/reporting is derived state.

---

## 3.10 IDP / FortiGate IPS Sensor Equivalent

### Mapping

```text
FortiGate:
config ips sensor

Junos:
security idp idp-policy <name> ...
```

### Official PDF

*Intrusion Detection and Prevention User Guide*

Relevant viewer pages: 98–105, 154–156, 463–465.

### IDP policy hierarchy

The PDF demonstrates:

```text
security idp idp-policy <name>
security idp idp-policy <name> rulebase-ips
security idp idp-policy <name> rulebase-ips rule <name> ...
```

Rule match concepts shown in the guide include:

```text
from-zone
source-address
to-zone
destination-address
application
attacks / attack groups
```

Rule actions/notifications shown include actions such as dropping a connection and logging/alerting attacks.

The guide also documents:

```text
security idp custom-attack ...
```

and attack groups.

### Activation/reference rule

The guide documents direct attachment of an IDP policy to a security policy through:

```text
then permit application-services idp-policy <name>
```

The older single `security idp active-policy` mechanism is documented as deprecated for the direct-security-policy use case in newer Junos releases.

### Extraction rules

- Preserve IDP policies independently.
- Preserve rulebase/rule ordering.
- Preserve rule match criteria.
- Preserve attack and attack-group references.
- Preserve custom attack definitions if explicitly configured.
- Preserve exemption rulebase configuration separately when present.
- Do not expand the Juniper predefined attack database into explicit user source configuration.
- Do not populate source with vendor default attacks/profiles that were not explicitly configured.
- Preserve deprecated `active-policy` if it is present in the source; do not silently rewrite it.

---

## 3.11 Static Routes

### Mapping

```text
FortiGate:
config router static

Junos:
routing-options static route <prefix> ...
```

and where scoped to a routing instance:

```text
routing-instances <name> ... static route ...
```

### Official PDF

*Protocol-Independent Routing Properties User Guide*

Relevant viewer pages: 46–53, 100, 117.

### Documented hierarchy/examples

The PDF demonstrates:

```text
routing-options static route <prefix> next-hop <address>
routing-options static route <prefix> qualified-next-hop <address> preference <value>
```

It also documents static-route properties including preference/metric behavior, BFD use, and discard behavior.

### Rules

- Preserve destination prefix.
- Preserve ordinary next hop and qualified next hop as different source structures.
- Preserve per-qualified-next-hop preference/metric separately from route-level values.
- Preserve BFD references/configuration when present.
- Preserve `discard` and other explicit next-hop semantics instead of converting them to an arbitrary gateway.
- Preserve routing-instance ownership.
- Preserve IPv4 and IPv6 semantics as configured.
- Do not infer a gateway from an interface or vice versa.
- Do not turn route selection outcomes into explicit source values.

---

## 3.12 Administrator Access Profiles / Login Classes

### Mapping

```text
FortiGate:
config system accprofile

Junos:
system login class <class-name> ...
```

### Official PDF

*User Access and Authentication Administration Guide*

Relevant viewer pages: 61–69.

### Login class hierarchy

The guide demonstrates login classes containing controls such as:

```text
system login class <name> permissions ...
system login class <name> allow-commands ...
system login class <name> deny-commands ...
system login class <name> allow-configuration-regexps ...
system login class <name> deny-configuration-regexps ...
system login class <name> security-role ...
```

### Rules

- Preserve the class definition separately from user assignment.
- Preserve the complete explicit permission set.
- Preserve allow/deny command regular expressions.
- Preserve allow/deny configuration regular expressions.
- Preserve security-role if explicitly configured.
- Do not collapse a Junos login class into a single synthetic read/write flag.
- Junos predefined classes may be referenced by users even if no local custom class definition exists.

---

## 3.13 Administrators / Login Users

### Mapping

```text
FortiGate:
config system admin

Junos:
system login user <username> ...
```

### Official PDF

*User Access and Authentication Administration Guide*

Relevant viewer pages: 61–69, 118.

### User hierarchy

The guide demonstrates:

```text
system login user <name> uid <uid>
system login user <name> class <class>
system login user <name> authentication ...
```

It documents predefined login classes such as:

```text
super-user
operator
read-only
unauthorized
```

### Secret rule

The guide documents password configuration under the user authentication hierarchy and explains that Junos stores password data in encrypted form.

For extraction:

```text
authentication secret/password leaf present
    -> Password Configured = Yes
    -> actual value omitted
```

Never place the encrypted representation into:

```text
raw_extra
debug logs
Markdown report
Excel
JSON export
```

### Rules

- Preserve username.
- Preserve UID only when explicitly configured.
- Preserve class reference.
- Preserve non-secret authentication metadata.
- Keep management login users separate from firewall-authentication users configured under `access profile`.

---

## 3.14 DHCP Server

### Mapping

```text
FortiGate:
config system dhcp server

Junos:
system services dhcp-local-server ...
access address-assignment ...
```

### Official PDF

*DHCP User Guide*

Relevant viewer pages: 46–56, 105–106, 368–404.

### A. DHCP local server

The current Junos DHCP architecture uses:

```text
system services dhcp-local-server ...
```

including group/interface-oriented server configuration.

The PDF also shows group-specific server options and DHCPv6 variants.

### B. Address-assignment pools

The PDF documents:

```text
access address-assignment pool <pool-name> family inet
```

with named ranges:

```text
range <range-name> low <address> high <address>
```

and static reservations:

```text
host <host-name> hardware-address <mac> ip-address <address>
```

The guide also documents pool linking:

```text
access address-assignment pool <primary> link <secondary>
```

and `dhcp-attributes` for DHCP-specific lease/options data.

IPv6 address-assignment configuration is also documented.

### Routing-instance scope

The PDF states that address-assignment configuration can be placed in routing-instance hierarchy when required by that deployment.

Preserve this ownership.

### Pool-selection behavior

The guide documents local-server pool matching mechanisms such as receiving-interface/giaddr behavior and optional external authority / option 82 matching.

These are behavioral/selection rules unless explicitly represented by source statements.

### Legacy DHCP

The PDF also contains legacy:

```text
system services dhcp ...
```

configuration, including static binding examples.

If legacy DHCP configuration exists in source:

```text
preserve it as legacy source state
```

Do not silently rewrite it into `dhcp-local-server`.

### Extraction rules

Keep separate:

```text
DHCP local-server configuration
address-assignment pool
range
reservation/host
DHCP attributes
routing-instance ownership
legacy DHCP source
```

Do not fabricate lease values/defaults that are not explicitly configured.

---

## 3.15 SD-WAN / APBR and AppQoE

### Mapping

```text
FortiGate:
config system sdwan

Junos:
security advance-policy-based-routing ...
```

plus referenced:

```text
interfaces
routing-instances
overlay/tunnel paths
applications/application groups
```

### Official PDF

*Application Security User Guide for Security Devices*

Relevant viewer pages: 373–380 and surrounding AppQoE/APBR chapters.

### Important model rule

The selected Junos documentation does not represent this as one FortiGate-style `sdwan` object.

Keep APBR/AppQoE components independently.

### Documented APBR/AppQoE hierarchy

The PDF demonstrates configuration under:

```text
security advance-policy-based-routing
```

including:

```text
metrics-profile <name> ...
destination-path-group <name> ...
overlay-path <name> ...
multipath-rule <name> ...
sla-rule <name> ...
active-probe-params <name> ...
passive-probe-params ...
```

Examples include metric thresholds such as:

```text
jitter
packet-loss
```

The guide also describes/uses RTT-related metrics in AppQoE operation.

### Destination path groups

Example source structure:

```text
security advance-policy-based-routing destination-path-group <name> probe-routing-instance <instance>
security advance-policy-based-routing destination-path-group <name> overlay-path <path>
```

### Multipath rule

The PDF demonstrates fields such as:

```text
bandwidth-limit
application
application-group
link-type
max-time-to-wait
number-of-paths
```

when explicitly configured.

### SLA rule

The PDF demonstrates:

```text
security advance-policy-based-routing sla-rule <name> switch-idle-time ...
security advance-policy-based-routing sla-rule <name> metrics-profile <profile>
security advance-policy-based-routing sla-rule <name> active-probe-params <profile>
security advance-policy-based-routing sla-rule <name> passive-probe-params ...
security advance-policy-based-routing sla-rule <name> multipath-rule <rule>
```

### Rules

Keep separate:

```text
metrics profile
probe profile/parameters
overlay path
destination path group
multipath rule
SLA rule
interfaces
routing instances
```

Resolve references later.

Do not create a source `SDWAN` object containing copied data from all of them.

Do not infer a FortiGate member ID, zone, or SLA object if Junos did not explicitly configure such an object.

Runtime measurements such as current jitter/RTT/loss are operational state, not explicit source configuration.

---

## 3.16 Security Zones

### Mapping

```text
FortiGate:
config system zone

Junos:
security zones security-zone <zone-name> ...
```

### Official PDF

*Security Policies User Guide for Security Devices*

Relevant viewer pages: 21, 29–30.

### Hierarchy

The guide defines a security zone as a logical entity containing one or more network segments and documents interfaces bound to zones.

Examples use:

```text
security zones security-zone <name> interfaces <interface> ...
```

with host-inbound traffic controls.

### Rules

- Preserve zone name.
- Preserve interface membership/attachment as explicit source relationship.
- Preserve host-inbound traffic configuration when present.
- Do not derive interface hierarchy in the parser.
- Zone membership comes from Junos zone/interface configuration, not from policy inference.
- Preserve interface unit names exactly.
- Do not create FortiGate-specific `intrazone` or interface-group fields unless source configuration explicitly represents the corresponding Junos behavior.

---

## 3.17 User Groups / Identity Roles

### Mapping

```text
FortiGate:
config user group

Junos:
access-profile client-group / user-group identity relationships
plus external AAA group configuration when present
```

### Official PDFs

- *Security Policies User Guide for Security Devices*
- *User Access and Authentication Administration Guide*
- *Juniper Secure Connect User Guide* for remote-access group restrictions

### Firewall-authentication identity model

The Security Policies guide documents firewall authentication using:

```text
access profile
security user-identification
security policy source-identity
```

The guide explains that authenticated user information is maintained in the user identification table, including associated group names used as identity roles for source-identity matching.

### Local client-group relationship

The access profile hierarchy supports client/group relationships for firewall authentication.

### External group sources

Secure Connect examples show access profiles using external AAA configuration such as LDAP allowed groups.

### Rules

Keep distinct:

```text
local firewall user
client-group relationship
external LDAP/RADIUS group restriction
runtime authenticated group/role
security-policy source-identity
```

Do not convert runtime directory membership into an explicit static Junos group.

Do not create a FortiGate-style standalone `UserGroup` source object unless the Junos source actually has an explicit reusable group construct being modeled.

Runtime identity-table contents are operational/derived state.

---

## 3.18 Local Firewall Users

### Mapping

```text
FortiGate:
config user local

Junos:
access profile <profile> client <name> firewall-user ...
```

### Official PDFs

- *Security Policies User Guide for Security Devices*, viewer pages 220–223
- *User Access and Authentication Administration Guide*, secret hierarchy references around viewer page 955

### Documented source form

The Security Policies PDF demonstrates local firewall-user configuration under an access profile:

```text
access profile <profile-name> client <client-name> firewall-user password ...
```

### Rules

- Preserve access-profile ownership.
- Preserve client/user name.
- Preserve non-secret user metadata.
- Preserve client-group relationships separately.
- Never preserve the password value.
- Record only safe metadata such as:

```text
Password Configured = Yes
```

- Keep these users separate from management administrators under `system login user`.

---

## 3.19 Site-to-Site IPsec VPN

### Mapping

```text
FortiGate:
config vpn ipsec phase1
config vpn ipsec phase1-interface
config vpn ipsec phase2
config vpn ipsec phase2-interface

Junos:
security ike proposal
security ike policy
security ike gateway
security ipsec proposal
security ipsec policy
security ipsec vpn
security ipsec vpn ... traffic-selector
```

### Official PDF

*IPsec VPN User Guide*

Relevant viewer pages: 246, 470–474, 570–571 and the corresponding IKE/IPsec configuration chapters.

### A. IKE proposal

The PDF demonstrates:

```text
security ike proposal <name> authentication-method ...
security ike proposal <name> dh-group ...
security ike proposal <name> authentication-algorithm ...
security ike proposal <name> encryption-algorithm ...
security ike proposal <name> lifetime-seconds ...
```

Only retain leaves explicitly configured.

### B. IKE policy

Examples show:

```text
security ike policy <name> mode ...
security ike policy <name> proposals <proposal>
security ike policy <name> certificate local-certificate <certificate>
security ike policy <name> pre-shared-key ...
```

### C. IKE gateway

Examples show:

```text
security ike gateway <name> address ...
security ike gateway <name> local-address ...
security ike gateway <name> ike-policy <policy>
security ike gateway <name> external-interface ...
security ike gateway <name> local-identity ...
security ike gateway <name> remote-identity ...
security ike gateway <name> version ...
```

Newer features can add additional explicit leaves. Preserve unknown non-secret leaves as raw/source-only configuration.

### D. IPsec proposal

Examples show:

```text
security ipsec proposal <name> protocol esp
security ipsec proposal <name> authentication-algorithm ...
security ipsec proposal <name> encryption-algorithm ...
```

### E. IPsec policy

Examples show:

```text
security ipsec policy <name> proposals <proposal>
```

and features such as Perfect Forward Secrecy when explicitly configured.

### F. IPsec VPN

Examples show:

```text
security ipsec vpn <name> bind-interface st0.<unit>
security ipsec vpn <name> ike gateway <gateway>
security ipsec vpn <name> ike ipsec-policy <policy>
```

### G. Traffic selectors

The PDF demonstrates:

```text
security ipsec vpn <name> traffic-selector <selector> local-ip <prefix>
security ipsec vpn <name> traffic-selector <selector> remote-ip <prefix>
```

and documents routing behavior associated with traffic selectors and the bound `st0` interface.

### Secret rule

The PDF contains IKE pre-shared-key examples.

Never export the pre-shared-key value.

Use:

```text
Pre-Shared Key Configured = Yes
```

where useful.

### Extraction rules

Do not collapse these into synthetic Junos `Phase1` / `Phase2` source objects.

Keep:

```text
IKEProposal
IKEPolicy
IKEGateway
IPsecProposal
IPsecPolicy
IPsecVPN
TrafficSelector
```

as independent Junos source objects/sections.

Relationships are resolved later.

Preserve IKE version, identities, external interface, tunnel interface, algorithms, lifetimes, PFS, and traffic selectors only when explicitly configured.

---

## 3.20 Remote Access / FortiGate SSL VPN Equivalent

### Mapping

```text
FortiGate:
config vpn ssl ...

Junos:
Juniper Secure Connect
security remote-access ...
```

with supporting:

```text
security ike
security ipsec
access profile
access address-assignment
interfaces st0
security zones
security policies
certificates/AAA where used
```

### Official PDF

*Juniper Secure Connect User Guide*

Relevant viewer pages: 72–121, 142, 168–169, 229–237.

### Important model rule

Juniper Secure Connect is not one FortiGate-style SSL-VPN object.

Keep its source components separate.

### A. Remote-access profile

The PDF demonstrates:

```text
security remote-access profile <name> access-profile <access-profile>
security remote-access profile <name> client-config <client-config>
security remote-access profile <name> ipsec-vpn <vpn>
security remote-access profile <name> options multi-access
```

depending on authentication/deployment mode.

### B. Client configuration

The guide documents:

```text
security remote-access client-config <name> ...
```

including client behavior and application-bypass/split-tunnel-related configuration in supported releases.

Preserve named terms and their match semantics rather than flattening them.

### C. Access profile / authentication

Secure Connect examples configure:

```text
access profile <name> ...
```

for local/external authentication.

Examples include LDAP search/bind settings and allowed groups.

Any password/secret value in this subtree must be redacted.

### D. Address pool

The PDF demonstrates:

```text
access address-assignment pool <name> family inet ...
```

with ranges and remote-access attributes such as DNS/WINS where applicable.

### E. IKE/IPsec

Secure Connect examples explicitly configure:

```text
security ike gateway ...
security ipsec proposal ...
security ipsec policy ...
security ipsec vpn ...
```

and bind the VPN to an `st0` interface.

### F. Tunnel interface and zone

Examples show:

```text
interfaces st0 unit <unit> ...
security zones security-zone <zone> interfaces st0.<unit>
```

### G. Security policy

Remote-user traffic still depends on security-policy configuration.

Do not treat creation of a Secure Connect profile as implicit authorization to internal resources.

### Secret handling

Secure Connect configuration examples include secret-bearing access-profile/LDAP/IKE authentication data.

Never export those values.

### Extraction rules

Keep separate:

```text
RemoteAccessProfile
RemoteAccessClientConfig
AccessProfile
AddressAssignmentPool
IKE objects
IPsec objects
st0 interface
SecurityZone
SecurityPolicy
```

Resolve their references later.

Do not create a synthetic Junos `SSLVPN` source object.

---

# 4. Recommended Extraction Order

This order is dependency-aware for extraction/reporting.

It is **not** a claim that Junos stores configuration in this order.

```text
1. Configuration groups / apply-groups / apply-groups-except
2. Scope inventory: logical systems and routing instances

3. Address books
4. Address objects
5. Address sets

6. Applications
7. Application sets
8. Schedulers
9. Security zones

10. Management login classes
11. Management login users

12. Access profiles
13. Local firewall-auth users / client-group relationships

14. UTM feature profiles referenced by selected UTM policies
15. UTM policies
16. IDP custom objects / attack groups explicitly configured
17. IDP policies

18. DHCP address-assignment pools
19. DHCP local-server configuration
20. Legacy DHCP source configuration if present

21. Static routes

22. IKE proposals
23. IKE policies
24. IKE gateways
25. IPsec proposals
26. IPsec policies
27. IPsec VPNs / traffic selectors

28. Source NAT pools
29. Source NAT rule sets/rules
30. Destination NAT pools/rules
31. Static NAT rules
32. NAT proxy-ARP configuration where present

33. APBR/AppQoE metrics/probe/path objects
34. APBR multipath/SLA rules

35. Security policies
36. Global security policies

37. Secure Connect remote-access profiles/client configs
38. Supporting Secure Connect relationships to access, address pool, IPsec, st0, zones, and policies
```

Why object-first:

```text
policies reference objects
NAT rules reference pools
IDP/UTM attachment references profiles/policies
IKE gateways reference IKE policies
IPsec VPNs reference gateways and IPsec policies
Secure Connect references several separately owned objects
APBR SLA rules reference metrics/probe/multipath/path objects
```

---

# 5. Parser / Source-Model Guidance

## 5.1 Suggested primary Junos source sections

Recognize at least:

```text
groups
apply-groups
apply-groups-except

logical-systems
routing-instances

security address-book

applications
schedulers

security zones
security policies

security nat source
security nat destination
security nat static
security nat proxy-arp

security utm
security idp

routing-options static

system login class
system login user

access profile
access address-assignment

system services dhcp-local-server
system services dhcp                  # legacy when present

security advance-policy-based-routing

security ike
security ipsec

security remote-access

interfaces                            # required relationships, especially st0
```

---

## 5.2 Preserve source hierarchy

Correct:

```text
security nat source
    pool P1
    rule-set RS1
        rule R1
            then source-nat pool P1
```

Incorrect:

```text
IPPool(
    name="P1",
    rule_match=...
)
```

if the match data actually belongs to a Junos NAT rule.

---

## 5.3 Preserve rule ordering

Order is significant for policy/rule processing.

Preserve original order for:

```text
security policies
NAT rules/rule sets where order is meaningful
IDP rules
APBR rules where source order affects evaluation
```

Do not sort by object name.

---

## 5.4 Preserve inactive state

The CLI guide shows that `display set` emits:

```text
deactivate ...
```

for inactive configuration.

Recommended source representation:

```text
statement = ...
active = false
```

or an equivalent explicit source marker.

Do not delete the statement.

---

## 5.5 Preserve configuration-group ownership

Correct:

```text
group "common-security"
    statement X

apply-groups common-security
```

Derived/effective view:

```text
statement X inherited at target hierarchy
```

Incorrect:

```text
target.explicit_statement = X
```

when it exists only through inheritance.

---

## 5.6 Unknown leaves

For a recognized selected object with an unmodeled non-secret leaf:

```text
preserve in raw_extra / Additional Settings / source appendix
```

For an unknown source section outside selected scope:

```text
Source Inventory / unsupported-source appendix
```

For an unknown secret-bearing field:

```text
detect
-> redact/drop value
-> optional safe presence metadata
```

Never blindly preserve an unknown value if it can contain credentials/key material.

---

# 6. Cross-Vendor Modeling Rules

## 6.1 Do not create a vendor-neutral IR in the Junos source layer

Keep Junos source state in Junos-native structures.

Cross-vendor comparison belongs in:

```text
relationships
transforms
derived views
```

---

## 6.2 Different-model mappings

Do not force these into fake Junos source objects:

```text
FortiGate profile-group
    -> Junos UTM policy + IDP policy + security-policy references

FortiGate VIP
    -> Junos destination NAT / static NAT

FortiGate VIP group
    -> no direct Junos VIP-group source object

FortiGate SD-WAN
    -> APBR/AppQoE metrics, probes, paths, rules, routing instances, interfaces

FortiGate user group
    -> Junos access-profile / client-group / AAA identity relationships

FortiGate phase1/phase2
    -> IKE proposal/policy/gateway + IPsec proposal/policy/VPN/traffic selectors

FortiGate SSL VPN
    -> Secure Connect remote-access architecture + supporting objects
```

---

## 6.3 Source vs derived examples

### NAT

Correct:

```text
Junos source:
source NAT pool "P1"
source NAT rule-set "RS1"
source NAT rule "R1"
    then source-nat pool "P1"

Derived:
FortiGate-style source NAT pool usage
    pool = P1
    referenced-by = RS1/R1
```

Incorrect:

```text
Junos source:
FortiGateIPPool(...)
```

---

### Secure Connect

Correct:

```text
Junos source:
remote-access profile "ra.example.com"
access profile "JSC-AUTH"
address pool "JSC-POOL"
IPsec VPN "JSC-VPN"
st0.0
zone "vpn"
security policy "vpn-to-trust"
```

Derived:

```text
Remote-access solution view
    resolves references across these source objects
```

Incorrect:

```text
Junos source:
SSLVPN(
    copied_auth=...
    copied_pool=...
    copied_policy=...
)
```

---

### Configuration inheritance

Correct:

```text
explicit source:
groups G { ... }
apply-groups G

derived/effective:
expanded inherited statement
```

Incorrect:

```text
explicit target field = inherited value
```

when the leaf was never locally configured.

---

# 7. Verification Checklist

For each Junos extraction:

- [ ] Use Junos-native source hierarchy.
- [ ] Preserve full object/rule names.
- [ ] Preserve logical-system ownership where present.
- [ ] Preserve routing-instance ownership where present.
- [ ] Preserve address-book ownership and zone attachment.
- [ ] Preserve explicit `set` statements.
- [ ] Preserve `deactivate` state.
- [ ] Preserve `groups`, `apply-groups`, and `apply-groups-except`.
- [ ] Do not overwrite explicit source with inherited/effective configuration.
- [ ] Do not fill missing values with Junos defaults.
- [ ] Preserve address representation: prefix/range/DNS/wildcard.
- [ ] Preserve address-set references.
- [ ] Preserve application vs application-set.
- [ ] Preserve scheduler type and policy reference.
- [ ] Preserve security-policy ordering.
- [ ] Preserve global policy separately from zone policies.
- [ ] Preserve UTM and IDP as separate source models.
- [ ] Preserve IDP rulebase ordering and attack references.
- [ ] Preserve source NAT pool separately from NAT rule.
- [ ] Preserve destination NAT separately from static NAT.
- [ ] Do not create a Junos VIP/VIP-group object.
- [ ] Preserve static-route next-hop type and qualified-next-hop properties.
- [ ] Keep management login users separate from firewall-auth users.
- [ ] Keep login class definition separate from user-to-class assignment.
- [ ] Preserve DHCP local-server and address-assignment pools separately.
- [ ] Preserve legacy DHCP hierarchy if actually present.
- [ ] Keep APBR/AppQoE metrics, paths, probes, multipath rules, and SLA rules separate.
- [ ] Keep IKE proposal, IKE policy, IKE gateway, IPsec proposal, IPsec policy, VPN, and traffic selector separate.
- [ ] Keep Secure Connect profile/client config separate from IKE/IPsec/access/address pool/interface/zone/policy.
- [ ] Preserve references and resolve them only in the relationship layer.
- [ ] Never export actual passwords, encrypted-password strings, PSKs, LDAP bind passwords, RADIUS secrets, shared secrets, private keys, or equivalent secret material.
- [ ] Preserve unknown non-secret selected-object leaves in `raw_extra`.
- [ ] Record unknown/out-of-scope sections in Source Inventory rather than silently dropping them.

---

# 8. Official PDF Sources

Only official Juniper Networks PDFs were used for the Junos content in this selected reference.

## 8.1 CLI User Guide for Junos OS

**Official PDF**

https://www.juniper.net/documentation/us/en/software/junos/cli/cli.pdf

Used for:

```text
configuration mode
display set
inactive/deactivate representation
configuration groups
apply-groups
apply-groups-except
display inheritance
commit check
```

The retrieved official PDF is dated **2026-06-18**.

---

## 8.2 Security Policies User Guide for Security Devices

**Official PDF**

https://www.juniper.net/documentation/us/en/software/junos/security-policies/security-policies.pdf

Used for:

```text
address books
address objects
address sets
applications
application sets
security zones
security policies
global policies
schedulers
firewall authentication / source identity
```

---

## 8.3 Network Address Translation User Guide

**Official PDF**

https://www.juniper.net/documentation/us/en/software/junos/nat/nat.pdf

Used for:

```text
source NAT pools
source NAT rule sets/rules
destination NAT pools/rules
static NAT rule sets/rules
proxy ARP relationships
NAT processing order
```

---

## 8.4 Intrusion Detection and Prevention User Guide

**Official PDF**

https://www.juniper.net/documentation/us/en/software/junos/idp-policy/idp-policy.pdf

Used for:

```text
IDP policies
rulebase-ips
IDP rules
attack/attack-group references
custom attacks
exemption rules
security-policy attachment
active-policy deprecation context
```

---

## 8.5 Content Security User Guide

**Official PDF**

https://www.juniper.net/documentation/us/en/software/junos/utm/utm.pdf

Used for:

```text
UTM policies
UTM feature-profile references
security-policy UTM attachment
```

---

## 8.6 DHCP User Guide

**Official PDF**

https://www.juniper.net/documentation/us/en/software/junos/dhcp/dhcp.pdf

Used for:

```text
DHCP local server
address-assignment pools
named ranges
static reservations
DHCP attributes
pool linking
routing-instance address assignment
legacy DHCP configuration
```

---

## 8.7 Application Security User Guide for Security Devices

**Official PDF**

https://www.juniper.net/documentation/us/en/software/junos/application-identification/application-identification.pdf

Used for:

```text
advanced policy-based routing
AppQoE
metrics profiles
active/passive probes
overlay paths
destination path groups
multipath rules
SLA rules
```

---

## 8.8 User Access and Authentication Administration Guide

**Official PDF**

https://www.juniper.net/documentation/us/en/software/junos/user-access/user-access.pdf

Used for:

```text
system login class
system login user
permissions
command/configuration regex restrictions
access-profile secret hierarchy
management authentication
```

---

## 8.9 Protocol-Independent Routing Properties User Guide

**Official PDF**

https://www.juniper.net/documentation/us/en/software/junos/static-routing/static-routing.pdf

Used for:

```text
static routes
next-hop
qualified-next-hop
preference/metric behavior
BFD
discard behavior
```

---

## 8.10 IPsec VPN User Guide

**Official PDF**

https://www.juniper.net/documentation/us/en/software/junos/vpn-ipsec/vpn-ipsec.pdf

Used for:

```text
IKE proposals
IKE policies
IKE gateways
IPsec proposals
IPsec policies
IPsec VPNs
traffic selectors
st0 binding
pre-shared-key secret handling
```

---

## 8.11 Juniper Secure Connect User Guide

**Official PDF**

https://www.juniper.net/documentation/us/en/software/secure-connect/secure-connect-user-guide/secure-connect-user-guide.pdf

Used for:

```text
security remote-access profile
security remote-access client-config
access profiles
address-assignment pools
IKE/IPsec dependencies
st0
security zones
security policies
local/external authentication
LDAP/group restrictions
remote-access secret handling
```

---

# 9. Scope Note

This document is a **selected extraction reference**, aligned to the project's 20 FortiGate baseline areas.

It intentionally does **not** attempt to reproduce every Junos statement in every official manual.

For a selected Junos object:

```text
recognized selected leaf
    -> structured source field

recognized selected object + unknown non-secret leaf
    -> raw_extra / source appendix

unknown/out-of-scope object
    -> Source Inventory / unsupported source section

secret-bearing leaf
    -> redact value
    -> optional safe presence metadata
```

When behavior is unclear:

```text
preserve source
-> mark unknown/source-only
-> do not guess
```

Priority:

```text
correctness
-> source preservation
-> clear semantics
-> traceability
-> maintainability
```
