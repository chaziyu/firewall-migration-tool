# Cisco Secure Firewall Threat Defense Selected Configuration References

> **Purpose:** Source-configuration extraction reference for the FortiGate Extract / firewall migration project.
>
> **Baseline:** The 20 selected FortiGate configuration areas used by this project.
>
> **Cisco scope:** Cisco Secure Firewall Threat Defense (FTD) managed by Cisco Secure Firewall Management Center (FMC), using the Cisco Secure Firewall Management Center 7.7 documentation set and REST API 7.7.0 as the primary baseline.
>
> **Source rule:** The configuration mappings and extraction rules in this document are based on official Cisco PDF documentation only. The REST API PDF is used to identify concrete read/extraction resources. Device Configuration Guide chapter PDFs are used for configuration semantics and policy behavior.
>
> **Modeling rule:** Preserve Cisco/FMC source architecture. Do not manufacture FortiGate-shaped Cisco source objects when FTD uses a different architecture.
>
> **Security rule:** Never export, log, persist, or report actual passwords, password hashes, pre-shared keys, private keys, API tokens, certificate private-key material, RADIUS/LDAP shared secrets, Secure Client secrets, or equivalent authentication secret values. Safe metadata such as `Password Configured = Yes`, `Pre-Shared Key Configured = Yes`, or `Private Key Present = Yes` is allowed.

---

# 1. Official PDF Sources

The following official Cisco PDFs form the source set for this reference.

## 1.1 Primary configuration and object references

1. **Cisco Secure Firewall Management Center Device Configuration Guide, 7.7 — Object Management**
   - PDF: https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/device-config/770/management-center-device-config-77/objects-object-mgmt.pdf
   - Relevant areas: network objects, network groups, port/protocol objects, time ranges, security zones, SLA monitors, VPN-related reusable objects, PKI objects.

2. **Cisco Secure Firewall Management Center REST API Quick Start Guide, Version 7.7.0**
   - PDF: https://www.cisco.com/c/en/us/td/docs/security/firepower/770/API/REST/secure_firewall_management_center_rest_api_quick_start_guide_770.pdf
   - Relevant areas: concrete FMC extraction endpoints for objects, policies, users, NAT, routing, DHCP, VPN, realms, intrusion policies, and related resources.

3. **Cisco Secure Firewall Management Center Device Configuration Guide, 7.7 — Network Address Translation**
   - PDF: https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/device-config/770/management-center-device-config-77/network-policies-nat.pdf

4. **Cisco Secure Firewall Management Center Device Configuration Guide, 7.7 — Access Control Policies**
   - PDF: https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/device-config/770/management-center-device-config-77/access-policies.pdf

5. **Cisco Secure Firewall Management Center Device Configuration Guide, 7.7 — Access Control Rules**
   - PDF: https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/device-config/770/management-center-device-config-77/access-rules.pdf

6. **Cisco Secure Firewall Management Center Device Configuration Guide, 7.7 — File Policies for Network Malware Protection**
   - PDF: https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/device-config/770/management-center-device-config-77/advanced-access-file.pdf

7. **Cisco Secure Firewall Management Center Device Configuration Guide, 7.7 — DNS Policies for Security Intelligence**
   - PDF: https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/device-config/770/management-center-device-config-77/advanced-access-dns.pdf

8. **Cisco Secure Firewall Management Center Device Configuration Guide, 7.7 — Decryption Policies**
   - PDF: https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/device-config/770/management-center-device-config-77/encrypted-traffic-policies.pdf

9. **Cisco Secure Firewall Management Center Device Configuration Guide, 7.7 — Intrusion Prevention**
   - PDF: https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/device-config/770/management-center-device-config-77/intrusion-overview.pdf

10. **Cisco Secure Firewall Management Center Device Configuration Guide, 7.7 — Static and Default Routes**
    - PDF: https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/device-config/770/management-center-device-config-77/routing-static.pdf

11. **Cisco Secure Firewall Management Center Device Configuration Guide, 7.7 — DHCP and DDNS**
    - PDF: https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/device-config/770/management-center-device-config-77/interfaces-settings-dhcp-ddns.pdf

12. **Cisco Secure Firewall Management Center Device Configuration Guide, 7.7 — SD-WAN**
    - PDF: https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/device-config/770/management-center-device-config-77/secure-connections-sd-wan.pdf

13. **Cisco Secure Firewall Management Center Device Configuration Guide, 7.7 — Realms**
    - PDF: https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/device-config/770/management-center-device-config-77/identity-realms.pdf

14. **Cisco Secure Firewall Management Center Device Configuration Guide, 7.7 — Site-to-Site VPN**
    - PDF: https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/device-config/770/management-center-device-config-77/secure-connections-s2s.pdf

15. **Cisco Secure Firewall Management Center Device Configuration Guide, 7.7 — Remote Access VPN**
    - PDF: https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/device-config/770/management-center-device-config-77/secure-connections-remote-access.pdf

16. **Cisco Secure Firewall Management Center Administration Guide, 7.7 — Users**
    - PDF: https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/admin/770/management-center-admin-77/system-users.pdf

17. **Cisco Secure Firewall Management Center Device Configuration Guide, 7.7 — FTD CLI Users**
    - PDF: https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/device-config/770/management-center-device-config-77/get-started-users.pdf

## 1.2 Supplied Cisco PDF

The supplied Cisco document:

- `Configure Firepower Threat Defense (FTD) Management Interface`
- Document ID 212420
- https://www.cisco.com/c/en/us/support/docs/security/asa-5500-x-series-firewalls/212420-configure-firepower-threat-defense-ftd.pdf

is an official Cisco document, but its scope is the FTD **management interface**. It is not a complete source reference for access control, NAT, objects, routing, DHCP, identity, IPS, site-to-site VPN, or remote-access VPN. Therefore it is not used as the primary semantic reference for those areas.

---

# 2. Extraction Principles

## 2.1 Preserve FMC domain and deployment ownership

FMC configuration is domain-scoped.

Preserve, where returned:

```text
domain UUID
domain ownership
object UUID
policy UUID
device UUID
target device/device group
container/policy UUID
```

Do not merge identically named objects from different FMC domains.

## 2.2 Preserve explicit source only

A missing Cisco/FMC field means:

```text
not explicitly present in the extracted source
```

Do not store documented defaults as explicit source values unless the API/configuration source actually returns them as configuration state.

Keep distinct:

```text
explicit source
resolved reference / relationship
derived migration view
effective/default behavior
operational state
unknown / unsupported source
```

## 2.3 Objects are references

Examples:

```text
Access Rule -> Network object / Network Group
Access Rule -> Port/Protocol object / Port Object Group
Access Rule -> Time Range
Access Rule -> Security Zone
Access Rule -> Realm User / Realm User Group
Access Rule -> Intrusion Policy
Access Rule -> File Policy

NAT Rule -> Network objects
Static Route -> destination/gateway objects
Static Route -> SLA Monitor
Security Zone -> interface references
S2S VPN -> endpoints / IKE policies / IPsec proposals / protected networks
RA VPN -> connection profiles / group policies / realms / address pools / certificates
```

Store the source reference first.

Resolve relationships separately.

Do not expand referenced objects into the owner and overwrite source representation.

## 2.4 Object overrides are source state

FMC supports device-specific overrides for several reusable object types.

When an object has an override:

```text
base object
device/domain-specific override
```

must remain distinguishable.

Do not silently replace the base object with an effective overridden value.

## 2.5 Policy order is source state

Order is significant for:

```text
Access Control Rules
NAT rules
Decryption rules
DNS rules
File rules
Intrusion rule overrides / policy behavior
Policy-Based Routing rules
```

Do not sort ordered policy rules alphabetically.

## 2.6 Deployment is not source mutation

FMC configuration changes are deployed to managed FTD devices.

The extractor must remain read-only.

Do not:

```text
POST
PUT
DELETE
deploy
publish changes
create tickets
modify policies
```

during extraction.

Use GET/GETALL resources only.

## 2.7 Secret handling

Never persist secret values from:

```text
FMC user passwords
FTD CLI user passwords
LDAP bind passwords
RADIUS shared secrets
IKE pre-shared keys
remote-access VPN secrets
certificate private keys
PKCS#12 passwords
API access tokens
refresh tokens
session tokens
```

Safe representation:

```text
Password Configured = Yes|No
Pre-Shared Key Configured = Yes|No
LDAP Bind Password Configured = Yes|No
RADIUS Secret Configured = Yes|No
Private Key Present = Yes|No
```

Never place secret values in:

```text
raw_extra
debug logs
JSON dumps
Markdown reports
Excel reports
error messages
```

---

# 3. Mapping Index

| # | FortiGate selected config | Cisco FTD/FMC source configuration to extract | Mapping |
|---|---|---|---|
| 1 | `config firewall address` | Network Address objects: Host, Network, Range, FQDN | Direct |
| 2 | `config firewall addrgrp` | Network Groups | Direct |
| 3 | `config firewall ippool` | FTD NAT Policy + NAT rules with source translation; object NAT where present | Different model |
| 4 | `config firewall policy` | Access Control Policy + ordered Access Control Rules | Direct |
| 5 | `config firewall profile-group` | Intrusion Policy, File Policy, Decryption Policy, DNS Policy/Security Intelligence, ACP application/URL controls and related inspection settings | No single equivalent |
| 6 | `config firewall schedule group/onetime/recurring` | Time Range objects | Mostly direct; no separate FortiGate-style schedule-group object |
| 7 | `config firewall service category/custom/group` | Protocol Port Objects + Port Object Groups | Direct except service category |
| 8 | `config firewall vip` | Destination translation in FTD NAT rules | Different NAT model |
| 9 | `config firewall vipgrp` | NAT rules + referenced Network/Network Group objects | No direct VIP-group object |
| 10 | `config ips sensor` | Intrusion Policy + intrusion rules/rule groups + variable set relationship | Closest direct equivalent |
| 11 | `config router static` | Device/Virtual Router Static Routes | Direct |
| 12 | `config system accprofile` | FMC web-interface User Roles; FTD CLI roles are a separate management-plane model | Split management model |
| 13 | `config system admin` | FMC users + separately configured per-device FTD CLI users | Split management model |
| 14 | `config system dhcp server` | FTD DHCPv4 Server configuration | Direct |
| 15 | `config system sdwan` | SD-WAN VPN topology + VTI + ECMP + PBR/path monitoring + routing/interface dependencies | Split model |
| 16 | `config system zone` | Security Zone objects + interface membership | Direct |
| 17 | `config user group` | Realms + Realm User Groups / synchronized directory groups | Different identity model |
| 18 | `config user local` | Local Realm Users | Closest direct equivalent |
| 19 | `config vpn ipsec phase1/phase2` | FTD Site-to-Site VPN topology + endpoints + IKE policies + IPsec proposals/settings + protected networks/VTI | Split model |
| 20 | `config vpn ssl ...` | FTD Remote Access VPN policy/topology + connection profiles + group policies + realms/AAA + address pools + certificates + Secure Client settings + NAT/ACP dependencies | Different architecture |

---

# 4. Address Objects

## 4.1 Mapping

```text
FortiGate:
config firewall address

Cisco FTD/FMC:
Network Address object
    Host
    Network
    Range
    FQDN
```

## 4.2 Official extraction root

REST API PDF, around printed pages 267-268:

```text
GETALL
/api/fmc_config/v1/domain/{domainUUID}/object/networkaddresses
```

Cisco documents this resource as returning all network object types including:

```text
Network
Host
Range
FQDN
```

Type-specific resources can also exist in the same REST API object hierarchy.

## 4.3 Source fields to retain

Retain the response fields returned by the running FMC API, including at minimum when present:

```text
id / UUID
name
type
value
description
domain ownership / metadata
override metadata
```

FQDN-specific state can include lookup/address-family semantics exposed by the source.

## 4.4 Extraction rules

- Preserve `Host`, `Network`, `Range`, and `FQDN` as distinct source types.
- Do not normalize every address into an IP subnet.
- Do not resolve an FQDN and replace the configured FQDN with the current resolved IP addresses.
- Runtime DNS resolution is effective/operational state, not the explicit object.
- Preserve object overrides separately from the base object.
- Preserve UUIDs for relationship resolution.
- Do not create a FortiGate-specific `Address.type` value unless it is a derived migration view.
- Unknown non-secret API fields should be retained as source-only/raw fields when useful.

---

# 5. Address Groups

## 5.1 Mapping

```text
FortiGate:
config firewall addrgrp

Cisco FTD/FMC:
Network Group
```

## 5.2 Official extraction root

REST API PDF, around printed pages 268-269:

```text
GETALL
/api/fmc_config/v1/domain/{domainUUID}/object/networkgroups
```

Per-object:

```text
GET
/api/fmc_config/v1/domain/{domainUUID}/object/networkgroups/{objectId}
```

Use expanded/full representation when required to retrieve members.

## 5.3 Source state to retain

```text
id / UUID
name
description
member object references
literal values if the API representation contains them
domain ownership
override metadata
other explicit non-secret fields returned by FMC
```

## 5.4 Extraction rules

- Group members remain references where Cisco stores references.
- Do not copy child Network Address objects into the group object.
- Do not flatten a group into a materialized list of IP ranges in explicit source state.
- Preserve literal entries separately if the source represents literals rather than references.
- Preserve object overrides.
- A resolved/materialized member list is derived state.

---

# 6. Source NAT / FortiGate IP Pool Equivalent

## 6.1 Mapping

```text
FortiGate:
config firewall ippool

Cisco FTD/FMC:
FTD NAT Policy
NAT Rule
    source translation
Object NAT where explicitly configured
```

There is no requirement for a standalone FortiGate-style Cisco `IPPool` source object.

## 6.2 Official extraction roots

REST API PDF, around printed page 355:

```text
GETALL
/api/fmc_config/v1/domain/{domainUUID}/policy/ftdnatpolicies
```

Then retrieve the ordered NAT rules contained by each NAT policy through the matching nested NAT-rule API resources exposed by FMC 7.7.

## 6.3 NAT source architecture

Cisco's NAT PDF documents two major configuration forms.

### A. Auto/Object NAT

Auto NAT is configured as a property of a network object.

Important source rule:

```text
Network Object
    -> Auto NAT configuration
```

Do not detach Auto NAT and store it as if it were an independent NAT rule with no object ownership.

Cisco documents that Auto NAT is not configured on a network group object.

### B. Manual/Twice NAT

Manual NAT can identify source and destination criteria in one rule and translate source, destination, or service depending on the configuration.

Keep:

```text
NAT Policy
    -> Manual NAT Rule
```

## 6.4 Translation types to preserve

Cisco's NAT reference documents these core NAT behaviors:

```text
Dynamic NAT
Dynamic PAT
Static NAT
Identity NAT
```

Retain the actual translation representation returned by the API rather than mapping it immediately to FortiGate pool types.

## 6.5 NAT rule source fields

Preserve the complete rule, not just translated source addresses.

Retain when present:

```text
rule id / UUID
rule name
enabled state
rule section
rule position/order

source interface / source interface objects
destination interface / destination interface objects

original source
original destination
original service

translated source
translated destination
translated service

NAT type
PAT / port translation settings
interface PAT settings
identity NAT state
DNS-related NAT options
proxy ARP options
route-lookup / destination interface behavior
IPv4 / IPv6 family
description/comments
other explicit advanced settings
```

Exact names depend on the FMC API representation.

## 6.6 NAT order rules

The official NAT PDF documents ordered NAT processing.

Preserve the rule section and position because NAT order is semantically significant.

The documented model includes:

```text
Section 1: manual NAT
Section 2: auto/object NAT
Section 3: manual NAT
```

System-generated NAT can occupy an even higher-priority system section.

Within the applicable ordered rule set, rule matching/order affects translation.

Do not discard section or sequence.

## 6.7 Extraction rules

- Keep `NATPolicy`, `NATRule`, and object-owned Auto NAT distinct.
- Extract both match criteria and translation fields.
- Preserve source and destination translation in the same source NAT rule.
- Preserve NAT rule order and section.
- Preserve interface criteria.
- Do not create a standalone source `CiscoIPPool`.
- A FortiGate-compatible `IPPool` view can be derived from translated-source configuration, but it must remain traceable to the owning Cisco NAT rule or network object's Auto NAT settings.
- Do not infer effective NAT behavior solely from translated addresses without considering rule order and match criteria.

---

# 7. Access Control Policy / Firewall Policy

## 7.1 Mapping

```text
FortiGate:
config firewall policy

Cisco FTD/FMC:
Access Control Policy
    ordered Access Control Rules
    default action
    associated subpolicies/settings
```

## 7.2 Official extraction roots

REST API PDF, around printed pages 321-324:

```text
GETALL
/api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies
```

Rules:

```text
GETALL
/api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies/{policyUUID}/accessrules
```

Retrieve full rule details when the collection representation is abbreviated.

## 7.3 Access Control Policy source state

Preserve, when present:

```text
policy id / UUID
name
description
domain ownership

target/assigned devices
base/parent policy relationship
inheritance state
mandatory/default inherited rule structure

ordered rules
default action

Security Intelligence configuration
associated Prefilter Policy
associated Decryption Policy
associated Identity Policy

logging configuration
advanced access-control settings
network analysis settings/references
other explicitly associated policies
```

## 7.4 Access Control Rule source state

The Access Control Rules PDF documents rule state, position, action, conditions, and inspection settings.

Preserve when present:

```text
rule id / UUID
name
enabled/disabled state
position/order
category/section
action
comments

source zones
destination zones

source networks
destination networks

source ports
destination ports
protocol/ICMP conditions

VLAN conditions
SGT conditions
dynamic-attribute conditions

realm
users
user groups
identity-related conditions

applications / application filters
URL/category/reputation conditions

Time Range

Intrusion Policy reference
Variable Set reference
File Policy reference

logging at beginning/end
syslog/event settings
other explicit rule settings
```

## 7.5 Actions

Cisco documents actions including:

```text
Monitor
Trust
Block
Block with reset
Interactive Block
Interactive Block with reset
Allow
```

Keep the configured action exactly.

Do not normalize all permit-like actions to `accept`, because they have different inspection semantics.

## 7.6 Rule order

Rules are evaluated in order.

Cisco documents that traffic is generally handled by the first rule whose conditions match, with special semantics for `Monitor`, which logs/matches and then allows evaluation to continue to a subsequent handling rule/default action.

Therefore preserve:

```text
policy ownership
section/category
position
enabled state
```

Do not sort by name.

## 7.7 Deep inspection relationships

For Allow/eligible interactive rules, Cisco can associate:

```text
Intrusion Policy
File Policy
```

Access control determines which traffic reaches these inspection policies.

File inspection occurs before intrusion inspection for a connection when both are configured.

Store references; do not copy the full intrusion/file policy into the Access Rule source object.

## 7.8 Time conditions

The Access Control Rules PDF documents:

```text
continuous time range
recurring time period
```

and states that time-based rules are evaluated using the local time of the device processing the traffic.

Do not convert this into an inferred UTC schedule in explicit source state.

## 7.9 Extraction rules

- Preserve policy inheritance relationships.
- Preserve mandatory/default ancestor rule structure when returned.
- Preserve rule position.
- Preserve disabled rules.
- Preserve `Monitor` as distinct from traffic-handling actions.
- Keep rule match conditions separate from inspection/action configuration.
- Preserve references to objects and subpolicies.
- Do not calculate an "effective flattened policy" into the source model.
- An effective flattened rulebase, if needed, belongs in derived/effective views.

---

# 8. FortiGate Profile Group Equivalent

## 8.1 Mapping

```text
FortiGate:
config firewall profile-group

Cisco FTD/FMC:
no single source object
```

Cisco splits traffic inspection/control across multiple native objects and rule settings.

## 8.2 Cisco configuration areas to collect

Depending on what is explicitly referenced by an Access Control Policy or rule, collect:

```text
Intrusion Policy
Variable Set
File Policy
Decryption Policy
DNS Policy
Security Intelligence configuration
application conditions / application filters
URL/category/reputation conditions
network analysis settings/policies
other explicitly referenced inspection settings
```

## 8.3 FortiGate profile-group field guidance

Do not force one-to-one mappings when Cisco does not have the same source concept.

| FortiGate profile-group reference | Cisco FTD/FMC source area | Rule |
|---|---|---|
| `application-list` | Access Rule application conditions / application filters | Different model |
| `av-profile` | File/Malware Policy is the closest native inspection area | Not a direct AV-profile object |
| `dnsfilter-profile` | DNS Policy / DNS Security Intelligence | Different model |
| `file-filter-profile` | File Policy | Closest direct inspection equivalent |
| `ips-sensor` | Intrusion Policy | Direct-ish |
| `ssl-ssh-profile` | Decryption Policy for supported TLS/SSL traffic inspection | Different model; do not claim generic FortiGate SSL/SSH equivalence |
| `webfilter-profile` | Access Rule URL/category/reputation conditions | Different model |
| `dlp-profile` | No single direct selected FTD source object in this reference set | Preserve as no-direct-equivalent |
| `emailfilter-profile` | No direct selected FTD profile object | Do not fabricate |
| `waf-profile` | No direct selected FTD WAF profile object | Do not fabricate |
| `icap-profile` | No direct selected FTD profile-group counterpart | Do not fabricate |
| `casb-profile` | No direct selected FTD profile-group counterpart | Do not fabricate |
| other FortiGate-specific profile references | Only map when an official FTD source object exists and is explicitly configured | Otherwise preserve no-equivalent/unknown |

## 8.4 File Policy

Official File Policy PDF:

```text
File Policy
    -> ordered File Rules
```

File Policies are referenced by eligible Access Control Rules.

Retain:

```text
policy id/name
file rules
rule order
application protocol condition
direction of transfer
file type
rule action
malware inspection settings
file-store settings where explicit
other explicit rule options
```

Do not materialize cloud malware verdicts as explicit configuration.

## 8.5 Decryption Policy

Official Decryption Policy PDF:

```text
Decryption Policy
    -> ordered Decryption Rules
    -> default action / undecryptable handling
```

Rule actions include configurations such as:

```text
Decrypt - Resign
Decrypt - Known Key
Do Not Decrypt
Block
Block with Reset
Monitor
```

Retain:

```text
policy identity
rule identity/order
rule action
network/port conditions
certificate/CA references
TLS/certificate-status conditions
default behavior
advanced settings
ACP association
```

**Never export private keys.**

For certificate objects, retain only non-secret metadata and reference IDs plus safe private-key presence metadata when useful.

## 8.6 DNS Policy

Official DNS Policy PDF:

```text
DNS Policy
    -> ordered DNS Rules
    -> block / do-not-block lists and feeds
```

Retain:

```text
policy identity
rule identity/order
rule action
security-zone conditions
network conditions
VLAN conditions
DNS list/feed references
ACP association
Umbrella-related explicit configuration if present
```

Do not replace a dynamic feed with its current downloaded membership as explicit configuration.

## 8.7 Extraction rules

- Do not create `CiscoProfileGroup`.
- Keep each native policy/object separate.
- Keep Access Rule references to those policies as relationships.
- Preserve order within ordered subpolicies.
- Do not manufacture an `Effective Security Stack` unless a later transform explicitly calculates it.
- If calculated, the effective stack is derived and must remain traceable to source Access Rules and referenced policies.

---

# 9. Schedules / Time Ranges

## 9.1 Mapping

```text
FortiGate:
config firewall schedule onetime
config firewall schedule recurring
config firewall schedule group

Cisco FTD/FMC:
Time Range object
```

## 9.2 Official extraction root

REST API PDF, around printed pages 305-306:

```text
GETALL
/api/fmc_config/v1/domain/{domainUUID}/object/timeranges
```

## 9.3 Source state

Retain the actual API representation, including when present:

```text
id / UUID
name
description
absolute / continuous range entries
recurring range entries
start/end date/time
day-of-week selections
start/end time
domain ownership
```

## 9.4 Rules

Cisco Access Control Rules document both:

```text
continuous time range
recurring time period
```

Time-based access rules use the local time of the device processing traffic.

## 9.5 Extraction rules

- Preserve continuous and recurring periods distinctly.
- Do not convert local-time source configuration to UTC in the explicit source model.
- Do not add a standalone Cisco schedule-group source object solely because FortiGate has one.
- If one Time Range contains multiple configured periods, retain those periods as part of the same Time Range.
- Policy references remain references.

---

# 10. Service Objects and Service Groups

## 10.1 Mapping

```text
FortiGate:
config firewall service custom
config firewall service group
config firewall service category

Cisco FTD/FMC:
Protocol Port Object
Port Object Group
```

No direct standalone FortiGate-style service-category object is required.

## 10.2 Official extraction roots

REST API PDF, around printed pages 274-277:

```text
GETALL
/api/fmc_config/v1/domain/{domainUUID}/object/protocolportobjects
```

Groups:

```text
GETALL
/api/fmc_config/v1/domain/{domainUUID}/object/portobjectgroups
```

## 10.3 Protocol/port object source state

Retain the API fields returned by FMC, including when present:

```text
id / UUID
name
description
protocol
port / destination port expression
ICMP type
ICMP code
domain ownership
override metadata
```

Cisco's object import rules document protocol, port, ICMP code, and ICMP type as distinct source columns.

## 10.4 Port Object Group source state

Retain:

```text
id / UUID
name
description
member references
domain ownership
override metadata
```

## 10.5 Extraction rules

- Preserve the protocol separately from the port expression.
- Preserve ICMP type/code semantics rather than coercing ICMP into TCP/UDP.
- Port Object Group members are references.
- Do not expand group members into the owning rule.
- Preserve references to predefined/system port objects without manufacturing local user-defined objects.
- Do not create a Cisco `ServiceCategory` unless Cisco actually exposes an explicit source object for it.
- A reporting category may be derived later.

---

# 11. Destination NAT / FortiGate VIP Equivalent

## 11.1 Mapping

```text
FortiGate:
config firewall vip

Cisco FTD/FMC:
FTD NAT Policy
    NAT Rule
        destination translation
```

Cisco does not require a standalone `VIP` source object.

## 11.2 Source configuration to retain

Use the NAT sources described in Section 6.

For DNAT/VIP-equivalent behavior retain the whole NAT rule:

```text
rule id/name
enabled
section/order

source interface
destination interface

original source
original destination
original service

translated source
translated destination
translated service

static/dynamic/identity NAT mode
port translation
advanced NAT settings
```

## 11.3 Extraction rules

- Destination translation stays attached to the NAT rule.
- Preserve original match criteria and translated destination together.
- Preserve translated service/port where configured.
- Do not detach translated destination and create `CiscoVIP` as explicit source.
- A FortiGate-like VIP view may be a derived migration/reporting view.
- Derived VIP records must retain traceability to NAT policy UUID and NAT rule UUID.

---

# 12. FortiGate VIP Group Equivalent

## 12.1 Mapping

```text
FortiGate:
config firewall vipgrp

Cisco FTD/FMC:
no direct VIP-group source object
```

## 12.2 Source configuration to collect

```text
FTD NAT policies
NAT rules
Network Address objects
Network Groups
Access Control Rules that reference the related translated/original addresses
```

## 12.3 Extraction rules

- Do not create a fake `CiscoVIPGroup`.
- Preserve NAT rules independently.
- Preserve Network/Network Group references.
- Preserve ACL/ACP relationships separately.
- Any grouping of related DNAT mappings for migration/reporting is derived state.

---

# 13. IPS / Intrusion Policy

## 13.1 Mapping

```text
FortiGate:
config ips sensor

Cisco FTD/FMC:
Intrusion Policy
Intrusion rule behavior
Snort 3 rule groups
Variable Set
```

## 13.2 Official extraction roots

REST API PDF, around printed pages 370-373:

```text
GETALL
/api/fmc_config/v1/domain/{domainUUID}/policy/intrusionpolicies
```

Snort 3 rule groups:

```text
GETALL
/api/fmc_config/v1/domain/{domainUUID}/policy/intrusionpolicies/{policyUUID}/intrusionrulegroups
```

Per-policy intrusion-rule behavior is exposed through the corresponding nested intrusion-rule resources.

## 13.3 Source state to retain

Retain, where returned:

```text
intrusion policy id / UUID
name
description
base/system policy relationship if explicitly represented
Snort version / inspection mode metadata
variable set reference
rule group configuration
rule identifiers
per-policy rule state/action
explicit rule overrides
policy advanced settings
network analysis relationship where applicable
```

For each Access Control Rule:

```text
Intrusion Policy reference
Variable Set reference
```

must remain source relationships.

## 13.4 Rules

Access Control Rules determine which traffic is passed to an Intrusion Policy.

Cisco documents that when both File Policy and Intrusion Policy are attached to a qualifying rule:

```text
file inspection
    -> intrusion inspection
```

for the relevant traffic flow.

## 13.5 Extraction rules

- Preserve Intrusion Policy independently from Access Control Policy.
- Preserve rule-level behavior/overrides rather than generating a flat list of every Cisco signature.
- Do not materialize Cisco's entire system/default signature database as explicit user configuration.
- Preserve the Variable Set reference.
- Do not infer a FortiGate IPS filter from Cisco rule metadata unless a derived transform explicitly performs that conversion.
- Preserve custom/local rule changes when returned.
- Do not export sensitive payload/event data as configuration.

---

# 14. Static Routes

## 14.1 Mapping

```text
FortiGate:
config router static

Cisco FTD/FMC:
Static Route
    device/global virtual router
    or explicit virtual router
```

## 14.2 Official extraction root

REST API PDF, around printed page 125:

```text
GETALL
/api/fmc_config/v1/domain/{domainUUID}/devices/devicerecords/{deviceUUID}/routing/staticroutes
```

For devices in multi-virtual-router mode, the device-level resource applies to the Global Virtual Router.

Also extract the matching virtual-router-specific static-route resources when virtual routers are explicitly configured.

## 14.3 Source fields

The Static and Default Routes PDF documents configuration fields including:

```text
virtual router ownership
IPv4 / IPv6
interface
destination network object
gateway / IPv6 gateway
metric
Tunneled default-route option
SLA Monitor / route tracking
Null0 interface
```

Preserve other explicit API fields as returned.

## 14.4 Important rules

- Default IPv4 route: `0.0.0.0/0`.
- Default IPv6 route: `::/0`.
- Data-interface routing and management-only/Linux routing are distinct.
- Static route tracking is associated with an SLA monitoring target.
- Static route tracking is documented for IPv4, not IPv6.
- `Null0` is an explicit drop/black-hole next-hop semantic.
- Virtual-router ownership matters.
- Route leaks between virtual routers must not be flattened into ordinary same-VR next-hop behavior.

## 14.5 Extraction rules

- Preserve IPv4 and IPv6 routes distinctly.
- Preserve `Null0` rather than inventing a gateway.
- Preserve virtual router ownership.
- Preserve destination and gateway object references.
- Preserve metric/admin-distance fields exactly as returned.
- Preserve SLA Monitor reference, not current probe result, in explicit source.
- Current route-up/down state is operational/effective state.
- Do not merge management Linux routes with data-plane static routes.

---

# 15. Administrator Access Profiles / User Roles

## 15.1 Mapping

```text
FortiGate:
config system accprofile
```

Cisco has two different management-plane concepts:

```text
FMC web-interface User Role
FTD device CLI role
```

They must remain separate.

## 15.2 A. FMC User Roles

Official sources:

- FMC Administration Guide — Users PDF.
- REST API Guide, around printed page 56.

REST extraction:

```text
GETALL
/api/fmc_config/v1/domain/{domainUUID}/users/authroles
```

The REST guide describes this as the list of existing user roles.

FMC includes predefined roles and supports custom roles.

Retain:

```text
role id / UUID
name
description
predefined/custom identity
menu-based permissions
system permissions
domain ownership
role-escalation settings if explicitly configured
other explicit permissions
```

Do not collapse granular permissions to one `read-write` flag.

## 15.3 B. FTD CLI roles

The FTD CLI Users PDF documents:

```text
None
Config
Basic
```

`Config` permits configuration commands.

`Basic` is restricted to a limited non-configuration command set in the documented 7.7 behavior.

This is not the same authorization model as an FMC web role.

## 15.4 Extraction rules

- Model FMC roles and device CLI roles separately.
- A FortiGate `accprofile` comparison can be derived from both management planes if needed.
- Preserve custom FMC role permissions.
- Preserve role-to-user assignment separately from role definition.
- Preserve FMC domain ownership.
- Do not infer a custom FMC role from an FTD CLI `Config`/`Basic` role.

---

# 16. Administrators

## 16.1 Mapping

```text
FortiGate:
config system admin

Cisco:
FMC User
FTD per-device CLI User
```

These are separate account stores.

## 16.2 A. FMC users

Official REST extraction:

```text
GETALL
/api/fmc_config/v1/domain/{domainUUID}/users/users
```

REST API PDF, around printed page 58.

Retain non-secret fields returned by FMC, such as:

```text
id / UUID
username
enabled/disabled state
internal/external/SSO authentication type
assigned role references
domain ownership
external authentication relationship
other non-secret account properties
```

FMC documentation states that a user added to FMC does not automatically become a login user on a managed FTD device.

## 16.3 B. FTD CLI users

Official FTD CLI Users PDF documents per-device users.

Retain non-secret state such as:

```text
username
authentication source/type
CLI role: None / Basic / Config
enabled/disabled
UID if explicitly returned
password-aging configuration
force-password-reset state
max failed logins
lock state
minimum password length
password-strength-check state
external LDAP/RADIUS configuration reference where used
```

Relevant read-only command output includes:

```text
show user
```

The PDF documents user management commands, but an extractor must not issue modifying commands.

## 16.4 Secret rule

Never record:

```text
password
password hash
LDAP bind password
RADIUS shared secret
```

Use safe metadata only.

## 16.5 Extraction rules

- Keep FMC accounts and device CLI accounts separate.
- Preserve account scope/device ownership.
- Preserve role references.
- Do not merge users solely because usernames match.
- Do not store passwords even if an API/export exposes a secret-bearing field.
- External directory credentials are references/authentication metadata, not local password values.

---

# 17. DHCP Server

## 17.1 Mapping

```text
FortiGate:
config system dhcp server

Cisco FTD:
DHCPv4 Server
```

## 17.2 Official extraction root

REST API PDF, around printed pages 93-94:

```text
GET
/api/fmc_config/v1/domain/{domainUUID}/devices/devicerecords/{deviceUUID}/dhcp/dhcpserver
```

Use the full device DHCP server representation returned by FMC.

## 17.3 Source state documented by the DHCP PDF

Global/server configuration includes:

```text
Ping Timeout
Lease Length
Auto-configuration enabled/disabled
auto-configuration interface
domain name
primary/secondary DNS server references
primary/secondary WINS server references
DHCP options
```

Per-interface DHCP server entry includes:

```text
interface
address pool
enabled/configured state
other explicit per-interface settings
```

The chapter also documents DHCPv6 stateless server and DHCP relay as separate features. Do not silently merge those into DHCPv4 server source objects.

## 17.4 Important source rules

The official PDF documents:

- One DHCP server per interface.
- Each interface can have its own address pool.
- Several settings such as DNS/WINS/domain/options are global and shared across DHCP servers.
- An FTD interface cannot simultaneously act as both DHCP client and DHCP server in the conflicting configuration.
- DHCP Server and DHCP Relay cannot both be configured on the same device in the documented model.
- Mode/interface restrictions differ for routed and transparent deployments.

## 17.5 Extraction rules

Keep separate:

```text
device DHCP server global settings
per-interface server entry
per-interface address pool
DHCP options
DHCPv6 stateless server
DHCP relay
```

- Preserve interface ownership.
- Do not synthesize reservations or options that are not explicitly configured.
- Do not populate documented default lease/ping values into explicit source fields if they are absent from the extracted configuration.
- Runtime leases are operational state, not source configuration.

---

# 18. SD-WAN

## 18.1 Mapping

```text
FortiGate:
config system sdwan

Cisco FTD/FMC:
split architecture
```

Cisco 7.7 documents an SD-WAN wizard/topology, but the resulting feature is composed from multiple native configuration areas.

## 18.2 Native source areas to collect

Depending on the deployment:

```text
Site-to-Site VPN / SD-WAN topology
hub/spoke endpoints
dynamic VTI / static VTI
physical WAN interfaces
ECMP Zones
Policy-Based Routing
path monitoring
SLA Monitor objects
static/default routes
routing/virtual-router ownership
NAT policies/rules
Access Control Policies/rules
IKE/IPsec configuration
```

Do not store all of this as one synthetic FortiGate-style `SDWAN` source object.

## 18.3 Official REST extraction roots

### ECMP Zones

REST API PDF, around printed pages 95-96:

```text
GETALL
/api/fmc_config/v1/domain/{domainUUID}/devices/devicerecords/{deviceUUID}/routing/ecmpzones
```

### Policy-Based Routing

REST API PDF, around printed pages 121-123:

```text
GETALL
/api/fmc_config/v1/domain/{domainUUID}/devices/devicerecords/{deviceUUID}/routing/policybasedroutes
```

Also use the virtual-router-specific form when the configuration is owned by a non-global virtual router.

### SLA Monitors

REST API PDF, around printed pages 299-300:

```text
GETALL
/api/fmc_config/v1/domain/{domainUUID}/object/slamonitors
```

### VPN topology

Use the S2S VPN resources in Section 22 for the tunnel topology created/used by SD-WAN.

## 18.4 SD-WAN wizard rules

The official SD-WAN PDF documents that:

- The wizard creates VPN tunnels between hub and spoke devices.
- Current documented wizard workflows use site-to-site VPN topology constructs.
- VTI interfaces are central to the topology.
- ECMP zones can contain WAN/VTI interfaces depending on design.
- Underlay routing, NAT, and access-control policies are prerequisites/dependencies.
- IKEv1 is not supported by the documented SD-WAN wizard workflow.
- Wizard-specific topology limits and platform/version requirements exist.

## 18.5 Extraction rules

Keep separate:

```text
SD-WAN/topology metadata if explicitly returned
S2S VPN topology
endpoint
VTI
ECMP zone
PBR rule
SLA monitor
static/default route
interface
NAT
ACP
```

- Preserve all references between these components.
- Preserve rule order for PBR.
- Preserve virtual-router ownership.
- Preserve interface ownership.
- Runtime latency/loss/jitter/probe status is operational data unless an explicit configured threshold/object is returned.
- Do not derive FortiGate `member-id`, `health-check`, or `service` objects as source configuration.
- A FortiGate-compatible SD-WAN view belongs in DerivedViews.

---

# 19. Security Zones

## 19.1 Mapping

```text
FortiGate:
config system zone

Cisco FTD/FMC:
Security Zone
```

## 19.2 Official extraction root

REST API PDF, around printed pages 289-291:

```text
GETALL
/api/fmc_config/v1/domain/{domainUUID}/object/securityzones
```

Per-zone retrieval can return interface membership.

The API documents `groupByDevice` for grouping interfaces by device.

## 19.3 Source state

Retain:

```text
id / UUID
name
interface mode/type
interface references
device ownership of interfaces
domain ownership
other explicit zone metadata
```

## 19.4 Extraction rules

- Zone membership comes from Security Zone/interface source relationships.
- Do not infer zone membership from Access Control Rules.
- Preserve interface references and device ownership.
- Preserve interface mode when returned.
- Do not derive physical/subinterface hierarchy in the parser.
- Interface topology belongs in the relationship/topology layer.
- Keep Security Zone distinct from Interface Group if both exist.

---

# 20. User Groups / Identity Realms

## 20.1 Mapping

```text
FortiGate:
config user group

Cisco FTD/FMC:
Realm
Realm User Group
Realm User
```

Cisco's external identity model is directory/realm based rather than a FortiGate local `user group` object model.

## 20.2 Official extraction roots

### Realms

REST API PDF, around printed pages 280-282:

```text
GETALL
/api/fmc_config/v1/domain/{domainUUID}/object/realms
```

Cisco documents realm types including:

```text
AD
LDAP
Local
SAML
```

as applicable to the API version.

### Realm User Groups

REST API PDF, around printed pages 282-283:

```text
GETALL
/api/fmc_config/v1/domain/{domainUUID}/object/realmusergroups
```

### Realm Users

```text
GETALL
/api/fmc_config/v1/domain/{domainUUID}/object/realmusers
```

## 20.3 Realm source state

Preserve, when returned:

```text
realm id / UUID
name
realm type
enabled state
directory/server configuration
directory base DN / search parameters
user/group object classes
user/group naming attributes
AD/LDAP domain settings
directory synchronization settings
other explicit non-secret fields
```

Never export bind passwords.

## 20.4 Realm group/user state

Preserve:

```text
object id
name
realm reference
group/user identifiers
resolved/synchronized state metadata where returned
relationships between realm users and groups
```

## 20.5 Important modeling distinction

Directory groups downloaded/synchronized from a Realm are not equivalent to a locally authored FortiGate `config user group` object.

Keep distinct:

```text
Realm configuration             explicit FMC source
Realm User Group identity       synchronized identity source state
Runtime authenticated identity  operational state
Access Rule group reference     policy source relationship
```

## 20.6 Extraction rules

- Preserve Realm ownership for every user/group.
- Do not copy current directory group members into an explicit static Cisco group object unless the API explicitly represents those memberships as configuration/source data.
- Preserve group references in Access Rules.
- Do not treat runtime identity mapping as persistent configuration.
- Never export LDAP/RADIUS secrets.
- Keep external identity state separate from FMC administrators and FTD CLI administrators.

---

# 21. Local Users

## 21.1 Mapping

```text
FortiGate:
config user local

Cisco FTD/FMC:
Local Realm User
```

This is for firewall/user identity, not FMC administration.

## 21.2 Official extraction root

REST API PDF, around printed pages 263-264:

```text
GETALL
/api/fmc_config/v1/domain/{domainUUID}/object/localrealmusers
```

The API allows filtering by realm and username.

## 21.3 Source state

Retain non-secret fields returned by FMC:

```text
id / UUID
username/name
local realm reference
enabled/disabled state where present
group/identity relationships where present
non-secret authentication metadata
domain ownership
```

## 21.4 Secret rule

Never export:

```text
password
password hash
password-equivalent token
```

Use:

```text
Password Configured = Yes|No
```

only if source safely exposes password-presence semantics.

## 21.5 Extraction rules

- Local Realm Users are firewall authentication identities.
- Do not merge them with FMC management users.
- Do not merge them with per-device FTD CLI users.
- Preserve local realm ownership/reference.
- Preserve policy references separately.

---

# 22. Site-to-Site IPsec VPN

## 22.1 Mapping

```text
FortiGate:
config vpn ipsec phase1
config vpn ipsec phase1-interface
config vpn ipsec phase2
config vpn ipsec phase2-interface

Cisco FTD/FMC:
FTD Site-to-Site VPN topology
VPN endpoints
IKE policy
IPsec proposal
IPsec/tunnel settings
protected networks / traffic selectors
VTI for route-based VPN where used
```

Do not create Cisco `Phase1` and `Phase2` source objects merely to resemble FortiGate.

## 22.2 Official extraction root

REST API PDF, around printed pages 346-350:

```text
GETALL
/api/fmc_config/v1/domain/{domainUUID}/policy/ftds2svpns
```

Endpoints:

```text
GETALL
/api/fmc_config/v1/domain/{domainUUID}/policy/ftds2svpns/{vpnUUID}/endpoints
```

Retrieve the nested advanced/IKE/IPsec resources supported by the running FMC API where required to reconstruct the explicit topology configuration.

## 22.3 Topology source state

Preserve:

```text
VPN topology id / UUID
name
topology type
enabled/state metadata
domain ownership

endpoint list/order/roles
managed device reference
external/extranet peer reference where applicable

interface / VPN interface reference
peer IP/addressing
protected network references

route-based / policy-based mode
VTI / tunnel interface references
NAT exemption dependencies/references where configured
```

## 22.4 IKE configuration

The Site-to-Site VPN PDF documents IKE configuration including:

```text
IKEv1 / IKEv2
IKE policy reference
authentication type
pre-shared key or certificate authentication
identity settings
keepalive / DPD-related configuration
peer identity validation
other advanced IKE options
```

Preserve only explicitly configured fields.

## 22.5 IPsec configuration

The PDF documents configuration including:

```text
IKEv1 IPsec Proposal
IKEv2 IPsec Proposal
encryption/integrity proposal references
SA-related settings
PFS where configured
tunnel/traffic settings
advanced IPsec options
```

Keep reusable IKE/IPsec objects separate from the VPN topology.

## 22.6 Secret handling

Pre-shared keys are secret.

Never store them.

Use:

```text
Pre-Shared Key Configured = Yes
```

Certificate authentication:

```text
certificate reference
Private Key Present = Yes|No
```

Never export the private key.

## 22.7 NAT and routing dependencies

Cisco documentation notes that VPN deployments can require:

```text
NAT exemption / identity NAT
routing
Access Control Policy rules
VTI routes
```

These are separate source configurations.

Do not copy them into the S2S VPN object.

Resolve their relationships later.

## 22.8 Extraction rules

Keep separate:

```text
S2SVPNTopology
S2SVPNEndpoint
IKEPolicy
IPsecProposal
advanced IKE settings
advanced IPsec settings
VTI/interface
protected-network references
NAT rule
static/dynamic route
ACP rule
certificate/PKI object
```

- Preserve topology ownership.
- Preserve endpoint relationships.
- Preserve IKE version.
- Preserve proposal references.
- Preserve route-based vs policy-based architecture.
- Preserve VTI/interface ownership.
- Do not map directly into synthetic Cisco Phase1/Phase2 objects.
- A FortiGate Phase1/Phase2 comparison belongs in DerivedViews.

---

# 23. Remote Access VPN / FortiGate SSL VPN Equivalent

## 23.1 Mapping

```text
FortiGate:
config vpn ssl ...

Cisco FTD/FMC:
Remote Access VPN policy/topology
Connection Profile
Group Policy
AAA / Realm
Address Pool
Access Interface
Certificate/PKI configuration
Secure Client configuration
IPsec/SSL settings
NAT exemption
Access Control Policy dependencies
```

Cisco Remote Access VPN is not a single FortiGate-style SSL-VPN source object.

## 23.2 Official extraction root

REST API PDF, around printed pages 377-401:

```text
GETALL
/api/fmc_config/v1/domain/{domainUUID}/policy/ravpns
```

The REST API documents nested RA VPN resources including configuration areas such as:

```text
connection profiles
IPsec settings
LDAP attribute maps
load-balance settings
other RA VPN topology children
```

Use the exact nested resources supported by the running FMC version.

## 23.3 Remote Access VPN source state

Preserve:

```text
RA VPN policy/topology id / UUID
name
target FTD devices
access interfaces
certificate references
SSL/TLS settings
DTLS settings
IPsec/IKEv2 settings where configured
Secure Client package/profile references
connection profile references
group policy references
AAA/realm references
address-pool references
DNS/domain/split-tunnel settings
session settings
certificate maps
LDAP attribute maps
load-balancing configuration
other explicit advanced settings
```

## 23.4 Connection Profiles

Connection Profile source state can include:

```text
name / alias
group URL / profile-selection settings
authentication server / realm
authorization server
accounting server
certificate authentication/mapping
address assignment policy
address pools
default Group Policy reference
other explicit connection settings
```

Connection-profile selection can use aliases/URLs and certificate maps.

Preserve the actual mapping configuration.

## 23.5 Group Policies

The Remote Access VPN PDF describes a Group Policy as a set of attributes defining the remote-access VPN experience.

Preserve:

```text
group policy id/name
VPN access state
protocol/connection settings
DNS/WINS/domain settings
split tunneling
Secure Client settings
session settings
simultaneous login settings
other explicit attributes
```

A RADIUS/ISE authorization server can override the group-policy selection.

Keep:

```text
configured default group-policy reference
external authorization relationship
```

separate from the effective runtime group policy.

## 23.6 Address Pools

Official Remote Access VPN PDF documents internal address pools for VPN clients.

Preserve:

```text
pool object/reference
IPv4 or IPv6
start/end range or source representation
connection-profile reference
device-level override where explicitly configured
address reuse delay where configured
```

Do not replace the configured pool with currently leased client addresses.

## 23.7 Access Control Policy dependency

Remote-access VPN traffic must still be authorized by appropriate access-control configuration.

Preserve ACP rules independently.

Do not treat RA VPN creation as an implicit allow rule.

## 23.8 NAT exemption

Cisco's Remote Access VPN PDF documents optional NAT exemption/identity NAT for remote-access traffic.

Keep the NAT rule as NAT source configuration.

Do not copy NAT exemption fields into the RA VPN source object.

Relationship:

```text
RA VPN
    -> uses client address pool
ACP rule
    -> permits relevant RA VPN traffic
NAT rule
    -> exempts/identity-translates relevant traffic
```

## 23.9 AAA and realm dependencies

Keep separate:

```text
Realm
RADIUS server group
LDAP server / realm
ISE authorization relationship
connection profile
group policy
```

Do not copy external directory users/groups into the RA VPN source object.

## 23.10 Certificate and secret handling

Never export:

```text
private keys
PKCS#12 passwords
pre-shared keys
LDAP bind passwords
RADIUS secrets
user passwords
Secure Client secret material
```

Retain references and safe presence metadata only.

## 23.11 Extraction rules

Keep separate:

```text
RemoteAccessVPN
ConnectionProfile
GroupPolicy
Realm
RealmUserGroup
AddressPool
Certificate/PKI object
CertificateMap
SecureClientProfile/package reference
LDAPAttributeMap
NATRule
AccessControlRule
```

- Preserve target-device ownership.
- Preserve access-interface references.
- Preserve group-policy and connection-profile relationships.
- Preserve external AAA relationships.
- Preserve address pool references.
- Preserve split-tunnel configuration when explicit.
- Preserve certificate references without private keys.
- Do not create a synthetic Cisco `SSLVPNPortal` merely to mirror FortiGate.
- Any FortiGate portal/auth-rule comparison is derived state.

---

# 24. Supporting Object and Policy Dependencies

The 20 selected FortiGate areas cause additional Cisco source dependencies that should be extracted when referenced.

## 24.1 Interface inventory

Needed for:

```text
Security Zones
Static Routes
NAT
DHCP
SD-WAN
S2S VPN
RA VPN
```

Preserve interface source separately from policies.

Useful relationship examples:

```text
SecurityZone -> Interface
DHCPServerEntry -> Interface
StaticRoute -> Interface
S2SVPNEndpoint -> Interface/VTI
RAVPN -> Access Interface
ECMPZone -> Interfaces
PBR -> egress/path interface
```

## 24.2 Virtual routers

Needed when multi-virtual-router mode is configured.

Preserve:

```text
VirtualRouter
    -> interfaces
    -> static routes
    -> ECMP/PBR ownership where applicable
```

Do not silently flatten all routes into a global table.

## 24.3 Certificates and PKI objects

Needed for:

```text
Decryption Policy
S2S VPN
RA VPN
external authentication
```

Retain:

```text
certificate object id/name
certificate metadata
issuer/subject metadata when returned
validity metadata
usage/reference relationships
Private Key Present = Yes|No
```

Never store private-key material.

## 24.4 Address Pools

Address Pool objects are distinct from ordinary Network Address objects and are used by RA VPN.

Do not merge them with NAT translated-address pools.

## 24.5 SLA Monitors

SLA Monitor objects can be referenced by:

```text
static route tracking
PBR/path monitoring
SD-WAN-related path selection
```

Keep the configured monitor object separate from current operational probe status.

---

# 25. Recommended Cisco Source Model Boundaries

The extractor should preserve native Cisco concepts approximately as:

```text
CiscoFMCConfig
├── domains
├── network_addresses
├── network_groups
├── protocol_port_objects
├── port_object_groups
├── time_ranges
├── security_zones
├── interfaces
├── virtual_routers
│
├── nat_policies
│   └── nat_rules
│
├── access_control_policies
│   ├── access_rules
│   └── default_action
│
├── intrusion_policies
│   ├── rule_groups
│   └── rule_behaviors / overrides
│
├── file_policies
│   └── file_rules
│
├── decryption_policies
│   └── decryption_rules
│
├── dns_policies
│   └── dns_rules
│
├── static_routes
├── sla_monitors
├── ecmp_zones
├── policy_based_routes
├── dhcp_server
│
├── realms
├── realm_users
├── realm_user_groups
├── local_realm_users
│
├── fmc_users
├── fmc_user_roles
├── ftd_cli_users
│
├── s2s_vpn_topologies
│   ├── endpoints
│   ├── ike_settings
│   └── ipsec_settings
│
└── remote_access_vpn
    ├── connection_profiles
    ├── group_policies
    ├── address_pool_refs
    ├── certificate_refs
    ├── aaa_references
    └── secure_client_settings
```

This is a responsibility/layout guide, not a requirement to use these exact class names.

The important rule is:

```text
Cisco explicit source
    != FortiGate compatibility view
```

---

# 26. Do Not Introduce These as Cisco Explicit Source Objects

Unless the Cisco API/source explicitly provides such a concept, do not manufacture:

```text
CiscoIPPool
CiscoVIP
CiscoVIPGroup
CiscoProfileGroup
CiscoScheduleGroup
CiscoServiceCategory
CiscoSDWANMember
CiscoSDWANHealthCheck
CiscoPhase1
CiscoPhase2
CiscoSSLVPNPortal
```

Instead:

```text
preserve Cisco source
-> resolve relationships
-> derive FortiGate-comparable view if needed
```

---

# 27. Relationship Layer Guidance

Resolve references after source extraction.

Examples:

```text
NetworkGroup
    -> NetworkAddress members

AccessRule
    -> source/destination SecurityZone
    -> NetworkAddress / NetworkGroup
    -> ProtocolPortObject / PortObjectGroup
    -> TimeRange
    -> RealmUser / RealmUserGroup
    -> IntrusionPolicy
    -> FilePolicy

NATRule
    -> NetworkAddress / NetworkGroup
    -> source/destination interface objects

StaticRoute
    -> VirtualRouter
    -> Interface
    -> destination Network object
    -> gateway Network/Host object
    -> SLAMonitor

SecurityZone
    -> Interface

S2SVPNTopology
    -> Endpoint
    -> IKEPolicy
    -> IPsecProposal
    -> protected networks
    -> VTI/interface

RemoteAccessVPN
    -> ConnectionProfile
    -> GroupPolicy
    -> Realm
    -> AddressPool
    -> Certificate
```

Do not perform these resolutions inside the tokenizer/parser.

---

# 28. Operational State vs Explicit Configuration

Do not mix operational state with explicit source configuration.

Examples of operational/effective data:

```text
current FQDN resolved IPs
current DHCP leases
current identity-session mappings
current logged-in VPN users
current VPN tunnel up/down state
current SA values
current route installation state
current ECMP path status
current SLA probe latency/loss
current intrusion events
current file/malware verdict events
downloaded dynamic feed membership
```

These can be collected separately if a future requirement needs operational inventory.

They must not overwrite source configuration.

---

# 29. Validation Rules

Validation must detect/report only.

Suggested checks:

```text
dangling object reference
missing Network/Port/Time object
dangling Security Zone reference
missing interface referenced by zone/route/VPN
missing Intrusion/File Policy referenced by Access Rule
missing SLA Monitor referenced by route/PBR
missing Realm referenced by identity rule
missing Group Policy referenced by connection profile
missing address pool referenced by RA VPN
missing IKE/IPsec reusable object referenced by S2S VPN
duplicate names within a source scope where invalid
invalid/unknown object type
unsupported source field retained in raw_extra
secret-bearing field detected and redacted
```

Do not repair the configuration.

Do not substitute defaults.

---

# 30. Source Inventory Rules

Every extracted source area should be visible in Source Inventory even if no FortiGate equivalent exists.

Suggested inventory columns:

```text
Domain
Source Type
Source Name
Source UUID
Owning Policy/Device
Enabled/Disabled
Referenced By
Support Status
Notes
```

Support status examples:

```text
Direct
Split Model
Different Model
No Direct FortiGate Equivalent
Source Only
Unsupported/Unknown
```

---

# 31. REST Extraction Order

A practical dependency-aware read order is:

```text
1. FMC domains / target devices
2. interfaces / virtual routers
3. reusable objects
   - network addresses
   - network groups
   - protocol-port objects
   - port groups
   - time ranges
   - security zones
   - SLA monitors
   - address pools
   - PKI/certificate metadata
4. identity
   - realms
   - realm users
   - realm user groups
   - local realm users
5. management identities
   - FMC roles
   - FMC users
   - per-device FTD CLI users
6. routing/DHCP
   - static routes
   - ECMP
   - PBR
   - DHCP
7. NAT policies/rules
8. inspection policies
   - intrusion
   - file
   - decryption
   - DNS/Security Intelligence
9. Access Control Policies/rules
10. S2S VPN
11. Remote Access VPN
12. relationships
13. derived comparison views
14. validation
15. Excel/reporting
```

This order is for extractor implementation convenience.

It must not be interpreted as Cisco runtime packet-processing order.

---

# 32. Pagination and Full Detail

For REST collection resources:

```text
GETALL
```

must be paginated until all records are collected.

Preserve:

```text
offset
limit
count/total where returned
```

as transport metadata if useful, but do not treat pagination metadata as firewall configuration.

Where a collection endpoint returns abbreviated object references:

```text
GET collection
-> identify object IDs
-> GET object details when required
```

Do not assume `expanded=true` always returns every nested source field.

Use the actual running FMC API schema/version as the final authority when it differs from a documentation example.

---

# 33. Secret-Field Redaction Gate

Secret redaction should occur before generic raw preservation.

Recommended flow:

```text
API/CLI field received
    -> classify field
        -> secret-bearing
            -> discard/redact value
            -> safe presence metadata only
        -> non-secret known
            -> typed source field
        -> non-secret unknown
            -> raw_extra / Additional Settings
```

Never run:

```text
unknown field
-> raw_extra
```

before checking whether the field is secret-bearing.

---

# 34. Final Mapping Summary

```text
FortiGate Address
    -> Cisco Network Address

FortiGate Address Group
    -> Cisco Network Group

FortiGate IP Pool
    -> Cisco NAT source translation
    -> derived FortiGate-compatible IPPool view only

FortiGate Firewall Policy
    -> Cisco Access Control Policy / Access Rule

FortiGate Profile Group
    -> Cisco split inspection architecture
    -> no source ProfileGroup

FortiGate Schedule
    -> Cisco Time Range

FortiGate Service
    -> Cisco Protocol Port Object

FortiGate Service Group
    -> Cisco Port Object Group

FortiGate Service Category
    -> no direct standalone Cisco source object

FortiGate VIP
    -> Cisco NAT destination translation
    -> derived VIP view only

FortiGate VIP Group
    -> no direct Cisco source object

FortiGate IPS Sensor
    -> Cisco Intrusion Policy

FortiGate Static Route
    -> Cisco Static Route

FortiGate Admin Profile
    -> FMC User Role
    + separate FTD CLI role model

FortiGate Admin
    -> FMC User
    + separate FTD CLI User

FortiGate DHCP Server
    -> Cisco FTD DHCPv4 Server

FortiGate SD-WAN
    -> Cisco S2S/SD-WAN topology + VTI + ECMP + PBR + SLA + routing dependencies

FortiGate Zone
    -> Cisco Security Zone

FortiGate User Group
    -> Cisco Realm / Realm User Group identity model

FortiGate Local User
    -> Cisco Local Realm User

FortiGate IPsec Phase1/Phase2
    -> Cisco S2S VPN topology + endpoints + IKE/IPsec reusable objects

FortiGate SSL VPN
    -> Cisco Remote Access VPN architecture
```

---

# 35. Implementation Constraint for FortiGate Extract

For this project:

```text
Tokenizer          syntax/API transport only
Parser/API reader  source structure only
Evaluator          only source operation semantics where applicable
Cisco source model explicit FMC/FTD state
Relationships      references / interface ownership / topology
Transforms         cross-vendor normalization / derived FortiGate-comparable views
Validation         detect and report only
Excel              presentation only
```

Do not add a Cisco source-model field only to satisfy Excel.

If a Cisco feature has no direct FortiGate equivalent:

```text
preserve source
-> mark source-only / no-direct-equivalent
-> expose in Source Inventory / appendix
```

When behavior is unclear:

```text
preserve source
-> mark unknown
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
