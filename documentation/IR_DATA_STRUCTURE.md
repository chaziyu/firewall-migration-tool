# Vendor-Neutral Intermediate Representation (IR) Data Structure

**Document status:** Proposed authoritative architecture specification
**Project:** Firewall Migration Tool
**Applies to:** FortiGate / FortiOS, Palo Alto Networks PAN-OS, Cisco ASA / FTD / FMC, Check Point, Juniper SRX, and future vendors
**Primary implementation location:** `src/fwmigrate/ir/`
**Related document:** `documentation/EXTRACTION_DATA_MODEL.md`

---

## 1. Purpose

The Vendor-Neutral Intermediate Representation (IR) is the canonical contract between source ingestion and target generation.

The required migration path is:

```text
Source configuration file
            |
            v
      Vendor parser/client
            |
            v
     ExtractionResult
            |
            +--> extraction-only / vendor-specific / unsupported records
            |
            v
       Canonical IR
            |
            v
 normalization + validation
            |
            v
      Target generator
            |
       +----+-----+
       |          |
       v          v
 Native config  Terraform / API deployment
```

The IR MUST represent **firewall intent**, not vendor CLI syntax. Vendor-specific syntax belongs in source adapters, target generators, or vendor-extension records.

The IR is not required to force every vendor setting into a common abstraction. Source configuration that has no useful vendor-neutral meaning must still be accounted for through the extraction model.

---

## 2. Core design principles

### 2.1 M x N architecture

Source parsers produce vendor-neutral IR. Target generators consume vendor-neutral IR.

Do not implement direct source-to-target converters such as:

```text
FortiGate -> PAN-OS
FortiGate -> Cisco
PAN-OS -> Juniper
```

The desired architecture is:

```text
FortiGate ----+
PAN-OS -------+
Cisco --------+----> Canonical IR ----> FortiGate
Check Point --+                    +--> PAN-OS
Juniper ------+                    +--> Cisco
                                   +--> Check Point
                                   +--> Juniper
```

### 2.2 Zero silent loss

Every migration-relevant source configuration element must end in one of these outcomes:

- `NORMALIZED` — represented in canonical IR.
- `PARTIALLY_NORMALIZED` — partly represented, with an explicit warning describing lost or approximated semantics.
- `EXTRACT_ONLY` — represented structurally for inventory/reporting but not used for cross-vendor migration.
- `VENDOR_EXTENSION` — preserved as structured vendor-specific data.
- `UNSUPPORTED` — recognized but not currently representable.
- `IGNORED_BY_POLICY` — intentionally excluded by documented product policy.
- `PARSE_ERROR` — recognized input could not be parsed safely.

Relevant configuration MUST NOT silently disappear.

### 2.3 No permissive fallback

Parser or transformation uncertainty must never silently broaden access.

Forbidden examples include:

- unresolved source address -> `any`
- unresolved destination address -> `any`
- unresolved service -> `any`
- unknown policy action -> `allow`
- unknown interface -> invented `trust` or `untrust` zone
- disabled rule -> enabled rule

Use unresolved references, warnings, blocking validation, or manual-review states instead.

### 2.4 Deterministic representation

Equivalent source semantics should normalize to equivalent IR regardless of vendor syntax.

Examples:

- `255.255.255.0` and `/24` should normalize to the same network prefix.
- TCP port `443` should have the same IR representation whether defined inline or through a named service object.
- A policy must preserve sequence/order where rule evaluation is ordered.

### 2.5 Source provenance

Every significant IR object should retain enough provenance to answer:

> Which source object/configuration statement produced this IR object?

This is required for audit, Excel extraction, troubleshooting, and semantic diff.

### 2.6 Secrets are not portable configuration data

Credentials and private secrets must not be embedded in normal serialized IR or exported reports.

Examples:

- API tokens
- admin passwords/password hashes
- private keys
- pre-shared keys
- SNMP community secrets
- LDAP bind passwords

IR may store a boolean such as `secret_present=true` or a secret reference identifier, but not the secret value in portable reports.

---

## 3. Current implementation versus target schema

The current implementation already contains core models for:

- metadata
- zones
- interfaces
- addresses
- address groups
- services
- service groups
- schedules
- security profile groups
- security policies
- NAT rules
- VPN tunnels
- routes
- Internet services
- audit entries

The target schema in this document expands that foundation so the project can support enterprise configurations without forcing vendor-specific behavior into generic fields.

During implementation, every schema change must be versioned and covered by tests.

---

## 4. Recommended top-level IRConfig

Conceptual target structure:

```python
IRConfig
    schema_version
    metadata
    scopes[]
    system

    network
        interfaces[]
        zones[]
        vlans[]
        routing_instances[]
        tunnels[]

    objects
        addresses[]
        address_groups[]
        services[]
        service_groups[]
        applications[]
        application_groups[]
        schedules[]
        tags[]
        internet_services[]
        external_lists[]

    policies
        security[]
        authentication[]
        decryption[]
        application_override[]
        policy_based_forwarding[]
        dos[]
        qos[]

    ip_pools[]
    virtual_ips[]
    nat_rules[]
    routing
    vpn
    security_profiles
    identity
    pki
    high_availability
    sdwan
    qos
    network_services
    management
    logging

    vendor_extensions[]
    audit_entries[]
```

Extraction-only and unsupported source data belongs primarily to `ExtractionResult`, not inside the canonical migration IR. A limited `vendor_extensions` collection is retained for structured data that is useful downstream but intentionally vendor-specific.

---

# 5. Common base structures

## 5.1 `IRSourceReference`

Every major object SHOULD contain a source reference.

| Field | Type | Required | Description |
|---|---|---:|---|
| `vendor` | string | yes | Source vendor identifier. |
| `product` | string | no | FortiGate, PAN-OS, ASA, etc. |
| `scope_id` | string | no | Source scope such as VDOM/vsys/domain. |
| `source_type` | string | no | Vendor object/config section type. |
| `source_id` | string | no | Native numeric ID, UUID, UID, or key. |
| `source_name` | string | no | Native object name. |
| `source_path` | string | no | CLI/XML/API hierarchy path. |
| `line_start` | integer | no | Source file start line when available. |
| `line_end` | integer | no | Source file end line when available. |

Example:

```json
{
  "vendor": "fortigate",
  "scope_id": "vdom:root",
  "source_type": "firewall policy",
  "source_id": "42",
  "source_name": "Allow-Web",
  "source_path": "config firewall policy/edit 42"
}
```

## 5.2 `IRObjectMetadata`

Common fields for named entities:

| Field | Type | Description |
|---|---|---|
| `id` | string | Stable IR identifier. |
| `name` | string | Canonical display name. |
| `scope_id` | string | Scope containing the object. |
| `description` | string/null | Description/comment. |
| `enabled` | bool/null | Object/rule operational status where applicable. |
| `tags` | list[string] | Canonical tag references. |
| `source` | `IRSourceReference` | Provenance. |
| `requires_manual_review` | bool | Whether migration requires operator action. |
| `confidence` | enum | Exact/High/Medium/Low/Unknown. |
| `notes` | list[string] | Non-secret migration notes. |

Recommended stable IDs should be generated independently of target naming, e.g. `address:vdom-root:web-01` or UUIDs.

---

# 6. Metadata and provenance

## 6.1 `IRMetadata`

| Field | Type | Required | Description |
|---|---|---:|---|
| `schema_version` | string | yes | IR schema version, e.g. `2.0`. |
| `source_vendor` | string | yes | Vendor identifier. |
| `source_product` | string | no | Product/family. |
| `source_version` | string | no | Software version. |
| `source_build` | string | no | Build identifier. |
| `source_model` | string | no | Hardware/virtual model. |
| `hostname` | string | no | Device hostname. |
| `serial_number` | string | no | Device serial if available and appropriate. |
| `config_revision` | string | no | Configuration revision/version. |
| `extraction_method` | enum | yes | `FILE`, `LIVE_SSH`, `OTHER`. |
| `source_filename` | string | no | Uploaded file name. |
| `extracted_at` | datetime | yes | Extraction timestamp. |
| `parser_version` | string | no | Parser implementation version. |
| `target_vendor` | string | no | Optional migration target, not required for extraction. |

`target_vendor` must not affect parser behavior.

---

# 7. Configuration scopes

Multi-tenant/context-aware firewall configuration requires explicit scope.

Examples:

- FortiGate: global / VDOM
- PAN-OS: shared / vsys / Panorama device-group / template
- Cisco: ASA security context / FMC domain
- Check Point: domain / package / layer
- Juniper: logical system / routing instance

## 7.1 `IRScope`

| Field | Type | Description |
|---|---|---|
| `id` | string | Stable scope identifier. |
| `name` | string | Source scope name. |
| `type` | enum/string | `GLOBAL`, `VDOM`, `VSYS`, `DEVICE_GROUP`, `DOMAIN`, `CONTEXT`, `LOGICAL_SYSTEM`, etc. |
| `parent_id` | string/null | Parent scope. |
| `description` | string/null | Scope description. |
| `source` | source reference | Provenance. |

All scope-sensitive objects should reference `scope_id`.

Cross-scope references must be explicit and validated.

---

# 8. System settings

`IRSystemSettings` contains portable or broadly useful device-wide settings.

Recommended fields:

- hostname
- timezone
- domain_name
- DNS servers
- NTP servers
- operation mode
- session timeout defaults when semantically portable
- IPv4/IPv6 forwarding mode
- basic management service enablement

Vendor-specific platform tuning should remain extract-only or a vendor extension.

The current FortiGate implementation retains configured hostname, timezone,
and administrative HTTPS port in `IRSystemSettings`, with primary/secondary
system DNS in a small vendor-neutral DNS settings record. Missing settings stay
unset; the parser does not invent defaults for extraction inventory.

---

# 9. Network topology

## 9.1 Interfaces

### `IRInterface`

Recommended fields:

| Field | Type | Description |
|---|---|---|
| `id` | string | Stable ID. |
| `name` | string | Interface name. |
| `scope_id` | string | Scope. |
| `type` | enum | `PHYSICAL`, `SUBINTERFACE`, `VLAN`, `LOOPBACK`, `TUNNEL`, `AGGREGATE`, `REDUNDANT`, `VIRTUAL_WIRE`, `OTHER`. |
| `parent_id` | string/null | Parent interface. |
| `addresses_v4` | list[prefix] | IPv4 interface addresses. |
| `addresses_v6` | list[prefix] | IPv6 interface addresses. |
| `vlan_id` | int/null | 802.1Q tag. |
| `vrf_id` | string/null | Routing instance/VRF. |
| `zone_id` | string/null | Zone membership where applicable. |
| `mtu` | int/null | MTU. |
| `mac_address` | string/null | Explicit/learned config MAC if relevant. |
| `enabled` | bool | Administrative state. |
| `role` | string/null | WAN/LAN/DMZ source role if explicitly configured. |
| `description` | string/null | Description/alias. |
| `management_access` | list[string] | HTTPS/SSH/PING/SNMP etc. when explicitly configured. |
| `dhcp_client` | bool/null | DHCP client mode. |
| `pppoe` | structured/null | PPPoE settings, secrets excluded. |
| `source` | source reference | Provenance. |

The current phase-1 executable `IRInterface` also retains `source_vdom`,
`interface_type`, `remote_ip` (the peer prefix for point-to-point or tunnel
interfaces), `secondary_ips` (list of `IRInterfaceSecondaryIP`), `role`,
`addressing_mode`, `management_access`, and `dhcp_client`.

### `IRInterfaceSecondaryIP`

Canonical representation of secondary IP addresses configured on an interface:

| Field | Type | Description |
|---|---|---|
| `source_id` | string/null | Source entry identifier (e.g. edit sequence ID). |
| `source_ip` | string/null | Exact raw source IP/netmask string as configured in the firewall definition. |
| `ip` | string/null | Normalized IPv4 CIDR prefix (e.g. `10.0.0.2/24`), or null if unparseable/unusable. |
| `management_access` | list[string] | Per-secondary administrative access permissions (ping, https, ssh, etc.). |
| `requires_manual_review` | bool | Flagged if child parsing, IP syntax, or unmodeled source settings require review. |
| `parse_error` | string/null | Explicit syntax error or failure reason when parsing the secondary IP. |
| `source_attributes` | dict | Sanitized unmodeled source settings retained for inventory/reporting. |

An extraction-only `source_attributes` map preserves sanitized,
explicitly configured source settings that do not yet have portable IR fields.
Target generators must ignore `source_attributes`; it exists for source
inventory and audit output only.

Do not infer zone, role, or trust level from interface names unless explicitly running an optional heuristic that produces a manual-review recommendation rather than canonical truth.

The FortiGate transformer assigns `IRInterface.zone` only from explicit
`zone_mapping` input, configured FortiGate system-zone membership, or explicit
SD-WAN zone membership. Interface names, aliases, descriptions, and FortiGate
roles such as `lan`, `wan`, and `dmz` are not converted into canonical
`trust`, `untrust`, or `dmz` zones. When no explicit zone exists,
`IRInterface.zone` remains null. Policy interface references remain preserved
in `source_from_interfaces` and `source_to_interfaces`; target generation must
not broaden unresolved zone semantics to `any`, `trust`, or `untrust`.

## 9.2 Zones

### `IRZone`

Fields:

- id
- name
- scope_id
- type
- interfaces[] / interface_ids[]
- description
- disabled (bool/null)
- requires_manual_review (bool)
- migration_status (`NORMALIZED`, `PARTIALLY_NORMALIZED`, `EXTRACT_ONLY`, etc.)
- review_reasons[]
- source_attributes
- intra_zone_default/action when portable
- source

## 9.3 VLANs

`IRVLAN` may be separate when the platform treats VLAN objects independently from subinterfaces.

Fields:

- id
- name
- vlan_id
- member interfaces
- L2/L3 mode
- scope

## 9.4 Routing instances / VRFs / virtual routers

### `IRRoutingInstance`

Fields:

- id
- name
- scope_id
- type (`VRF`, `VIRTUAL_ROUTER`, `ROUTING_INSTANCE`, etc.)
- interface_ids[]
- route_distinguisher where applicable
- description

---

# 10. Address and identity objects

## 10.1 `IRAddress`

Supported conceptual types should include:

- `HOST`
- `NETWORK`
- `RANGE`
- `FQDN`
- `WILDCARD_FQDN`
- `WILDCARD_IP`
- `MAC`
- `GEOGRAPHY`
- `DYNAMIC`
- `EXTERNAL_LIST_REFERENCE`
- `VENDOR_SPECIFIC`
- `SPECIAL`

Recommended fields:

| Field | Type |
|---|---|
| `id` | string |
| `name` | string |
| `scope_id` | string |
| `type` | enum |
| `subnet` | prefix/null |
| `range_start` | IP/null |
| `range_end` | IP/null |
| `fqdn` | string/null |
| `wildcard_mask` | string/null |
| `mac` | string/null |
| `geo_code` | string/null |
| `dynamic_filter` | string/null |
| `description` | string/null |
| `tags` | list[string] |
| `source` | source reference |
| `source_uuid` | string/null |
| `associated_interface` | string/null |
| `allow_routing` | boolean/null |
| `source_color` | integer/null |
| `source_sub_type` | string/null |
| `source_obj_tag` | string/null |
| `source_tag_type` | string/null |
| `source_obj_type` | string/null |
| `source_dirty` | string/null |
| `source_attributes` | map[string, any] |

Validation MUST ensure values match the selected type.

The `source_*`, `associated_interface`, and `allow_routing` compatibility
fields preserve source address provenance and extraction metadata while the
full `ExtractionResult` inventory is being implemented. `source_attributes`
contains sanitized, unmodeled source settings. Target generators must not
interpret these source-only fields as portable address semantics. A configured
FortiGate geography country is normalized into `geo_code`; it must not be
fabricated when absent. FortiGate `address6` prefixes remain IPv6 prefixes and
must not pass through IPv4 netmask conversion.

## 10.2 `IRAddressGroup`

Fields:

- id
- name
- scope_id
- static_members[]
- dynamic_filter
- exclude_members[] if semantics require
- description
- source

Dynamic address groups may carry the same source-only EMS metadata fields as
`IRAddress` so that a FortiGate dynamic address converted into an
`IRAddressGroup` does not lose its original `obj-tag`, tag/object type, dirty
state, UUID, or sanitized additional settings.

The current compatibility model also preserves `source_uuid`,
`allow_routing`, `source_color`, `source_category`, and `source_attributes`
for static source groups. These fields are source inventory metadata and must
not be interpreted as target-vendor semantics. In particular, a FortiGate
category such as `ztna-ems-tag` remains source metadata.

FortiGate address groups retain `source_section` and `address_family` so IPv4
and IPv6 source namespaces cannot be silently merged. `members` are ordered
positive references; `exclusion_enabled` and ordered `exclude_members` retain
negative references. An exclusion group must never be reduced to `members`
alone. `source_group_type`, `source_category`, `source_fabric_object_setting`,
and extraction-only `source_tagging_entries` preserve source fidelity. Targets
without exact exclusion support must withhold the group and dependent rules.

References must resolve within permitted scope rules.

FortiGate multicast address objects whose source type is `EIGRP` or `OSPF`
remain explicit address inventory. They must not be discarded merely because
their vendor type is not portable; the source type is retained for extraction
review. Explicit FortiGate reserved address objects named `all`, `none`,
`FABRIC_DEVICE`, or `FIREWALL_AUTH_PORTAL_ADDRESS` are retained as
`IRAddress(type=SPECIAL)` source inventory, including IPv6 and multicast
variants. Their visible value remains the exact source name; raw configured
address fields are retained as source attributes and are never replaced with
an artificial network. `none`, `FABRIC_DEVICE`, and
`FIREWALL_AUTH_PORTAL_ADDRESS` require manual review. Policy references to
`all` remain independently normalized to the canonical any-address built-in.

## 10.3 Tags

### `IRTag`

Fields:

- id
- name
- scope_id
- value/color metadata if relevant
- description

Tags should not be forced to share semantics across products when they are merely cosmetic.

---

# 11. Service and application objects

### Extraction-fidelity additions in schemas 1.10, 1.11, and 1.12

`IRAddress` retains `source_section`, `address_family`, `source_type`,
`source_list_entries`, and typed `source_tagging_entries`. The normalized
`type` remains distinct from the exact source-vendor `source_type`. Nested list
and tagging values are extraction metadata and target generators must not
interpret them as portable address semantics. A source object with no explicit
portable value is retained as `SPECIAL` with a deliberately blank
`original_value`, partial status, and manual review; no replacement subnet is
inferred from names, routes, interfaces, zones, or tunnels.

`ServiceProtocol.SCTP` represents SCTP distinctly and preserves raw FortiGate
source/destination port constraints. A target without verified SCTP support
must withhold the service rather than convert it to TCP, UDP, or `ANY`.

`IRServiceGroup` retains `source_color`, `source_proxy`,
`source_fabric_object`, `migration_status`, and `requires_manual_review`.
Proxy service-group semantics require target review.

Schema 1.11 distinguishes the literal configured FortiGate service protocol
(`source_protocol_configured`) from the effective protocol after FortiOS
defaults (`source_protocol`). An omitted configured protocol remains `None`
while the effective value may be `tcp/udp/sctp`. It also retains explicit
protocol-number zero, source color/fabric metadata, and the names of settings
whose traffic semantics remain only in sanitized `source_attributes` through
`source_unmodeled_semantic_settings`.

`IRServiceGroup.unsafe_members` preserves direct member names that require
review because they are partial services, unsafe nested groups, or unresolved
references. Such groups are partially normalized and target generators must
withhold them rather than emit a group referencing a withheld member.

Schema 1.12 adds source-complete VPN extraction fields. `IRVPNTunnel` remains
partially normalized and retains only PSK presence; PSK content is never
serialized. `IRVPNPhase2` retains its explicit `phase1_name`, proposals,
selectors, source-only fields, and `PARTIALLY_NORMALIZED` status, and now
requires manual review by default.

SSL VPN remains `EXTRACT_ONLY`. `IRConfig.ssl_vpn_host_checks` owns top-level
`IRSSLVPNHostCheck` definitions. Each definition retains name, type, OS type,
version, GUID, sanitized source attributes, and ordered
`IRSSLVPNHostCheckItem` children containing source ID, action, MD5 values,
target, type, version, and sanitized child attributes. Portal-owned
`host_checks` remains only as a backward-compatible field.

`IRSSLVPNPortal` retains `host_check`, ordered `host_check_policies`, interval,
selected source portal fields, and `unresolved_host_check_policies` without
embedding or substituting definitions. `IRSSLVPNSettings` retains selected
protocol, certificate-presence, authentication/timeout, DNS/WINS, interface,
address, pool, and default-portal source fields. An explicitly empty server
certificate is represented by a blank `server_certificate` plus
`server_certificate_configured=True`; no certificate is inferred.
`IRSSLVPNAuthenticationRule` retains selected access-control source fields and
unknown safe settings. Missing SSL VPN references are preserved and audited.

## 11.1 `IRService`

Represent protocol and ports structurally.

```python
IRService
    id
    name
    scope_id
    protocol
    source_ports[]
    destination_ports[]
    icmp_type
    icmp_code
    timeout
    description
```

Supported protocol families may include TCP, UDP, SCTP, ICMP, ICMPv6, IP protocol number, and vendor-specific protocols.

Port ranges should normalize to explicit range structures rather than vendor strings where practical.

The current compatibility model retains `IRServicePort.port` as the
destination-port field and adds optional `source_port` and `raw_source_value`
fields. A source expression such as `513:512-1023` is represented as
destination port `513`, source port `512-1023`, with the complete source value
retained. Port zero and ranges beginning at zero are not rewritten during
source normalization.

Exact destination port `0` has FortiGate non-matching/block-style semantics
and requires manual review. A range such as `0-65535` is not classified as
exact port zero. The original `destination:source` expression remains in
`raw_source_value`, so `513:512-1023` is never flattened to destination-only
port `513`.

`IRService` also retains additive source-inventory fields for source UUID,
category, protocol/protocol number, proxy status, sanitized additional
settings, migration status, manual-review state, and an audit note. Proxy
services or values whose target support is uncertain are partially normalized
and must not be emitted as ordinary destination-port-only services by a target
that cannot preserve their semantics.

FortiGate `protocol IP` with an omitted or explicit-zero `protocol-number`
normalizes to canonical `ANY` based on source fields, never on the object name.
An omitted number remains `None`; explicit zero remains numeric zero. Advanced
settings such as helper, FQDN/IP-range matching, session timers, and application
constraints remain exact in `source_attributes`, are named in
`source_unmodeled_semantic_settings`, and force partial/manual-review status
until canonical semantics exist.

FortiGate service categories are retained in the current phase as
`IRServiceCategory` extract-only inventory. Target generators ignore this
collection.

### Internet Service Definitions

`IRInternetServiceDefinition` is a dedicated extract-only hierarchy for
vendor-defined Internet Service Definitions. It retains the source definition
ID, entries with original sequence/category/name/numeric protocol values, and
port ranges with original IDs and bounds. `migration_status` is `EXTRACT_ONLY`
…5305 tokens truncated…IR and is reported as `EXTRACT_ONLY`.

---

# 18. Identity and AAA

Target data structures should support:

- local users
- local groups
- LDAP servers/profiles
- RADIUS servers/profiles
- TACACS+ servers/profiles
- SAML identity providers
- Kerberos
- user-to-IP identity systems (FSSO/User-ID equivalents)
- authentication profiles/rules
- MFA references

Secrets must be redacted or represented as external secret references.

FortiGate LDAP, SAML, and FSSO server metadata, FSSO AD-group/provider
relationships, local-user non-secret metadata, user groups, nested group
matches, authentication schemes, and authentication rules are retained as
typed `EXTRACT_ONLY` inventory. FSSO inventory remains distinct from LDAP
authentication semantics. Missing FSSO provider and AD-group references stay
unchanged and produce manual-review diagnostics. Credential material is never
serialized; at most a non-secret presence flag may be retained where useful for
review.

Schema 1.13 adds source-oriented Security/Identity dependency results without
turning the output-order dependency helper into a global graph engine.
`IRIdentityDependency` records the exact source reference, source dependency
type, resolution state, optional resolved target name, and source context.
`IRUserGroup` retains original members alongside resolved/unresolved members,
typed member dependencies, and unresolved local match-server references.
External LDAP distinguished group names remain external identifiers and are
not treated as missing FortiGate objects.

`IRUserSAML` records IdP-certificate existence separately from certificate
trust semantics. `IRAuthenticationScheme` records resolved and unresolved
user-database dependencies while retaining the original scalar
`user_database`. `IRAuthenticationRule` records authentication-scheme
resolution. `IRAdministrator` records FortiToken and access-profile existence
without serializing credentials or token seeds.

`IRPolicy` now distinguishes source-object resolution from portable migration:
`unresolved_user_groups`, `unresolved_users`, and
`identity_dependency_review` preserve identity dependency state. Every policy
with FortiGate users or groups requires target-specific identity mapping and
must be withheld unless equivalent enforcement exists. Security-profile
references similarly use `unresolved_security_profiles` and
`security_profile_semantics_review`; a matching FortiGate profile name does
not prove target semantic equivalence. Auto-correlated
`IRSecurityProfileGroup` objects retain source profile provenance and default
to partial/manual-review status.

`IRVPNTunnel.unresolved_auth_user_groups` and
`IRSSLVPNAuthenticationRule.unresolved_groups` propagate missing identity
dependencies to VPN consumers. `IRUserAuthenticationSettings` and
`IRUserQuarantineSettings` provide typed `EXTRACT_ONLY` singleton inventory for
FortiGate user authentication settings and quarantine firewall-group
references.

---

# 19. PKI and certificates

### `IRCertificate`

Recommended non-secret fields:

- id
- name
- scope

## 9.5 Static routes

`IRRoute.destination` is a portable canonical IPv4 or IPv6 network prefix only.
It must be null when the FortiGate source uses `dstaddr`, contains malformed
destination syntax, or otherwise cannot be represented as a safe prefix.

`IRRoute.source_destination_reference` preserves the exact FortiGate firewall
address/address-group route destination reference. A configured reference must
never become a default route merely because `set dst` is absent. An omitted
`dst` with no `dstaddr` retains FortiGate default-route semantics:
`0.0.0.0/0` for IPv4 and `::/0` for IPv6.

The authoritative SD-WAN route field is `sdwan_zones[]`. The compatibility
scalar `sdwan_zone` is populated only when exactly one zone is present. Route
source matching, dynamic gateway, link-monitor exemption, Internet Service
matching, parse failures, multiple SD-WAN zones, and unknown settings require
manual review. Target generators may emit a route only when
`safe_for_target_generation` is true.
- certificate type
- subject
- issuer
- serial number
- SANs
- valid from/to
- fingerprint
- key algorithm/size
- `has_private_key`
- source reference

Private key bytes and passphrases must not be included in standard IR serialization or Excel output.

The current executable `IRCertificate` retains FortiGate remote, local, and CA
certificate inventory as `EXTRACT_ONLY`. It includes public certificate PEM and
derived X.509 metadata, source range/origin, validity, fingerprint, public-key
metadata, CA/self-signed state, and boolean secret-presence indicators. Private
key and password values are discarded before the source model is built and are
never represented in IR or Excel. Factory local certificates remain inventory
only and are not automatically migrated.

FortiGate SSH local keys and local CAs remain distinct `EXTRACT_ONLY` SSH-key
inventory. Public-key data and safe source metadata may be retained, while
private-key and password contents are discarded immediately and represented
only by boolean presence indicators.

Also model:

- CA certificates
- certificate profiles
- CRL
- OCSP
- trust stores

---

# 20. High availability / clustering

`IRHighAvailability` should be capable of representing:

- enabled/mode
- active-passive / active-active / cluster mode
- group/cluster ID
- member metadata
- election priority
- heartbeat/control interfaces
- monitored interfaces
- session/state synchronization
- management addresses
- failover timers/settings

HA may initially be extract-only for some targets but should be visible in inventory.

---

# 21. SD-WAN

`IRSDWAN` should support:

- members/links
- zones
- health checks/performance probes
- SLA thresholds
- steering/service rules
- priorities
- load-balancing strategy
- preferred links
- failover behavior

References to routing and interfaces must be explicit.

The current FortiGate compatibility model retains the complete discovered
SD-WAN source hierarchy as typed `EXTRACT_ONLY` inventory: global settings,
zones, expanded members, health checks and nested SLAs, service/steering rules
and their nested SLAs, duplication rules, and neighbors. Multi-health-check
and other list cardinality remains intact. Values are preserved without
inventing target-vendor routing or failover semantics. `IRSDWAN` does not imply
cross-vendor SD-WAN equivalence, and unmodeled future `system sdwan` children
remain visible through generic FortiGate source inventory.

---

# 22. QoS / traffic shaping

Structured representation should support:

- shapers
- shared shapers
- per-IP shapers
- bandwidth guarantees/limits
- priority
- DSCP marking/matching
- QoS policies
- policy-level shaper references

The current FortiGate compatibility model inventories traffic shapers as
`PARTIALLY_NORMALIZED`, retaining configured bandwidth values, the explicitly
configured source unit, priority, per-policy state, and sanitized source
attributes. An omitted bandwidth unit remains absent because exact target QoS
behavior is vendor-specific and requires manual review.

FortiGate proxy addresses and global web-proxy settings are retained as
`EXTRACT_ONLY` source inventory. Proxy host regular expressions remain exact
source values and are not converted into ordinary firewall addresses, FQDNs,
services, or policies.

---

# 23. Network infrastructure services

Extractable structured categories include:

- DHCP servers
- DHCP relay
- DNS settings/proxy
- NTP
- SNMP configuration (secrets removed)
- LLDP where relevant
- static ARP / neighbor configuration
- dynamic DNS

These may be migration IR or extract-only depending on product scope.

### 23.1 Session helpers / application-layer gateways

FortiGate `system session-helper` entries are retained as structured,
extract-only inventory in `IRConfig.session_helpers` for the current reporting
phase. They are not firewall service objects and target generators must not
treat them as service definitions.

Each `IRSessionHelper` records the source edit ID, name, IP protocol number and
display name, port, source-only attributes, migration status, and manual-review
requirement. Its classification is one of:

- `DEFAULT`: exactly matches the known built-in FortiOS baseline;
- `CUSTOMIZED`: a known built-in ID has changed values;
- `CUSTOM`: the ID is outside the known baseline;
- `UNKNOWN`: required classification fields are missing.

All entries have migration status `EXTRACT_ONLY`. `CUSTOM`, `CUSTOMIZED`, and
`UNKNOWN` entries require manual target-platform review. The baseline is not
version-aware yet, so it must be revised when reliable source-version detection
becomes available.

### 23.2 Session TTL port overrides

FortiGate `system session-ttl port` entries are retained as structured,
extract-only inventory in `IRConfig.session_ttl_overrides` for the current
reporting phase. They are not firewall service objects and target generators
must not treat them as service definitions.

Each `IRSessionTTLOverride` records the source edit ID, IP protocol number and
display name, start port, end port, timeout in seconds, source-only attributes,
migration status, and manual-review requirement. All entries have migration
status `EXTRACT_ONLY` and require manual target-platform review because session
timeout behavior is target-platform dependent.

---

# 24. Management plane

Structured management data may include:

- administrator accounts (no password/hash)
- administrator roles/profiles
- management interfaces
- HTTPS/SSH/API access enablement
- trusted management source networks
- management service profiles
- login/session security settings

Do not export secrets.

The current FortiGate extraction retains administrator accounts,
administrator access profiles, and FortiToken assignment metadata as typed
`EXTRACT_ONLY` inventory. Administrator credentials and FortiToken seed or
activation values are discarded during parsing; only a non-secret
administrator credential-configured flag may be retained. These records are
not target administrator accounts or portable target roles and always require
manual review.

FortiGate administrator inventory also retains ordered guest groups, all
explicit IPv4/IPv6 trusted-host slots, and relevant authentication metadata.
Access-profile permission blocks remain source-specific child inventory and
are not canonical target-role semantics.

---

# 25. Logging and telemetry

Structured representation should support:

- syslog destinations
- SIEM/log collector profiles
- SNMP destinations
- NetFlow/IPFIX
- traffic/threat/system logging settings
- local logging policy
- log forwarding profiles

Credential-bearing integration settings require secret redaction.

---

# 26. Vendor extensions

### `IRVendorExtension`

Use vendor extensions only when data is useful downstream but cannot be represented correctly in canonical IR.

Recommended fields:

| Field | Description |
|---|---|
| `id` | Stable identifier. |
| `vendor` | Vendor. |
| `feature` | Feature name. |
| `scope_id` | Scope. |
| `normalized_metadata` | Structured, non-secret vendor-specific fields. |
| `source` | Provenance. |
| `migration_status` | Extract-only/manual/unsupported. |

Examples may include vendor ecosystems or proprietary objects with no portable equivalent.

Do not use `vendor_extensions` as a dumping ground for features that should have canonical models.

---

# 27. Audit and migration diagnostics

### `IRAuditEntry`

Recommended fields:

- id
- severity (`INFO`, `WARNING`, `ERROR`, `BLOCKING`)
- category
- object_id
- scope_id
- message
- confidence
- source reference
- target vendor if target-specific
- remediation recommendation

Typical categories:

- unresolved reference
- unsupported source feature
- approximated translation
- naming collision
- semantic broadening risk
- dropped capability
- secret redaction
- parser anomaly

---

# 28. Built-ins and special references

Avoid representing `any`, `all`, built-in service names, or vendor defaults as ordinary user-created objects unless necessary.

Use explicit canonical built-ins such as:

```text
builtin:any-address
builtin:any-service
builtin:any-application
builtin:any-zone
```

Generators must map these to the target vendor's correct syntax.

An unresolved reference must never be converted into a built-in `any` reference.

---

# 29. Cross-object references

All object references should resolve by stable IR IDs after normalization.

Example:

```text
Security Policy
  source_addresses[] ------> Address / Address Group IDs
  services[] --------------> Service / Service Group IDs
  schedule_id -------------> Schedule ID
  security_profiles -------> Profile IDs
```

Recommended normalization flow:

```text
Vendor parsed model
      |
      v
Create canonical objects + IDs
      |
      v
Resolve references
      |
      v
Detect missing/cross-scope/cyclic references
      |
      v
Validated canonical IR
```

Names may be retained for display, but logic should use stable IDs where practical.

## 29.1 FortiGate policy source fidelity

`IRPolicy` retains portable policy fields alongside the exact typed FortiGate
source semantics needed for audit. Source-oriented fields include the source
rule ID and UUID, interfaces, IPv4 and IPv6 address references, independent
address-family negate settings, service references and negation, users/groups,
source action and schedule, separate `logtraffic` and `logtraffic-start`
settings, UTM/inspection/profile metadata, Internet Service status, VPN tunnel,
ZTNA data, NAT pool names for both families, and sanitized extra settings.

The canonical `source` and `destination` match lists currently represent the
portable IPv4 view only. FortiGate IPv6 references are not merged into those
lists because IPv4 and IPv6 have independent negate controls. Negation,
policy-based IPsec, family-specific IPv6 semantics, and FortiGate source
profile-group semantics are source-preserved with `PARTIALLY_NORMALIZED` and
`requires_manual_review = true` where the canonical expression cannot preserve
their full traffic meaning. Target generators must withhold those policies
instead of converting them to ordinary allow/deny rules.

## 29.2 FortiGate NAT source fidelity and derived rules

`IRIPPool`, `IRVirtualIP`, `IRVirtualIPRealServer`, and
`IRVirtualIPGroup` are source-resource inventory. They preserve pool ranges,
exclusions/full-cone/PBA/CGN/cross-family settings, VIP family and translation
fields, real-server address-object references and health/monitor controls,
group metadata, sanitized extra settings, and migration-review state. IPv6
pools, VIPs, and VIP groups remain `EXTRACT_ONLY` and are not correlated into
IPv4 NAT.

`IRNATRule` is a correlated, derived representation created from a policy and
its referenced IPv4 resources; it never replaces the source inventories. It
retains pool exclusions/full-cone/original ranges, VIP type/state/restrictions,
policy NAT controls, migration status, and deduplicated review reasons.

A NAT rule is eligible for target generation only when its migration status is
`NORMALIZED`, `requires_manual_review` is false, and `review_reasons` is empty.
Manual-review rules remain visible in Excel for analysis but are withheld from
automatic generation. Advanced pools, disabled/restricted or non-static VIPs,
cross-family NAT, and ambiguous policy controls are never simplified into
ordinary SNAT/DNAT.

---

# 30. Naming and target constraints

The canonical IR should preserve the original source name where possible.

Target-specific naming restrictions belong in target generation.

Recommended fields when renaming becomes necessary:

- original source name in provenance
- canonical IR name
- target generated name in target mapping/report

Do not permanently mutate IR names just because one target vendor has a shorter name limit.

---

# 31. IPv4 and IPv6

IPv4 and IPv6 must be first-class throughout the schema.

Relevant structures must explicitly support address family:

- interfaces
- addresses
- policies
- NAT
- routes
- VPN selectors
- dynamic routing

Do not model IPv6 merely as an optional flag attached to an otherwise IPv4-only field design.

---

# 32. Serialization and schema versioning

## 32.1 Version field

`IRConfig.schema_version` identifies the serialized vendor-neutral IR
contract. It is a root field and is independent from the source firewall
version, parser version, and application version. Every serialized IR document
must contain:

```json
{
  "schema_version": "1.14"
}
```

The format is `MAJOR.MINOR`:

- `MINOR` changes add backward-compatible optional serialized fields that old
  consumers can safely ignore.
- `MAJOR` changes remove or rename fields, incompatibly change field types or
  meaning, or replace required structures.

Parser bug fixes, report formatting, internal refactors, tests, and
non-serialized helpers do not require a schema bump. Unsupported declared
versions must be rejected rather than guessed. Unversioned legacy payloads may
be accepted only through explicit migration logic that makes the compatibility
decision observable.

## 32.2 Stable serialization

Serialized IR should be:

- deterministic
- UTF-8
- explicit about null/empty behavior
- free of plaintext secrets
- suitable for regression testing

JSON is recommended for golden fixtures.

---

# 33. Compatibility and migration confidence

Every target conversion should classify semantic compatibility.

Recommended enum:

- `EXACT`
- `EQUIVALENT`
- `TRANSFORMED`
- `APPROXIMATED`
- `MANUAL_ACTION_REQUIRED`
- `UNSUPPORTED`
- `BLOCKED`

Examples:

```text
FortiGate address subnet -> PAN-OS IP Netmask        EXACT
Vendor-specific app signature -> generic service    APPROXIMATED
Unknown security profile -> silently omitted        FORBIDDEN
```

---

# 34. Validation invariants

Before target generation, canonical IR must pass validation.

Minimum invariants:

1. Every required reference resolves.
2. No duplicate stable IDs exist.
3. Policy sequence is preserved.
4. Policy action is explicit and recognized.
5. Disabled/enabled state is preserved.
6. Address values match their declared type.
7. Service ports/protocols are valid.
8. NAT rules have valid match and translation semantics.
9. VPN Phase 2/selectors reference valid Phase 1/tunnel objects.
10. Interface-zone and interface-routing relationships are valid or explicitly unresolved.
11. Scope-crossing references obey source semantics.
12. No unresolved item is converted to permissive `any` automatically.
13. Secrets are absent from portable serialization.
14. Blocking extraction/normalization errors prevent live deployment.

---

# 35. Target generator contract

A target generator must:

- accept validated canonical IR;
- not inspect source-vendor parser models;
- perform target capability analysis;
- generate deterministic output;
- report unsupported/approximated semantics;
- preserve ordering and disabled state;
- never broaden access silently;
- return artifacts plus compatibility/audit results.

Target generators may map canonical intent into vendor-specific constructs, but must not mutate the source IR in place.

---

# 36. Excel/report contract

Excel extraction should consume the **pre-optimization extraction result / canonical IR**, not an optimized migration copy.

The workbook should expose normalized data using sheets such as:

- Summary
- Interfaces
- Zones
- Addresses
- Address Groups
- Services
- Service Groups
- Applications
- Schedules
- Policies
- IP Pools
- Virtual IPs
- VIP Real Servers
- NAT Rules
- Routes
- VPN Tunnels
- VPN Selectors
- Security Profiles
- Identity / AAA
- Certificates
- HA
- SD-WAN
- QoS
- Network Services
- Management
- Logging
- Vendor Extensions
- Unsupported
- Extraction Coverage
- Warnings

Secrets must be redacted.

---

# 37. Recommended Python module layout

As the schema grows, split it by domain rather than keeping everything in a single `core.py`.

Recommended structure:

```text
src/fwmigrate/ir/
├── __init__.py
├── enums.py
├── base.py
├── metadata.py
├── scope.py
├── system.py
├── network.py
├── objects.py
├── policy.py
├── nat.py
├── routing.py
├── vpn.py
├── security.py
├── identity.py
├── pki.py
├── ha.py
├── sdwan.py
├── qos.py
├── services.py
├── management.py
├── logging.py
├── vendor_extension.py
├── audit.py
└── config.py
```

Avoid large import cycles by keeping common base/reference types in `base.py`.

---

# 38. Current-to-target migration map

The current compact model can evolve incrementally.

| Current concept | Target concept | Action |
|---|---|---|
| `IRMetadata` | expanded `IRMetadata` | Add version/product/provenance fields. |
| `IRZone` | `network.zones[]` | Add stable ID/scope/source. |
| `IRInterface` | `network.interfaces[]` | Add type, IPv6, VRF, multiple addresses, explicit source. |
| `IRAddress` | `objects.addresses[]` | Add ID/scope/source; preserve existing typed values. |
| `IRAddressGroup` | `objects.address_groups[]` | Add stable references/scope. |
| `IRService` | `objects.services[]` | Add source ports/protocol details. |
| `IRSchedule` | `objects.schedules[]` | Replace simple string times with structured windows. |
| `IRPolicy` | `policies.security[]` | Add ID, sequence, scope, identity, explicit policy semantics. |
| `IRIPPool` | canonical NAT translation-resource inventory | Preserve pool allocation, address, port, interface, ARP, PBA, NAT64, and quota semantics independently of NAT rules. |
| `IRVirtualIP` | canonical destination-translation and load-balancer inventory | Preserve all mapped IPs, filtering, port-forwarding, load-balancing, nested real-server, and additional source settings independently of NAT rules. |
| `IRNATRule` | comprehensive NAT model | Separate match and translation. |
| `IRVPNTunnel` | IKE/IPsec/selectors model | Remove plaintext PSK from portable IR. |
| `IRRoute` | `routing.static_routes[]` | Add routing instance/address family/preference. |
| `IRSecurityProfileGroup` | `security_profiles` | Expand individual profile families. |
| `IRAuditEntry` | expanded audit model | Add severity/object/source/remediation. |

Backward compatibility adapters may be used during transition.

---

# 39. FortiGate-specific implications

For the initial FortiGate completeness effort, the canonical IR must at minimum account for:

### Migration-normalized priority

- system interfaces and explicit zones
- IPv4/IPv6 addresses and groups
- services and groups
- schedules
- firewall policies including order and security profiles
- policy SNAT and IP pools
- VIP/DNAT and VIP groups
- central NAT when present
- static IPv4/IPv6 routes
- policy routes if supported by project scope
- IPsec Phase 1 and all Phase 2 selectors
- SD-WAN members/zones/rules required for migration
- Internet-service references
- VDOM scope

### Extract-only / vendor-extension priority

Until normalized migration models exist, still extract and report:

- HA
- BGP/OSPF/dynamic routing
- administrator configuration with secrets removed
- DNS/NTP/SNMP/logging
- FortiAnalyzer/FortiManager/Security Fabric integration
- DHCP
- local users/groups/AAA
- certificate metadata
- advanced UTM/vendor-specific profiles

No present section may silently vanish from coverage reporting.

---

# 40. Definition of done for an IR schema change

An IR schema change is complete when:

- executable Pydantic models are updated;
- this document is updated;
- serialization version impact is assessed;
- all affected source parsers are updated or explicitly marked unsupported;
- all affected target generators are updated or explicitly marked unsupported;
- Excel/report exporters are updated;
- semantic tests are added/updated;
- no security-relevant data is silently dropped;
- no secrets are exposed;
- migration compatibility is explicitly reported.

---

# 41. Final architectural rule

The canonical IR should be comprehensive enough to represent **portable firewall intent** across vendors.

It should **not** pretend every vendor setting is portable.

The complete source configuration is accounted for by the combination of:

```text
Canonical migration IR
        +
Extract-only structured inventory
        +
Vendor extensions
        +
Unsupported/residual records
        +
Extraction coverage/audit
```

That combination, rather than an ever-growing flat `IRConfig`, is the project's complete configuration accounting model.

---

### Interface-address source NAT

For source platforms where NAT may use the outgoing interface address, the NAT IR
must distinguish the translation mode from the resolved translated address.

Example FortiGate source:

    set nat enable

without an IP pool represents source NAT using the actual outgoing interface address.

Canonical representation:

    source_translation_mode = "interface-address"

If the source configuration identifies exactly one statically addressed outgoing
interface, `translated_source` may additionally contain the resolved primary
interface IP.

Example:

    dstintf = "port10"
    port10 primary IP = 192.168.42.30

becomes:

    source_translation_mode = "interface-address"
    translated_source = "192.168.42.30"

The translation mode remains `interface-address`; the resolved IP does not convert
the rule into pool-based/static-address NAT.

When the actual outgoing interface/address depends on runtime state, the translated
address must remain unresolved.

Examples include:

- SD-WAN/member selection;
- PPPoE;
- DHCP or other dynamically assigned interfaces;
- multiple possible outgoing interfaces;
- `any`;
- missing or unconfigured interface addresses.

In those cases:

    source_translation_mode = "interface-address"
    translated_source = None
    requires_manual_review = true

The implementation must not guess a runtime-selected address.

---

## Nested interface source hierarchy addendum

This addendum defines the authoritative extraction-only compatibility model for nested source configuration retained under normalized interfaces.

### Interface model additions

### `IRInterface`

Recommended portable interface fields remain unchanged. The current executable compatibility model also retains source-oriented fields needed for extraction fidelity:

```text
source_vdom
interface_type
remote_ip
secondary_ips[]
role
addressing_mode
management_access[]
dhcp_client
source_attributes
nested_source_configs[]
requires_manual_review
parse_errors[]
```

The canonical interface fields represent portable network intent where semantics are understood. Source-only compatibility fields must not be interpreted by target generators as portable behavior.

### Interface type source fidelity

An omitted source interface type is not equivalent to an explicit physical interface.

The source adapter should preserve:

```text
explicit set type <value> -> explicit source value
omitted set type          -> None/unset in source model
```

A source transformer may derive a normalized VLAN type when unambiguous structural evidence exists, such as a configured parent interface plus VLAN ID. Any derived value belongs only in the normalized interface field and must not be written back into source-preservation metadata.

---

## `IRSourceConfigCommand`

`IRSourceConfigCommand` is a recursive-source compatibility type used when a source adapter needs to preserve structured, non-portable configuration under an otherwise normalized object.

```python
class IRSourceConfigCommand(BaseModel):
    operation: str
    key: str
    values: List[str] = Field(default_factory=list)
```

Fields:

| Field | Type | Description |
| --- | --- | --- |
| `operation` | string | Source operation such as `set`, `unset`, or `append`. |
| `key` | string | Original/sanitized source setting key. |
| `values` | list[string] | Ordered sanitized source tokens. |

The values must already have passed source secret sanitization. This type must never contain plaintext passwords, PSKs, private keys, API tokens, SNMP communities, or equivalent secret material.

---

## `IRSourceConfigNode`

`IRSourceConfigNode` preserves recursive source hierarchy without claiming cross-vendor semantics.

```python
class IRSourceConfigNode(BaseModel):
    node_type: str
    name: str
    commands: List[IRSourceConfigCommand] = Field(default_factory=list)
    children: List["IRSourceConfigNode"] = Field(default_factory=list)
```

Fields:

| Field | Type | Description |
| --- | --- | --- |
| `node_type` | string | Source hierarchy node type, normally `config` or `edit`. |
| `name` | string | Native config subsection name or edit identity. |
| `commands` | list[IRSourceConfigCommand] | Sanitized commands directly attached to this node. |
| `children` | list[IRSourceConfigNode] | Ordered recursive child nodes. |

Required invariants:

1. Preserve source hierarchy.
2. Preserve child ordering.
3. Preserve command ordering.
4. Preserve edit identity.
5. Preserve source operation (`set`, `unset`, `append`).
6. Do not synthesize FortiOS defaults.
7. Sanitize secrets before the node reaches IR.
8. Target generators must ignore the node unless a future explicitly designed canonical model consumes the equivalent semantics.

This is not intended as a generic replacement for canonical IR. It is a temporary/extraction-oriented compatibility structure for source semantics that are important to account for but not yet portable.

---

## `IRInterface.nested_source_configs`

Add to the executable `IRInterface`:

```python
nested_source_configs: List[
    IRSourceConfigNode
] = Field(default_factory=list)
```

Meaning:

> Recursive, sanitized source configuration found inside an interface that has not been normalized into portable interface semantics.

Examples for FortiGate include:

```text
config client-options
config dhcp-snooping-server-list
config egress-queues
config ipv6
config l2tp-client-settings
config tagging
config vrrp
config wifi-mac-list
config wifi-networks
```

`config secondaryip` is excluded from this generic collection because it already has the dedicated typed path:

```text
IRInterface.secondary_ips[]
```

When `nested_source_configs` is non-empty:

```text
IRInterface.requires_manual_review = true
```

unless a future implementation has normalized every retained nested node into portable semantics and removed the source-only condition.

`nested_source_configs` must be ignored by target generators. A target generator must never discover a FortiGate-specific nested setting in this collection and opportunistically translate it. Promotion to target-consumable behavior requires a dedicated canonical model, explicit source transformer logic, validation, compatibility analysis, and tests.

---

## `IRInterfaceSecondaryIP`

The existing typed secondary-IP representation remains authoritative for FortiGate `config secondaryip`:

| Field | Type | Description |
| --- | --- | --- |
| `source_id` | string/null | Source edit ID. |
| `source_ip` | string/null | Exact raw source IP/netmask value. |
| `ip` | string/null | Strictly normalized IPv4 CIDR value, or null when invalid/unusable. |
| `management_access` | list[string] | Explicit per-secondary management access. |
| `requires_manual_review` | bool | True for invalid/missing values or retained unmodeled child settings. |
| `parse_error` | string/null | Explicit parsing/normalization failure. |
| `source_attributes` | dict | Sanitized unmodeled child settings. |

Do not duplicate secondary-IP child nodes into `nested_source_configs`.

---

## Source-only IR compatibility boundary

The architectural preference remains:

```text
portable semantics -> canonical IR
source/vendor-specific extraction -> ExtractionResult inventory
```

The current executable implementation permits limited source-oriented compatibility fields such as:

```text
IRInterface.source_attributes
IRInterface.nested_source_configs
```

because Excel and existing migration flows still consume the executable IR object directly.

These fields have strict rules:

```text
target generators must ignore them
they must contain no plaintext secrets
they must not change normalized firewall behavior
they must not create permissive fallback semantics
they must remain clearly documented as extraction-only
```

When the broader structured `ExtractionResult.inventory.network.interfaces` model becomes the sole reporting source, these compatibility fields may be migrated out of canonical IR through an explicit schema/version transition.

---

### IPv4 and IPv6

IPv4 and IPv6 remain first-class target-schema requirements.

During the current FortiGate nested-interface preservation phase, an unmodeled:

```text
config system interface
    edit "port1"
        config ipv6
            ...
        end
    next
end
```

is retained recursively in:

```text
IRInterface.nested_source_configs
```

with `EXTRACT_ONLY` semantics and manual review.

This is not equivalent to full canonical IPv6 interface support. Full normalization requires dedicated IPv6 interface fields such as addresses, delegated prefixes, router advertisements, DHCPv6 behavior, VRRP6, and related source semantics to be modeled and validated explicitly.

The recursive source node is the zero-silent-loss fallback until that normalization exists.

---

### Excel/report contract

The interface-related workbook sheets should include:

```text
Interfaces
Interface Secondary IPs
Interface Source Settings
Interface Nested Configuration
```

Their responsibilities are distinct:

| Sheet | Responsibility |
| --- | --- |
| Interfaces | Portable/normalized interface inventory plus selected source provenance. |
| Interface Secondary IPs | Dedicated typed nested secondary IPv4 addresses. |
| Interface Source Settings | Sanitized explicit top-level source `set` settings. |
| Interface Nested Configuration | Recursive extraction-only source hierarchy not yet represented as portable interface semantics. |

`Interface Nested Configuration` should expose at least:

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

Secrets must remain redacted.

---

### Schema-version assessment

Adding serialized optional fields such as:

```text
IRInterface.nested_source_configs
IRSourceConfigNode
IRSourceConfigCommand
```

is additive but still changes the serialized IR contract.

Before merging, assess `IR_SCHEMA_VERSION` according to the project's versioning rules:

```text
optional backward-compatible serialized field -> MINOR version candidate
field removal/rename/incompatible meaning      -> MAJOR version
internal helper only                           -> no schema bump
```

Do not bump the version mechanically if these structures are explicitly excluded from serialized IR. If they are emitted by normal `IRConfig.model_dump()`/JSON serialization, treat the addition as a serialized schema change and update fixtures/tests accordingly.

---

### Validation invariants for nested source configuration

Add these invariants to interface/source-validation expectations:

1. Every nested source node remains associated with its source interface.
2. Source order is deterministic.
3. No nested source node can change target behavior directly.
4. Secret-like values are absent/redacted.
5. `secondaryip` is not duplicated between typed and generic child collections.
6. Presence of unmodeled nested source configuration is observable through manual-review/audit state.
7. Invalid nested data must not be converted into `any`, default routes, guessed addresses, guessed zones, or other permissive semantics.
8. A future promotion from source-only node to canonical semantics must preserve the original source evidence for audit.

## Check Point R81 canonicalization safety boundary

Check Point rule columns are OR lists. A Security Zone plus an address object in
one source/destination column cannot be encoded as canonical `zone AND address`.
Likewise, a network service plus an application in the Check Point service
column cannot be encoded as canonical `service AND application`. These mixed
forms remain in `ExtractionResult` and are withheld from canonical rule output.

Canonical Check Point Access actions are limited to Accept (`ALLOW`), Drop
(`DROP`), and Reject (`DENY` with `source_action = "Reject"`). Unsupported,
missing, or unresolved actions do not create placeholder policies.

Check Point VPN match and inline-layer dimensions are outside the current flat
`IRPolicy` contract. A VPN-community constraint, unresolved/nonportable VPN
reference, inline-layer parent, or inline-layer child is retained in source
accounting and does not create a canonical policy. Command-aware Access input
must explicitly prove an unrestricted VPN dimension with `Any`; missing package
or layer scope is never replaced with a fabricated management default.

Canonical Check Point NAT type is derived only from translated address
dimensions. A translated service never determines an address NAT type and
currently makes the rule unsafe for target generation. Missing original match
fields, missing translated fields, missing/non-boolean enabled state, incomplete
pagination, and ambiguous or incomplete scope never acquire permissive canonical
defaults. Source/Twice NAT `source_translation_mode` is assigned only from
explicit rule method data, correlated object `nat-settings`, or explicit
hide-behind gateway/interface evidence. Translated-source presence alone does
not establish static, hide, PAT, pool, or interface-address semantics.

Source-evidence dictionaries retained by canonical objects are sanitized before
serialization. Credential values and PSKs are not portable canonical semantics.
