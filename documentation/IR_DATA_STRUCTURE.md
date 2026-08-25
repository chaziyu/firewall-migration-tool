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
Source configuration or live API
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
| `api_path` | string | no | API endpoint/object location for live ingestion. |

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
| `extraction_method` | enum | yes | `FILE`, `LIVE_API`, `LIVE_SSH`, `OTHER`. |
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
interfaces), `role`, `addressing_mode`, `management_access`, and
`dhcp_client`. An extraction-only `source_attributes` map preserves sanitized,
explicitly configured source settings that do not yet have portable IR fields.
Target generators must ignore `source_attributes`; it exists for source
inventory and audit output only.

Do not infer zone, role, or trust level from interface names unless explicitly running an optional heuristic that produces a manual-review recommendation rather than canonical truth.

## 9.2 Zones

### `IRZone`

Fields:

- id
- name
- scope_id
- type
- interface_ids[]
- description
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

References must resolve within permitted scope rules.

FortiGate multicast address objects whose source type is `EIGRP` or `OSPF`
remain explicit address inventory. They must not be discarded merely because
their vendor type is not portable; the source type is retained for extraction
review. Reserved pseudo-objects such as `all` and `none` are not fabricated as
ordinary canonical address objects.

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

`IRService` also retains additive source-inventory fields for source UUID,
category, protocol/protocol number, proxy status, sanitized additional
settings, migration status, manual-review state, and an audit note. Proxy
services or values whose target support is uncertain are partially normalized
and must not be emitted as ordinary destination-port-only services by a target
that cannot preserve their semantics.

FortiGate service categories are retained in the current phase as
`IRServiceCategory` extract-only inventory. Target generators ignore this
collection.

## 11.2 `IRServiceGroup`

- id
- name
- scope_id
- member_service_ids[]
- description

The current compatibility model additionally preserves source UUID and
sanitized source attributes for service-group inventory.

## 11.3 Applications

Application-aware vendors require application semantics separate from L4 services.

### `IRApplication`

Fields may include:

- id
- name
- scope_id
- category
- subcategory
- technology
- risk
- default services
- vendor_builtin flag
- description

### `IRApplicationGroup`

- id
- name
- member_application_ids[]

If an application has no cross-vendor equivalent, preserve its vendor identity and mark compatibility during target analysis.

---

# 12. Schedules

### `IRSchedule`

Must support:

- always
- absolute one-time ranges
- recurring day/time windows
- time zones if relevant
- multiple time windows

Recommended structure:

```python
IRSchedule
    id
    name
    scope_id
    type
    timezone
    windows[]
    description
```

A recurring window should use structured day/time values, not a single opaque vendor string.

The current compatibility model preserves `schedule_type`, source color,
expiration days, and sanitized source attributes in addition to the existing
start, end, and day fields. FortiGate one-time timestamps remain one-time
values; recurring days and omitted expiration settings are never fabricated.

---

# 13. Security policy model

## 13.1 Common policy fields

### `IRPolicyBase`

| Field | Description |
|---|---|
| `id` | Stable IR ID. |
| `name` | Rule name. |
| `scope_id` | Scope. |
| `sequence` | Effective evaluation order. |
| `native_rule_id` | Vendor-native rule number/UUID/UID. |
| `enabled` | Operational status. |
| `source_zones` | Zone references. |
| `destination_zones` | Zone references. |
| `source_addresses` | Address/group references or explicit built-in `any`. |
| `destination_addresses` | Address/group references or explicit built-in `any`. |
| `services` | Service/group references. |
| `applications` | Application/group references. |
| `users` | User/group references. |
| `schedule_id` | Schedule reference. |
| `description` | Description/comment. |
| `tags` | Tags. |
| `log_start` | Log start. |
| `log_end` | Log end. |
| `source` | Provenance. |

The current `IRPolicy` compatibility model also preserves additive, optional
source-policy audit fields. These fields are vendor-neutral and do not create
NAT rules or otherwise change normalized policy behavior:

| Field | Description |
|---|---|
| `source_rule_id` | Original vendor-native policy number, UUID, UID, or key as a string. |
| `source_uuid` | UUID supplied by the source firewall policy; it is source metadata and is not automatically used as a target rule UUID. |
| `source_from_interfaces` | Source interface names exactly as represented by the source policy. |
| `source_to_interfaces` | Destination interface names exactly as represented by the source policy. |
| `source_user_groups` | Source firewall user-group selectors, preserved in source order without identity resolution or normalization. |
| `source_users` | Source firewall individual-user selectors, preserved in source order without identity resolution or normalization. |
| `source_log_setting` | Original non-secret logging mode or setting. |
| `source_inspection_mode` | Explicit source policy inspection mode, preserved for audit without implying target-vendor translation; null when omitted by the source. |
| `source_ztna_status` | Explicit source policy ZTNA status, preserved for audit without implying portable ZTNA semantics; null when omitted by the source. |
| `source_ztna_ems_tags` | Source ZTNA EMS tag selectors, preserving quoted value boundaries and source order. |
| `source_extra_settings` | Migration-relevant source policy settings without dedicated canonical fields. Secret-like values are redacted before storage. |
| `nat_enabled` | Whether policy-coupled NAT was explicitly enabled; null when unknown or inapplicable. |
| `nat_pool_enabled` | Whether use of a source NAT pool was explicitly enabled; null when unknown or inapplicable. |
| `nat_pool_names` | Source NAT pool references attached to the policy. |

These optional fields are an additive, backward-compatible schema extension.
Target generators must not interpret them as complete translation semantics;
policy-derived NAT correlation remains the responsibility of the canonical NAT
normalization stage.

### `IRSecurityPolicy`

Additional fields:

- action (`ALLOW`, `DENY`, `DROP`, `REJECT`, `RESET`, etc.)
- security profile/group references
- SSL/decryption inspection references if attached at policy level
- QoS/shaper references
- NAT linkage/reference where source product couples NAT to policy
- Internet-service references
- negate-source/destination semantics
- policy type (IPv4, IPv6, mixed when semantically valid)

Unknown source actions must never normalize to `ALLOW`.

## 13.2 Other policy families

Canonical IR should be capable of representing separately:

- authentication policy
- decryption/SSL inspection policy
- application override policy
- policy-based forwarding (PBF/PBR)
- DoS policy
- QoS policy

These may initially be extract-only for vendors/targets without implemented migration support.

---

# 14. NAT model

NAT must represent match semantics separately from translation semantics.

## 14.1 `IRIPPool`

An IP pool is a named translation resource and inventory object. It is distinct
from a NAT rule, which supplies match criteria and references or otherwise uses
the translation resource.

The current compatibility model preserves these optional fields:

| Field | Description |
|---|---|
| `name` | Canonical pool name. |
| `pool_type` | Source pool allocation mode, such as overload or one-to-one. |
| `start_ip` / `end_ip` | Translated address range. |
| `source_start_ip` / `source_end_ip` | Source range associated with one-to-one mappings when configured. |
| `source_prefix6` | IPv6 source prefix used by applicable pool modes. |
| `start_port` / `end_port` | Translation port range. |
| `associated_interface` | Explicit interface association. |
| `arp_reply` / `arp_interface` | ARP response behavior and interface. |
| `permit_any_host` | Whether any host may use the pool. |
| `excluded_ips` | Addresses excluded from allocation. |
| `block_size`, `blocks_per_user`, `pba_timeout`, `pba_interim_log`, `ports_per_user`, `privileged_port_use_pba` | Port-block allocation settings. |
| `nat64`, `add_nat64_route`, `client_prefix_length`, `include_subnet_broadcast` | NAT64 and subnet behavior. |
| `tcp_session_quota`, `udp_session_quota`, `icmp_session_quota` | Per-protocol session quotas. |
| `description` | Non-secret source comments or description. |

Source parsers preserve supported pool attributes independently from
`IRNATRule`. A pool enters a NAT rule only through an explicit policy reference;
an unreferenced pool remains inventory and never becomes a standalone NAT rule.

## 14.2 `IRVirtualIP`

A virtual IP is a named source inventory object for destination translation,
port forwarding, and server load balancing. It is preserved independently from
normalized NAT rules so that source settings remain auditable before policy-to-
VIP correlation is implemented.

The current compatibility model preserves:

- source ID/UUID, name, type, enabled state, color, and description;
- external IP/address objects and external interface;
- all mapped IPs and the mapped-address reference;
- port-forward, protocol, external/mapped ports, and port-mapping type;
- ARP reply/gratuitous interval, source-NAT-VIP, source filters, interface
  filters, and services;
- load-balancing method, server type, persistence, HTTP redirect, monitors, and
  connection limits;
- nested real servers with ID, address, port, status, weight, and holddown
  interval; and
- additional non-secret source settings that do not yet have dedicated fields.

When several mapped IPs exist, inventory and correlated NAT IR preserve all
values. A target that cannot safely render the complete mapping must withhold
the rule and emit a partial/manual-review result. An unreferenced VIP remains
inventory and never becomes a standalone NAT rule.

FortiGate VIP groups are also preserved as independent source inventory with
their UUID, interface, color, comment, ordered member references, and sanitized
additional settings. Group inventory alone must not create a NAT rule; only an
explicit policy destination reference may participate in DNAT correlation.

## 14.3 `IRNATRule`

Recommended structure:

```python
IRNATRule
    id
    name
    scope_id
    sequence
    enabled
    nat_type

    match:
        source_zones[]
        destination_zones[]
        source_interfaces[]
        destination_interfaces[]
        source_addresses[]
        destination_addresses[]
        protocol
        source_ports[]
        destination_ports[]

    translation:
        source:
            mode
            translated_addresses[]
            translated_ports[]
            interface_address
            pool_reference
        destination:
            mode
            translated_addresses[]
            translated_ports[]

    bidirectional
    hairpin
    source_policy_reference
    description
    source
```

The current executable compatibility model represents these semantics with
additive fields while retaining the earlier scalar translation fields for
serialized-input compatibility:

| Field | Description |
|---|---|
| `source_policy_reference`, `source_policy_uuid`, `source_policy_name` | Native policy provenance that caused the NAT correlation. |
| `sequence` | Source policy order used for deterministic NAT ordering. |
| `enabled` | Operational state inherited from the source policy. |
| `source_from_interfaces`, `source_to_interfaces` | Source policy interface match/provenance. |
| `from_zone`, `to_zone` | Canonical NAT match zones; target generators must preserve pre-NAT/post-NAT distinctions. |
| `source`, `destination` | Original packet address match. |
| `services` | All original packet service references; a target may split one canonical rule deterministically when it accepts only one service. |
| `internet_services` | Source Internet-service match references that must not become unrestricted `any`. |
| `source_translation_mode` | `none`, `interface-address`, `pool`, `static`, or `dynamic-ip-and-port`. |
| `source_pool_references`, `source_pool_type` | Referenced source pools and preserved allocation intent. |
| `translated_sources`, `translated_destinations` | Complete translated address/range values. |
| `destination_protocol`, `original_destination_port`, `translated_port` | Explicit PAT match and translation semantics. |
| `source_vip_reference`, `source_vip_group_reference` | VIP provenance, including the group that was expanded. |
| `requires_manual_review` | Prevents unsafe target generation when correlation is incomplete or target semantics are ambiguous. |

The older `service`, `translated_source`, and `translated_destination` scalar
fields remain compatibility aliases. New parser and generator behavior uses the
list and mode fields and must not select only the first source value silently.

FortiGate policy correlation follows source policy order. `nat enable` without
an IP pool is `interface-address`; `ippool enable` preserves explicit pool
references and never falls back when a pool is missing. Direct VIP references
create policy-correlated destination NAT, VIP groups expand deterministically,
and a policy applying source and destination translation to the same traffic is
represented as one `TWICE` rule. Mixed VIP and ordinary destinations are
partitioned so DNAT is not applied to ordinary destinations.

For FortiGate interface-address source NAT, `translated_sources` preserves the
primary host IP only when the policy names exactly one statically addressed
egress interface. SD-WAN zones, dynamic interface modes, `any`, multiple or
missing interfaces, and interfaces without a usable primary IP remain
unresolved and require manual review; runtime addresses are never inferred.

This is an additive backward-compatible extension of the current compact IR;
the serialized schema major version does not change.

## 14.4 NAT types

The model should support at least:

- source NAT
- destination NAT
- static NAT
- dynamic NAT
- PAT / overload
- interface-address NAT
- twice NAT
- identity/no-NAT
- central NAT
- NAT64
- NAT46

A NAT pool object is not itself a NAT rule. The rule must preserve the match criteria and reference the translation resource.

---

# 15. Routing

## 15.1 Static routes

### `IRStaticRoute`

Fields:

- id
- name
- scope_id
- routing_instance_id
- address_family
- destination
- next_hop type/address
- interface_id
- administrative_distance/preference
- metric
- priority
- blackhole/reject flag
- enabled
- description

## 15.2 Policy-based routing

### `IRPolicyRoute`

Fields should represent:

- sequence
- source/destination
- protocol/service
- ingress interface/zone
- next hop
- egress interface
- routing instance

## 15.3 Dynamic routing

Target schema should allow structured representation for:

- BGP
- OSPF/OSPFv3
- RIP
- IS-IS where applicable
- BFD
- redistribution
- prefix lists
- route maps / route policies
- community lists

Dynamic routing may initially be extract-only, but the data model should not require storing it as opaque strings.

---

# 16. VPN

VPN must separate tunnel identity, IKE/Phase 1, IPsec/Phase 2, selectors, and remote-access semantics.

## 16.1 Site-to-site IPsec

### `IRIPsecTunnel`

```python
IRIPsecTunnel
    id
    name
    scope_id
    enabled
    tunnel_type
    local_interface_id
    tunnel_interface_id
    peer
    authentication
    ike_gateway
    ipsec_profile
    selectors[]
    routing_reference
    policy_references[]
    description
```

### `IRIKEGateway`

Fields:

- IKE version
- local ID
- peer ID
- peer address/FQDN/dynamic
- authentication method
- secret reference/presence flag, never plaintext PSK in exports
- encryption algorithms
- integrity algorithms
- DH groups
- lifetime
- DPD
- NAT traversal
- mode/aggressive/main as applicable

### `IRIPsecProfile`

Fields:

- encryption algorithms
- authentication/integrity algorithms
- PFS
- DH/PFS group
- lifetime
- replay settings where portable

### `IRTrafficSelector`

- local networks
- remote networks
- protocol
- local ports
- remote ports

Multiple Phase 2/selectors must be representable under one tunnel.

## 16.2 Remote-access / SSL VPN

Separate structures should allow representation of:

- portal/profile
- address pool
- authentication source/group
- split tunnel routes
- DNS settings
- client policy
- SSL VPN web/tunnel mode

Not all remote-access semantics are portable; unsupported parts must remain explicit.

The current FortiGate extraction retains SSL VPN global settings, portals,
authentication rules, and nested host-check software as typed `EXTRACT_ONLY`
inventory. Passwords, keys, tokens, activation codes, and similar credential
material are discarded rather than copied into the IR or reports.

---

# 17. Security profiles and inspection

Security profiles should represent security intent rather than vendor profile syntax.

Target categories include:

- antivirus
- IPS / vulnerability prevention
- anti-spyware
- web/URL filtering
- DNS filtering/security
- application control
- file filtering/blocking
- sandbox / malware analysis
- DLP
- email/anti-spam
- SSL/TLS inspection/decryption
- DoS / zone protection
- profile groups / bundles

Each profile should retain:

- stable ID
- name
- scope
- enabled state
- structured policy where practical
- vendor capability metadata
- source reference

Do not claim semantic equivalence when a target only approximates the source profile.

The current FortiGate implementation retains IPS sensors and their nested
entries as typed `EXTRACT_ONLY` inventory. FortiGate signature IDs remain
unchanged source signature IDs; they are not correlated with PAN-OS threat IDs,
Snort or Suricata SIDs, or any other target-vendor signature namespace. Nested
entry filters, actions, rate limits, quarantine settings, and sanitized unknown
source attributes remain attached to their source sensor entry and require
manual review.

Other FortiGate security-profile families are retained in the extraction
accounting model as a recursive structured source tree. The tree preserves
section, subsection, edit identity, command operation (`set`, `unset`, or
`append`), and sanitized values without pretending that vendor syntax has
portable security-profile semantics. This source tree is deliberately outside
the canonical migration IR and is reported as `EXTRACT_ONLY`.

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

FortiGate LDAP and SAML server metadata, local-user non-secret metadata, user
groups, nested group matches, authentication schemes, and authentication rules
are retained as typed `EXTRACT_ONLY` inventory. Credential material is never
serialized; at most a non-secret presence flag may be retained where useful for
review.

---

# 19. PKI and certificates

### `IRCertificate`

Recommended non-secret fields:

- id
- name
- scope
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
zones, members, health checks, nested SLAs, and service/steering rules. Values
are preserved without inventing target-vendor routing or failover semantics.

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

Every serialized IR document must contain:

```json
{
  "schema_version": "2.0"
}
```

Use semantic versioning principles for schema evolution:

- PATCH: documentation/validation bug fixes without structural incompatibility.
- MINOR: additive backward-compatible fields.
- MAJOR: incompatible structural/semantic changes.

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
