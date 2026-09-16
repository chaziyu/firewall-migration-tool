# Canonical IR Model

**Status:** Current executable model snapshot<br>
**Verified:** 2026-09-16<br>
**Schema version:** `2`

This document records the implemented canonical intermediate representation
(IR). The Pydantic models and serialization code remain authoritative if this
document and the code disagree.

## Boundary

The migration path is:

```text
source configuration
        |
        v
vendor parser -> ExtractionResult
                 |         |
                 |         +-> source inventory, coverage, unsupported/residual evidence
                 v
       canonical_ir: IRConfig
                 |
                 +-> validation / optimization -> target generator
                 |
                 +-> Excel / reporting (with ExtractionResult accounting)
```

`IRConfig` is the shared contract used by validators, optimizers, reports, and
target generators. Its serialized root contains only canonical collections plus
typed `vendor_extensions`; source-only and vendor-specific data is not a second
canonical root surface. `ExtractionResult` is separate: it accounts for source
data that was normalized, partially normalized, retained as extract-only
evidence, unsupported, ignored, or affected by a parse error.

This is the implemented final V2 snapshot. `ir-schema-v2-plan.md` is historical
design rationale and compatibility guidance.

Parsers must produce IR; generators must consume IR. Vendor syntax must not be
implemented as a direct source-to-target converter.

## Aggregate root: `IRConfig`

`IRConfig` is the serialized aggregate root. `metadata` is required. Collection
fields default to an empty list; optional singleton fields default to `null`.
The V2 canonical collections are the only serialized root collections. Legacy
root names remain accepted as input and Python compatibility projections, but
they are normalized into canonical collections or typed vendor extensions.

### Root control fields

| Field | Type | Default | Meaning |
|---|---|---:|---|
| `schema_version` | literal `2` | `2` | Serialized schema discriminator. Only V2 can be constructed after loading/migration. |
| `generation_safe` | `boolean` | `true` | Whole-IR generation gate. |
| `generation_blocking_reasons` | `list[string]` | `[]` | Reasons generation is blocked. |
| `requires_manual_review` | `boolean` | `false` | Whole-IR review flag. |
| `metadata` | `IRMetadata` | required | Source and migration metadata. |
| `vendor_extensions` | `IRVendorExtensions` | empty typed containers | Typed nonportable vendor semantics. Each vendor container forbids undeclared fields. |

### Root collections

| Area | JSON field | Model |
|---|---|---|
| Network | `zones` | `list[IRZone]` |
| Network | `interface_groups` | `list[IRInterfaceGroup]` |
| Network | `interfaces` | `list[IRInterface]` |
| Network | `high_availability` | `list[IRHighAvailability]` |
| Network | `system_settings` | `IRSystemSettings \| null` |
| Network | `dns_settings` | `IRDNSSettings \| null` |
| Network | `ntp_settings` | `IRNTPSettings \| null` |
| Network | `management_service_routes` | `list[IRManagementServiceRoute]` |
| Network | `routes` | `list[IRRoute]` |
| Network | `dhcp_servers` | `list[IRDHCPServer]` |
| Network | `virtual_firewall_contexts` | `list[IRVirtualFirewallContext]` |
| Address | `addresses` | `list[IRAddress]` |
| Address | `address_groups` | `list[IRAddressGroup]` |
| Service | `service_categories` | `list[IRServiceCategory]` |
| Service | `services` | `list[IRService]` |
| Service | `service_groups` | `list[IRServiceGroup]` |
| Service | `schedules` | `list[IRSchedule]` |
| Service | `schedule_groups` | `list[IRScheduleGroup]` |
| Service | `applications` | `list[IRApplication]` |
| Service | `application_groups` | `list[IRApplicationGroup]` |
| Service | `application_categories` | `list[IRApplicationCategory]` |
| Service | `proxy_request_matches` | `list[IRProxyRequestMatch]` |
| Service | `web_proxies` | `list[IRWebProxy]` |
| Policy | `security_policies` | `list[IRSecurityPolicy]` |
| Policy | `default_security_rules` | `list[IRDefaultSecurityRule]` |
| Policy | `multicast_policies` | `list[IRMulticastPolicy]` |
| Policy | `firewall_filters` | `list[IRFirewallFilter]` |
| Policy | `security_profile_groups` | `list[IRSecurityProfileGroup]` |
| Policy | `security_profile_definitions` | `list[IRSecurityProfileDefinition]` |
| Policy | `identity_sources` | `list[IRIdentitySource]` |
| Policy | `identity_mapping_providers` | `list[IRIdentityMappingProvider]` |
| Policy | `access_roles` | `list[IRAccessRole]` |
| Policy | `management_access_policies` | `list[IRManagementAccessPolicy]` |
| Policy | `https_inspection_rules` | `list[IRHTTPSInspectionRule]` |
| Policy | `custom_url_categories` | `list[IRCustomURLCategory]` |
| Policy | `ips_sensors` | `list[IRIPSSensor]` |
| Policy | `endpoint_context_providers` | `list[IREndpointContextProvider]` |
| NAT | `nat_pools` | `list[IRNATPool]` |
| NAT | `published_services` | `list[IRPublishedService]` |
| NAT | `published_service_groups` | `list[IRPublishedServiceGroup]` |
| NAT | `nat_rules` | `list[IRNATRule]` |
| Routing | `forwarding_policies` | `list[IRForwardingPolicy]` |
| Routing | `policy_route_rules` | `list[IRPolicyRoute]` |
| Routing | `path_monitors` | `list[IRPathMonitor]` |
| VPN | `vpn_tunnels` | `list[IRVPNTunnel]` |
| VPN | `vpn_phase2` | `list[IRVPNPhase2]` |
| VPN | `vpn_communities` | `list[IRVPNCommunity]` |
| VPN | `vpn_gateways` | `list[IRVPNGateway]` |
| VPN | `remote_access_vpns` | `list[IRRemoteAccessVPN]` |
| Security | `certificates` | `list[IRCertificate]` |
| Security | `ssh_keys` | `list[IRSSHKey]` |
| Audit | `audit_entries` | `list[IRAuditEntry]` |
| Observability | `log_destination_profiles` | `list[IRLogDestinationProfile]` |
| Observability | `log_forwarding_policies` | `list[IRLogForwardingPolicy]` |
| Observability | `dns_proxies` | `list[IRDNSProxy]` |
| Observability | `monitor_profiles` | `list[IRMonitorProfile]` |
| Observability | `qos_profiles` | `list[IRQoSProfile]` |
| Observability | `report_definitions` | `list[IRReportDefinition]` |
The root exposes 67 Pydantic fields. Legacy names such as `policies`, `ip_pools`,
`pbf_rules`, and vendor-specific roots are input aliases or Python compatibility
projections; they are not serialized V2 root fields.

## Shared model conventions

| Convention | Current behavior |
|---|---|
| Identity | Most objects use `name`; some also retain `source_uuid`, `uid`, or source IDs. Names are not assumed globally unique. |
| Scope | `source_context` carries VDOM, VSYS, domain, or another source scope where applicable. |
| Portable intent | Fields such as `subnet`, `fqdn`, `members`, `ports`, `source`, `destination`, `service`, `action`, `translated_*`, and `next_hop` are the main cross-vendor mapping surface. |
| Source evidence | `source_*`, `source_attributes`, `source_explicit_fields`, `source_effective_settings`, `nested_source_configs`, and unresolved-reference fields preserve source meaning or accounting. |
| Safety | Models commonly carry `migration_status`, `requires_manual_review`, `review_reasons`, `audit_note`, or `parse_error`. These flags must survive serialization. |
| Secrets | Sensitive content must not be exposed in logs, reports, fixtures, API responses, or generated artifacts. Presence/format fields such as `has_psk`, `has_private_key`, and `has_password` are safe evidence. |

### Common status values

The executable extraction status vocabulary is:

`NORMALIZED`, `PARTIALLY_NORMALIZED`, `EXTRACT_ONLY`, `UNSUPPORTED`,
`IGNORED_BY_POLICY`, and `PARSE_ERROR`.

An object with a non-normalized status or unresolved semantics is not silently
broadened into a target value such as `any`, `allow`, `/0`, or an enabled rule.

## Core mapping surface

These are the models that vendor mapping tables should normally reference.
Compatibility names are shown separately and should not be used for new
serialized output.

| Model | Main fields used by mappings | Related IR objects |
|---|---|---|
| `IRZone` | `name`, `zone_type`, `source_context`, `interfaces`, `description`, `disabled`, status/review fields | `IRInterface`, `IRSecurityPolicy`, `IRNATRule` |
| `IRInterface` | `name`, `zone`, `ip`, `ipv6_address`, `interface_type`, `members`, `role`, `addressing_mode`, `management_access`, `parent`, status/review fields | `IRZone`, `IRInterfaceGroup`, routes |
| `IRVirtualFirewallContext` | `context_id`, `context_type`, `parent_context`, interfaces, routing instances, administrators, limits, mode, status/review fields | scoped objects and metadata |
| `IRAddress` | `name`, `type`, `address_family`, `subnet`, `ip_range_start`, `ip_range_end`, `fqdn`, `mac`, `geo_code`, `wildcard_mask`, `dynamic_filter`, `tag_name`, `description`, `tags` | `IRAddressGroup`, `IRSecurityPolicy`, `IRNATRule` |
| `IRAddressGroup` | `name`, `members`, `exclude_members`, `is_dynamic`, `dynamic_filter`, `description`, `tags` | `IRAddress` |
| `IRService` | `name`, `ports`, `source_protocol`, `source_protocol_number`, `match_for_any`, `description` | `IRServicePort`, `IRServiceGroup`, `IRSecurityPolicy` |
| `IRServicePort` | `protocol`, `port`, `source_port`, `icmptype`, `icmpcode` | `IRService` |
| `IRServiceGroup` | `name`, `members`, `unsafe_members`, `description` | `IRService` |
| `IRSchedule` | `name`, `start`, `end`, `days`, `windows`, `schedule_type`, `start_utc`, `end_utc`, `recurrence`, `timezone` | `IRSecurityPolicy` |
| `IRApplication` | `name`, `category`, `urls`, `description`, `risk`, `metadata` | `IRSecurityPolicy` |
| `IRSecurityProfileGroup` | profile lists and references for antivirus, vulnerability, antispyware, URL, file, WildFire, data filtering, and SSL decryption | `IRSecurityPolicy` |
| `IRSecurityPolicy` | `name`, zones, addresses, services, ports, `action`, schedules, applications, users, security profiles, NAT evidence, logging, status/review fields | addresses, services, zones, schedules, applications |
| `IRNATPool` | `name`, `address_family`, `routing_instance`, addresses/ranges, port range, exclusions, status/review fields | `IRNATRule`; FortiOS PBA/CGN/NAT64 pool evidence is in `vendor_extensions.fortios.nat_pool_extensions` |
| `IRPublishedService` | frontend/external and backend/mapped addresses and ports, protocol, interfaces, source filters, real servers, load balancing, persistence, monitors, TLS, status/review fields | `IRNATRule`, `IRPublishedServiceGroup` |
| `IRNATRule` | match zones/interfaces/routing instances, addresses, services, families and protocol, source/destination address and port translation, pools, identity/exemption, sequence, enabled, status/review fields | addresses, services, zones, `IRNATPool`, `IRPublishedService` |
| `IRRoute` | `name`, `address_family`, `destination`, `interface`, `next_hop`, `next_hops`, `next_hop_type`, route metrics, `vrf`, `sdwan_zone`, enabled/status fields | `IRInterface`, `IRSDWAN` |
| `IRPathMonitor` | enabled state, failure condition, hold/recovery time, preemption, destinations, review/source fields | routes and forwarding policies |
| `IRForwardingPolicy` | match zones/interfaces, source/destination/user/application/service/schedule, action, egress/next hop, monitor, symmetric return, priority, enabled/status fields | addresses, services, zones, routes |
| `IRPolicyRoute` | ACL match evidence, ingress/output interface, next hops, action, enabled/status fields | interfaces, source ACL evidence |
| `IRVPNTunnel` | `name`, `peer_address`, `local_interface`, IKE/IPsec profiles, PSK presence, certificates, DH groups, split include/exclude, unresolved references, status/review fields | `IRVPNPhase2`, `IRCertificate`, interfaces |
| `IRVPNPhase2` | `name`, `phase1_name`, proposals, source/destination names and subnets/ranges, PFS, lifetimes, protocol/ports, status/review fields | `IRVPNTunnel`, addresses |
| `IRVPNCommunity` | gateway membership/topology, IKE/IPsec settings, authentication, users/groups, client settings | `IRVPNGateway`, `IRVPNTunnel` |
| `IRVPNGateway` | `name`, `uid`, `main_ip`, VPN status, topology, encryption domain, certificates, community membership | `IRVPNCommunity`, `IRCertificate` |
| `IRRemoteAccessVPN` | protocols, listeners, client pools, DNS/WINS, split include/exclude, authentication, certificate, timeouts, client settings | identity, certificates, interfaces |
| `IRIdentitySource` | source type, servers, port, TLS/certificate, credential presence, directory lookup settings | authentication and access roles |
| `IRIdentityMappingProvider` | provider type, endpoints, domain/groups, polling and mapping timeouts, source interfaces | policies and access roles |
| `IRAccessRole` | users, groups, machines, networks, remote-access roles, conditions | security and authentication policies |
| `IRAuthenticationProfile` | method, identity source, servers, realm/domain, user database, certificate/MFA, timeout, resolved dependencies | `IRAuthenticationPolicy` |
| `IRAuthenticationPolicy` | sources, destinations, interfaces/zones, services/users/schedule, profile/sequence, action | identity and authentication objects |
| `IRManagementAccessPolicy` | services, interfaces, sources, administrators, roles, enabled/status fields | management-plane settings |
| `IRProxyRequestMatch` / `IRWebProxy` | portable proxy request matching and listener/upstream/authentication settings | policies, interfaces, DNS |
| `IREndpointContextProvider` | provider/endpoints/tenant, certificate trust, attributes, capabilities, connection status | policies and identity |
| `IRLogDestinationProfile` / `IRLogForwardingPolicy` | portable log destination and forwarding/filter/action settings | policies and system settings |
| `IRDNSProxy` / `IRMonitorProfile` / `IRQoSProfile` / `IRReportDefinition` | portable DNS proxy, monitoring, QoS, and reporting settings | network and policy objects |
| `IRCertificate` | identity/status, public certificate metadata, validity, fingerprints, CA/usage references, secret-presence flags, status/review fields | VPN, interfaces, authentication, SSL inspection |

## Model module catalog

The package currently exports 248 Pydantic model names. This count includes
compatibility aliases that refer to the same class, so it is not a count of
distinct schemas. Exact fields are defined by each class's `model_fields` and
generated JSON schema; fixed field counts are intentionally not duplicated
here because they become stale whenever a field is added.

| Module | Responsibility |
|---|---|
| `config.py` | `IRConfig`, its 67 serialized fields, legacy input normalization, and compatibility properties. |
| `extensions.py` | Typed per-vendor extension containers. Extension models forbid undeclared fields. |
| `common.py` | Canonical virtual-firewall context and the legacy `IRExecutionContext` alias. |
| `metadata.py` | Source metadata, audit entries, and Check Point management/performance records. |
| `provenance.py` | Source configuration commands and nodes. |
| `network.py` | Zones, interfaces, HA, DHCP, system, DNS, NTP, and related source evidence. |
| `address.py` | Addresses and address groups. |
| `service.py` | Services, schedules, applications, proxy models, and Internet Service families. |
| `policy.py` | Canonical security/identity/access models plus source-specific policy records. |
| `nat.py` | Canonical NAT pools, published services, NAT rules, and legacy aliases. |
| `routing.py` | Routes, path monitors, forwarding policies, policy routing, SD-WAN, and legacy aliases. |
| `vpn.py` | Site-to-site VPN, remote-access VPN, phases, communities, and gateways. |
| `security_profiles.py` | Security definitions, certificates, identity/authentication, SSL VPN, DoS, GlobalProtect, logging, DNS, monitoring, QoS, reporting, and retained vendor records. |

Current Python compatibility aliases are:

| Legacy name | Canonical class |
|---|---|
| `IRExecutionContext` | `IRVirtualFirewallContext` |
| `IRPolicy` | `IRSecurityPolicy` |
| `IRCheckpointIdentitySource` | `IRIdentitySource` |
| `IRCheckpointAccessRole` | `IRAccessRole` |
| `IRAuthenticationScheme` | `IRAuthenticationProfile` |
| `IRAuthenticationRule` | `IRAuthenticationPolicy` |
| `IRIPPool` | `IRNATPool` |
| `IRVirtualIP` | `IRPublishedService` |
| `IRVirtualIPGroup` | `IRPublishedServiceGroup` |
| `IRPolicyBasedForwardingRule` | `IRForwardingPolicy` |
| `IRRoutePathMonitor` | `IRPathMonitor` |
| `IRProxyAddress` | `IRProxyRequestMatch` |
| `IRWebProxySettings` | `IRWebProxy` |
| `IRZTNAProvider` | `IREndpointContextProvider` |

## Enums

| Enum | Current values |
|---|---|
| `AddressType` | `network`, `host`, `range`, `fqdn`, `wildcard`, `dynamic`, `geo`, `wildcard_mask`, `mac`, `ems_tag`, `special`, `stub_unsupported` |
| `ServiceProtocol` | `tcp`, `udp`, `sctp`, `icmp`, `icmpv6`, `ip`, `any` |
| `PolicyAction` | `allow`, `deny`, `drop`, `reset-client`, `reset-server`, `reset-both`, `ipsec` |
| `NATType` | `source`, `destination`, `static`, `twice`, `service`, `central`, `address-translation` |
| `NATFamily` | `nat44`, `nat46`, `nat64`, `nat66` |
| `NATSourcePortBehavior` | `dynamic`, `preserve-if-available`, `preserve-strict`, `always-translate`, `explicit-range` |
| `NATTranslationMode` | `none`, `interface-address`, `pool`, `static`, `dynamic-ip`, `dynamic-ip-and-port`, `persistent-dynamic-ip-and-port` |
| `NATTranslationAddressSource` | `translated-address`, `interface-address` |
| `IRRouteNextHopType` | `ip-address`, `fqdn`, `next-vr`, `next-lr`, `next-routing-instance`, `discard`, `none` |
| `MigrationConfidence` | `full`, `partial`, `manual`, `unsupported` |

`NATType.SERVICE`, `NATType.CENTRAL`, `IRRouteNextHopType.NEXT_VR`, and
`IRRouteNextHopType.NEXT_LR` remain for compatibility/source fidelity. New V2
output should use independent service/port translation dimensions, source
provenance for central rulebases, and `next-routing-instance` where applicable.

## References and dependency behavior

`IRIndex` is a derived read-only index. It indexes list objects by `name` and
by any available `id`, `uid`, or `source_uuid`; duplicate names are retained as
tuples instead of being silently overwritten.

`DependencyGraph` resolves policy and NAT references to zones, addresses,
address groups, services, and service groups. Unresolved references become
dependency issues. Its normal dependency order is:

```text
zones -> interfaces -> addresses -> address groups -> services
-> service groups -> schedules -> NAT rules -> policies -> routes -> VPN
```

This graph is derived data. It does not replace the IR or mutate it.

## Serialization and schema changes

- `dump_ir_json()` serializes `IRConfig` through Pydantic.
- `load_ir_payload()` requires a JSON object. It treats a missing version or version `1` as legacy, migrates it to V2, and rejects booleans, non-integers, and versions other than `1` or `2`.
- V2 metadata requires an explicit `source_vendor`. The legacy loader supplies the historical `fortinet` default only for unversioned/V1 payloads.
- In a legacy payload, `policies` becomes canonical `security_policies`; the old top-level `security_policies` source-record collection moves to `vendor_extensions.fortios.security_policies`.
- Legacy NAT rules with `type: central` load as source NAT with `source_origin: central-snat-map`.
- `IRConfig` input normalization maps `execution_contexts`, `ip_pools`, `virtual_ips`, `virtual_ip_groups`, `pbf_rules`, `checkpoint_identity_sources`, `checkpoint_access_roles`, `authentication_schemes`, `authentication_rules`, `proxy_addresses`, `ztna_providers`, and `policies` to their V2 field names.
- A legacy singleton `web_proxy_settings` becomes zero or one `web_proxies` entry. A pre-VDOM singleton `sdwan` becomes `sdwans`; the corresponding compatibility properties return a value only when the collection contains exactly one item.
- Python properties retain the legacy names above. `threat_prevention_rules` and `threat_prevention_profiles` are read-only shorthand for their `checkpoint_` collections.
- `IRConfig` and the `IRVendorExtensions` wrapper retain compatible handling for unknown outer keys. Each per-vendor extension model uses `extra="forbid"`.

Any serialized field addition, removal, rename, or meaning change requires a
schema-version update, migration handling, and regression tests.

## Source authority

- `src/fwmigrate/ir/config.py` — aggregate root
- `src/fwmigrate/ir/extensions.py` — typed vendor extensions
- `src/fwmigrate/ir/common.py` — virtual-firewall context and legacy alias
- `src/fwmigrate/ir/metadata.py` — metadata, audit, Check Point management records
- `src/fwmigrate/ir/provenance.py` — source configuration evidence
- `src/fwmigrate/ir/network.py` — zones, interfaces, DHCP, system/network settings
- `src/fwmigrate/ir/address.py` — addresses and address groups
- `src/fwmigrate/ir/service.py` — services, schedules, applications, proxies, Internet services
- `src/fwmigrate/ir/policy.py` — security, identity, access, profile, and source-policy models
- `src/fwmigrate/ir/nat.py` — NAT pools, published services, NAT rules, and legacy aliases
- `src/fwmigrate/ir/routing.py` — routes, path monitors, forwarding/policy routing, SD-WAN
- `src/fwmigrate/ir/vpn.py` — site-to-site and remote-access VPN models
- `src/fwmigrate/ir/security_profiles.py` — certificates, identity, remote access, authentication, PAN-specific records
- `src/fwmigrate/extraction/models.py` and `src/fwmigrate/extraction/` — source accounting and extraction statuses
- `src/fwmigrate/ir/enums.py` — shared enum values
- `src/fwmigrate/ir/version.py` and `io.py` — schema version and serialized-payload migration behavior
