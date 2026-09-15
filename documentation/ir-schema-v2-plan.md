# IR Schema V2 Plan

Status: Planned target contract. Not yet the implemented schema.

This file is the single source of truth for the planned IR refactor. `documentation/ir-model.md` continues to describe the currently implemented schema until migration is complete.

## Goals

- Keep the canonical IR vendor-neutral.
- Preserve vendor-specific semantics without forcing false equivalence.
- Separate portable intent from source fidelity and vendor-only behavior.
- Keep old serialized IR and Python names compatible during migration.
- Make every vendor parser target the same canonical model and extension pattern.

## Classification Rules

- `GENERIC`: portable semantic intent shared across vendors.
- `GENERIC + EXT`: portable core plus typed vendor-specific extensions.
- `VENDOR SPECIFIC`: no proven portable canonical equivalent; retain only under vendor extensions.
- `UNCERTAIN`: do not generalize until semantics are verified.

## Root Contract

Planned `IRConfig` structure:

```text
IRConfig
├── schema_version
├── generation_safe
├── generation_blocking_reasons
├── requires_manual_review
├── metadata
├── canonical collections
│   ├── zones
│   ├── interfaces
│   ├── interface_groups
│   ├── virtual_firewall_contexts
│   ├── high_availability
│   ├── addresses
│   ├── address_groups
│   ├── services
│   ├── service_groups
│   ├── applications
│   ├── application_groups
│   ├── schedules
│   ├── schedule_groups
│   ├── security_policies
│   ├── security_profiles
│   ├── security_profile_groups
│   ├── nat_pools
│   ├── published_services
│   ├── published_service_groups
│   ├── nat_rules
│   ├── forwarding_policies
│   ├── routes
│   ├── path_monitors
│   ├── vpn_tunnels
│   ├── remote_access_vpns
│   ├── identity_sources
│   ├── identity_mapping_providers
│   ├── access_roles
│   ├── authentication_profiles
│   ├── authentication_sequences
│   ├── authentication_policies
│   ├── management_access_policies
│   ├── web_proxies
│   ├── proxy_request_matches
│   ├── endpoint_context_providers
│   ├── log_destination_profiles
│   ├── log_forwarding_policies
│   ├── dns_proxies
│   ├── monitor_profiles
│   ├── qos_profiles
│   ├── report_definitions
│   └── source_provenance / audit data
└── vendor_extensions
    ├── fortios
    ├── panos
    ├── checkpoint
    ├── cisco_asa
    ├── cisco_ftd
    └── junos
```

## Common Metadata and Provenance

Generic fields:

- `name` / canonical identifier where applicable
- `enabled`
- `description`
- `source_vendor`
- `source_context`
- `source_id` / `source_uuid`
- `source_origin`
- `migration_status`
- `requires_manual_review`
- `review_reasons`
- `source_attributes`
- explicit/effective source settings where needed for fidelity

`IRMetadata.source_vendor` must not default to Fortinet. Parsers must set it explicitly.

## Canonical Models

### `IRAddress`

Classification: `GENERIC + EXT`

Generic fields:

- `type`
- `address_family`
- `subnet`
- `range_start`
- `range_end`
- `fqdn`
- `wildcard_mask`
- `mac`
- `geo_code`
- `dynamic_filter`
- `interface`
- `tags`

Vendor extensions:

- FortiOS EMS/FSSO/SDN/fabric metadata
- Check Point domain/global-object identifiers
- provider-specific dynamic tag semantics

### `IRAddressGroup`

Classification: `GENERIC + EXT`

Generic fields:

- `members`
- `nested_members`
- `exclude_members`
- `is_dynamic`
- `dynamic_filter`
- `tags`

Vendor extensions contain vendor-specific dynamic-group and exclusion behavior.

### `IRService`

Classification: `GENERIC + EXT`

Generic fields:

- `protocol`
- `source_ports`
- `destination_ports`
- `icmp_type`
- `icmp_code`

Vendor extensions contain service aging, synchronization, provider/category, and vendor-only flags.

### `IRServiceGroup`

Classification: `GENERIC + EXT`

Generic fields:

- `members`

Vendor extensions contain vendor-only grouping metadata.

### `IRSchedule` / `IRScheduleGroup`

Classification: `GENERIC + EXT`

Generic schedule fields:

- `schedule_type`
- `start`
- `end`
- `days`
- `windows`
- `recurrence`
- `timezone`
- `expiration`

Group fields:

- `members`

Vendor extensions retain management-domain/global-assignment/fabric metadata.

### `IRApplication` / `IRApplicationGroup`

Classification: `GENERIC + EXT`

Generic application fields:

- `category`
- `risk`
- `protocols`
- `ports`
- `urls`
- `criteria`
- `tags`

Group fields:

- `members`

Vendor extensions retain App-ID signatures/dependencies, Check Point Application/Site behavior, Forti application IDs/categories, and equivalent vendor data.

### `IRSecurityPolicy`

Classification: `GENERIC + EXT`

Generic fields:

- `sequence`
- `from_zones`
- `to_zones`
- `from_interfaces`
- `to_interfaces`
- `source`
- `destination`
- `services`
- `applications`
- `users`
- `schedule`
- `action`
- `logging`
- `security_profiles`

Vendor extensions:

- Check Point package/layer/section/inline-layer/`install_on`
- PAN pre/post rulebase, device-group hierarchy, target metadata
- Forti `match_vip`, ASIC/NPU and policy-mode details
- other vendor-only rule options

Legacy alias during migration: `IRPolicy`.

### `IRSecurityProfile` / `IRSecurityProfileGroup`

Classification: `GENERIC + EXT`

Generic profile fields:

- `family`
- `rules`
- `applications`
- `file_types`
- `severities`
- `cves`
- `categories`
- `action`
- `direction`

Group field:

- `profiles_by_family`

Vendor signature IDs, sandbox behavior, profile family semantics, and proprietary actions stay in extensions.

## NAT and Published Services

### `IRNATRule`

Classification: `GENERIC + EXT`

Generic match fields:

- `sequence`
- `from_zones`
- `to_zones`
- `from_interfaces`
- `to_interfaces`
- `from_routing_instances`
- `to_routing_instances`
- `source`
- `destination`
- `services`
- `nat_family`
- protocol match data

Generic translation dimensions:

- source address translation
- destination address translation
- source port translation
- destination port translation
- translation mode
- address selection
- identity/exemption
- address range mappings

Rules:

- service/port translation is a translation dimension, not a canonical NAT direction.
- central/manual/automatic NAT is rulebase placement/provenance, not canonical translation type.
- old `NATType.SERVICE` and `NATType.CENTRAL` remain legacy-load compatibility only.

Vendor extensions:

- Check Point domain/package/rulebase hierarchy
- Forti VIP refs, `match_vip`, fixed-port and source policy evidence
- vendor-specific NAT ordering and runtime behavior

### `IRNATPool`

Classification: `GENERIC + EXT`

Generic fields:

- `address_family`
- `routing_instance`
- `addresses`
- `address_ranges`
- `port_range`
- `associated_interface`
- `excluded_ips`
- `description`

FortiOS extension:

- PBA/CGN controls
- session quotas
- NAT46/NAT64 route controls
- utilization alarms
- vendor ARP behavior

Check Point extension:

- network/group/range/gateway references
- applicability
- precedence
- VPN scope
- MEP
- member assignments

Legacy alias: `IRIPPool`.

### `IRPublishedService`

Classification: `GENERIC + EXT`

Generic fields:

- `frontend_addresses`
- `frontend_port`
- `protocol`
- `backend_addresses`
- `backend_port`
- `source_filters`
- `interfaces`
- `backend_servers`
- `load_balance_method`
- `persistence`
- `health_monitors`
- `tls_profile`

FortiOS extension keeps:

- `nat_source_vip`
- Forti port-mapping type
- GSLB fields
- QUIC
- HTTP/2/HTTP/3 knobs
- HTTP multiplex
- SSL cipher details
- ARP/NDP behavior
- NAT46/NAT64 source semantics

Legacy alias: `IRVirtualIP`.

### `IRPublishedServiceGroup`

Classification: `GENERIC + EXT`

Generic fields:

- `members`
- `interface`
- `address_family`

Legacy alias: `IRVirtualIPGroup`.

## Routing and Context

### `IRPolicyRoute`

Classification: `GENERIC`

Generic fields:

- `sequence`
- `match_criteria`
- `ingress_interface`
- `next_hops`
- `output_interfaces`
- `priority`
- `action`

### `IRForwardingPolicy`

Classification: `GENERIC + EXT`

Generic fields:

- `source`
- `destination`
- `user`
- `application`
- `service`
- `schedule`
- `ingress`
- `next_hop`
- `egress`
- `monitor`
- `priority`

Vendor extensions:

- PAN symmetric-return / forward-to-vsys / monitor semantics
- Forti TOS / Internet Service / source-port behavior

Legacy alias: `IRPolicyBasedForwardingRule`.

### `IRRoute`

Classification: `GENERIC + EXT`

Generic fields:

- `address_family`
- `destination`
- `routing_instance`
- `interface`
- `next_hop`
- `next_hop_type`
- `administrative_distance`
- `metric`
- `priority`
- `weight`
- `blackhole`

Canonical next-hop enum should include `NEXT_ROUTING_INSTANCE`. PAN `NEXT_VR` and `NEXT_LR` remain compatibility/source evidence.

### `IRPathMonitor`

Classification: `GENERIC + EXT`

Generic fields:

- `targets`
- `source`
- `source_interface`
- `interval`
- `timeout`
- `failure_threshold`
- `recovery_threshold`
- `failure_condition`
- `preemptive`

Vendor probe semantics stay in extensions.

### `IRVirtualFirewallContext`

Classification: `GENERIC + EXT`

Generic fields:

- `context_id`
- `context_type`
- `parent_context`
- `interfaces`
- `routing_instances`
- `administrators`
- `resource_limits`
- `mode`

Vendor extensions:

- Forti VDOM / central NAT / NGFW mode / opmode
- PAN vsys/shared-gateway/network ownership
- Check Point VSX virtual system
- ASA context/system context
- FTD instance/resource assignment
- Junos logical-system/tenant specifics

Check Point Management Domain and Panorama device group are management-scope concepts and must not be treated as equivalent virtual firewall contexts.

Legacy alias: `IRExecutionContext`.

### `IRHighAvailability`

Classification: `GENERIC + EXT`

Generic fields:

- `cluster_id`
- `mode`
- `members`
- `virtual_ips`
- `sync_interfaces`
- `monitored_interfaces`
- `priority`
- `preemption`
- `state_sync`

Vendor cluster protocols and topology details stay in extensions.

## Identity and Authentication

### `IRIdentitySource`

Classification: `GENERIC + EXT`

Generic fields:

- `source_type`
- `servers`
- `port`
- `tls`
- `certificate`
- `credentials_present`
- `base_dn`
- `user_lookup`
- `group_lookup`

Vendor protocol and identity-awareness settings stay in extensions.

### `IRIdentityMappingProvider`

Classification: `GENERIC + EXT`

Generic fields:

- `provider_type`
- `endpoints`
- `domain`
- `groups`
- `polling_interval`
- `mapping_timeout`
- `source_interfaces`

Vendor extensions cover FSSO, User-ID, Identity Awareness, ISE/passive identity, and equivalent mechanisms.

### `IRAccessRole`

Classification: `GENERIC + EXT`

Generic fields:

- `users`
- `user_groups`
- `machines`
- `networks`
- `conditions`
- `remote_access_roles`

Check Point Access Role details remain in its extension.

### `IRAuthenticationProfile`

Classification: `GENERIC + EXT`

Generic fields:

- `method`
- `identity_source`
- `server_refs`
- `realm`
- `domain`
- `user_database`
- `certificate_profile`
- `mfa_provider`
- `timeout`

Legacy alias: `IRAuthenticationScheme`.

### `IRAuthenticationSequence`

Classification: `GENERIC + EXT`

Generic fields:

- `profiles`
- `order`
- `continue_on_failure`
- `stop_on_failure`

### `IRAuthenticationPolicy`

Classification: `GENERIC + EXT`

Generic fields:

- `source`
- `destination`
- `interfaces`
- `zones`
- `services`
- `users`
- `schedule`
- `authentication_profile`
- `authentication_sequence`
- `action`

Legacy alias: `IRAuthenticationRule`.

### `IRManagementAccessPolicy`

Classification: `GENERIC + EXT`

Generic fields:

- `services`
- `interfaces`
- `sources`
- `administrators`
- `roles`
- `enabled`

Check Point Gaia management-access specifics and other vendor controls stay in extensions.

## VPN

### `IRRemoteAccessVPN`

Classification: `GENERIC + EXT`

Generic fields:

- `protocols`
- `listener_interfaces`
- `client_ipv4_pools`
- `client_ipv6_pools`
- `dns_servers`
- `wins_servers`
- `split_include`
- `split_exclude`
- `authentication`
- `certificate`
- `idle_timeout`
- `session_timeout`
- `client_settings`

Vendor extensions:

- Forti SSL-VPN portals, bookmarks, web mode, FortiClient settings
- PAN GlobalProtect portal/gateway/HIP data
- Cisco tunnel-group/group-policy details
- Check Point Office Mode/community data
- Juniper Secure Connect details

Site-to-site `IRVPNTunnel` remains separate.

## Proxy and Endpoint Context

### `IRProxyRequestMatch`

Classification: `GENERIC + EXT`

Generic fields:

- `host`
- `host_pattern`
- `path_pattern`
- `query_pattern`
- `method`
- `headers`
- `url_category`

Legacy alias: `IRProxyAddress`.

### `IRWebProxy`

Classification: `GENERIC + EXT`

Generic fields:

- `mode`
- `listener_interfaces`
- `listener_address`
- `listener_port`
- `fqdn`
- `authentication`
- `upstream_proxy`
- `dns`
- `policy_refs`

Legacy alias: `IRWebProxySettings`.

### `IREndpointContextProvider`

Classification: `GENERIC + EXT`

Generic fields:

- `provider_type`
- `endpoints`
- `tenant`
- `trust_certificate`
- `attributes`
- `capabilities`
- `connection_status`

Forti EMS serial/cloud-auth/capability flags and equivalent provider-specific details stay in extensions.

Legacy alias: `IRZTNAProvider`.

## Logging, DNS, Monitoring, QoS and Reporting

### `IRLogDestinationProfile`

Classification: `GENERIC + EXT`

Generic fields:

- `destination_type`
- `servers`
- `address`
- `transport`
- `port`
- `tls`
- `format`
- `facility`

### `IRLogForwardingPolicy`

Classification: `GENERIC + EXT`

Generic fields:

- `log_type`
- `filter`
- `severity`
- `destinations`
- `actions`

### `IRDNSProxy`

Classification: `GENERIC + EXT`

Generic fields:

- `interfaces`
- `default_servers`
- `domain_rules`
- `cache_enabled`
- `tcp_enabled`
- `conditional_forwarding`

### `IRMonitorProfile`

Classification: `GENERIC + EXT`

Generic fields:

- `probe_type`
- `targets`
- `interval`
- `timeout`
- `failure_threshold`
- `recovery_threshold`
- `action`

### `IRQoSProfile`

Classification: `GENERIC + EXT`

Generic fields:

- `classes`
- `priority`
- `guaranteed_bandwidth`
- `maximum_bandwidth`
- `queue`
- `dscp`

### `IRReportDefinition`

Classification: `GENERIC + EXT`

Generic fields:

- `report_type`
- `data_source`
- `filters`
- `query`
- `columns`
- `metrics`
- `group_by`
- `sort_by`
- `limit`
- `time_range`
- `schedule`

## Vendor-Specific Root Extensions

These must not be represented as portable canonical objects unless future semantic evidence proves a generic core.

### FortiOS

- Internet Service Database families
- FortiToken details
- Forti firewall sniffer configuration
- hardware ASIC/NPU/offload details
- source-only Forti rule families without canonical equivalents
- Forti-specific EMS connector details beyond generic endpoint context

### PAN-OS

- botnet report settings
- Panorama-specific device-group/template-stack inheritance metadata
- PAN-only operational settings without a proven generic equivalent

### Check Point

- Policy Package
- Management Domain
- Global Assignment
- SIC metadata
- SecureXL
- CoreXL

### Cisco ASA / FTD / Junos

- retain vendor-only source objects here when no proven canonical equivalent exists
- do not create a generic model solely to avoid an extension

## Legacy Name Mapping

| Legacy | Planned canonical name |
|---|---|
| `IRPolicy` | `IRSecurityPolicy` |
| `IRIPPool` | `IRNATPool` |
| `IRVirtualIP` | `IRPublishedService` |
| `IRVirtualIPGroup` | `IRPublishedServiceGroup` |
| `IRPolicyBasedForwardingRule` | `IRForwardingPolicy` |
| `IRExecutionContext` | `IRVirtualFirewallContext` |
| `IRAuthenticationScheme` | `IRAuthenticationProfile` |
| `IRAuthenticationRule` | `IRAuthenticationPolicy` |
| `IRProxyAddress` | `IRProxyRequestMatch` |
| `IRWebProxySettings` | `IRWebProxy` |
| `IRZTNAProvider` | `IREndpointContextProvider` |

Compatibility aliases must remain during the migration window.

## Enum Changes

Planned changes:

- Keep source/destination/twice/static NAT concepts where semantically meaningful.
- Do not use `NATType.SERVICE` for new canonical output.
- Do not use `NATType.CENTRAL` for new canonical output.
- Model service/port translation independently.
- Add generic `NEXT_ROUTING_INSTANCE`.
- Preserve PAN `NEXT_VR` / `NEXT_LR` for compatibility/source evidence.
- Preserve `RESET_CLIENT`, `RESET_SERVER`, `RESET_BOTH` until generic termination semantics and target mappings are implemented.
- Do not generalize `PolicyAction.IPSEC` until attachment semantics are verified across vendors.

## Compatibility Rules

- Old serialized IR must continue to load during V2 migration.
- Add `schema_version` before moving/removing fields.
- `load_ir_payload()` must perform legacy-shape migration before Pydantic validation.
- Legacy Python class names remain aliases until the migration is complete.
- Legacy top-level vendor fields may remain compatibility properties while authoritative storage moves under `vendor_extensions`.
- Target generators must consume canonical fields only unless intentionally generating same-vendor extension semantics.
- Vendor extensions must never silently broaden or alter canonical intent.

## Parser Contract After IR Stabilization

Every built-in vendor parser should follow the same high-level process:

```text
Raw Source
→ Input Adapter / Source Normalization
→ Parse / Tokenize / Load
→ Vendor Source Model
→ Context / Scope / Inheritance Resolution
→ Reference / Dependency Resolution
→ Source Inventory + Coverage Accounting
→ Semantic Transformation
   ├── Canonical IR
   └── Vendor Extensions
→ Semantic Validation
→ Extraction Safety
→ ExtractionResult
```

`BaseSourceParser.extract()` becomes the authoritative parser API. `parse()` becomes a compatibility projection returning `extract(...).canonical_ir`.

## Open / Uncertain Items

Do not generalize these further without additional vendor-specific validation:

- exact standalone service-only NAT support on every target
- exact directional reset mapping outside PAN-OS
- exact proxy-request object crosswalk for Cisco, Check Point and Juniper
- exact endpoint-posture provider connector equivalence across EMS, HIP, ISE/posture and other systems
- Juniper passive user/IP identity acquisition equivalence
- universal meaning of policy action `IPSEC`

These uncertainties must not block the generic architecture, but must remain fail-closed for generation where semantics are not proven.

## Implementation Rule

When adding or modifying an IR field:

1. Define the portable semantic meaning first.
2. Verify whether at least two vendors implement equivalent processing semantics.
3. If yes, place the portable portion in canonical IR.
4. Put non-portable behavior in typed vendor extensions.
5. If no proven portable equivalent exists, keep it vendor-specific.
6. Preserve source evidence and unresolved semantics.
7. Never map by name alone.
