# Canonical IR Model

**Status:** Current executable model snapshot<br>
**Verified:** 2026-09-15<br>
**Schema version:** `1.68`

This document records the implemented canonical intermediate representation
(IR). The Pydantic models and serialization code remain authoritative if this
document and the code disagree.

## Boundary

The migration path is:

```text
source configuration
        |
        v
vendor parser -> ExtractionResult + IRConfig
                         |
                         v
                validation / normalization
                         |
                         v
                    target generator
```

`IRConfig` is the vendor-neutral contract used by validators, optimizers,
reports, and target generators. `ExtractionResult` is separate: it accounts
for source data that was normalized, partially normalized, retained as
extract-only evidence, unsupported, ignored, or affected by a parse error.

Parsers must produce IR; generators must consume IR. Vendor syntax must not be
implemented as a direct source-to-target converter.

## Aggregate root: `IRConfig`

`IRConfig` is a flat Pydantic model. `metadata` is required. Collection fields
default to an empty list; optional singleton fields default to `null`.

### Root control fields

| Field | Type | Default | Meaning |
|---|---|---:|---|
| `generation_safe` | `boolean` | `true` | Whole-IR generation gate. |
| `generation_blocking_reasons` | `list[string]` | `[]` | Reasons generation is blocked. |
| `requires_manual_review` | `boolean` | `false` | Whole-IR review flag. |
| `metadata` | `IRMetadata` | required | Source and migration metadata. |

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
| Network | `dhcp6_servers` | `list[IRFortiGateSourceRule]` |
| Network | `sdwans` | `list[IRSDWAN]` |
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
| Service | `traffic_shapers` | `list[IRTrafficShaper]` |
| Service | `proxy_addresses` | `list[IRProxyAddress]` |
| Service | `web_proxy_settings` | `IRWebProxySettings \| null` |
| Service | `internet_services` | `list[IRInternetService]` |
| Service | `internet_service_definitions` | `list[IRInternetServiceDefinition]` |
| Service | `internet_service_additions` | `list[IRInternetServiceAddition]` |
| Service | `internet_service_appends` | `list[IRInternetServiceAppend]` |
| Service | `custom_internet_services` | `list[IRInternetServiceCustom]` |
| Service | `custom_internet_service_groups` | `list[IRInternetServiceCustomGroup]` |
| Service | `internet_service_extensions` | `list[IRInternetServiceExtension]` |
| Service | `internet_service_groups` | `list[IRInternetServiceGroup]` |
| Policy | `policies` | `list[IRPolicy]` |
| Policy | `default_security_rules` | `list[IRDefaultSecurityRule]` |
| Policy | `multicast_policies` | `list[IRMulticastPolicy]` |
| Policy | `firewall_filters` | `list[IRFirewallFilter]` |
| Policy | `security_profile_groups` | `list[IRSecurityProfileGroup]` |
| Policy | `security_profile_definitions` | `list[IRSecurityProfileDefinition]` |
| Policy | `https_inspection_rules` | `list[IRHTTPSInspectionRule]` |
| Policy | `custom_url_categories` | `list[IRCustomURLCategory]` |
| Policy | `ips_sensors` | `list[IRIPSSensor]` |
| Policy | `ztna_providers` | `list[IRZTNAProvider]` |
| Policy | `session_helpers` | `list[IRSessionHelper]` |
| Policy | `session_ttl_overrides` | `list[IRSessionTTLOverride]` |
| Policy | `session_ttl_settings` | `IRSessionTTLSettings \| null` |
| NAT | `ip_pools` | `list[IRIPPool]` |
| NAT | `virtual_ips` | `list[IRVirtualIP]` |
| NAT | `virtual_ip_groups` | `list[IRVirtualIPGroup]` |
| NAT | `nat_rules` | `list[IRNATRule]` |
| Routing | `pbf_rules` | `list[IRPolicyBasedForwardingRule]` |
| Routing | `policy_route_rules` | `list[IRPolicyRoute]` |
| VPN | `vpn_tunnels` | `list[IRVPNTunnel]` |
| VPN | `vpn_phase2` | `list[IRVPNPhase2]` |
| VPN | `vpn_communities` | `list[IRVPNCommunity]` |
| VPN | `vpn_gateways` | `list[IRVPNGateway]` |
| Security | `certificates` | `list[IRCertificate]` |
| Security | `ssh_keys` | `list[IRSSHKey]` |
| Audit | `audit_entries` | `list[IRAuditEntry]` |
| Context | `execution_contexts` | `list[IRExecutionContext]` |
| FortiGate | `central_snat_rules` | `list[IRFortiGateSourceRule]` |
| FortiGate | `security_policies` | `list[IRFortiGateSourceRule]` |
| FortiGate | `policy_routes` | `list[IRFortiGatePolicyRoute]` |
| FortiGate | `local_in_policies` | `list[IRLocalDeviceAccessRule]` |
| FortiGate | `proxy_policies` | `list[IRFortiGateSourceRule]` |
| FortiGate | `shaping_policies` | `list[IRFortiGateSourceRule]` |
| FortiGate | `source_only_rules` | `list[IRFortiGateSourceRule]` |
| FortiGate | `ssl_vpn_portals` | `list[IRSSLVPNPortal]` |
| FortiGate | `ssl_vpn_host_checks` | `list[IRSSLVPNHostCheck]` |
| FortiGate | `ssl_vpn_settings` | `IRSSLVPNSettings \| null` |
| FortiGate | `dos_policies` | `list[IRDoSPolicy]` |
| FortiGate | `firewall_sniffers` | `list[IRFirewallSniffer]` |
| FortiGate | `authentication_schemes` | `list[IRAuthenticationScheme]` |
| FortiGate | `authentication_sequences` | `list[IRAuthenticationSequence]` |
| FortiGate | `ssl_tls_service_profiles` | `list[IRSSLTLSServiceProfile]` |
| FortiGate | `authentication_rules` | `list[IRAuthenticationRule]` |
| FortiGate | `user_authentication_settings` | `IRUserAuthenticationSettings \| null` |
| FortiGate | `user_quarantine_settings` | `IRUserQuarantineSettings \| null` |
| FortiGate | `user_ldap_servers` | `list[IRUserLDAP]` |
| FortiGate | `user_radius_servers` | `list[IRUserRADIUS]` |
| FortiGate | `user_tacacs_servers` | `list[IRUserTACACS]` |
| FortiGate | `fsso_providers` | `list[IRFSSOProvider]` |
| FortiGate | `fsso_ad_groups` | `list[IRFSSOADGroup]` |
| FortiGate | `fsso_polling` | `list[IRFSSOPolling]` |
| FortiGate | `user_saml_servers` | `list[IRUserSAML]` |
| FortiGate | `local_users` | `list[IRLocalUser]` |
| FortiGate | `user_groups` | `list[IRUserGroup]` |
| FortiGate | `administrators` | `list[IRAdministrator]` |
| FortiGate | `admin_profiles` | `list[IRAdminProfile]` |
| FortiGate | `fortitokens` | `list[IRFortiToken]` |
| Palo Alto | `global_protect_portals` | `list[IRGlobalProtectPortal]` |
| Palo Alto | `global_protect_gateways` | `list[IRGlobalProtectGateway]` |
| Palo Alto | `global_protect_network_gateways` | `list[IRGlobalProtectNetworkGateway]` |
| Palo Alto | `pan_log_server_profiles` | `list[IRPANLogServerProfile]` |
| Palo Alto | `pan_log_forwarding_profiles` | `list[IRPANLogForwardingProfile]` |
| Palo Alto | `pan_management_log_settings` | `list[IRPANManagementLogSetting]` |
| Palo Alto | `pan_dns_proxies` | `list[IRPANDNSProxy]` |
| Palo Alto | `pan_monitor_profiles` | `list[IRPANMonitorProfile]` |
| Palo Alto | `pan_qos_profiles` | `list[IRPANQoSProfile]` |
| Palo Alto | `pan_sdwan_interface_profiles` | `list[IRPANSDWANInterfaceProfile]` |
| Palo Alto | `pan_sdwan_link_settings` | `list[IRPANSDWANLinkSettings]` |
| Palo Alto | `pan_sdwan_path_quality_profiles` | `list[IRPANSDWANPathQualityProfile]` |
| Palo Alto | `pan_sdwan_traffic_distribution_profiles` | `list[IRPANSDWANTrafficDistributionProfile]` |
| Palo Alto | `pan_sdwan_rules` | `list[IRPANSDWANRule]` |
| Palo Alto | `pan_high_availability` | `IRPANHighAvailability \| null` |
| Palo Alto | `pan_virtual_wires` | `list[IRPANVirtualWire]` |
| Palo Alto | `pan_device_operational_settings` | `IRPANDeviceOperationalSettings \| null` |
| Palo Alto | `pan_vsys_settings` | `list[IRPANVsysSettings]` |
| Palo Alto | `pan_botnet_report_settings` | `IRPANBotnetReportSettings \| null` |
| Palo Alto | `pan_custom_reports` | `list[IRPANCustomReport]` |
| Check Point | `checkpoint_management_access` | `list[IRCheckpointManagementAccess]` |
| Check Point | `checkpoint_performance` | `list[IRCheckpointPerformanceSettings]` |
| Check Point | `checkpoint_policy_packages` | `list[IRCheckpointPolicyPackage]` |
| Check Point | `checkpoint_access_layers` | `list[IRCheckpointAccessLayer]` |
| Check Point | `checkpoint_domains` | `list[IRCheckpointDomain]` |
| Check Point | `checkpoint_global_assignments` | `list[IRCheckpointGlobalAssignment]` |
| Check Point | `checkpoint_identity_sources` | `list[IRCheckpointIdentitySource]` |
| Check Point | `checkpoint_access_roles` | `list[IRCheckpointAccessRole]` |
| Check Point | `checkpoint_access_rules` | `list[IRCheckpointAccessRule]` |
| Check Point | `checkpoint_threat_prevention_rules` | `list[IRCheckpointThreatPreventionRule]` |
| Check Point | `checkpoint_threat_prevention_profiles` | `list[IRCheckpointThreatPreventionProfile]` |
| Check Point | `checkpoint_sic_metadata` | `list[IRCheckpointSICMetadata]` |

The root currently exposes 127 Pydantic fields. The complete field names and
types above are the serialization surface, not a claim that every field is
portable to every target.

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
They are followed by the model catalog so source-specific models remain visible
without pretending they are portable.

| Model | Main fields used by mappings | Related IR objects |
|---|---|---|
| `IRZone` | `name`, `zone_type`, `source_context`, `interfaces`, `description`, `disabled`, status/review fields | `IRInterface`, `IRPolicy`, `IRNATRule` |
| `IRInterface` | `name`, `zone`, `ip`, `ipv6_address`, `interface_type`, `members`, `role`, `addressing_mode`, `management_access`, `parent`, status/review fields | `IRZone`, `IRInterfaceGroup`, routes |
| `IRAddress` | `name`, `type`, `address_family`, `subnet`, `ip_range_start`, `ip_range_end`, `fqdn`, `mac`, `geo_code`, `wildcard_mask`, `dynamic_filter`, `tag_name`, `description`, `tags` | `IRAddressGroup`, `IRPolicy`, `IRNATRule` |
| `IRAddressGroup` | `name`, `members`, `exclude_members`, `is_dynamic`, `dynamic_filter`, `description`, `tags` | `IRAddress` |
| `IRService` | `name`, `ports`, `source_protocol`, `source_protocol_number`, `match_for_any`, `description` | `IRServicePort`, `IRServiceGroup`, `IRPolicy` |
| `IRServicePort` | `protocol`, `port`, `source_port`, `icmptype`, `icmpcode` | `IRService` |
| `IRServiceGroup` | `name`, `members`, `unsafe_members`, `description` | `IRService` |
| `IRSchedule` | `name`, `start`, `end`, `days`, `windows`, `schedule_type`, `start_utc`, `end_utc`, `recurrence`, `timezone` | `IRPolicy` |
| `IRApplication` | `name`, `category`, `urls`, `description`, `risk`, `metadata` | `IRPolicy` |
| `IRSecurityProfileGroup` | profile lists and references for antivirus, vulnerability, antispyware, URL, file, WildFire, data filtering, and SSL decryption | `IRPolicy` |
| `IRPolicy` | `name`, `from_zone`, `to_zone`, `source`, `destination`, `service`, `source_ports`, `action`, `schedule`, `applications`, security-profile fields, `disabled`, logging fields | addresses, services, zones, schedules, applications, NAT |
| `IRIPPool` | `name`, `address_family`, `addresses`, `address_ranges`, `start_ip`, `end_ip`, port range, exclusions, NAT46/NAT64 settings | `IRNATRule` |
| `IRVirtualIP` | `name`, `external_ip`, `external_addresses`, `mapped_ips`, `port_forward`, `protocol`, ports, interface filters, services, real servers, SSL/GSLB fields | `IRNATRule`, `IRVirtualIPGroup` |
| `IRNATRule` | match zones/interfaces, `source`, `destination`, `services`, address families, source/destination translation modes, translated addresses/services/ports, pool references, sequence, enabled, status/review fields | addresses, services, zones, `IRIPPool`, `IRVirtualIP` |
| `IRRoute` | `name`, `address_family`, `destination`, `interface`, `next_hop`, `next_hops`, `next_hop_type`, route metrics, `vrf`, `sdwan_zone`, enabled/status fields | `IRInterface`, `IRSDWAN` |
| `IRPolicyBasedForwardingRule` | match zones/interfaces, source/destination/application/service, action, egress/next hop, monitor, symmetric return, priority, enabled/status fields | addresses, services, zones, routes |
| `IRPolicyRoute` | ACL match evidence, ingress/output interface, next hops, action, enabled/status fields | interfaces, source ACL evidence |
| `IRVPNTunnel` | `name`, `peer_address`, `local_interface`, IKE/IPsec profiles, PSK presence, certificates, DH groups, split include/exclude, unresolved references, status/review fields | `IRVPNPhase2`, `IRCertificate`, interfaces |
| `IRVPNPhase2` | `name`, `phase1_name`, proposals, source/destination names and subnets/ranges, PFS, lifetimes, protocol/ports, status/review fields | `IRVPNTunnel`, addresses |
| `IRVPNCommunity` | gateway membership/topology, IKE/IPsec settings, authentication, users/groups, client settings | `IRVPNGateway`, `IRVPNTunnel` |
| `IRVPNGateway` | `name`, `uid`, `main_ip`, VPN status, topology, encryption domain, certificates, community membership | `IRVPNCommunity`, `IRCertificate` |
| `IRCertificate` | identity/status, public certificate metadata, validity, fingerprints, CA/usage references, secret-presence flags, status/review fields | VPN, interfaces, authentication, SSL inspection |

## Complete model catalog

The implementation currently exports 218 Pydantic IR classes. Field counts are
included to make changes easy to spot; the Python modules remain the detailed
field authority.

| Module | Models |
|---|---|
| `common.py` | `IRExecutionContext` (8) |
| `metadata.py` | `IRMetadata` (9), `IRCheckpointManagementAccess` (20), `IRCheckpointPerformanceSettings` (11), `IRCheckpointSecureXLSettings` (11), `IRCheckpointCoreXLSettings` (11), `IRAuditEntry` (5) |
| `provenance.py` | `IRSourceConfigCommand` (3), `IRSourceConfigNode` (4) |
| `network.py` | `IRZoneTaggingEntry` (4), `IRZone` (18), `IRInterfaceGroup` (8), `IRInterfaceSecondaryIP` (7), `IRInterfaceIPv6Address` (7), `IRInterfaceIPv4Address` (5), `IRInterfaceIPv6PrefixAdvertisement` (8), `IRInterfaceIPv6DelegatedPrefix` (9), `IRInterfaceDHCPv6IAPD` (5), `IRInterfaceVRRP6` (14), `IRCheckpointInterfaceContext` (8), `IRInterface` (103), `IRClusterInterface` (9), `IRHighAvailability` (18), `IRDHCPIPRange` (12), `IRDHCPExcludeRange` (12), `IRDHCPReservation` (14), `IRDHCPOption` (14), `IRDHCPServer` (51), `IRSystemSettings` (6), `IRCheckpointSICMetadata` (12), `IRManagementPlaneSettings` (12), `IRNTPServer` (4), `IRNTPSettings` (4), `IRDNSSettings` (6) |
| `address.py` | `IRAddressTaggingEntry` (4), `IRMACAddressEntry` (2), `IRAddress` (70), `IRAddressGroupTaggingEntry` (6), `IRAddressGroup` (31) |
| `service.py` | `IRServicePort` (6), `IRServiceCategory` (8), `IRService` (35), `IRServiceGroup` (13), `IRSchedule` (30), `IRTrafficShaper` (10), `IRProxyAddress` (11), `IRWebProxySettings` (4), `IRApplication` (18), `IRApplicationGroup` (19), `IRApplicationCategory` (19), `IRInternetService` (8), `IRInternetServiceDefinitionPortRange` (4), `IRInternetServiceDefinitionEntry` (6), `IRInternetServiceDefinition` (5), `IRInternetServiceCustomPortRange` (4), `IRInternetServiceCustomEntry` (7), `IRInternetServiceCustom` (8), `IRInternetServiceCustomGroup` (7), `IRInternetServiceAdditionPortRange` (4), `IRInternetServiceAdditionEntry` (5), `IRInternetServiceAddition` (7), `IRInternetServiceAppend` (7), `IRInternetServiceExtensionIPv4Range` (4), `IRInternetServiceExtensionIPv6Range` (4), `IRInternetServiceExtensionPortRange` (4), `IRInternetServiceExtensionDisableEntry` (7), `IRInternetServiceExtensionEntry` (7), `IRInternetServiceExtension` (8), `IRInternetServiceGroup` (8), `IRScheduleGroup` (16) |
| `policy.py` | `IRSecurityProfileGroup` (23), `IRHTTPSInspectionRule` (16), `IRCheckpointIdentitySource` (8), `IRCheckpointAccessRole` (12), `IRCheckpointAccessRule` (32), `IRCheckpointThreatPreventionRule` (17), `IRCheckpointThreatPreventionProfile` (12), `IRCustomURLCategory` (10), `IRIPSSensorExemptIP` (3), `IRIPSSensorEntry` (25), `IRIPSSensor` (11), `IRCheckpointPolicyPackage` (17), `IRCheckpointAccessLayer` (18), `IRCheckpointDomain` (16), `IRCheckpointGlobalAssignment` (17), `IRMulticastPolicy` (28), `IRPolicy` (140), `IRDefaultSecurityRule` (33), `IRFirewallFilterTerm` (9), `IRFirewallFilter` (9), `IRZTNAProvider` (15), `IRSessionHelper` (9), `IRSessionTTLOverride` (11), `IRSessionTTLSettings` (5), `IRFortiGateSourceRule` (11), `IRLocalDeviceAccessRule` (19) |
| `nat.py` | `IRIPPool` (64), `IRIPPoolRange` (2), `IRVirtualIPRealServer` (18), `IRVirtualIPGSLBPublicIP` (3), `IRVirtualIPQUICSettings` (9), `IRVirtualIPSSLCipherSuite` (4), `IRVirtualIP` (69), `IRNATPortRange` (2), `IRNATServiceMatch` (4), `IRNATDestinationDistribution` (2), `IRNATDestinationDNSRewrite` (3), `IRNATAddressRangeMapping` (4), `IRNATRuntimeBehavior` (12), `IRNATTranslationAddressSelection` (5), `IRNATSourceTranslationFallback` (6), `IRNATRule` (92), `IRVirtualIPGroup` (13) |
| `routing.py` | `IRRoutePathMonitorDestination` (13), `IRRoutePathMonitor` (8), `IRRoute` (42), `IRPBFSymmetricReturn` (3), `IRPolicyBasedForwardingRule` (40), `IRPolicyRoute` (20), `IRFortiGatePolicyRoute` (40), `IRManagementServiceRoute` (8), `IRSDWANZone` (7), `IRSDWANMember` (24), `IRSDWANSLA` (14), `IRSDWANHealthCheck` (54), `IRSDWANRuleSLA` (7), `IRSDWANRule` (72), `IRSDWANDuplicationRule` (16), `IRSDWANNeighbor` (5), `IRSDWAN` (12) |
| `vpn.py` | `IRVPNTunnel` (58), `IRVPNPhase2` (39), `IRVPNCommunity` (25), `IRVPNGateway` (12) |
| `security_profiles.py` | Identity, certificate, administrator, SSL VPN, authentication, DoS, GlobalProtect, PAN logging/DNS/SD-WAN/HA/report models; 83 exported classes in total. See the module and `IRConfig` fields for the exact current names. |

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
| `IRRouteNextHopType` | `ip-address`, `fqdn`, `next-vr`, `next-lr`, `discard`, `none` |
| `MigrationConfidence` | `full`, `partial`, `manual`, `unsupported` |

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
- `load_ir_payload()` requires a JSON object, applies explicit migrations, validates the resulting schema version, and constructs `IRConfig`.
- Future or malformed versions are rejected. Older versions require an explicit migration path.
- Unversioned legacy payloads are handled only by the explicit legacy migration path.
- `IRConfig` accepts the pre-VDOM `sdwan` input and normalizes it to `sdwans`; the `sdwan` property remains only for an unambiguous single-SD-WAN configuration.
- Compatibility properties expose Check Point identity sources, access roles, and threat-prevention collections under their shorter legacy names.

Any serialized field addition, removal, rename, or meaning change requires a
schema-version update, migration handling, and regression tests.

## Source authority

- `src/fwmigrate/ir/config.py` — aggregate root
- `src/fwmigrate/ir/common.py` — execution context
- `src/fwmigrate/ir/metadata.py` — metadata, audit, Check Point management records
- `src/fwmigrate/ir/provenance.py` — source configuration evidence
- `src/fwmigrate/ir/network.py` — zones, interfaces, DHCP, system/network settings
- `src/fwmigrate/ir/address.py` — addresses and address groups
- `src/fwmigrate/ir/service.py` — services, schedules, applications, Internet services
- `src/fwmigrate/ir/policy.py` — policies, security profiles, source-specific policy records
- `src/fwmigrate/ir/nat.py` — pools, VIPs, and NAT rules
- `src/fwmigrate/ir/routing.py` — routes, PBF, policy routing, SD-WAN
- `src/fwmigrate/ir/vpn.py` — VPN tunnels, phases, communities, gateways
- `src/fwmigrate/ir/security_profiles.py` — certificates, identity, remote access, authentication, PAN-specific records
- `src/fwmigrate/extraction/models.py` and `src/fwmigrate/extraction/` — source accounting and extraction statuses
- `src/fwmigrate/ir/enums.py` — shared enum values
- `src/fwmigrate/ir/version.py`, `io.py`, and `migrations*.py` — schema and serialization behavior
