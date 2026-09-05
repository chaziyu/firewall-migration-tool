# Check Point R81 Support Matrix

This is the authoritative Phase 29 inventory of the current Check Point R80/R81
extraction implementation. Status describes source extraction, not target
equivalence or automatic deployment safety.

The inventory is grouped by the original audit areas: Network and Routing;
Firewall, Policy and NAT; Objects; VPN; Identity and Authentication; Security
and Threat Prevention; IPv6; System and Platform; and Management and
Multi-Domain. A feature can map to a shared live coverage section.

| Feature | Coverage section | Status | Phase 30 classification | Source / parser | Representative regression test | Current limitation |
| --- | --- | --- | --- | --- | --- | --- |
| Physical interfaces | Network Interfaces | PARTIALLY_NORMALIZED | VENDOR_SPECIFIC_NONPORTABLE | Gaia / `gaia.py` | `test_gaia_r81_interface_tokens_and_loopback_creation` | Secondary and vendor-specific interface behavior remains source evidence. |
| VLAN and subinterfaces | Network Interfaces | PARTIALLY_NORMALIZED | VENDOR_SPECIFIC_NONPORTABLE | Gaia / `gaia.py` | `test_gaia_ipv6_vlan_secondary_addresses_and_route_priority` | Legacy VLAN syntax is compatibility-only. |
| Bridge and bonding | Network Interfaces | PARTIALLY_NORMALIZED | VENDOR_SPECIFIC_NONPORTABLE | Gaia / `gaia.py` | `test_gaia_bridge_preserves_members_and_interface_settings` | Platform-specific topology is not target-equivalent. |
| Loopback | Network Interfaces | PARTIALLY_NORMALIZED | VENDOR_SPECIFIC_NONPORTABLE | Gaia / `gaia.py` | `test_gaia_loopback_generated_name_merges_with_explicit_settings` | Only represented Gaia fields are portable. |
| IPv4 static routes | IPv4 Static Routes | PARTIALLY_NORMALIZED | VENDOR_SPECIFIC_NONPORTABLE | Gaia / `gaia.py` | `test_gaia_static_routes_are_family_aware_and_preserve_route_fields` | Blackhole, reject, monitoring, and other behavior-changing options remain partial. |
| IPv6 static routes | IPv6 Static Routes | PARTIALLY_NORMALIZED | VENDOR_SPECIFIC_NONPORTABLE | Gaia / `gaia.py` | `test_gaia_invalid_ipv6_route_does_not_become_default` | Unsupported route actions are not synthesized. |
| Policy-based routing | PBR | EXTRACT_ONLY | NEEDS_FUTURE_IR_DESIGN | Gaia / `gaia.py` | `test_gaia_pbr_keeps_tables_rules_order_and_match_fields_as_extract_only` | No portable target PBR mapping. |
| DNS and domain | DNS | PARTIALLY_NORMALIZED | SOURCE_DATA_MISSING | Gaia / `gaia.py` | `test_gaia_system_settings_are_structured_and_snmp_is_redacted_inventory` | Unmodeled Gaia DNS settings remain evidence. |
| DHCP server | DHCP | PARTIALLY_NORMALIZED | VENDOR_SPECIFIC_NONPORTABLE | Gaia / `gaia.py` | `test_gaia_dhcp_server_is_structured_and_mapped_without_treating_client_mode_as_server` | Full DHCP behavior is not target-generated. |
| NTP | NTP | PARTIALLY_NORMALIZED | SOURCE_DATA_MISSING | Gaia / `gaia.py` | `test_gaia_system_settings_are_structured_and_snmp_is_redacted_inventory` | Only explicitly modeled settings normalize. |
| SNMP | SNMP | EXTRACT_ONLY | OPERATIONAL_ONLY | Gaia / `gaia.py` | `test_gaia_system_settings_are_structured_and_snmp_is_redacted_inventory` | Secret material is removed; no target configuration is generated. |
| Management interface and access | Management Access | PARTIALLY_NORMALIZED | VENDOR_SPECIFIC_NONPORTABLE | Gaia / `gaia.py` | `test_gaia_r81_management_access_is_command_specific_and_validates_clients` | WebUI, SSH, allowed clients, and management conflicts require review. |
| Local users and RBAC | Authentication | PARTIALLY_NORMALIZED | VENDOR_SPECIFIC_NONPORTABLE | Gaia / `authentication.py` | `test_gaia_local_user_metadata_is_secret_safe_and_scoped` | Passwords and credential material are never extracted. |
| Policy packages | Policy Packages | NORMALIZED | IMPLEMENTABLE_NOW | Management API / `extractor.py` | `test_packages_are_domain_scoped_by_uid` | Package installation metadata is separate from rule semantics. |
| Access Layers and sections | Access Layers | PARTIALLY_NORMALIZED | NEEDS_FUTURE_IR_DESIGN | Management API / `access.py` | `test_inline_layer_keeps_parent_and_child_context` | Inline layers remain separate and are not flattened. |
| Access rules and ordering | Access Control | PARTIALLY_NORMALIZED | NEEDS_FUTURE_IR_DESIGN | Management API / `access.py` | `test_extract_access_rules_basic` | Unsupported dimensions, actions, and dependencies withhold rules. |
| Install-on | Access Control | PARTIALLY_NORMALIZED | VENDOR_SPECIFIC_NONPORTABLE | Management API / `access.py` | `test_install_on_selected_gateway_is_enforced` | Package and rule-level targets remain distinct. |
| Applications and URL objects | Application Control | PARTIALLY_NORMALIZED | VENDOR_SPECIFIC_NONPORTABLE | Management API / `extractor.py` | `test_application_objects_and_policy_dimension_are_not_services` | Vendor-specific application behavior is source-oriented. |
| Identity dependencies and Access Roles | Identity Awareness | PARTIALLY_NORMALIZED | VENDOR_SPECIFIC_NONPORTABLE | Management API / `authentication.py`, `access.py` | `test_unresolved_uid_taints_policy` | Unresolved or nonportable identity matches require review. |
| NAT rules | NAT | PARTIALLY_NORMALIZED | SOURCE_DATA_MISSING | Management API / `nat.py` | `test_extract_source_nat_hide` | Unknown methods, translated services, and incomplete fields are withheld. |
| Automatic NAT | NAT | PARTIALLY_NORMALIZED | SOURCE_DATA_MISSING | Management API / `nat.py` | `test_automatic_nat_completeness_is_domain_and_package_scoped` | Correlation is conservative and source-scoped. |
| IPv6 NAT, NAT46, and NAT64 | NAT | EXTRACT_ONLY | NEEDS_FUTURE_IR_DESIGN | Management API / `nat.py` | `test_translated_service_taints_every_address_nat_shape` | No exact portable semantics are claimed. |
| VPN communities and gateways | VPN | PARTIALLY_NORMALIZED | VENDOR_SPECIFIC_NONPORTABLE | Management API / `vpn.py` | `test_checkpoint_vpn_communities_and_gateway_properties_are_extracted` | Community topology and cryptographic behavior remain source metadata. |
| LDAP, RADIUS, TACACS, and SAML | Authentication | EXTRACT_ONLY | VENDOR_SPECIFIC_NONPORTABLE | Management API / `authentication.py` | `test_gaia_local_user_metadata_is_secret_safe_and_scoped` | Credentials and secrets are excluded. |
| Threat Prevention profiles and rules | Threat Prevention | PARTIALLY_NORMALIZED | VENDOR_SPECIFIC_NONPORTABLE | Management API / `threat_prevention.py` | `test_threat_prevention_is_separate_and_ordered` | Protection-engine behavior is not target-equivalent. |
| HTTPS Inspection | HTTPS Inspection | PARTIALLY_NORMALIZED | VENDOR_SPECIFIC_NONPORTABLE | Management API / `https_inspection.py` | `test_checkpoint_fixture_extracts_without_global_failure` | Certificate references and policy metadata do not normalize inspection behavior. |
| ClusterXL identity, members, VIPs, and sync | ClusterXL | PARTIALLY_NORMALIZED | VENDOR_SPECIFIC_NONPORTABLE | Management API / `cluster.py` | `test_cluster_management_object_preserves_members_and_vip` | Member-local Gaia configuration and advanced HA behavior remain partial. |
| ClusterXL runtime evidence | ClusterXL | EXTRACT_ONLY | OPERATIONAL_ONLY | Operational responses / `cluster.py` | `test_operational_clusterxl_state_does_not_change_persistent_mode` | Runtime state is not persistent configuration. |
| SecureXL persistent settings | SecureXL | PARTIALLY_NORMALIZED | VENDOR_SPECIFIC_NONPORTABLE | Gaia / `performance.py` | `test_performance_extracts_explicit_settings_only` | No target performance tuning is implied. |
| CoreXL persistent settings | CoreXL | PARTIALLY_NORMALIZED | VENDOR_SPECIFIC_NONPORTABLE | Gaia / `performance.py` | `test_performance_extracts_explicit_settings_only` | No target performance tuning is implied. |
| SecureXL and CoreXL operational evidence | SecureXL | EXTRACT_ONLY | OPERATIONAL_ONLY | Operational commands / `performance.py` | `test_runtime_commands_do_not_create_persistent_settings` | Counters and diagnostics are not configuration. |
| Certificates and certificate usage | Certificates | PARTIALLY_NORMALIZED | VENDOR_SPECIFIC_NONPORTABLE | Management API / `certificates.py` | `test_certificate_metadata_is_extracted_without_private_material` | No private keys; automatic certificate migration is not claimed. |
| SIC metadata | SIC | EXTRACT_ONLY | VENDOR_SPECIFIC_NONPORTABLE | Management API / `certificates.py` | `test_sic_state_is_separate_and_unknown_state_is_preserved` | SIC state is evidence, not proof of reachability or activation. |
| Multi-Domain identity and scope | Multi-Domain | PARTIALLY_NORMALIZED | NEEDS_FUTURE_IR_DESIGN | Management API / `resolver.py` | `test_multidomain_fixture_does_not_merge_same_names` | Effective global/local evaluation order is not synthesized. |
| Global assignments | Global Assignments | PARTIALLY_NORMALIZED | SOURCE_DATA_MISSING | Management API / `resolver.py` | `test_multidomain_fixture_does_not_merge_same_names` | Only explicit assignments are followed; names do not imply overrides. |
| Cross-domain references | Multi-Domain | UNSUPPORTED | INTENTIONALLY_UNSUPPORTED | Resolver / `resolver.py` | `test_cross_domain_reference_is_blocked` | No permissive fallback or cross-domain leakage. |
| Collector contract and completeness | Other Check Point | NORMALIZED | IMPLEMENTABLE_NOW | `export_checkpoint_bundle.py`, `bundle_builder.py` | `test_collection_contract_is_complete_and_duplicate_free` | Gaia and runtime collection are separate from the Management API manifest. |
| Pagination and collection failures | Other Check Point | PARTIALLY_NORMALIZED | SOURCE_DATA_MISSING | `loader.py`, collector | `test_command_failure_states_are_distINCT_and_sanitized` | Failed collection remains visible and cannot be treated as empty. |
| Advanced object families | Objects | EXTRACT_ONLY | VENDOR_SPECIFIC_NONPORTABLE | Management API / `objects.py` | `test_group_with_exclusion_and_special_types` | Dynamic, updatable, data-center, wildcard, and exclusion semantics are not portable. |
| Hosts, networks, ranges, and ordinary groups | Objects | NORMALIZED | IMPLEMENTABLE_NOW | Management API / `objects.py` | `test_extract_hosts_networks_and_ranges` | Invalid source values remain review evidence. |
| Dual-stack objects | Objects | PARTIALLY_NORMALIZED | NEEDS_FUTURE_IR_DESIGN | Management API / `objects.py` | `test_dual_stack_object_expands_deterministically_and_keeps_uid` | One source object can require family-specific review. |
| Services and service groups | Services | PARTIALLY_NORMALIZED | VENDOR_SPECIFIC_NONPORTABLE | Management API / `services.py` | `test_extract_tcp_udp_sctp_icmp_services` | Specialized and INSPECT behavior remains source-only. |
| Schedules and time groups | Schedules | PARTIALLY_NORMALIZED | NEEDS_FUTURE_IR_DESIGN | Management API / `schedules.py` | `test_time_fields_and_groups_are_preserved` | Complex recurrence, timezone, multiple windows, and groups require review. |

## Status meanings

- `NORMALIZED`: source semantics are represented in the current extraction model for the covered feature.
- `PARTIALLY_NORMALIZED`: some semantics are represented; the remaining source evidence and review boundary are explicit.
- `EXTRACT_ONLY`: source evidence is retained, but no portable canonical behavior is claimed.
- `UNSUPPORTED`: the feature or cross-scope behavior is not safely represented; it remains visible as a limitation or review record.

`PARSE_ERROR` is an observed extraction outcome, not a support capability. It
is reported by coverage when input is malformed or collection fails. Coverage
status and object-level target-generation safety are separate concepts.

## Phase 30 classifications

- `IMPLEMENTABLE_NOW`: exact source semantics are already represented and covered.
- `SOURCE_DATA_MISSING`: the collector or supplied bundle lacks authoritative evidence.
- `VENDOR_SPECIFIC_NONPORTABLE`: the data is useful source evidence but has no safe portable equivalent.
- `OPERATIONAL_ONLY`: the record describes runtime state, not persistent configuration.
- `INTENTIONALLY_UNSUPPORTED`: accepting it as deployable would violate a safety invariant.
- `NEEDS_FUTURE_IR_DESIGN`: exact support requires a richer vendor-neutral model.

## Remaining gaps

The implementation intentionally leaves advanced PBR, complex Gaia service
settings, specialized object and service behavior, advanced VPN cryptography,
Threat Prevention engine semantics, HTTPS Inspection behavior, effective
Multi-Domain policy ordering, and runtime performance tuning outside portable
target generation. These are source-accounted rather than silently discarded.
