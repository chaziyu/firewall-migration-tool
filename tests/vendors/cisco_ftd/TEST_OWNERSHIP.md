# Cisco FTD test ownership migration

Baseline: 34 vendor tests and 27 parser tests; both suites passed before moves.
Baseline vendor modules: `test_fmc_adapter.py`, `test_fmc_collection.py`, `test_fmc_relationships.py`, `test_fmc_time_ranges.py`, `test_package_boundary.py`, `test_ra_vpn_depth.py`, `test_reporting.py`, and `test_secret_redaction.py`.

## Moved from `test_fmc_adapter.py`

- `test_selected_fmc_domains_preserve_native_ownership_and_order` — keep in `test_fmc_adapter.py` as the fixture smoke test.
- `test_inspection_policy_rules_are_typed_ordered_resolved_and_complete` — move to `test_fmc_inspection.py`.
- `test_identity_admin_sources_are_typed_resolved_and_secret_safe` — move to `test_fmc_identity.py`; reporting and generic secret assertions now belong to their central suites.
- `test_fmc_dhcp_interface_reference_is_typed_scoped_and_keeps_missing_state`, `test_fmc_routes_preserve_selected_networks_family_provenance_and_ownership` — move to `test_fmc_routing.py`.
- `test_fmc_override_acp_assignment_ips_and_dhcp_source_state_remain_separate` — move to `test_fmc_routing.py`; object and ACP behaviors also have focused owner tests.
- `test_failed_override_collection_is_not_reported_as_known_empty_or_capability_missing`, `test_failed_pbr_collection_remains_failed_when_typed_collection_is_empty` — move to `test_fmc_completeness.py`.
- `test_canonical_networkaddresses_suppresses_historical_duplicates`, `test_typed_source_fields_keep_reference_identity_and_missing_state` — move to `test_fmc_objects.py`.
- `test_intrusion_behavior_group_membership_conflicts_and_acp_references`, `test_intrusion_group_only_and_missing_vs_empty_child_collections` — move to `test_fmc_inspection.py`.
- `test_fmc_ike_ipsec_objects_are_typed_with_version_and_without_native_duplicates`, `test_legacy_ike_ipsec_bundle_uses_top_level_collections_without_guessing_version`, `test_s2s_crypto_fields_keep_fmc_ownership_and_redact_manual_psk` — move to `test_fmc_s2s_vpn.py`.
- `test_expanded_fmc_source_families_are_typed_scoped_and_secret_safe` — split its assertions across `test_fmc_routing.py`, `test_fmc_s2s_vpn.py`, `test_ra_vpn_depth.py`, `test_fmc_inspection.py`, and `test_fmc_native_fallback.py`.
- `test_acp_child_collections_and_explicit_inheritance_are_source_safe` — move to `test_fmc_acp.py`.

## Moved from other vendor modules

- `test_identity_and_vpn_relationships_are_derived_without_source_mutation` — move from `test_fmc_relationships.py` to `test_fmc_identity.py`.
- `test_route_sla_monitor_is_a_typed_resolvable_source_reference`, `test_fmc_route_normalization_and_interface_topology_keep_device_scope` — move from `test_fmc_relationships.py` to `test_fmc_routing.py`.
- `test_fmc_secret_fields_are_removed_and_presence_metadata_survives` — keep in renamed `test_security.py`.
- `test_fmc_collector_collects_device_owned_routes_and_dhcp_read_only`, `test_fmc_detail_fetch_uses_endpoint_fields_and_keeps_query_parameters`, `test_fmc_access_rule_with_unrelated_extra_field_still_fetches_details`, `test_fmc_detail_failure_marks_family_partial_and_does_not_claim_success` — keep in `test_fmc_collection.py`.
- Both `test_fmc_time_range_*` tests, both `test_ra_*` tests, both reporting tests, and all three `test_package_boundary.py` tests — keep in their existing owning modules.

## Added regressions

- `test_fmc_pages_follow_paging_next_until_total_is_collected`, `test_fmc_pages_mark_incomplete_when_total_exceeds_collected_items`, `test_fmc_pages_reject_cross_host_pagination_url`, `test_fmc_auth_credentials_and_access_token_never_enter_collected_source` — `test_fmc_collection.py`.
- `test_device_object_override_keeps_base_and_target_identity_separate` — `test_fmc_objects.py`.
- `test_unknown_safe_resource_uses_native_fallback` — `test_fmc_native_fallback.py`.
- `test_prefilter_and_network_analysis_children_are_typed_and_owned` — `test_fmc_inspection.py`.
- `test_fmc_virtual_router_pbr_and_ecmp_keep_device_scope` — `test_fmc_routing.py`.
- `test_excel_formula_like_source_text_is_literal` — `test_reporting.py`.
- `test_fmc_secrets_stay_redacted_through_ftd_reports` — `test_security.py`.
