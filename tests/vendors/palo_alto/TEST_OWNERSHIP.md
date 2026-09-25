# Palo Alto test ownership migration

Baseline from `HEAD` before this migration: 21 modules, 63 test functions, 69 collected cases (parameter expansion), 69 passed.
Each baseline test function has one disposition below. `keep` means it remains in its owning suite.

| Baseline test | Disposition | Replacement or destination |
|---|---|---|
| `tests/vendors/palo_alto/test_dhcp.py::test_dhcp_xml_reaches_typed_server_and_preserves_unknown_source` | keep | same test |
| `tests/vendors/palo_alto/test_dhcp.py::test_selected_dhcp_missing_options_stay_unknown_and_unlimited_is_explicit` | keep | same test |
| `tests/vendors/palo_alto/test_dhcp.py::test_selected_interface_server_options_pools_reservations_and_unknowns` | keep | same test |
| `tests/vendors/palo_alto/test_excel_report.py::test_declared_source_columns_and_path_monitor_sheet_are_populated` | split | security, NAT, zone, vulnerability, and path-monitor tests in test_excel_report.py |
| `tests/vendors/palo_alto/test_excel_report.py::test_excel_report_activates_typed_dhcp_sdwan_identity_and_globalprotect_sheets` | split | DHCP, SD-WAN, identity, and GlobalProtect row tests in test_excel_report.py |
| `tests/vendors/palo_alto/test_excel_report.py::test_excel_report_contains_native_domain_sheets` | keep | same test |
| `tests/vendors/palo_alto/test_excel_report.py::test_excel_validation_sheet_contains_validation_issue` | move | test_excel_review.py::test_validation_issue_is_exported_to_validation_sheet |
| `tests/vendors/palo_alto/test_excel_report.py::test_partial_extraction_status_and_source_appendix_evidence` | keep | same test |
| `tests/vendors/palo_alto/test_extraction_registry.py::test_active_excel_sheets_have_headers_and_row_generation_paths` | rewrite-publicly | test_excel_schema.py::test_active_sheets_have_declared_headers_and_status |
| `tests/vendors/palo_alto/test_extraction_registry.py::test_failed_typed_extraction_preserves_inventory_and_later_objects` | move | test_source_preservation.py::test_failed_typed_extraction_preserves_inventory_and_later_objects |
| `tests/vendors/palo_alto/test_extraction_registry.py::test_implemented_source_sheets_do_not_use_empty_placeholder_builders` | remove-as-duplicate | replaced by public sheet schema and row-export checks |
| `tests/vendors/palo_alto/test_extraction_registry.py::test_not_implemented_sheets_need_no_row_builder` | remove-as-duplicate | replaced by public sheet schema and row-export checks |
| `tests/vendors/palo_alto/test_extraction_registry.py::test_registered_collections_are_deterministic` | keep | same test |
| `tests/vendors/palo_alto/test_extraction_registry.py::test_registered_collections_are_unique_and_initialized` | keep | same test |
| `tests/vendors/palo_alto/test_extraction_registry.py::test_representative_source_paths_reach_typed_collections` | keep | same test |
| `tests/vendors/palo_alto/test_globalprotect.py::test_globalprotect_xml_reaches_typed_portal_and_gateway` | keep | same test |
| `tests/vendors/palo_alto/test_globalprotect.py::test_selected_globalprotect_roots_and_nested_shapes_are_typed` | keep | same test |
| `tests/vendors/palo_alto/test_identity_admin.py::test_admin_custom_role_subtree_is_preserved_without_guessing_profile_leaf` | keep | same test |
| `tests/vendors/palo_alto/test_identity_admin.py::test_admin_role_missing_and_empty_permissions_preserve_source_presence` | keep | same test |
| `tests/vendors/palo_alto/test_identity_admin.py::test_admin_xml_reaches_typed_administrators_and_roles` | keep | same test |
| `tests/vendors/palo_alto/test_identity_admin.py::test_identity_admin_unknown_source_is_retained_separately` | keep | same test |
| `tests/vendors/palo_alto/test_identity_admin.py::test_identity_xml_reaches_typed_users_groups_and_mappings` | keep | same test |
| `tests/vendors/palo_alto/test_identity_admin.py::test_selected_admin_role_nested_channel_permissions_keep_order_and_values` | keep | same test |
| `tests/vendors/palo_alto/test_identity_admin.py::test_selected_identity_roots_group_mapping_names_and_phash_redaction` | keep | same test |
| `tests/vendors/palo_alto/test_interface_topology.py::test_interfaces_preserve_parent_aggregate_and_tunnel_relationships` | rewrite-publicly | same test now targets derived interface topology |
| `tests/vendors/palo_alto/test_nat_semantics.py::test_destination_translation_dns_rewrite_is_typed_without_inferred_enablement` | keep | same test |
| `tests/vendors/palo_alto/test_nat_semantics.py::test_nat_translation_variants_remain_explicit` | keep | same test |
| `tests/vendors/palo_alto/test_policy_order.py::test_security_rule_order_is_retained_per_source_rulebase` | keep | same test |
| `tests/vendors/palo_alto/test_policy_semantics.py::test_icmp_unreachable_is_extracted_for_ordinary_security_rules` | keep | same test |
| `tests/vendors/palo_alto/test_reference_semantics.py::test_address_nat_sdwan_and_zone_references_are_in_relationships` | keep | same test |
| `tests/vendors/palo_alto/test_reference_semantics.py::test_reference_resolution_reports_missing_references_without_repairing_source` | rewrite-publicly | same test now checks UNRESOLVED, validation, and unchanged source |
| `tests/vendors/palo_alto/test_reference_semantics.py::test_sdwan_local_user_and_globalprotect_reference_semantics` | keep | same test |
| `tests/vendors/palo_alto/test_reference_semantics.py::test_source_only_target_is_reviewed_but_missing_target_is_error` | keep | same test |
| `tests/vendors/palo_alto/test_scope_semantics.py::test_shared_device_group_and_nested_scopes_remain_explicit` | keep | same test |
| `tests/vendors/palo_alto/test_scope_semantics.py::test_template_and_template_stack_owners_remain_distinct` | keep | same test |
| `tests/vendors/palo_alto/test_sdwan.py::test_sdwan_links_and_interface_bindings_reach_existing_typed_models` | split | source assertions remain in test_sdwan.py; workbook assertions move to test_excel_report.py |
| `tests/vendors/palo_alto/test_sdwan.py::test_sdwan_missing_and_empty_links_preserve_source_presence` | keep | same test |
| `tests/vendors/palo_alto/test_sdwan.py::test_sdwan_unknown_source_is_retained_separately` | keep | same test |
| `tests/vendors/palo_alto/test_sdwan.py::test_sdwan_xml_reaches_typed_profiles_and_rules` | keep | same test |
| `tests/vendors/palo_alto/test_secret_redaction.py::test_secret_leaves_are_redacted_from_result_preview_and_workbook` | rewrite-publicly | renamed and expanded in test_security.py |
| `tests/vendors/palo_alto/test_security_profiles.py::test_security_profile_unknown_source_is_retained_separately` | keep | same test |
| `tests/vendors/palo_alto/test_security_profiles.py::test_security_profile_xml_reaches_typed_profile_group_and_rule` | keep | same test |
| `tests/vendors/palo_alto/test_security_profiles.py::test_selected_threat_exception_time_attribute_and_exempt_ip_are_extracted` | keep | same test |
| `tests/vendors/palo_alto/test_security_profiles.py::test_vulnerability_block_ip_and_exempt_ips_are_extracted_explicitly` | keep | same test |
| `tests/vendors/palo_alto/test_security_profiles.py::test_vulnerability_missing_and_empty_nested_sections_preserve_source_presence` | keep | same test |
| `tests/vendors/palo_alto/test_service_semantics.py::test_service_override_preserves_yes_no_presence_through_excel` | split | source contract in test_service_semantics.py; workbook contract in test_excel_report.py |
| `tests/vendors/palo_alto/test_source_reporting.py::test_reporter_returns_native_opaque_result_and_all_reporting_layers` | keep | same test |
| `tests/vendors/palo_alto/test_validation_semantics.py::test_pan_os_wildcard_addresses_use_ipv4_wildcard_masks` | rewrite-publicly | public reporter validation tests in test_validation_semantics.py |
| `tests/vendors/palo_alto/test_validation_semantics.py::test_port_ranges_apply_source_context_limits` | rewrite-publicly | public reporter validation tests in test_validation_semantics.py |
| `tests/vendors/palo_alto/test_validation_semantics.py::test_validator_accepts_wildcards_and_service_proxy_zero_but_rejects_nat_zero` | split | five focused public reporter validation tests in test_validation_semantics.py |
| `tests/vendors/palo_alto/test_vpn_semantics.py::test_ike_id_scalar_compatibility_and_unverified_subtree_preservation` | keep | same test |
| `tests/vendors/palo_alto/test_vpn_semantics.py::test_ipsec_proxy_ids_extract_both_auto_key_families_without_manual_secrets` | keep | same test |
| `tests/vendors/palo_alto/test_vpn_semantics.py::test_malformed_proxy_extraction_is_visible_and_does_not_hide_failure` | keep | same test |
| `tests/vendors/palo_alto/test_vpn_semantics.py::test_missing_manual_key_stays_unconfigured_and_proxy_family_is_structural` | keep | same test |
| `tests/vendors/palo_alto/test_vpn_semantics.py::test_reference_shaped_nested_proxy_protocol_and_auto_key_profile` | keep | same test |
| `tests/vendors/palo_alto/test_vpn_semantics.py::test_vpn_unknown_source_is_retained_separately` | keep | same test |
| `tests/vendors/palo_alto/test_vpn_semantics.py::test_vpn_xml_reaches_typed_gateways_profiles_and_tunnels` | keep | same test |
| `tests/vendors/palo_alto/test_web_report.py::test_preview_includes_logical_router_routes_with_ownership` | keep | same test |
| `tests/vendors/palo_alto/test_web_report.py::test_same_named_scoped_policies_keep_review_reasons_in_their_scope` | keep | same test |
| `tests/vendors/palo_alto/test_web_report.py::test_web_report_counts_and_sections_include_identity_and_sdwan_domains` | keep | same test |
| `tests/vendors/palo_alto/test_web_report.py::test_web_report_has_expected_sections` | keep | same test |
| `tests/vendors/palo_alto/test_zone_semantics.py::test_selected_zone_nested_fields_and_members_are_source_faithful` | keep | same test |
| `tests/vendors/palo_alto/test_zone_semantics.py::test_selected_zone_without_network_type_does_not_infer_one` | keep | same test |
