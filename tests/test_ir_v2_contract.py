import ast
import json
from pathlib import Path

import pytest

from fwmigrate.ir import (
    IRAddress,
    IRAddressGroup,
    IRApplication,
    IRApplicationCategory,
    IRApplicationGroup,
    IRConfig,
    IRInterface,
    IRNATPool,
    IRNATRule,
    IRPublishedService,
    IRPublishedServiceGroup,
    IRRoute,
    IRForwardingPolicy,
    IRVirtualFirewallContext,
    IRHighAvailability,
    IRSchedule,
    IRScheduleGroup,
    IRSecurityPolicy,
    IRService,
    IRServiceGroup,
    IRFortiOSPublishedServiceExtension,
)
from fwmigrate.ir.enums import AddressType, NATType
from fwmigrate.ir.errors import IRSchemaError
from fwmigrate.ir.io import dump_ir_json, load_ir_payload


FINAL_CANONICAL_ROOTS = {
    "schema_version", "generation_safe", "generation_blocking_reasons",
    "requires_manual_review", "metadata", "vendor_extensions", "zones",
    "interface_groups", "interfaces", "high_availability", "addresses",
    "address_groups", "service_categories", "services", "service_groups",
    "applications", "application_groups", "application_categories", "schedules",
    "schedule_groups", "security_profile_groups", "security_profile_definitions",
    "identity_sources", "identity_mapping_providers", "access_roles",
    "https_inspection_rules", "custom_url_categories", "ips_sensors",
    "security_policies", "default_security_rules", "multicast_policies", "nat_pools",
    "published_services", "published_service_groups", "nat_rules",
    "forwarding_policies", "policy_route_rules", "firewall_filters", "vpn_tunnels",
    "vpn_phase2", "vpn_communities", "vpn_gateways", "certificates", "ssh_keys",
    "system_settings", "dns_settings", "ntp_settings", "management_service_routes",
    "routes", "audit_entries", "endpoint_context_providers",
    "virtual_firewall_contexts", "dhcp_servers", "authentication_profiles",
    "authentication_sequences", "authentication_policies", "path_monitors",
    "remote_access_vpns", "management_access_policies", "proxy_request_matches", "web_proxies",
    "log_destination_profiles", "log_forwarding_policies", "dns_proxies",
    "monitor_profiles", "qos_profiles", "report_definitions",
}


def _metadata(vendor="fortigate"):
    return {"source_vendor": vendor}


def test_final_canonical_root_surface_is_explicit_and_vendor_neutral():
    assert set(IRConfig.model_fields) == FINAL_CANONICAL_ROOTS
    assert not any(
        name.startswith(("pan_", "checkpoint_"))
        for name in IRConfig.model_fields
    )


@pytest.mark.parametrize(
    "model",
    [
        IRAddress,
        IRAddressGroup,
        IRService,
        IRServiceGroup,
        IRSchedule,
        IRScheduleGroup,
        IRApplication,
        IRApplicationGroup,
        IRApplicationCategory,
        IRInterface,
        IRSecurityPolicy,
        IRNATPool,
        IRNATRule,
    ],
)
def test_canonical_models_have_no_vendor_prefixed_fields(model):
    assert not [
        field for field in model.model_fields
        if field.startswith(("pan_", "checkpoint_"))
    ]


CANONICAL_MODEL_FIELDS = {
    IRAddress: {
        "name", "type", "source_context", "source_uuid", "vendor_extension", "source_section",
        "address_family", "source_type", "source_list_entries", "source_tagging_entries",
        "associated_interface", "allow_routing", "source_color", "source_interface",
        "resolved_interface_subnet", "interface_reference_resolved", "source_attributes",
        "migration_status", "requires_manual_review",
        "audit_note", "subnet", "ip_range_start", "ip_range_end", "fqdn", "mac", "mac_entries",
        "geo_code", "wildcard_mask", "dynamic_filter", "tag_name", "stub_value", "original_type",
        "original_value", "parse_error", "raw_value", "description", "tags", "is_ipv6", "is_multicast",
    },
    IRAddressGroup: {
        "name", "source_context", "members", "source_direct_members", "source_nested_group_members",
        "description", "is_dynamic", "dynamic_filter", "tags", "source_uuid", "vendor_extension",
        "associated_interface", "allow_routing", "source_color", "source_category", "source_section",
        "address_family", "exclusion_enabled",
        "exclude_members", "source_tagging_entries", "source_attributes", "migration_status",
        "requires_manual_review", "audit_note",
    },
    IRService: {
        "name", "source_context", "ports", "source_uuid", "vendor_extension", "source_category",
        "source_protocol_configured", "source_protocol", "source_protocol_number", "source_proxy",
        "source_color", "source_fabric_object", "source_unmodeled_semantic_settings", "match_for_any",
        "session_timeout", "use_default_session_timeout", "aggressive_aging", "sync_connections_on_cluster",
        "keep_connections_open_after_policy_installation", "protocol_signatures", "match", "action",
        "accept_replies", "session_behavior", "source_attributes", "migration_status",
        "requires_manual_review", "audit_note", "description",
    },
    IRServiceGroup: {
        "name", "source_context", "members", "unsafe_members", "source_uuid", "source_color",
        "source_proxy", "source_fabric_object", "source_attributes", "migration_status",
        "requires_manual_review", "audit_note", "description",
    },
    IRSchedule: {
        "name", "source_context", "start", "end", "days", "windows", "schedule_type", "source_color",
        "vendor_extension", "expiration_days", "source_fabric_object", "start_utc", "end_utc",
        "hours_ranges", "start_endpoint", "end_endpoint", "start_now", "end_never", "recurrence",
        "timezone", "migration_status", "requires_manual_review", "review_reasons", "source_attributes",
    },
    IRApplication: {
        "name", "source_uuid", "vendor_extension", "source_context", "category", "urls", "description",
        "risk", "metadata", "migration_status", "requires_manual_review", "source_attributes",
    },
    IRSecurityPolicy: {
        "name", "source_context", "vendor_extension", "from_zone", "to_zone", "source", "destination",
        "service", "source_ports", "source_port_reference_statuses", "vlan_criteria", "variable_sets",
        "action", "source_rule_id", "source_uuid", "source_from_interfaces", "source_to_interfaces",
        "source_address_references", "destination_address_references", "source_ipv6_address_references",
        "destination_ipv6_address_references", "source_address_negate_setting",
        "destination_address_negate_setting", "source_ipv6_address_negate_setting",
        "destination_ipv6_address_negate_setting", "source_service_references", "source_service_negate_setting",
        "source_action", "source_schedule", "source_user_groups", "source_users", "unresolved_user_groups",
        "unresolved_users", "identity_dependency_review", "source_log_setting", "source_log_setting_resolved",
        "resolved_source_log_setting", "source_log_start_setting", "source_extra_setting_commands",
        "source_profile_type", "source_profile_group", "source_profile_protocol_options",
        "unresolved_security_profiles", "source_security_profile_references", "security_profile_reference_statuses",
        "unresolved_security_profile_references", "security_profile_semantics_review", "source_extra_settings",
        "nat_enabled", "nat_pool_enabled", "nat_pool_names", "nat_pool_names6", "migration_status",
        "review_reasons", "requires_manual_review", "description", "schedule", "schedules", "log_start",
        "log_end", "disabled", "url_categories", "url_category_reference_statuses", "unresolved_url_categories",
        "security_profile_groups", "antivirus_profiles", "vulnerability_profiles", "antispyware_profiles",
        "url_filtering_profiles", "file_blocking_profiles", "wildfire_analysis_profiles", "data_filtering_profiles",
        "security_profile_group", "antivirus", "ips_sensor", "webfilter", "application_list",
        "ssl_ssh_profile", "applications", "application_categories", "internet_service",
    },
    IRNATPool: {
        "name", "source_context", "address_family", "routing_instance", "source_explicit_fields",
        "source_effective_settings", "pool_type", "addresses", "address_ranges", "start_ip", "end_ip",
        "source_start_ip", "source_end_ip", "source_prefix6", "start_port", "end_port",
        "associated_interface", "permit_any_host", "excluded_ips",
        "migration_status", "requires_manual_review", "audit_note", "source_attributes", "description",
        "source_uuid", "vendor_extension", "source_origin",
    },
    IRNATRule: {
        "name", "type", "source_context", "vendor_extension", "source_policy_reference", "source_policy_uuid",
        "source_policy_name", "sequence", "source_rule_set", "from_routing_instances", "to_routing_instances",
        "enabled", "source_from_interfaces", "source_to_interfaces", "from_zone", "to_zone", "source",
        "destination", "services", "internet_services", "nat_family", "original_address_family",
        "translated_address_family", "protocol_number", "protocol_name", "original_source_ports",
        "original_destination_ports", "service_matches", "translated_source_ports", "translated_destination_ports",
        "source_port_behavior", "address_range_mappings", "install_translation_route", "runtime_behavior",
        "source_origin", "traffic_type", "source_translation_mode", "source_translation_address_selection",
        "source_translation_bidirectional", "source_translation_fallback", "destination_translation_mode",
        "destination_translation_distribution", "destination_dns_rewrite", "source_device_binding", "identity",
        "exemption", "source_pool_references", "translated_source_address_references", "destination_pool_references",
        "translated_destination_address_references", "translated_sources", "translated_destinations",
        "translated_services", "source_rule_id", "source_attributes", "destination_protocol",
        "original_destination_port", "migration_status", "review_reasons", "requires_manual_review", "service",
        "translated_source", "translated_destination", "translated_port", "description",
    },
    IRPublishedService: {
        "name", "source_context", "address_family", "source_id", "source_uuid", "vendor_extension", "enabled",
        "external_ip", "external_addresses", "external_interface", "mapped_ips", "mapped_address",
        "port_forward", "protocol", "external_port", "mapped_port", "source_filters", "source_interface_filters",
        "services", "load_balance_method", "persistence", "ssl_certificate", "monitors", "real_servers",
        "source_explicit_fields", "source_effective_settings", "nested_source_configs", "color", "description",
        "extra_settings", "migration_status", "requires_manual_review", "audit_note",
    },
    IRPublishedServiceGroup: {
        "name", "source_context", "address_family", "source_uuid", "interface", "members", "unresolved_members",
        "source_color", "description", "migration_status", "requires_manual_review", "audit_note", "source_attributes",
    },
    IRRoute: {
        "name", "source_context", "routing_instance", "address_family", "destination", "source_destination",
        "source_destination_reference", "source_prefix", "source_preferred_source", "source_route_id", "interface",
        "next_hop", "next_hops", "next_hop_type", "route_type", "rank", "scope_local", "monitoring",
        "administrative_distance", "metric", "priority", "weight", "blackhole", "enabled", "installation",
        "source_explicit_fields", "sdwan_zone", "sdwan_zones", "dynamic_gateway", "link_monitor_exempt", "bfd",
        "path_monitor", "vrf", "route_tag", "internet_service", "internet_service_custom", "description",
        "migration_status", "review_reasons", "parse_error", "requires_manual_review", "source_fabric_object",
        "source_attributes",
    },
    IRForwardingPolicy: {
        "name", "source_context", "source_rule_id", "source_order", "rulebase_position", "from_zone",
        "from_interface", "to", "source", "destination", "source_user", "application", "service", "schedule",
        "source_negated", "destination_negated", "action", "forward_to_vsys", "egress_interface", "next_hop_type",
        "next_hop", "next_vr", "monitor_profile", "monitor_ip", "monitor_enabled", "disable_if_unreachable",
        "enforce_symmetric_return", "symmetric_return", "enabled", "description", "migration_status",
        "requires_manual_review", "review_reasons", "source_attributes", "priority", "protocol", "destination_port",
        "routing_table", "table_next_hop", "table_output_interface",
    },
    IRVirtualFirewallContext: {
        "context_id", "context_type", "parent_context", "interfaces", "routing_instances", "administrators",
        "resource_limits", "mode", "vdom", "scope", "central_nat", "ngfw_mode", "opmode", "migration_status",
        "requires_manual_review", "source_attributes",
    },
    IRHighAvailability: {
        "source_uuid", "name", "cluster_type", "mode", "member_references", "member_names", "virtual_ips",
        "member_interface_ips", "sync_interfaces", "cluster_uid", "cluster_interfaces", "sync_network",
        "installation_targets", "topology", "ha_settings", "source_attributes", "migration_status",
        "requires_manual_review",
    },
}


@pytest.mark.parametrize("model, expected", list(CANONICAL_MODEL_FIELDS.items()))
def test_major_canonical_model_surfaces_are_explicit(model, expected):
    assert set(model.model_fields) == expected


def test_serialized_canonical_objects_do_not_carry_embedded_extensions():
    payload = json.loads(dump_ir_json(load_ir_payload({"metadata": _metadata()})))
    for value in payload.values():
        if not isinstance(value, list):
            continue
        for item in value:
            if isinstance(item, dict) and "vendor_extension" in item:
                assert item["vendor_extension"] is None


def test_major_canonical_models_have_no_known_vendor_leakage():
    fortios_only = {
        "vip_type", "port_mapping_type", "arp_reply", "gratuitous_arp_interval", "nat_source_vip",
        "nat44", "nat46", "nat64", "nat66", "add_nat46_route", "add_nat64_route", "ndp_reply",
        "ipv6_mapped_ip", "ipv6_mapped_port", "ipv4_mapped_ip", "ipv4_mapped_port",
        "embedded_ipv4_address", "server_type", "http_redirect", "h2_support", "h3_support",
        "http_multiplex", "ssl_mode", "ssl_algorithm", "ssl_min_version", "ssl_max_version",
        "ssl_server_algorithm", "ssl_server_min_version", "ssl_server_max_version", "ssl_pfs",
        "gslb_domain_name", "gslb_hostname", "max_embryonic_connections", "source_gslb_public_ips",
        "source_quic", "source_ssl_cipher_suites", "source_ssl_server_cipher_suites",
        "source_hw_model", "source_hw_vendor", "source_cache_ttl", "source_clearpass_spt",
        "source_epg_name", "source_organization", "source_os", "source_policy_group",
        "source_route_tag", "source_sdn", "source_sdn_addr_type", "source_sdn_tag",
        "source_node_ip_only", "source_obj_id", "source_sub_type", "source_obj_tag",
        "source_tag_type", "source_obj_type", "source_dirty", "source_subnet_name",
        "source_sw_version", "source_tag_detection_level", "source_tenant",
    }
    for model in CANONICAL_MODEL_FIELDS:
        fields = set(model.model_fields)
        assert not fields.intersection(fortios_only)
        assert not any(field.startswith(("pan_", "checkpoint_")) for field in fields)


def test_known_fortios_details_are_not_canonical_model_fields():
    expected = {
        "source_fsso_group", "source_fabric_object_setting", "source_template",
        "pba_timeout", "pba_interim_log", "cgn_block_size", "cgn_port_start",
        "source_vip_reference", "source_vip_group_reference", "source_policy_nat_ip",
        "source_effective_utm_status", "source_ztna_status",
    }
    models = (IRAddress, IRAddressGroup, IRSecurityPolicy, IRNATPool, IRNATRule)
    assert not expected.intersection(
        field for model in models for field in model.model_fields
    )


def test_transitional_roots_move_to_typed_extensions_and_dump_final_shape():
    ir = load_ir_payload({
        "schema_version": 2,
        "metadata": _metadata("palo_alto"),
        "pan_monitor_profiles": [{"name": "monitor"}],
        "addresses": [{
            "name": "host",
            "type": "host",
            "subnet": "192.0.2.10",
            "checkpoint_domain_uid": "domain-1",
        }],
    })

    assert ir.vendor_extensions.panos.pan_monitor_profiles[0].name == "monitor"
    assert ir.addresses[0].checkpoint_domain_uid == "domain-1"
    payload = json.loads(dump_ir_json(ir))
    assert "pan_monitor_profiles" not in payload
    assert "checkpoint_domain_uid" not in payload["addresses"][0]
    assert payload["addresses"][0]["vendor_extension"] is None
    assert payload["vendor_extensions"]["panos"]["pan_monitor_profiles"][0]["name"] == "monitor"
    assert payload["vendor_extensions"]["checkpoint"]["object_extensions"][0]["checkpoint_domain_uid"] == "domain-1"


def test_identical_old_and_final_extension_representations_are_accepted():
    ir = load_ir_payload({
        "schema_version": 2,
        "metadata": _metadata("palo_alto"),
        "pan_monitor_profiles": [{"name": "monitor"}],
        "vendor_extensions": {"panos": {"pan_monitor_profiles": [{"name": "monitor"}]}},
    })
    assert [item.name for item in ir.vendor_extensions.panos.pan_monitor_profiles] == ["monitor"]


def test_conflicting_old_and_final_extension_representations_fail_closed():
    with pytest.raises(IRSchemaError):
        load_ir_payload({
            "schema_version": 2,
            "metadata": _metadata("palo_alto"),
            "pan_monitor_profiles": [{"name": "old"}],
            "vendor_extensions": {"panos": {"pan_monitor_profiles": [{"name": "new"}]}},
        })


def test_typed_extension_rejects_unknown_fields():
    with pytest.raises(IRSchemaError):
        load_ir_payload({
            "schema_version": 2,
            "metadata": _metadata(),
            "vendor_extensions": {"fortios": {"not_a_real_extension": []}},
        })


def test_central_and_service_nat_are_not_emitted_as_canonical_types():
    central = load_ir_payload({
        "schema_version": 2,
        "metadata": _metadata(),
        "nat_rules": [{"name": "central", "type": "central"}],
    })
    assert central.nat_rules[0].type == NATType.SOURCE
    assert central.nat_rules[0].source_origin == "central-snat-map"

    service = load_ir_payload({
        "schema_version": 2,
        "metadata": _metadata("checkpoint"),
        "nat_rules": [{
            "name": "service-only",
            "type": "service",
            "services": ["HTTP"],
            "translated_services": ["HTTPS"],
        }],
    })
    assert service.nat_rules == []
    assert service.vendor_extensions.checkpoint.nat_rule_extensions[0].translation_type == "service"
    payload = json.loads(dump_ir_json(service))
    assert all(rule.get("type") != "service" for rule in payload["nat_rules"])


def test_final_v2_dump_load_is_stable():
    ir = IRConfig(metadata={"source_vendor": "fortigate"})
    first = dump_ir_json(ir)
    second = dump_ir_json(load_ir_payload(json.loads(first)))
    assert json.loads(first) == json.loads(second)


def test_ir_classes_are_not_patched_after_definition():
    source_root = Path(__file__).parents[1] / "src"
    violations = []
    for path in (source_root / "fwmigrate").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "setattr":
                if node.args and isinstance(node.args[0], ast.Name) and node.args[0].id.startswith("IR"):
                    violations.append(f"{path}:{node.lineno}: setattr")
            for target in getattr(node, "targets", []):
                if (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id.startswith("IR")
                ):
                    violations.append(f"{path}:{node.lineno}: class attribute assignment")
    assert not violations, "\n".join(violations)


def test_compatibility_setter_keeps_extension_identity():
    address = IRAddress(
        name="host",
        type=AddressType.SPECIAL,
        source_context="root",
        source_uuid="addr-1",
    )
    address.source_hw_model = "model"
    assert address.vendor_extension.canonical_name == "host"
    assert address.vendor_extension.source_context == "root"
    assert address.vendor_extension.source_uuid == "addr-1"
    assert address.vendor_extension.source_hw_model == "model"


def test_legacy_published_service_fields_move_to_fortios_extension():
    ir = load_ir_payload({
        "schema_version": 2,
        "metadata": _metadata(),
        "published_services": [{
            "name": "vip",
            "gslb_hostname": "vip.example.test",
            "h3_support": "enable",
            "nat64": True,
        }],
    })

    service = ir.published_services[0]
    extension = ir.vendor_extensions.fortios.published_service_extensions[0]
    assert isinstance(service.vendor_extension, IRFortiOSPublishedServiceExtension)
    assert service.gslb_hostname == extension.gslb_hostname == "vip.example.test"
    assert service.h3_support == extension.h3_support == "enable"
    assert service.nat64 is extension.nat64 is True
    assert {"gslb_hostname", "h3_support", "nat64"}.isdisjoint(type(service).model_fields)


def test_published_service_extension_round_trip_has_one_authoritative_copy():
    ir = load_ir_payload({
        "schema_version": 2,
        "metadata": _metadata(),
        "published_services": [{"name": "vip", "nat64": True}],
    })
    first = json.loads(dump_ir_json(ir))
    second = json.loads(dump_ir_json(load_ir_payload(first)))
    assert first == second
    assert first["published_services"][0]["vendor_extension"] is None
    assert first["vendor_extensions"]["fortios"]["published_service_extensions"][0]["nat64"] is True
    assert "nat64" not in first["published_services"][0]


def test_aggregate_published_service_extension_binds_compatibility_surface():
    ir = load_ir_payload({
        "schema_version": 2,
        "metadata": _metadata(),
        "published_services": [{"name": "vip"}],
        "vendor_extensions": {
            "fortios": {
                "published_service_extensions": [{
                    "canonical_name": "vip",
                    "nat64": True,
                }],
            },
        },
    })
    assert ir.published_services[0].nat64 is True
    payload = json.loads(dump_ir_json(ir))
    assert payload["published_services"][0]["vendor_extension"] is None
    assert payload["vendor_extensions"]["fortios"]["published_service_extensions"][0]["nat64"] is True


def test_conflicting_embedded_and_published_service_extensions_fail_closed():
    with pytest.raises(IRSchemaError):
        load_ir_payload({
            "schema_version": 2,
            "metadata": _metadata(),
            "published_services": [{"name": "vip", "nat64": True}],
            "vendor_extensions": {
                "fortios": {
                    "published_service_extensions": [{
                        "canonical_name": "vip",
                        "nat64": False,
                    }],
                },
            },
        })
