import json

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
    IRSchedule,
    IRScheduleGroup,
    IRSecurityPolicy,
    IRService,
    IRServiceGroup,
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
