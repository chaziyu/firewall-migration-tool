import logging

import pytest

from fwmigrate.ir import IR_SCHEMA_VERSION
from fwmigrate.ir.core import IRConfig, IRMetadata
from fwmigrate.ir.errors import IRSchemaError, UnsupportedIRSchemaError
from fwmigrate.ir.io import dump_ir_json, load_ir_json, load_ir_payload
from fwmigrate.ir.version import (
    parse_schema_version,
    validate_supported_schema_version,
)


def _metadata(source_version=None):
    return IRMetadata(
        hostname="FW01",
        source_vendor="fortigate",
        source_version=source_version,
    )


def test_ir_config_defaults_to_current_schema_version():
    ir = IRConfig(metadata=_metadata(source_version="7.4.5"))

    assert IR_SCHEMA_VERSION == "1.16"
    assert ir.schema_version == IR_SCHEMA_VERSION
    assert ir.metadata.source_version == "7.4.5"


def test_explicit_current_version_serialization_and_deep_copy():
    ir = IRConfig(schema_version=IR_SCHEMA_VERSION, metadata=_metadata())

    assert ir.model_dump()["schema_version"] == IR_SCHEMA_VERSION
    assert f'"schema_version":"{IR_SCHEMA_VERSION}"' in (
        ir.model_dump_json().replace(" ", "")
    )
    assert dump_ir_json(ir) == ir.model_dump_json()
    assert ir.model_copy(deep=True).schema_version == ir.schema_version


@pytest.mark.parametrize(
    "value",
    ["abc", "1", "1.x", "v1", "1.0-beta", "", None, 1.0],
)
def test_malformed_schema_versions_are_rejected(value):
    with pytest.raises(IRSchemaError):
        parse_schema_version(value)
    with pytest.raises(IRSchemaError):
        load_ir_payload({
            "schema_version": value,
            "metadata": {"hostname": "FW", "source_vendor": "fortigate"},
        })


@pytest.mark.parametrize("value", ["0.9", "1.17", "2.0"])
def test_unsupported_schema_versions_are_rejected(value):
    with pytest.raises(UnsupportedIRSchemaError):
        validate_supported_schema_version(value)
    with pytest.raises(UnsupportedIRSchemaError):
        load_ir_payload({
            "schema_version": value,
            "metadata": {"hostname": "FW", "source_vendor": "fortigate"},
        })


def test_current_version_payload_and_json_load_successfully():
    payload = {
        "schema_version": IR_SCHEMA_VERSION,
        "metadata": {"hostname": "FW", "source_vendor": "fortigate"},
    }

    assert load_ir_payload(payload).schema_version == IR_SCHEMA_VERSION
    assert load_ir_json(dump_ir_json(load_ir_payload(payload))).metadata.hostname == "FW"


def test_unversioned_legacy_payload_uses_explicit_migration_and_warns(caplog):
    payload = {
        "metadata": {"hostname": "Legacy-FW", "source_vendor": "fortigate"},
        "routes": [],
    }

    with caplog.at_level(logging.WARNING, logger="fwmigrate.ir.migrations"):
        ir = load_ir_payload(payload)

    assert "schema_version" not in payload
    assert ir.schema_version == IR_SCHEMA_VERSION
    assert "Loaded unversioned legacy IR" in caplog.text


def test_schema_1_0_payload_adds_empty_phase2_inventory(caplog):
    payload = {
        "schema_version": "1.0",
        "metadata": {"hostname": "Legacy-FW", "source_vendor": "fortigate"},
    }

    with caplog.at_level(logging.WARNING, logger="fwmigrate.ir.migrations"):
        ir = load_ir_payload(payload)

    assert payload["schema_version"] == "1.0"
    assert ir.schema_version == IR_SCHEMA_VERSION
    assert ir.vpn_phase2 == []
    assert ir.fsso_providers == []
    assert ir.fsso_ad_groups == []
    assert "Loaded IR schema 1.0" in caplog.text


def test_schema_1_1_payload_adds_empty_fsso_inventory(caplog):
    payload = {
        "schema_version": "1.1",
        "metadata": {"hostname": "Legacy-FW", "source_vendor": "fortigate"},
    }

    with caplog.at_level(logging.WARNING, logger="fwmigrate.ir.migrations"):
        ir = load_ir_payload(payload)

    assert payload["schema_version"] == "1.1"
    assert ir.schema_version == IR_SCHEMA_VERSION
    assert ir.fsso_providers == []
    assert ir.fsso_ad_groups == []
    assert "Loaded IR schema 1.1" in caplog.text


def test_schema_1_2_payload_uses_explicit_additive_migration(caplog):
    payload = {
        "schema_version": "1.2",
        "metadata": {"hostname": "Legacy-FW", "source_vendor": "fortigate"},
    }

    with caplog.at_level(logging.WARNING, logger="fwmigrate.ir.migrations"):
        ir = load_ir_payload(payload)

    assert payload["schema_version"] == "1.2"
    assert ir.schema_version == IR_SCHEMA_VERSION
    assert "Loaded IR schema 1.2" in caplog.text


def test_schema_1_3_payload_uses_explicit_additive_migration(caplog):
    payload = {
        "schema_version": "1.3",
        "metadata": {"hostname": "Legacy-FW", "source_vendor": "fortigate"},
    }

    with caplog.at_level(logging.WARNING, logger="fwmigrate.ir.migrations"):
        ir = load_ir_payload(payload)

    assert payload["schema_version"] == "1.3"
    assert ir.schema_version == IR_SCHEMA_VERSION
    assert "Loaded IR schema 1.3" in caplog.text


def test_schema_1_4_payload_uses_explicit_additive_migration(caplog):
    payload = {
        "schema_version": "1.4",
        "metadata": {"hostname": "Legacy-FW", "source_vendor": "fortigate"},
    }

    with caplog.at_level(logging.WARNING, logger="fwmigrate.ir.migrations"):
        ir = load_ir_payload(payload)

    assert payload["schema_version"] == "1.4"
    assert ir.schema_version == IR_SCHEMA_VERSION
    assert "Loaded IR schema 1.4" in caplog.text


def test_schema_1_5_payload_adds_administrator_inventory(caplog):
    payload = {
        "schema_version": "1.5",
        "metadata": {"hostname": "Legacy-FW", "source_vendor": "fortigate"},
    }

    with caplog.at_level(logging.WARNING, logger="fwmigrate.ir.migrations"):
        ir = load_ir_payload(payload)

    assert payload["schema_version"] == "1.5"
    assert ir.schema_version == IR_SCHEMA_VERSION
    assert ir.administrators == []
    assert ir.admin_profiles == []
    assert ir.fortitokens == []
    assert "Loaded IR schema 1.5" in caplog.text


def test_schema_1_6_payload_adds_internet_service_source_attributes(caplog):
    payload = {
        "schema_version": "1.6",
        "metadata": {"hostname": "Legacy-FW", "source_vendor": "fortigate"},
        "internet_services": [
            {"name": "Google-Web", "source_id": 65537},
        ],
    }

    with caplog.at_level(logging.WARNING, logger="fwmigrate.ir.migrations"):
        ir = load_ir_payload(payload)

    assert payload["schema_version"] == "1.6"
    assert ir.schema_version == IR_SCHEMA_VERSION
    assert ir.internet_services[0].source_attributes == {}
    assert "Loaded IR schema 1.6" in caplog.text


def test_schema_1_8_route_zone_scalar_migrates_to_authoritative_list():
    ir = load_ir_payload({
        "schema_version": "1.8",
        "metadata": {"hostname": "Legacy-FW", "source_vendor": "fortigate"},
        "routes": [{
            "name": "legacy-route",
            "destination": "0.0.0.0/0",
            "sdwan_zone": "Internet",
        }],
    })

    assert ir.routes[0].sdwan_zone == "Internet"
    assert ir.routes[0].sdwan_zones == ["Internet"]


def test_schema_1_8_sdwan_health_check_scalar_migrates_to_list():
    ir = load_ir_payload({
        "schema_version": "1.8",
        "metadata": {"hostname": "Legacy-FW", "source_vendor": "fortigate"},
        "sdwan": {
            "rules": [{"source_id": 1, "health_check": "google"}],
        },
    })

    assert ir.sdwan is not None
    assert ir.sdwan.rules[0].health_check == "google"
    assert ir.sdwan.rules[0].health_checks == ["google"]
    assert ir.sdwan.rules[0].sla == []


def test_schema_1_10_adds_service_extraction_fidelity_defaults():
    payload = {
        "schema_version": "1.10",
        "metadata": {"hostname": "Legacy-FW", "source_vendor": "fortigate"},
        "services": [{
            "name": "HTTPS",
            "ports": [{"protocol": "tcp", "port": "443"}],
            "source_protocol": "tcp/udp/sctp",
        }],
        "service_groups": [{"name": "Web", "members": ["HTTPS"]}],
    }

    ir = load_ir_payload(payload)

    assert ir.schema_version == "1.16"
    assert ir.services[0].name == "HTTPS"
    assert ir.services[0].ports[0].port == "443"
    assert ir.services[0].source_protocol_configured is None
    assert ir.services[0].source_color is None
    assert ir.services[0].source_fabric_object is None
    assert ir.services[0].source_unmodeled_semantic_settings == []
    assert ir.service_groups[0].members == ["HTTPS"]
    assert ir.service_groups[0].unsafe_members == []


def test_schema_1_11_adds_ssl_vpn_fidelity_defaults_and_marks_phase2_for_review():
    payload = {
        "schema_version": "1.11",
        "metadata": {"hostname": "Legacy-FW", "source_vendor": "fortigate"},
        "vpn_phase2": [{
            "name": "legacy-phase2",
            "phase1_name": "legacy-phase1",
            "requires_manual_review": False,
        }],
        "ssl_vpn_portals": [{"name": "legacy-portal"}],
        "ssl_vpn_settings": {
            "authentication_rules": [{
                "source_id": 1,
                "groups": ["legacy-group"],
                "portal": "legacy-portal",
            }],
        },
    }

    ir = load_ir_payload(payload)

    assert ir.schema_version == "1.16"
    assert ir.vpn_phase2[0].requires_manual_review is True
    assert ir.ssl_vpn_host_checks == []
    portal = ir.ssl_vpn_portals[0]
    assert portal.host_check is None
    assert portal.host_check_policies == []
    assert portal.unresolved_host_check_policies == []
    assert ir.ssl_vpn_settings is not None
    assert ir.ssl_vpn_settings.server_certificate_configured is False
    assert ir.ssl_vpn_settings.dns_server1 is None
    rule = ir.ssl_vpn_settings.authentication_rules[0]
    assert rule.source_addresses == []
    assert rule.users == []
    assert rule.requires_manual_review is True


def test_non_object_serialized_ir_is_rejected():
    with pytest.raises(IRSchemaError):
        load_ir_json("[]")


def test_schema_1_12_migration_conservatively_blocks_identity_and_utm_policies():
    ir = load_ir_payload({
        "schema_version": "1.12",
        "metadata": {"hostname": "Legacy-FW", "source_vendor": "fortigate"},
        "policies": [{
            "name": "legacy-identity-policy",
            "from_zone": ["trust"],
            "to_zone": ["untrust"],
            "source": ["any"],
            "destination": ["any"],
            "service": ["any"],
            "action": "allow",
            "source_user_groups": ["LegacyGroup"],
            "ips_sensor": "LegacyIPS",
            "migration_status": "NORMALIZED",
            "requires_manual_review": False,
        }],
    })

    policy = ir.policies[0]
    assert ir.schema_version == "1.16"
    assert policy.migration_status == "PARTIALLY_NORMALIZED"
    assert policy.requires_manual_review is True
    assert policy.identity_dependency_review is True
    assert policy.security_profile_semantics_review is True


def test_schema_1_13_migration_adds_nat_and_policy_fields(caplog):
    payload = {
        "schema_version": "1.13",
        "metadata": {"hostname": "Legacy-FW", "source_vendor": "checkpoint"},
        "policies": [{
            "name": "legacy-policy",
            "from_zone": ["any"],
            "to_zone": ["any"],
            "source": ["any"],
            "destination": ["any"],
            "service": ["any"],
            "action": "allow",
        }],
        "nat_rules": [{
            "name": "legacy-nat",
            "type": "source",
            "from_zone": ["any"],
            "to_zone": ["any"],
            "source": ["any"],
            "destination": ["any"],
            "services": ["any"],
            "translated_sources": ["1.1.1.1"],
        }],
    }

    with caplog.at_level(logging.WARNING, logger="fwmigrate.ir.migrations"):
        ir = load_ir_payload(payload)

    assert ir.schema_version == "1.16"
    assert ir.policies[0].review_reasons == []
    assert ir.nat_rules[0].translated_services == []
    assert ir.nat_rules[0].source_attributes == {}
    assert "Loaded IR schema 1.13" in caplog.text


def test_schema_1_14_adds_zone_safety_defaults(caplog):
    payload = {
        "schema_version": "1.14",
        "metadata": {"hostname": "Legacy-FW", "source_vendor": "juniper_srx"},
        "zones": [
            {
                "name": "trust",
                "interfaces": ["ge-0/0/0.0"],
            }
        ],
    }

    with caplog.at_level(logging.WARNING, logger="fwmigrate.ir.migrations"):
        ir = load_ir_payload(payload)

    assert ir.schema_version == "1.16"
    zone = ir.zones[0]
    assert zone.disabled is None
    assert zone.requires_manual_review is False
    assert zone.migration_status == "NORMALIZED"
    assert zone.review_reasons == []
    assert zone.source_attributes == {}
    assert "Loaded IR schema 1.14" in caplog.text


def test_schema_1_15_adds_fortigate_context_and_source_only_collections(caplog):
    payload = {
        "schema_version": "1.15",
        "metadata": {"hostname": "Legacy-FW", "source_vendor": "fortigate"},
    }
    with caplog.at_level(logging.WARNING, logger="fwmigrate.ir.migrations"):
        ir = load_ir_payload(payload)

    assert ir.schema_version == "1.16"
    assert ir.execution_contexts == []
    assert ir.central_snat_rules == []
    assert ir.security_policies == []
    assert ir.policy_routes == []
    assert ir.dhcp6_servers == []
    assert ir.session_ttl_settings is None
    assert "Loaded IR schema 1.15" in caplog.text
