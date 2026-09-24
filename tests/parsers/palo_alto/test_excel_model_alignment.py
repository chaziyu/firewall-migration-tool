from fwmigrate.vendors.palo_alto.export.excel_schema import SHEET_HEADERS, SHEET_ORDER
from fwmigrate.vendors.palo_alto.model import (
    PANAdministrator,
    PANAdminRole,
    PANDHCPServer,
    PANDestinationTranslation,
    PANDynamicIPTranslation,
    PANGlobalProtectGateway,
    PANGlobalProtectPortal,
    PANGroupMapping,
    PANIKEGateway,
    PANIPsecTunnel,
    PANLocalUser,
    PANNATRule,
    PANRoutePathMonitor,
    PANStaticRoute,
    PANInterface,
    PANSDWANInterfaceProfile,
    PANSDWANRule,
    PANSecurityProfileGroup,
    PANVulnerabilityProfile,
    PANZone,
)
from fwmigrate.vendors.palo_alto.model.source import PANOSConfig


def test_excel_schema_order_and_headers_have_the_same_unique_sheets():
    assert len(SHEET_ORDER) == len(set(SHEET_ORDER))
    assert set(SHEET_ORDER) == set(SHEET_HEADERS)


def test_source_model_has_native_roots_for_excel_domain_sheets():
    expected = {
        "tags",
        "addresses",
        "address_groups",
        "services",
        "service_groups",
        "schedules",
        "security_rules",
        "nat_rules",
        "vulnerability_profiles",
        "security_profile_groups",
        "interfaces",
        "zones",
        "virtual_routers",
        "logical_routers",
        "dhcp_servers",
        "sdwan_interface_profiles",
        "sdwan_path_quality_profiles",
        "sdwan_traffic_distribution_profiles",
        "sdwan_saas_quality_profiles",
        "sdwan_error_correction_profiles",
        "sdwan_rules",
        "local_users",
        "local_user_groups",
        "group_mappings",
        "administrators",
        "admin_roles",
        "ike_gateways",
        "ike_crypto_profiles",
        "ipsec_crypto_profiles",
        "ipsec_tunnels",
        "globalprotect_portals",
        "globalprotect_gateways",
    }

    assert expected <= PANOSConfig.model_fields.keys()


def test_nested_source_models_cover_excel_detail_sheets_without_report_fields():
    assert {"rules", "exceptions"} <= PANVulnerabilityProfile.model_fields.keys()
    assert {"permissions", "role_scope"} <= PANAdminRole.model_fields.keys()
    assert {"ip_pools", "reservations", "options"} <= PANDHCPServer.model_fields.keys()
    assert {"client_configs", "clientless_vpn"} <= PANGlobalProtectPortal.model_fields.keys()
    assert {"client_authentication", "remote_user_tunnels"} <= PANGlobalProtectGateway.model_fields.keys()
    assert "proxy_ids" in PANIPsecTunnel.model_fields
    assert "targets" in PANRoutePathMonitor.model_fields

    for model in (
        PANAdministrator,
        PANGlobalProtectGateway,
        PANGroupMapping,
        PANIKEGateway,
        PANLocalUser,
        PANSDWANInterfaceProfile,
        PANSDWANRule,
        PANSecurityProfileGroup,
        PANZone,
    ):
        assert {"raw_extra", "explicit_fields"} <= model.model_fields.keys()
        assert "analysis_status" not in model.model_fields
        assert "review_reasons" not in model.model_fields


def test_existing_models_cover_excel_fields_that_were_previously_raw_only():
    assert {
        "nat_type",
        "to_interface",
        "tags",
        "description",
        "source_translation",
        "destination_translation",
        "dynamic_destination_translation",
    } <= PANNATRule.model_fields.keys()
    assert {
        "sdwan_enabled",
        "ipv6_sdwan_enabled",
        "sdwan_interface_profile",
        "upstream_nat",
    } <= PANInterface.model_fields.keys()
    assert {
        "address_family",
        "nexthop_type",
        "admin_distance",
        "route_table",
        "bfd_profile",
        "path_monitor",
    } <= PANStaticRoute.model_fields.keys()
    assert {"translation_type", "fallback"} <= PANDynamicIPTranslation.model_fields.keys()
    assert "dns_rewrite" in PANDestinationTranslation.model_fields


def test_secret_models_store_presence_metadata_not_secret_values():
    assert "password_configured" in PANAdministrator.model_fields
    assert "password_configured" in PANLocalUser.model_fields
    assert "pre_shared_key_configured" in PANIKEGateway.model_fields
    assert "manual_key_configured" in PANIPsecTunnel.model_fields

    forbidden = {"password", "phash", "pre_shared_key", "private_key"}
    for model in (PANAdministrator, PANLocalUser, PANIKEGateway, PANIPsecTunnel):
        assert forbidden.isdisjoint(model.model_fields)
