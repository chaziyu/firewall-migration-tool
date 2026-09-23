from pathlib import Path

from fwmigrate.vendors.palo_alto.model.address import PANAddress, PANAddressGroup
from fwmigrate.vendors.palo_alto.model.globalprotect import PANGlobalProtectGateway, PANGlobalProtectGatewayClientAuth
from fwmigrate.vendors.palo_alto.model.identity import PANLocalUser, PANLocalUserGroup
from fwmigrate.vendors.palo_alto.model.sdwan import PANSDWANRule
from fwmigrate.vendors.palo_alto.model.service import PANService
from fwmigrate.vendors.palo_alto.model.source import PANOSConfig
from fwmigrate.vendors.palo_alto.model.tag import PANTag
from fwmigrate.vendors.palo_alto.model.zone import PANZone
from fwmigrate.vendors.palo_alto.relationships.references import resolve_references
from fwmigrate.vendors.palo_alto.source_model import PANScope
from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter


def test_reference_resolution_reports_missing_references_without_repairing_source():
    source = (Path(__file__).parents[2] / "fixtures" / "palo_alto" / "integrated_panorama.xml").read_text()
    result = PaloAltoSourceReporter().analyze_source(source)
    assert isinstance(result.derived.relationship_issues, tuple)
    assert result.config.source_inventory


def test_sdwan_local_user_and_globalprotect_reference_semantics():
    shared = PANScope(kind="shared", name="shared")
    rule_scope = PANScope(kind="device-group", name="child", parent_device_group="parent")
    parent = PANScope(kind="device-group", name="parent")
    rule = PANSDWANRule(
        name="sdwan-rule",
        scope=rule_scope,
        from_zones=["shared-zone"],
        to_zones=["missing-zone"],
        source=["shared-address"],
        destination=["ambiguous"],
        service=["shared-service"],
        tags=["shared-tag"],
        source_user=["domain-user"],
        application=["web-browsing"],
    )
    resolutions, _ = resolve_references(PANOSConfig(
        scopes=[shared, parent, rule_scope],
        zones=[PANZone(name="shared-zone", source_path="zone", scope=shared)],
        addresses=[PANAddress(name="shared-address", source_path="address", scope=shared), PANAddress(name="ambiguous", source_path="address", scope=shared)],
        address_groups=[PANAddressGroup(name="ambiguous", source_path="address-group", scope=shared)],
        services=[PANService(name="shared-service", source_path="service", scope=shared)],
        tags=[PANTag(name="shared-tag", scope=shared)],
        sdwan_rules=[rule],
        local_users=[PANLocalUser(name="local-user", scope=parent)],
        local_user_groups=[PANLocalUserGroup(name="local-group", scope=rule_scope, members=["local-user", "external-group"])],
        globalprotect_gateways=[PANGlobalProtectGateway(name="gateway", scope=rule_scope, certificate_profile="cert", ssl_tls_service_profile="tls", client_authentication=[PANGlobalProtectGatewayClientAuth(authentication_profile="auth")])],
    ))
    by_field = {(item.owner_field, item.reference_name): item for item in resolutions}
    assert by_field[("from_zones", "shared-zone")].status == "RESOLVED"
    assert by_field[("to_zones", "missing-zone")].status == "UNRESOLVED"
    assert by_field[("destination", "ambiguous")].status == "AMBIGUOUS"
    assert by_field[("source_user", "domain-user")].status == "SOURCE_ONLY"
    assert by_field[("application", "web-browsing")].status == "SOURCE_ONLY"
    assert by_field[("members", "local-user")].status == "RESOLVED"
    assert by_field[("members", "external-group")].status == "SOURCE_ONLY"
    assert by_field[("certificate_profile", "cert")].status == "SOURCE_ONLY"
    assert by_field[("ssl_tls_service_profile", "tls")].status == "SOURCE_ONLY"
    assert by_field[("client_authentication.authentication_profile", "auth")].status == "SOURCE_ONLY"
