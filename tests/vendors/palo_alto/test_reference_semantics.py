from pathlib import Path

from fwmigrate.vendors.palo_alto.model.address import PANAddress, PANAddressGroup
from fwmigrate.vendors.palo_alto.model.globalprotect import PANGlobalProtectGateway, PANGlobalProtectGatewayClientAuth
from fwmigrate.vendors.palo_alto.model.interface import PANInterface, PANInterfaceUnit
from fwmigrate.vendors.palo_alto.model.identity import PANLocalUser, PANLocalUserGroup
from fwmigrate.vendors.palo_alto.model.nat import PANDestinationTranslation, PANDynamicDestinationTranslation, PANDynamicIPAndPortTranslation, PANNATRule
from fwmigrate.vendors.palo_alto.model.sdwan import PANSDWANInterfaceProfile, PANSDWANRule
from fwmigrate.vendors.palo_alto.model.service import PANService
from fwmigrate.vendors.palo_alto.model.source import PANOSConfig
from fwmigrate.vendors.palo_alto.model.tag import PANTag
from fwmigrate.vendors.palo_alto.model.zone import PANZone
from fwmigrate.vendors.palo_alto.relationships.references import resolve_references
from fwmigrate.vendors.palo_alto.source_model import PANScope
from fwmigrate.vendors.palo_alto.source_model import PANSourceRecord
from fwmigrate.vendors.palo_alto.model.security_profile import PANSecurityProfileGroup
from fwmigrate.vendors.palo_alto.validation.validator import validate_panos_config
from fwmigrate.vendors.palo_alto.native import build_derived_views
from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter


def test_reference_resolution_reports_missing_references_without_repairing_source():
    result = PaloAltoSourceReporter().analyze_source("""<config><shared><rulebase><security><rules>
      <entry name='missing-reference'><source><member>missing-x</member></source></entry>
    </rules></security></rulebase></shared></config>""")
    rule = result.config.security_rules[0]
    relationship = next(item for item in result.derived.reference_resolutions if item.reference_name == "missing-x")
    assert rule.source == ["missing-x"]
    assert relationship.status == "UNRESOLVED"
    assert any(item.severity == "error" and "missing-x" in item.message for item in result.validation.issues)
    assert result.config.addresses == []
    assert rule.source == ["missing-x"]


def test_source_only_target_is_reviewed_but_missing_target_is_error():
    shared = PANScope(kind="shared", name="shared")
    config = PANOSConfig(scopes=[shared], security_profile_groups=[PANSecurityProfileGroup(name="group", scope=shared, vulnerability=["visible", "missing"])],
                        source_inventory=[PANSourceRecord(kind="vulnerability", source_path="config/shared/profiles/vulnerability/entry", name="visible", scope=shared)])
    resolutions, _ = resolve_references(config)
    assert [(item.reference_name, item.status) for item in resolutions] == [("visible", "SOURCE_ONLY"), ("missing", "UNRESOLVED")]
    assert resolutions[0].resolution_reason.startswith("EXTRACTION_INCOMPLETE")
    derived = build_derived_views(config)
    issues = validate_panos_config(config, derived).issues
    assert any(item.severity == "warning" and "visible" in item.message for item in issues)
    assert any(item.severity == "error" and "missing" in item.message for item in issues)


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


def test_address_nat_sdwan_and_zone_references_are_in_relationships():
    scope = PANScope(kind="shared", name="shared")
    source = PANAddress(name="source-object", source_path="address", scope=scope)
    destination = PANAddress(name="destination-object", source_path="address-dest", scope=scope)
    profile = PANSDWANInterfaceProfile(name="wan-profile", scope=scope)
    address = PANAddress(name="tagged-address", source_path="address-tagged", scope=scope, tags=["tag-missing"])
    nat = PANNATRule(name="nat", source_path="nat", scope=scope,
                     source_translation=PANDynamicIPAndPortTranslation(translated_addresses=["source-object", "192.0.2.1"]),
                     destination_translation=PANDestinationTranslation(translated_address="destination-object"),
                     dynamic_destination_translation=PANDynamicDestinationTranslation(translated_addresses=["destination-object"]))
    interface = PANInterface(name="ethernet1/1", source_path="interface", scope=scope, sdwan_interface_profile="wan-profile")
    unit = PANInterfaceUnit(name="ethernet1/1.10", source_path="unit", scope=scope, sdwan_interface_profile="missing-profile")
    zone = PANZone(name="inside", source_path="zone", scope=scope, zone_protection_profile="protection")
    resolutions, _ = resolve_references(PANOSConfig(
        scopes=[scope], addresses=[source, destination, address], tags=[], nat_rules=[nat],
        interfaces=[interface], interface_units=[unit], sdwan_interface_profiles=[profile], zones=[zone],
    ))
    found = {(item.owner_family, item.owner_name, item.owner_field, item.reference_name): item for item in resolutions}
    assert found[("address", "tagged-address", "tags", "tag-missing")].status == "UNRESOLVED"
    assert found[("nat", "nat", "source_translation.translated_addresses", "source-object")].status == "RESOLVED"
    assert found[("nat", "nat", "source_translation.translated_addresses", "192.0.2.1")].status == "SOURCE_ONLY"
    assert found[("nat", "nat", "destination_translation.translated_address", "destination-object")].status == "RESOLVED"
    assert found[("nat", "nat", "dynamic_destination_translation.translated_addresses", "destination-object")].status == "RESOLVED"
    assert found[("interface", "ethernet1/1", "sdwan_interface_profile", "wan-profile")].status == "RESOLVED"
    assert found[("interface", "ethernet1/1.10", "sdwan_interface_profile", "missing-profile")].status == "UNRESOLVED"
    protection = found[("zone", "inside", "zone_protection_profile", "protection")]
    assert protection.status == "SOURCE_ONLY" and protection.expected_family == "zone-protection-profile"
