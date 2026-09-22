from fwmigrate.vendors.palo_alto.model import PANAddress, PANOSConfig, PANService, PANServiceProtocol, PANSecurityRule
from fwmigrate.vendors.palo_alto.native import build_derived_views
from fwmigrate.vendors.palo_alto.validation import validate_panos_config


def _config(*items):
    return PANOSConfig(addresses=[item for item in items if isinstance(item, PANAddress)],
                       services=[item for item in items if isinstance(item, PANService)],
                       security_rules=[item for item in items if isinstance(item, PANSecurityRule)],
                       source_inventory=[])


def test_validation_reports_malformed_explicit_values_without_rewriting_source():
    address = PANAddress(name="bad", source_path="shared/address/bad", ip_range="10.0.0.9-10.0.0.1", explicit_fields={"ip_range"})
    service = PANService(name="bad-svc", source_path="shared/service/bad-svc",
                         tcp=PANServiceProtocol(port="0-70000"), explicit_fields={"tcp"})
    config = _config(address, service)
    before = config.model_dump(mode="json")

    result = validate_panos_config(config, build_derived_views(config))

    assert any(issue.domain == "address" for issue in result.errors)
    assert any(issue.domain == "service" for issue in result.errors)
    assert config.model_dump(mode="json") == before


def test_validation_distinguishes_missing_policy_fields_from_explicit_any():
    missing = PANSecurityRule(name="missing", source_path="rules/missing")
    explicit_any = PANSecurityRule(name="any", source_path="rules/any", action="allow", source=["any"],
                                   destination=["any"], from_zones=["any"], to_zones=["any"], explicit_fields={
                                       "action", "source", "destination", "from_zones", "to_zones"})

    result = validate_panos_config(_config(missing, explicit_any), build_derived_views(_config(missing, explicit_any)))

    assert any(issue.source_name == "missing" and issue.field == "action" for issue in result.errors)
    assert not any(issue.source_name == "any" and issue.domain == "policy" for issue in result.issues)
