from pathlib import Path

from fwmigrate.vendors.checkpoint.derived import CheckPointDerivedViews
from fwmigrate.vendors.checkpoint.model.address import CPHost
from fwmigrate.vendors.checkpoint.model.gaia import CPGaiaStaticRoute
from fwmigrate.vendors.checkpoint.model.source import CheckPointConfig
from fwmigrate.vendors.checkpoint.models import ScopeSelectionResult
from fwmigrate.vendors.checkpoint.source_report import extract_checkpoint_source
from fwmigrate.vendors.checkpoint.validation import CheckPointValidationIndex, validate_checkpoint_config


def test_unknown_commands_and_permission_failures_are_validation_evidence():
    source = (Path(__file__).parents[2] / "fixtures" / "checkpoint" / "partial_collection.json").read_text()
    result = extract_checkpoint_source(source)
    assert result.validation.issues


def test_validation_is_scoped_and_does_not_mutate_source_or_derived():
    config = CheckPointConfig(
        hosts=[CPHost(uid="duplicate", name="host", domain="A"),
               CPHost(uid="duplicate", name="host", domain="A"),
               CPHost(uid="duplicate", name="host", domain="B")],
        gaia_static_routes=[CPGaiaStaticRoute(name="bad-route", address_family="ipv4", ipv6_destination="2001:db8::/64")],
    )
    derived = CheckPointDerivedViews()
    before, derived_before = config.model_dump(), repr(derived)
    result = validate_checkpoint_config(config, derived, scope=ScopeSelectionResult(ambiguous=True, reasons=["multiple-domains-without-selector"]))
    assert config.model_dump() == before
    assert repr(derived) == derived_before
    assert {item.code for item in result.issues} >= {"duplicate_uid", "duplicate_name", "scope_ambiguous", "gaia_route_malformed"}
    assert all(item.domain in {"A", None} for item in result.issues if item.code.startswith("duplicate_"))


def test_validation_index_queries_stable_issue_metadata():
    issue = validate_checkpoint_config(
        CheckPointConfig(hosts=[CPHost(uid="h1", name="host", domain="A"), CPHost(uid="h1", name="host2", domain="A")]),
        CheckPointDerivedViews(),
    ).issues[0]
    index = CheckPointValidationIndex((issue,))
    assert index.issues_for_uid("h1") == (issue,)
    assert index.issues_for_reference("h1") == (issue,)
    assert index.issues_for_category("duplicate") == (issue,)


def test_secret_finding_never_includes_material():
    secret = "phase7-secret-sentinel"
    config = CheckPointConfig(hosts=[CPHost(uid="h1", name="host", raw_extra={"authentication": {"password": secret}})])
    result = validate_checkpoint_config(config, CheckPointDerivedViews())
    findings = [item for item in result.issues if item.code == "secret_material_detected"]
    assert findings
    assert secret not in repr(findings)
    assert findings[0].field == "config.hosts[0].raw_extra.authentication.password"
    safe = CheckPointConfig(hosts=[CPHost(uid="h2", name="safe", password_configured=True)])
    assert not any(item.code == "secret_material_detected" for item in validate_checkpoint_config(safe, CheckPointDerivedViews()).issues)
