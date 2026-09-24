from pathlib import Path

from fwmigrate.vendors.checkpoint.derived import CheckPointDerivedViews, build_checkpoint_derived_views
from fwmigrate.vendors.checkpoint.model.address import CPHost
from fwmigrate.vendors.checkpoint.model.gaia import CPVTI, CPGaiaDHCPServer, CPGaiaStaticRoute
from fwmigrate.vendors.checkpoint.model.gateway import CPGateway, CPGatewayInterface
from fwmigrate.vendors.checkpoint.model.policy import CPAccessLayer, CPAccessRule, CPNATRule, CPPolicyPackage
from fwmigrate.vendors.checkpoint.model.source import CheckPointConfig
from fwmigrate.vendors.checkpoint.model.vpn import CPVPNCommunity
from fwmigrate.vendors.checkpoint.models import CheckPointCollectionDiagnostic, CollectionStatus, ScopeSelectionResult
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


def test_nat_rule_order_is_unique_within_package_scope():
    from fwmigrate.vendors.checkpoint.model.policy import CPNATRule
    from fwmigrate.vendors.checkpoint.validation.validator import _validate_nat
    config = CheckPointConfig(nat_rules=[
        CPNATRule(uid="n1", name="n1", package="P1", order=1),
        CPNATRule(uid="n2", name="n2", package="P2", order=1),
    ])
    assert not any(item.code == "nat_order_malformed" for item in _validate_nat(config, CheckPointDerivedViews()))
    config.nat_rules.append(CPNATRule(uid="n3", name="n3", package="P1", order=1))
    assert any(item.code == "nat_order_malformed" for item in _validate_nat(config, CheckPointDerivedViews()))


def test_shared_access_layer_is_valid_package_reuse_and_missing_layer_still_fails():
    layer = CPAccessLayer(uid="layer", name="Shared")
    shared = CheckPointConfig(policy_packages=[
        CPPolicyPackage(uid="p1", name="Package A", access_layers=["layer"]),
        CPPolicyPackage(uid="p2", name="Package B", access_layers=["layer"]),
    ], access_layers=[layer])
    before = shared.model_dump()
    derived = build_checkpoint_derived_views(shared)
    issues = validate_checkpoint_config(shared, derived).issues
    assert len(derived.policy_structure.package_layers) == 2
    assert all(relation.layer is layer for relation in derived.policy_structure.package_layers)
    assert "policy_duplicate_ownership" not in {issue.code for issue in issues}
    assert shared.model_dump() == before

    missing = CheckPointConfig(policy_packages=[CPPolicyPackage(uid="p3", name="Package C", access_layers=["absent"])])
    missing_derived = build_checkpoint_derived_views(missing)
    assert "package_layer_missing" in {issue.code for issue in validate_checkpoint_config(missing, missing_derived).issues}


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


def test_relationship_findings_reuse_derived_evidence_and_keep_expected_kinds():
    config = CheckPointConfig(
        policy_packages=[CPPolicyPackage(uid="pkg", name="pkg", access_layers=["layer"])],
        access_layers=[CPAccessLayer(uid="layer", name="layer")],
        access_rules=[CPAccessRule(uid="rule", name="rule", layer_uid="layer", source=["missing"], inline_layer="missing-layer")],
        nat_rules=[CPNATRule(uid="nat", name="nat", method="static", translated_source=["host"])],
        gateways=[CPGateway(uid="gw", name="gw", interfaces=[CPGatewayInterface(name="eth0", zone="missing-zone")])],
        vpn_communities=[CPVPNCommunity(uid="vpn", name="vpn", participating_gateways=["missing-gateway"])],
    )
    before = config.model_dump()
    derived = build_checkpoint_derived_views(config)
    derived_before = repr(derived)
    result = validate_checkpoint_config(config, derived)
    by_code = {issue.code: issue for issue in result.issues}
    assert by_code["reference_missing"].expected_kinds
    assert "inline_layer_missing" in by_code
    assert "nat_structure_incomplete" in by_code
    assert "zone_reference_missing" in by_code
    assert "vpn_member_missing" in by_code
    assert config.model_dump() == before
    assert repr(derived) == derived_before


def test_collection_and_dhcp_findings_preserve_operation_context():
    diagnostic = CheckPointCollectionDiagnostic(
        command="show-access-rulebase", source_plane="management", domain="Domain A",
        package="Package A", layer="Layer A", status=CollectionStatus.PERMISSION_DENIED,
        complete=False, error="denied",
    )
    config = CheckPointConfig(gaia_dhcp_servers=[CPGaiaDHCPServer(name="dhcp", subnets=[{
        "name": "subnet", "subnet": "192.0.2.0", "prefix": 24,
        "included_pools": [{"start": "192.0.2.20"}],
    }])])
    result = validate_checkpoint_config(config, CheckPointDerivedViews(), collection=(diagnostic,))
    collection_issue = next(issue for issue in result.issues if issue.code == "collection_incomplete")
    assert collection_issue.package == "Package A" and collection_issue.layer == "Layer A"
    assert any(issue.code == "gaia_dhcp_malformed" for issue in result.issues)


def test_collection_findings_deduplicate_only_when_full_source_scope_matches():
    def finding(command, package=None, layer=None):
        return CheckPointCollectionDiagnostic(
            command=command, source_plane="management", domain="Domain A", package=package,
            layer=layer, status=CollectionStatus.PERMISSION_DENIED, complete=False,
        )

    diagnostics = (finding("show-hosts"), finding("show-networks"),
                   finding("show-access-rulebase", "Package A", "Layer X"),
                   finding("show-access-rulebase", "Package B", "Layer Y"),
                   finding("show-hosts"),)
    issues = validate_checkpoint_config(CheckPointConfig(), CheckPointDerivedViews(), collection=diagnostics).issues
    collection = [issue for issue in issues if issue.code == "collection_incomplete"]

    assert len(collection) == 4
    assert {(issue.command, issue.package, issue.layer) for issue in collection} == {
        ("show-hosts", None, None), ("show-networks", None, None),
        ("show-access-rulebase", "Package A", "Layer X"),
        ("show-access-rulebase", "Package B", "Layer Y"),
    }


def test_vti_validation_checks_tunnel_constraints_and_unknown_owner():
    config = CheckPointConfig(vtis=[
        CPVTI(uid="good1", tunnel_id=1, tunnel_type="numbered", local_address="192.0.2.1",
              remote_address="192.0.2.2", peer="gateway"),
        CPVTI(uid="good99", tunnel_id=99, tunnel_type="unnumbered", peer="gateway", local_device="eth0"),
        CPVTI(uid="bad0", tunnel_id=0, tunnel_type="numbered", remote_address="192.0.2.2"),
        CPVTI(uid="bad100", tunnel_id=100, tunnel_type="bogus"),
    ])
    issues = validate_checkpoint_config(config, build_checkpoint_derived_views(config)).issues
    malformed = [issue for issue in issues if issue.code == "gaia_vti_malformed"]

    assert len(malformed) == 5
    assert sum(issue.code == "vti_gateway_unresolved" for issue in issues) == 4
