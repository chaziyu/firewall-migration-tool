from copy import deepcopy
from hashlib import sha256
from io import BytesIO
from pathlib import Path

from fwmigrate.vendors.palo_alto.native import build_derived_views, validate_panos_config
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config
from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter
from fwmigrate.vendors.palo_alto.source_model import pan_scope_identity


FIXTURE = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "all_targets_explicit.xml"


def test_all_target_fixture_has_explicit_native_policy_and_topology_evidence():
    source = FIXTURE.read_text(encoding="utf-8")
    analysis = PaloAltoSourceReporter().analyze_source(source)
    config = analysis.config

    assert config.source_version == "11.1.0"
    assert {item.name for item in config.interfaces} >= {"ethernet1/1", "ethernet1/2"}
    assert {item.name for item in config.zones} >= {"inside", "outside"}
    assert {item.name for item in config.addresses} >= {"inside-net", "app-server"}
    assert any(item.name == "inside-hosts" for item in config.address_groups)
    assert {item.name for item in config.services} >= {"tcp-range", "udp-range"}
    assert any(item.name == "approved-services" for item in config.service_groups)

    policies = {item.name: item for item in config.security_rules}
    assert list(policies).index("deny-app-before-allow") < list(policies).index("allow-inside-services")
    assert policies["deny-app-before-allow"].application == ["custom-business-app"]
    assert policies["deny-app-before-allow"].action == "deny"
    assert policies["disabled-predecessor"].disabled == "yes"
    assert policies["allow-inside-services"].service == ["approved-services"]
    unrestricted = policies["unrestricted-l3-l4"]
    assert unrestricted.from_zones == ["any"] and unrestricted.to_zones == ["any"]
    assert unrestricted.action == "allow" and unrestricted.disabled == "no"

    route = next(route for router in config.virtual_routers for route in router.static_routes or ())
    assert route.destination == "0.0.0.0/0"
    assert route.nexthop_ip_address == "198.51.100.254"
    assert route.nexthop_ip_address != "198.51.100.1"
    nat = next(item for item in config.nat_rules if item.name == "disabled-unsupported-nat")
    assert nat.disabled == "yes"
    assert "future-translation-mode" in nat.raw_extra

    assert not any(item.disabled != "yes" for item in config.nat_rules)
    assert analysis.validation is not None
    assert analysis.derived is not None


def test_source_contract_preserves_scope_order_missing_values_unknown_xml_and_redacts_secrets():
    source = """<config version='11.1.0'><shared>
      <address><entry name='same'><ip-netmask>192.0.2.1</ip-netmask></entry></address>
      <future-settings><api-key>never-export-this</api-key><mode>custom</mode></future-settings>
    </shared><devices>
      <entry name='fw-a'><vsys><entry name='vsys1'><address><entry name='same'><ip-netmask>198.51.100.1</ip-netmask></entry><entry name='malformed-address'><ip-range>10.0.0.9-10.0.0.1</ip-range></entry></address>
        <pre-rulebase><security><rules><entry name='before'><action>deny</action></entry></rules></security></pre-rulebase>
        <rulebase><security><rules><entry name='omitted-fields'/><entry name='malformed'><action>maybe</action></entry></rules></security></rulebase>
        <post-rulebase><security><rules><entry name='after'><action>allow</action></entry></rules></security></post-rulebase>
      </entry></vsys></entry>
      <entry name='fw-b'><vsys><entry name='vsys1'><address><entry name='same'><ip-netmask>203.0.113.1</ip-netmask></entry></address></entry></vsys></entry>
    </devices></config>"""
    config = build_panos_config(source)
    identities = {pan_scope_identity(scope) for scope in config.scopes if scope.kind == "vsys"}
    assert len(identities) == 2
    assert len({pan_scope_identity(item.scope) for item in config.addresses}) == 3
    assert {item.name: item.rulebase_position for item in config.security_rules} == {
        "before": "pre", "omitted-fields": "local", "malformed": "local", "after": "post"
    }
    assert config.security_rules[1].action is None
    assert config.security_rules[2].action == "maybe"
    assert "never-export-this" not in repr(config.model_dump())
    assert any("[REDACTED]" in item.raw_xml for item in config.source_inventory)
    assert any("future-settings" in item.source_path for item in config.source_inventory)

    derived = build_derived_views(config)
    validation = validate_panos_config(config, derived)
    assert any(issue.domain == "address" for issue in validation.errors)


def test_active_nat_variants_are_distinct_source_evidence():
    source = """<config><devices><entry name='fw'><vsys><entry name='vsys1'><rulebase><nat><rules>
      <entry name='active-snat'><source-translation><dynamic-ip-and-port><interface-address><interface>ethernet1/2</interface></interface-address></dynamic-ip-and-port></source-translation></entry>
      <entry name='active-dnat'><destination-translation><translated-address>10.0.0.20</translated-address><translated-port>8443</translated-port></destination-translation></entry>
    </rules></nat></rulebase></entry></vsys></entry></devices></config>"""
    config = build_panos_config(source)
    nat = {item.name: item for item in config.nat_rules}
    assert nat["active-snat"].disabled is None
    assert nat["active-snat"].source_translation is not None
    assert nat["active-dnat"].disabled is None
    assert nat["active-dnat"].destination_translation is not None


def test_analysis_does_not_mutate_source_model_and_preview_and_excel_work():
    source = FIXTURE.read_text(encoding="utf-8")
    reporter = PaloAltoSourceReporter()
    analysis = reporter.analyze_source(source)
    before = analysis.config.model_dump(mode="json")
    digest = sha256(repr(before).encode("utf-8")).hexdigest()

    preview = reporter.build_preview(analysis)
    output = BytesIO()
    reporter.export_excel(analysis, output)

    assert preview
    assert output.getvalue().startswith(b"PK")
    assert analysis.config.model_dump(mode="json") == before
    assert sha256(repr(analysis.config.model_dump(mode="json")).encode("utf-8")).hexdigest() == digest
