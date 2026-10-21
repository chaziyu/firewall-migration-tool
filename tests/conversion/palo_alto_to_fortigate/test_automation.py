from copy import deepcopy

import pytest

from fwmigrate.conversion.palo_alto_to_fortigate.application import run_migration_pipeline
from fwmigrate.conversion.palo_alto_to_fortigate.planning.source_scope import identity

from .conftest import SOURCE
from .test_fortios_semantics import NAT


@pytest.mark.parametrize("override,ready", [
    ("<no/>", True),
    ("<yes/>", False),
    ("", False),
    ("<no><timeout>60</timeout></no>", False),
    ("<no><future-setting>yes</future-setting></no>", False),
    ("<no/><future-setting>yes</future-setting>", False),
    ("<no/><yes/>", False),
    ("<no>unexpected</no>", False),
    ("<enabled>no</enabled>", False),
])
def test_service_override_requires_exact_explicit_inactive_state(analyze, options, override, ready):
    source = SOURCE.replace("</tcp>", f"<override>{override}</override></tcp>")
    analysis = analyze(source)
    before = analysis.config.model_dump(mode="json")
    _, rendered, _ = run_migration_pipeline(analysis, options)
    row = next(r for r in rendered.report["items"] if r["family"] == "service")
    assert (not row["blocking_reasons"]) is ready
    assert ("config firewall policy" in rendered.text) is ready
    assert analysis.config.model_dump(mode="json") == before


@pytest.mark.parametrize("before,after", [
    ("<protocol>", '<protocol future-control="yes">'),
    ("</protocol>", '<future-protocol><port>444</port></future-protocol></protocol>'),
    ("</tcp>", '<override future-control="yes"><no/></override></tcp>'),
    ("</tcp>", '<override><no/></override><override><yes><timeout>60</timeout></yes></override></tcp>'),
])
def test_unknown_service_container_evidence_is_preserved_and_blocks(analyze, options, before, after):
    analysis = analyze(SOURCE.replace(before, after))
    service = analysis.config.services[0]
    assert service.raw_extra or service.tcp.raw_extra or service.tcp.override.raw_extra
    _, rendered, _ = run_migration_pipeline(analysis, options)
    assert "config firewall service custom" not in rendered.text
    assert "config firewall policy" not in rendered.text


@pytest.mark.parametrize("attributes,ready", [
    ('uuid="d1aa9dbb-2e70-4780-9a69-c62e10d70752"', True),
    ('uuid="metadata" future-control="yes"', False),
])
def test_rule_uuid_and_unrestricted_hip_do_not_block_matching(analyze, options, attributes, ready):
    source = SOURCE.replace('<entry name="allow-web">', f'<entry name="allow-web" {attributes}>')
    source = source.replace("<action>allow</action>", "<group-tag>Operations</group-tag><source-hip><member>any</member></source-hip><destination-hip><member>any</member></destination-hip><action>allow</action>")
    analysis = analyze(source)
    before = analysis.config.model_dump(mode="json")
    _, rendered, _ = run_migration_pipeline(analysis, options)
    assert ("config firewall policy" in rendered.text) is ready
    assert analysis.config.model_dump(mode="json") == before


def test_restricted_hip_still_blocks(analyze, options):
    source = SOURCE.replace("<action>allow</action>", "<source-hip><member>managed-host</member></source-hip><action>allow</action>")
    _, rendered, _ = run_migration_pipeline(analyze(source), options)
    assert "config firewall policy" not in rendered.text
    assert any("Restricted source_hip" in reason for row in rendered.report["items"] for reason in row["blocking_reasons"])


@pytest.mark.parametrize("version,ready", [("11.1.0", True), ("11.1.13-h1", True), ("11.2.0", False), ("", False)])
def test_predefined_services_use_versioned_ports_and_approval_dependencies(analyze, options, version, ready):
    from fwmigrate.conversion.palo_alto_to_fortigate.application import approve_design, build_review

    group = '<service-group><entry name="web-group"><members><member>service-http</member><member>service-https</member></members></entry></service-group>'
    source = SOURCE.replace('version="11.1.0"', f'version="{version}"').replace('<zone>', group + '<zone>', 1)
    analysis = analyze(source)
    opts = deepcopy(options)
    opts["policy_settings"] = {identity(analysis.config.security_rules[0], "policy"): {"schedule": "always"}}
    before = analysis.config.model_dump(mode="json")
    plan, rendered, _ = run_migration_pipeline(analysis, opts)
    predefined = [i for i in plan.items if i.key.startswith("predefined-service:")]
    row = next(r for r in rendered.report["items"] if r["family"] == "service_group")
    assert (not row["blocking_reasons"]) is ready
    if ready:
        assert {i.target_name: dict(i.settings)["tcp-portrange"] for i in predefined} == {
            "service-http": ("80", "8080"), "service-https": ("443",)}
        assert all(i.source_scope == "predefined:PAN-OS:" + version for i in predefined)
        review = build_review(analysis, opts, "source")
        approval = approve_design(review, review["draft"], [row["key"]])
        assert {i.key for i in predefined} <= approval["configuration"].keys()
    else:
        assert not predefined
    assert analysis.config.model_dump(mode="json") == before
    assert len(analysis.config.services) == 1


def test_predefined_service_does_not_replace_explicit_custom_service(analyze, options):
    source = SOURCE.replace('name="web"', 'name="service-http"').replace('<member>web</member>', '<member>service-http</member>').replace('<port>443</port>', '<port>8081</port>')
    plan, rendered, _ = run_migration_pipeline(analyze(source), options)
    assert not any(i.key.startswith("predefined-service:") for i in plan.items)
    custom = next(i for i in plan.items if i.family == "service")
    assert dict(custom.settings)["tcp-portrange"] == ("8081:1024-65535",)
    assert "config firewall policy" in rendered.text


def test_ambiguous_predefined_name_cannot_bypass_custom_scope_resolution(analyze, options):
    source = SOURCE.replace('name="web"', 'name="service-http"').replace('<member>web</member>', '<member>service-http</member>')
    shared = '<shared><service><entry name="service-http"><protocol><tcp><port>8081</port></tcp></protocol></entry></service></shared>'
    source = source.replace('<devices>', shared + '<devices>')
    plan, rendered, _ = run_migration_pipeline(analyze(source), options)
    assert not any(i.key.startswith("predefined-service:") for i in plan.items)
    assert "config firewall policy" not in rendered.text


def test_ipv6_controls_survive_physical_and_vlan_extraction(analyze, options):
    ipv6 = '<ipv6><neighbor-discovery><router-advertisement><enable>yes</enable></router-advertisement></neighbor-discovery><address future-control="yes"/></ipv6>'
    source = SOURCE.replace('</ip></layer3>', '</ip>' + ipv6 + '<units><entry name="ethernet1/1.10"><tag>10</tag><ip><entry name="10.1.0.1/24"/></ip>' + ipv6 + '</entry></units></layer3>', 1)
    source = source.replace('<member>ethernet1/1</member>', '<member>ethernet1/1</member><member>ethernet1/1.10</member>', 1)
    analysis = analyze(source)
    expected = {"neighbor-discovery": {"router-advertisement": {"enable": "yes"}}, "address": {"@attributes": {"future-control": "yes"}}}
    assert analysis.config.interfaces[0].raw_extra["layer3"]["ipv6"] == expected
    assert analysis.config.interface_units[0].raw_extra["ipv6"] == expected
    opts = deepcopy(options)
    opts["interfaces"]["ethernet1/1.10"] = "port1.10"
    _, rendered, _ = run_migration_pipeline(analysis, opts)
    rows = [r for r in rendered.report["items"] if r["family"] == "interface" and r["source_name"] in {"ethernet1/1", "ethernet1/1.10"}]
    assert len(rows) == 2
    assert all(r["render_disposition"] == "BLOCK" for r in rows)


def test_ipv6_in_unsupported_interface_mode_retains_its_address_evidence(analyze):
    ipv6 = '<ipv6><address><entry name="2001:db8::1/64"/></address><future-control>yes</future-control></ipv6>'
    source = SOURCE.replace('<layer3><ip><entry name="10.0.0.1/24"/></ip></layer3>', '<layer2>' + ipv6 + '</layer2>')
    interface = analyze(source).config.interfaces[0]
    assert interface.ipv6_addresses is None
    assert interface.raw_extra["layer2"]["ipv6"] == {
        "address": {"entry": {"@attributes": {"name": "2001:db8::1/64"}}}, "future-control": "yes"}


@pytest.mark.parametrize("gateway,ready", [("192.0.2.1", False), ("192.0.2.254", True)])
def test_static_route_rejects_own_interface_gateway(analyze, options, gateway, ready):
    router = f'<virtual-router><entry name="vr"><interface><member>ethernet1/2</member></interface><routing-table><ip><static-route><entry name="default"><destination>0.0.0.0/0</destination><interface>ethernet1/2</interface><nexthop><ip-address>{gateway}</ip-address></nexthop><admin-dist>10</admin-dist></entry></static-route></ip></routing-table></entry></virtual-router>'
    source = SOURCE.replace('</interface></network>', '</interface>' + router + '</network>', 1)
    source = source.replace('</interface></network></import>', '</interface><virtual-router><member>vr</member></virtual-router></network></import>')
    _, rendered, _ = run_migration_pipeline(analyze(source), {**options, "routers": {"vr": 0}})
    assert ("config router static" in rendered.text) is ready
    if not ready:
        assert any("own address" in reason for row in rendered.report["items"] for reason in row["blocking_reasons"])


@pytest.mark.parametrize("state,ready", [("<disabled>yes</disabled>", True), ("<disabled>no</disabled>", False), ("", False)])
def test_only_explicitly_disabled_nat_is_excluded_from_traffic_dependencies(analyze, options, state, ready):
    nat = '<nat><rules><entry name="unsupported-nat">' + state + '<source-translation><static-ip><translated-address>203.0.113.10</translated-address><bi-directional>yes</bi-directional></static-ip></source-translation></entry></rules></nat>'
    analysis = analyze(SOURCE.replace('</rulebase>', nat + '</rulebase>'))
    before = analysis.config.model_dump(mode="json")
    plan, rendered, _ = run_migration_pipeline(analysis, options)
    assert ("config firewall policy" in rendered.text) is ready
    assert not any(i.section for i in plan.items if i.family == "inactive_nat")
    assert any(row["source_name"] == "unsupported-nat" and row["render_disposition"] == "BLOCK" for row in rendered.report["items"])
    assert analysis.config.model_dump(mode="json") == before


def test_disabled_nat_does_not_break_active_snat_independence(analyze, options):
    nat = NAT.replace('</rules>', '<entry name="inactive"><disabled>yes</disabled></entry></rules>')
    _, rendered, _ = run_migration_pipeline(analyze(SOURCE.replace('</rulebase>', nat + '</rulebase>')), options)
    assert "config firewall central-snat-map" in rendered.text
    assert "config firewall policy" in rendered.text
    inactive = next(r for r in rendered.report["items"] if r["family"] == "inactive_nat")
    assert not inactive["settings"] and inactive["render_disposition"] == "BLOCK"


def test_inactive_nat_cannot_be_approved_or_become_an_active_dependency(analyze, options):
    from fwmigrate.conversion.palo_alto_to_fortigate.application import approve_design, build_review

    nat = NAT.replace('<disabled>no</disabled>', '<disabled>yes</disabled>')
    analysis = analyze(SOURCE.replace('</rulebase>', nat + '</rulebase>'))
    review = build_review(analysis, options, "source")
    inactive = next(r for r in review["draft"]["configuration"] if r["family"] == "inactive_nat")
    policy = next(r for r in review["draft"]["configuration"] if r["family"] == "policy")
    approval = approve_design(review, review["draft"], [policy["key"]])
    assert inactive["key"] not in approval["configuration"]
    with pytest.raises(ValueError):
        approve_design(review, review["draft"], [inactive["key"]])


@pytest.mark.parametrize("first_supported", [False, True])
def test_disabled_policy_does_not_sever_active_predecessor_chain(analyze, options, first_supported):
    first = SOURCE[SOURCE.index('<entry name="allow-web">'):SOURCE.index('</rules></security>')]
    inactive = first.replace('name="allow-web"', 'name="inactive"').replace('<disabled>no', '<disabled>yes').replace('<member>any</member></application>', '<member>unknown-app</member></application>')
    second = first.replace('name="allow-web"', 'name="second"')
    source = SOURCE.replace('</rules></security>', inactive + second + '</rules></security>')
    if not first_supported:
        source = source.replace('<member>any</member></application>', '<member>unsupported-app</member></application>', 1)
    analysis = analyze(source)
    opts = deepcopy(options)
    for rule in analysis.config.security_rules:
        opts["policy_settings"][identity(rule, "policy")] = {"schedule": "always"}
    plan, rendered, _ = run_migration_pipeline(analysis, opts)
    policies = [i for i in plan.items if i.family == "policy"]
    assert policies[0].key in policies[2].dependencies
    assert policies[1].key not in policies[2].dependencies
    rows = [r for r in rendered.report["items"] if r["family"] == "policy"]
    assert (not rows[2]["blocking_reasons"]) is first_supported
