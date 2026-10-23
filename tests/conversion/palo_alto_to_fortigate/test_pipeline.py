from copy import deepcopy
import hashlib

import pytest

from fwmigrate.conversion.palo_alto_to_fortigate import FGMigrationOptions, PaloAltoToFortiGatePlanner
from fwmigrate.conversion.palo_alto_to_fortigate.application import build_artifact, build_review, approve_design, import_decisions, export_decisions, run_migration_pipeline
from fwmigrate.conversion.palo_alto_to_fortigate.models import FGMigrationPlan, FGPlannedItem
from fwmigrate.conversion.palo_alto_to_fortigate.rendering.renderer import FGCLIRenderer
from fwmigrate.vendors.fortigate.parser import parse_fortigate_config

from .conftest import SOURCE


def test_real_pipeline_preserves_source_and_renders_scoped_cli(analysis, options):
    before = analysis.config.model_dump()
    plan, rendered, _ = run_migration_pipeline(analysis, options)
    assert analysis.config.model_dump() == before
    assert plan.items
    assert 'set subnet "10.0.0.0" "255.255.255.0"' in rendered.text
    assert 'set tcp-portrange "443:1024-65535"' in rendered.text
    assert 'set dstaddr "all"' in rendered.text
    assert 'set schedule "always"' in rendered.text
    assert 'set srcintf "inside"' in rendered.text
    assert 'set intrazone "deny"' in rendered.text
    parse_fortigate_config(rendered.text)
    assert rendered.report["command_sha256"] == hashlib.sha256(rendered.text.encode()).hexdigest()


def test_missing_scope_profile_and_mappings_produce_no_commands(analysis):
    _, rendered, _ = run_migration_pipeline(analysis)
    assert not rendered.commands
    assert rendered.report["plan_status"] == "PARTIAL"


def test_deterministic_approval_and_exact_artifact_binding(analysis, options):
    review = build_review(analysis, options, "source")
    selected = [row["key"] for row in review["draft"]["configuration"] if row["family"] == "policy"]
    assert selected
    assert not next(row for row in review["draft"]["configuration"] if row["family"] == "policy")["blocking_reasons"]
    approval = approve_design(review, review["draft"], selected)
    artifact = build_artifact(analysis, options, "source", approval)
    assert artifact["commands"]
    assert artifact["report"]["deployment_eligibility"]["eligible"] is False
    assert artifact["report"]["workflow_mode"] == "OFFLINE_EXPORT"
    assert artifact["report"]["verification"].startswith("Offline reviewed FortiOS export.")
    assert "Destination collisions" in artifact["report"]["verification"]
    assert len(approval["configuration"]) > 1
    with pytest.raises(ValueError, match="context"):
        build_artifact(analysis, {**options, "vdom": "other"}, "source", approval)
    with pytest.raises(ValueError, match="expired"):
        build_artifact(analysis, options, "source", {**approval, "expires_at": 0})


def test_unsupported_application_and_preceding_deny_cannot_be_omitted(analyze, options):
    first = SOURCE[SOURCE.index('<entry name="allow-web">'):SOURCE.index('</rules></security>')]
    first = first.replace('name="allow-web"', 'name="deny-app"').replace('<action>allow</action>', '<action>deny</action>').replace('<application><member>any', '<application><member>ssl')
    source = SOURCE.replace('<rules><entry name="allow-web">', '<rules>' + first + '<entry name="allow-web">')
    analysis = analyze(source)
    _, rendered, _ = run_migration_pipeline(analysis, options)
    policies = [r for r in rendered.report["items"] if r["family"] == "policy"]
    assert len(policies) == 2
    assert all(r["render_disposition"] == "BLOCK" for r in policies)
    assert any("Blocked dependency" in reason for reason in policies[1]["blocking_reasons"])
    assert "config firewall policy" not in rendered.text


def test_partial_approval_includes_every_preceding_rule(analyze, options):
    rule = SOURCE[SOURCE.index('<entry name="allow-web">'):SOURCE.index('</rules></security>')]
    source = SOURCE.replace('</rules></security>', rule.replace('name="allow-web"', 'name="second"') + '</rules></security>')
    analysis = analyze(source)
    from fwmigrate.conversion.palo_alto_to_fortigate.planning.source_scope import identity
    opts = deepcopy(options)
    opts["policy_settings"][identity(analysis.config.security_rules[1], "policy")] = {"schedule": "always"}
    review = build_review(analysis, opts, "source")
    policies = [r for r in review["draft"]["configuration"] if r["family"] == "policy"]
    approval = approve_design(review, review["draft"], [policies[1]["key"]])
    assert policies[0]["key"] in approval["configuration"]


@pytest.mark.parametrize("change", [
    lambda s: s.replace('<service><member>web</member></service>', '<service><member>application-default</member></service>'),
    lambda s: s.replace('<disabled>no</disabled>', ''),
    lambda s: s.replace('<source><member>clients</member></source>', ''),
    lambda s: s.replace('<action>allow</action>', '<action>reset-both</action>'),
    lambda s: s.replace('<action>allow</action>', '<action>deny</action>'),
    lambda s: s.replace('<log-start>no</log-start><log-end>yes</log-end>', '<log-start>yes</log-start><log-end>no</log-end>'),
    lambda s: s.replace('<ip-netmask>10.0.0.0/24</ip-netmask>', '<ip-netmask>bad</ip-netmask>'),
])
def test_unknown_or_unsupported_policy_inputs_never_render(analyze, options, change):
    _, rendered, _ = run_migration_pipeline(analyze(change(SOURCE)), options)
    assert "config firewall policy" not in rendered.text


def test_explicit_source_values_cannot_be_overridden(analysis, options):
    opts = deepcopy(options)
    key = next(iter(opts["policy_settings"]))
    opts["policy_settings"][key]["disabled"] = "yes"
    with pytest.raises(ValueError, match="override"):
        run_migration_pipeline(analysis, opts)


def test_managed_source_fails_closed(analysis, options):
    source = analysis.config.model_copy(deep=True)
    next(s for s in source.scopes if s.kind == "vsys").device_group = "managed"
    plan = PaloAltoToFortiGatePlanner().plan(source, analysis.derived, options)
    assert plan.findings
    assert all(i.disposition == "BLOCK" for i in plan.items)


def test_names_preserve_scopes_and_ambiguous_shadowing_stays_blocked(analyze, options):
    source = SOURCE.replace('<devices>', '<shared><address><entry name="net"><ip-netmask>172.16.0.0/16</ip-netmask></entry></address></shared><devices>')
    _, rendered, _ = run_migration_pipeline(analyze(source), options)
    addresses = [row for row in rendered.report["items"] if row["family"] == "address"]
    assert len({r["target_name"] for r in addresses}) == 2
    group = next(r for r in rendered.report["items"] if r["family"] == "address_group")
    assert group["render_disposition"] == "BLOCK"
    assert any("Unresolved" in reason for reason in group["blocking_reasons"])


def test_cycles_block_without_partial_rendering(analysis, options):
    item = FGPlannedItem("a", "address_group", "scope", "a", "a", "a", "root", "firewall addrgrp", (("member", ("a",)),), dependencies=("a",))
    rendered = FGCLIRenderer().render(FGMigrationPlan((item,)), FGMigrationOptions(**options))
    assert not rendered.commands


def test_control_characters_rejected_before_cli_output(analysis, options):
    opts = {**options, "vdom": "root\nend"}
    with pytest.raises(ValueError):
        run_migration_pipeline(analysis, opts)
    item = FGPlannedItem("x", "address", "scope", "x", "x", "x", "root", "firewall address", (("comment", ("bad\nend",)),))
    with pytest.raises(ValueError):
        FGCLIRenderer().render(FGMigrationPlan((item,)), FGMigrationOptions(**options))


def test_multi_vdom_cli_balances_global_and_vdom_context(analysis, options):
    opts = deepcopy(options)
    opts["profile"]["vdom_mode"] = "multi"
    _, rendered, _ = run_migration_pipeline(analysis, opts)
    assert "config global" in rendered.commands
    assert "config vdom" in rendered.commands
    parse_fortigate_config(rendered.text)


def test_decisions_are_pair_and_source_bound_proposals(analysis, options):
    document = export_decisions("source", options)
    document["design_approval"] = {"forged": True}
    assert import_decisions(document, "source") == FGMigrationOptions(**options).to_dict()
    for bad in ({**document, "source_vendor": "fortigate"}, {**document, "source_digest": "different"}, {**document, "format_version": 9}):
        with pytest.raises(ValueError):
            import_decisions(bad, "source")


def test_approval_cannot_drop_dependencies(analysis, options):
    review = build_review(analysis, options, "source")
    policy = next(r for r in review["draft"]["configuration"] if r["family"] == "policy")
    approval = approve_design(review, review["draft"], [policy["key"]])
    approval["configuration"] = {policy["key"]: approval["configuration"][policy["key"]]}
    with pytest.raises(ValueError, match="dependencies"):
        build_artifact(analysis, options, "source", approval)


def test_large_predecessor_chain_can_be_reviewed_and_rendered_without_recursion(options):
    from fwmigrate.conversion.palo_alto_to_fortigate.design.deterministic import approve_draft
    items = tuple(FGPlannedItem(str(i), "address_group", "scope", str(i), "path", str(i), "root", "firewall addrgrp",
                  (("member", (str(i - 1) if i else "all",)),), (str(i - 1),) if i else ()) for i in range(2500))
    rendered = FGCLIRenderer().render(FGMigrationPlan(items), FGMigrationOptions(**options))
    assert len(rendered.report['items']) == 2500
    approval = approve_draft({'context': {}, 'digest': 'draft', 'configuration': rendered.report['items']}, ['2499'])
    assert len(approval['configuration']) == 2500


def test_block_disposition_without_reasons_cannot_satisfy_dependency(options):
    blocked = FGPlannedItem('a', 'manual', 'scope', 'a', 'a', 'a', 'root', '', disposition='BLOCK')
    dependent = FGPlannedItem('b', 'address_group', 'scope', 'b', 'b', 'b', 'root', 'firewall addrgrp', (("member", ('a',)),), ('a',))
    rendered = FGCLIRenderer().render(FGMigrationPlan((blocked, dependent)), FGMigrationOptions(**options))
    assert not rendered.commands
