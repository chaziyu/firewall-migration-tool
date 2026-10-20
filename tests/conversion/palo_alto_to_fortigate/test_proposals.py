from copy import deepcopy
from dataclasses import replace
import re

import pytest

from fwmigrate.conversion.palo_alto_to_fortigate.application import approve_design, build_artifact, build_review, run_migration_pipeline
from fwmigrate.conversion.palo_alto_to_fortigate.design.proposals import build_target_proposals
from fwmigrate.conversion.palo_alto_to_fortigate.options import FGMigrationOptions
from fwmigrate.conversion.palo_alto_to_fortigate.planning.source_scope import identity
from fwmigrate.conversion.palo_alto_to_fortigate.target.evidence import build_target_evidence
from fwmigrate.source_reporting import source_reporters

from .conftest import SOURCE


def test_source_only_review_proposes_same_layout_without_claiming_hardware_or_approval(analysis):
    before = analysis.config.model_dump()
    review = build_review(analysis, {}, "source")
    resolved = review["resolved_options"]
    assert resolved["source_scope"].startswith("vsys:vsys1:")
    assert resolved["vdom"] == "root"
    assert resolved["profile"]["fortios_version"] == "7.4.6"
    assert resolved["zones"] == {"trust": "trust", "untrust": "untrust"}
    assert resolved["interfaces"] == {"ethernet1/1": "port1", "ethernet1/2": "port2"}
    assert resolved["profile"]["ports"] == ["port1", "port2"]
    assumed = [row for row in review["proposals"] if row["evidence_source"] == "ASSUMED_LAYOUT"]
    assert {row["key"] for row in assumed} == {"profile:ports", "interfaces:ethernet1/1", "interfaces:ethernet1/2"}
    assert all("unverified" in row["reason"] or "review target hardware" in row["reason"] for row in assumed)
    assert review["draft"]["context"]["requested_options"]["interfaces"] == {}
    assert "ports" not in review["draft"]["context"]["requested_options"]["profile"]
    assert review["draft"]["readiness"]["deployment"]["eligible"] is False
    assert any(row["family"] == "address" and not row["blocking_reasons"] for row in review["draft"]["configuration"])
    assert all(row["review_state"] == "PENDING" for row in review["proposals"])
    assert analysis.config.model_dump() == before


def test_same_layout_preserves_sparse_port_numbers(analyze):
    review = build_review(analyze(SOURCE.replace("ethernet1/2", "ethernet1/10")), {}, "source")
    assert review["resolved_options"]["interfaces"] == {"ethernet1/1": "port1", "ethernet1/10": "port10"}
    assert review["resolved_options"]["profile"]["ports"] == ["port1", "port10"]


def test_same_layout_preserves_vlan_parent_and_explicit_tag(analyze):
    units = '<units><entry name="ethernet1/1.201"><tag>201</tag><ip><entry name="10.201.0.1/24"/></ip></entry></units>'
    text = SOURCE.replace('10.0.0.1/24"/></ip>', '10.0.0.1/24"/></ip>' + units, 1)
    text = text.replace('<member>ethernet1/1</member>', '<member>ethernet1/1.201</member>')
    review = build_review(analyze(text), {}, "source")
    assert review["resolved_options"]["interfaces"]["ethernet1/1.201"] == "port1.201"
    items = {row["source_name"]: row for row in review["draft"]["configuration"] if row["family"] == "interface"}
    assert items["ethernet1/1"]["key"] in items["ethernet1/1.201"]["dependencies"]
    assert review["resolved_options"]["profile"]["ports"] == ["port1", "port2"]


def test_same_layout_preserves_engineer_overrides_without_reassigning_contested_ports(analysis):
    review = build_review(analysis, {"interfaces": {"ethernet1/1": "port2"}}, "source")
    assert review["resolved_options"]["interfaces"] == {"ethernet1/1": "port2"}
    assert review["resolved_options"]["profile"]["ports"] == ["port2"]
    assert all(row["blocking_reasons"] for row in review["draft"]["configuration"] if row["family"] == "policy")
    override = build_review(analysis, {"interfaces": {"ethernet1/1": "port5"}}, "source")
    assert override["resolved_options"]["interfaces"] == {"ethernet1/1": "port5", "ethernet1/2": "port2"}


def test_explicit_empty_port_list_disables_assumed_layout(analysis):
    review = build_review(analysis, {"profile": {"ports": []}}, "source")
    assert review["resolved_options"]["interfaces"] == {}
    assert review["resolved_options"]["profile"]["ports"] == []
    assert not any(row["evidence_source"] == "ASSUMED_LAYOUT" for row in review["proposals"])


@pytest.mark.parametrize("name", ["ethernet2/2", "ethernet1/0", "ethernet1/02", "ae1", "loopback.1"])
def test_same_layout_does_not_guess_nonmatching_names(analyze, name):
    review = build_review(analyze(SOURCE.replace("ethernet1/2", name)), {}, "source")
    assert name not in review["resolved_options"]["interfaces"]
    assert review["resolved_options"]["profile"]["ports"] == ["port1"]


def test_same_layout_assumptions_are_bound_to_signed_approval(analysis):
    review = build_review(analysis, {}, "source")
    policy = next(row for row in review["draft"]["configuration"] if row["family"] == "policy")
    approval = approve_design(review, review["draft"], [policy["key"]])
    artifact = build_artifact(analysis, {}, "source", approval)
    assert 'config firewall policy' in artifact["commands"]
    assert artifact["report"]["destination_verified"] is False
    assert any(row["evidence_source"] == "ASSUMED_LAYOUT" for row in artifact["report"]["target_proposals"])
    with pytest.raises(ValueError, match="context"):
        build_artifact(analysis, {"profile": {"ports": ["port1", "port2"]}}, "source", approval)


def test_declared_ports_unlock_supported_policy_and_signed_artifact(analysis):
    requested = {"profile": {"ports": ["port2", "port1"]}}
    before = deepcopy(requested)
    review = build_review(analysis, requested, "source")
    assert review == build_review(analysis, requested, "source")
    assert requested == before
    assert review["resolved_options"]["interfaces"] == {"ethernet1/1": "port1", "ethernet1/2": "port2"}
    policies = [r for r in review["draft"]["configuration"] if r["family"] == "policy"]
    assert not policies[0]["blocking_reasons"]
    approval = approve_design(review, review["draft"], [policies[0]["key"]])
    artifact = build_artifact(analysis, requested, "source", approval)
    assert 'config firewall policy' in artifact["commands"]
    assert artifact["design_approval"]["context"]["options"] == review["resolved_options"]
    assert artifact["design_approval"]["context"]["requested_options"] == FGMigrationOptions(**requested).to_dict()
    assert artifact["report"]["deployment_eligibility"]["eligible"] is False
    with pytest.raises(ValueError, match="context"):
        build_artifact(analysis, {"profile": {"ports": ["port3", "port4"]}}, "source", approval)


def test_engineer_mapping_takes_precedence_and_port_exhaustion_stays_blocked(analysis):
    requested = {"interfaces": {"ethernet1/1": "port5"}, "zones": {"trust": "inside"}, "profile": {"ports": ["port5"]}}
    review = build_review(analysis, requested, "source")
    assert review["resolved_options"]["interfaces"] == {"ethernet1/1": "port5"}
    assert review["resolved_options"]["zones"]["trust"] == "inside"
    assert all(r["blocking_reasons"] for r in review["draft"]["configuration"] if r["family"] == "policy")


def test_manual_appid_policy_has_no_ineffective_choices(analyze):
    text = re.sub(r"<(schedule|disabled|log-start|log-end|negate-source|negate-destination|rule-type|source-user|category)>.*?</\1>", "", SOURCE)
    analysis = analyze(text.replace('<application><member>any', '<application><member>ssl'))
    review = build_review(analysis, {}, "source")
    assert not any(row.get("policy_key") for row in review["requirements"]["decisions"])
    assert review["requirements"]["manual"][0]["source_name"] == "allow-web"
    assert all(row["render_disposition"] == "BLOCK" for row in review["draft"]["configuration"] if row["family"] == "policy")


def test_explicit_default_security_behavior_keeps_policies_manual_without_choice_noise(analyze):
    defaults = '<default-security-rules><rules><entry name="intrazone-default"><action>allow</action></entry></rules></default-security-rules>'
    text = SOURCE.replace('<disabled>no</disabled>', '').replace('</rulebase>', defaults + '</rulebase>')
    analysis = analyze(text)
    assert analysis.config.default_security_rules
    review = build_review(analysis, {"profile": {"ports": ["port1", "port2"]}}, "source")
    assert not any(row.get("policy_key") for row in review["requirements"]["decisions"])
    assert all(row["render_disposition"] == "BLOCK" for row in review["draft"]["configuration"] if row["family"] == "policy")


def test_multiple_source_routers_are_never_merged_into_vrf_zero(analyze):
    routers = '<virtual-router><entry name="one"><interface><member>ethernet1/1</member></interface></entry><entry name="two"><interface><member>ethernet1/2</member></interface></entry></virtual-router>'
    text = SOURCE.replace('</interface></network>', '</interface>' + routers + '</network>', 1)
    analysis = analyze(text)
    assert len(analysis.config.virtual_routers) == 2
    review = build_review(analysis, {"profile": {"ports": ["port1", "port2"]}}, "source")
    assert review["resolved_options"]["routers"] == {}


def test_only_unknown_policy_fields_need_choices_and_bulk_values_are_validated(analyze):
    text = re.sub(r"<(schedule|disabled|log-start|log-end|negate-source|negate-destination|rule-type|source-user|category)>.*?</\1>", "", SOURCE)
    analysis = analyze(text)
    review = build_review(analysis, {"profile": {"ports": ["port1", "port2"]}}, "source")
    rows = [r for r in review["requirements"]["decisions"] if r.get("policy_key")]
    assert {r["field"] for r in rows} == {"disabled", "negate_source", "negate_destination", "category"}
    policy = identity(analysis.config.security_rules[0], "policy")
    requested = {"profile": {"ports": ["port1", "port2"]}, "policy_settings": {policy: {"disabled": "no", "negate_source": "no", "negate_destination": "no", "category": "any"}}}
    resolved = build_review(analysis, requested, "source")
    assert not next(r for r in resolved["draft"]["configuration"] if r["family"] == "policy")["blocking_reasons"]
    for choices in ({"not-a-policy": {"disabled": "no"}}, {policy: {"disabled": "maybe"}}, {policy: {"log_end": "no"}}):
        with pytest.raises(ValueError):
            build_review(analysis, {**requested, "policy_settings": choices}, "source")


def test_explicit_policy_values_cannot_be_bulk_overridden(analysis):
    key = identity(analysis.config.security_rules[0], "policy")
    with pytest.raises(ValueError, match="override"):
        build_review(analysis, {"policy_settings": {key: {"disabled": "yes"}}}, "source")


def test_ambiguous_scope_and_managed_inheritance_are_not_selected(analyze):
    text = SOURCE.replace('</vsys>', '<entry name="vsys2"/></vsys>')
    review = build_review(analyze(text), {}, "source")
    assert not review["resolved_options"]["source_scope"]
    assert not review["report"]["command_count"]
    managed = SOURCE.replace('<devices>', '<template><entry name="managed"/></template><devices>')
    review = build_review(analyze(managed), {}, "source")
    assert not review["report"]["command_count"]


def test_zone_names_obey_limits_reserved_names_and_port_collisions(analysis):
    source = analysis.config.model_copy(deep=True)
    source.zones = [source.zones[0].model_copy(update={"name": name}) for name in ("port1", "any", "ALL", "invalid zone", "x" * 80)]
    options, _ = build_target_proposals(source, analysis.derived, {"profile": {"ports": ["port1"]}})
    names = list(options.zones.values())
    assert len(set(names)) == len(names)
    assert all(len(name) <= 35 and re.fullmatch(r"[A-Za-z0-9_.-]+", name) for name in names)
    assert not set(names) & {"port1", "any", "ALL"}


def test_vlan_proposal_uses_mapped_parent_and_keeps_parent_dependency(analyze):
    units = '<units><entry name="ethernet1/1.201"><tag>201</tag><ip><entry name="10.201.0.1/24"/></ip></entry></units>'
    text = SOURCE.replace('10.0.0.1/24"/></ip>', '10.0.0.1/24"/></ip>' + units, 1)
    text = text.replace('<member>ethernet1/1</member>', '<member>ethernet1/1</member><member>ethernet1/1.201</member>')
    review = build_review(analyze(text), {"profile": {"ports": ["port1", "port2"]}}, "source")
    assert review["resolved_options"]["interfaces"]["ethernet1/1.201"] == "port1.201"
    unit = next(row for row in review["draft"]["configuration"] if row["source_name"] == "ethernet1/1.201")
    parent = next(row for row in review["draft"]["configuration"] if row["source_name"] == "ethernet1/1")
    assert parent["key"] in unit["dependencies"]


def test_destination_modes_are_observed_and_conflicts_do_not_get_hidden(analysis):
    text = '''#config-version=FGT-7.4.8-FW-build0001-1
config system global
 set vdom-mode no-vdom
end
config system settings
 set opmode transparent
 set ngfw-mode profile-based
 set central-nat disable
end
'''
    target = source_reporters.get("fortigate").analyze_source(text)
    review = build_review(analysis, {}, "source", target=target, target_digest="target")
    assert review["resolved_options"]["profile"]["fortios_version"] == "7.4.8"
    assert review["resolved_options"]["profile"]["operating_mode"] == "transparent"
    assert review["resolved_options"]["profile"]["nat_mode"] == "policy"
    assert review["report"]["command_count"] == 0


def test_only_explicit_unused_destination_ports_are_proposed(analysis):
    from types import SimpleNamespace
    def port(name, ip, **extra):
        return SimpleNamespace(source_path="system interface", object_name=name, cli_scope="global", vdom="root",
                               values={"type": "physical", "vdom": "root", "ip": ip, **extra})
    records = [port("port1", "0.0.0.0 0.0.0.0"), port("port2", "192.0.2.1 255.255.255.0"), port("port3", "")]
    evidence = {"records": records, "version": "7.4.6", "duplicates": set(), "validation_errors": False}
    resolved, _ = build_target_proposals(analysis.config, analysis.derived, {"vdom": "root"}, evidence)
    assert resolved.profile["ports"] == ["port1"]
    referenced = SimpleNamespace(source_path="system zone", object_name="used", vdom="root", values={"interface": "port1"})
    resolved, _ = build_target_proposals(analysis.config, analysis.derived, {"vdom": "root"}, {**evidence, "records": [*records, referenced]})
    assert not resolved.profile.get("ports")


def test_effective_provenance_changes_invalidate_approval(analysis):
    requested = {"profile": {"ports": ["port1", "port2"]}}
    review = build_review(analysis, requested, "source")
    policy = next(r for r in review["draft"]["configuration"] if r["family"] == "policy")
    approval = approve_design(review, review["draft"], [policy["key"]])
    changed = replace(analysis, derived=replace(analysis.derived, effective_values=()))
    with pytest.raises(ValueError, match="context"):
        build_artifact(changed, requested, "source", approval)


def test_cli_pipeline_keeps_explicit_placement_requirement(analysis):
    _, rendered, _ = run_migration_pipeline(analysis)
    assert not rendered.commands


def test_native_target_evidence_still_blocks_unverified_absence(analysis):
    target = source_reporters.get("fortigate").analyze_source("config firewall address\nend\n")
    evidence = build_target_evidence(target, "target")
    assert not evidence["version"]
    review = build_review(analysis, {}, "source", target=target, target_digest="target")
    assert review["report"]["command_count"] == 0
