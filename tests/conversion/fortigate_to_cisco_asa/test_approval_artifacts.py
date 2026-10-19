import pytest
from copy import deepcopy

from fwmigrate.conversion.fortigate_to_cisco_asa.application.workflow import (
    approve_design, build_artifact, build_review, verify_export_artifact,
)
from fwmigrate.conversion.fortigate_to_cisco_asa.planning.naming import item_key


def test_artifact_report_marks_unselected_items(asa_source, asa_options):
    review = build_review(asa_source, asa_options, "source")
    selected = item_key("root", "address", "clients")
    approval = approve_design(review, review["draft"], [selected])
    artifact = build_artifact(asa_source, asa_options, "source", approval)
    for row in artifact["report"]["items"]:
        if row["key"] not in approval["selected_items"]:
            assert row["render_disposition"] in {"NOT_APPROVED", "BLOCK"}


def test_selected_reuse_is_satisfied_without_commands(asa_source, asa_options):
    from dataclasses import replace
    from fwmigrate.conversion.fortigate_to_cisco_asa.rendering.renderer import ASACLIRenderer

    review = build_review(asa_source, asa_options, "source")
    address = next(item for item in review["plan"].items if item.family == "address")
    plan = replace(review["plan"], items=(replace(address, target_disposition="REUSE"),))
    rendered = ASACLIRenderer().render(plan, approved_items={address.key})
    assert not rendered.commands
    assert rendered.report["plan_status"] == "READY_FOR_REVIEW"


@pytest.mark.parametrize("expiry", [None, True, "tomorrow", float("nan"), float("inf"), -1])
def test_export_rejects_invalid_expiry(asa_source, asa_options, expiry):
    review = build_review(asa_source, asa_options, "source")
    approval = approve_design(review, review["draft"], [item_key("root", "address", "clients")])
    artifact = deepcopy(build_artifact(asa_source, asa_options, "source", approval))
    artifact["expires_at"] = expiry
    artifact["design_approval"]["expires_at"] = expiry
    with pytest.raises(ValueError, match="expir"):
        verify_export_artifact(artifact)


def test_export_rejects_mismatched_expiry(asa_source, asa_options):
    review = build_review(asa_source, asa_options, "source")
    approval = approve_design(review, review["draft"], [item_key("root", "address", "clients")])
    artifact = build_artifact(asa_source, asa_options, "source", approval)
    artifact["expires_at"] += 1
    with pytest.raises(ValueError, match="expir"):
        verify_export_artifact(artifact)


def test_approval_expands_dependencies_and_binds_exact_asa_bytes(asa_source, asa_options):
    review = build_review(asa_source, asa_options.to_dict(), "source-digest")
    policy_key = item_key("root", "policy", "10")
    approval = approve_design(review, review["draft"], [policy_key])
    artifact = build_artifact(asa_source, asa_options.to_dict(), "source-digest", approval)
    assert artifact["command_count"] > 0
    assert artifact["command_sha256"] == artifact["report"]["command_sha256"]
    assert verify_export_artifact(artifact) is artifact
    assert not any(line.strip().casefold().startswith(("write memory", "changeto ", "commit"))
                   for line in artifact["commands"])


def test_changed_policy_invalidates_prior_approval(asa_source, asa_options):
    review = build_review(asa_source, asa_options.to_dict(), "source-digest")
    approval = approve_design(review, review["draft"], [item_key("root", "policy", "10")])
    asa_source.extracted.config.policies[0].dstaddr = ["clients"]
    with pytest.raises(ValueError, match="approval|bytes|changed"):
        build_artifact(asa_source, asa_options.to_dict(), "source-digest", approval)
