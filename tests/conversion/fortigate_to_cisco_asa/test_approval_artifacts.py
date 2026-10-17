import pytest

from fwmigrate.conversion.fortigate_to_cisco_asa.application.workflow import (
    approve_design, build_artifact, build_review, verify_export_artifact,
)
from fwmigrate.conversion.fortigate_to_cisco_asa.planning.naming import item_key


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
