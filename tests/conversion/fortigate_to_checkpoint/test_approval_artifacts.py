import copy
import time

import pytest

from fwmigrate.conversion.fortigate_to_checkpoint.application import (
    approve_design, build_artifact, build_review, export_decisions,
    import_decisions, verify_export_artifact,
)


def test_dependency_closed_approval_binds_exact_split_files(checkpoint_analysis, checkpoint_source_text, checkpoint_options):
    import hashlib

    source_digest = hashlib.sha256(checkpoint_source_text.encode() + b"\0fortigate").hexdigest()
    review = build_review(checkpoint_analysis, checkpoint_options.to_dict(), source_digest)
    first_rule = next(item for item in review["plan"].items if item.family == "policy")
    approval = approve_design(review, review["draft"], [first_rule.key])
    assert first_rule.key in approval["selected_items"]
    assert set(first_rule.dependencies) <= set(approval["selected_items"])
    artifact = build_artifact(checkpoint_analysis, checkpoint_options.to_dict(), source_digest, approval)
    assert verify_export_artifact(artifact) is artifact
    assert artifact["files"]["checkpoint_management_operations.json"]["sha256"] == approval["file_sha256"]["checkpoint_management_operations.json"]
    assert artifact["report"]["destination_snapshot_compared"] is False
    assert artifact["deployment_available"] is False

    tampered = copy.deepcopy(artifact)
    tampered["files"]["gaia_config.clish"]["content"] += "save config\n"
    with pytest.raises(ValueError, match="integrity"):
        verify_export_artifact(tampered)


def test_changed_options_expired_approval_and_foreign_mapping_are_rejected(checkpoint_analysis, checkpoint_source_text, checkpoint_options):
    import hashlib

    source_digest = hashlib.sha256(checkpoint_source_text.encode() + b"\0fortigate").hexdigest()
    review = build_review(checkpoint_analysis, checkpoint_options.to_dict(), source_digest)
    item = next(item for item in review["plan"].items if item.family == "policy")
    approval = approve_design(review, review["draft"], [item.key])
    stale = dict(approval, expires_at=time.time() - 1)
    with pytest.raises(ValueError, match="approval"):
        build_artifact(checkpoint_analysis, checkpoint_options.to_dict(), source_digest, stale)
    changed = dict(checkpoint_options.to_dict(), management_domain="Other Domain")
    with pytest.raises(ValueError, match="approval"):
        build_artifact(checkpoint_analysis, changed, source_digest, approval)

    proposal = export_decisions(source_digest, checkpoint_options.to_dict())
    restored = import_decisions(proposal, source_digest)
    assert restored == checkpoint_options.to_dict()
    assert "approval" not in restored
    with pytest.raises(ValueError, match="different pair or source"):
        import_decisions(proposal, "different-source")
