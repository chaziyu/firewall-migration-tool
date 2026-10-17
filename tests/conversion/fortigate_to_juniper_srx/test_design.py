from pathlib import Path
import time

import pytest

from fwmigrate.conversion.fortigate_to_juniper_srx.application.workflow import (
    approve_design,
    build_artifact,
    build_review,
    export_decisions,
    import_decisions,
    verify_export_artifact,
)
from fwmigrate.conversion.fortigate_to_juniper_srx.design.deterministic import (
    validate_approval,
)
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


FIXTURE = Path(__file__).parents[2] / "fixtures" / "fortigate" / "multi_vendor_explicit.conf"


def _analysis(source=None):
    source = source or FIXTURE.read_text(encoding="utf-8")
    source = source.replace('set interface "lan" "app-vlan"', 'set interface "lan"', 1)
    return FortiGateSourceReporter().analyze_source(source)


def _options(complete_options):
    return {
        "source_vdom": complete_options.source_vdom,
        "target_context": complete_options.target_context,
        "target_version": complete_options.target_version,
        "target_mode": complete_options.target_mode,
        "routing_table": complete_options.routing_table,
        "timezone": complete_options.timezone,
        "interfaces": {vdom: {
            name: {"target_interface": mapping.target_interface, "unit": mapping.unit}
            for name, mapping in entries.items()
        } for vdom, entries in complete_options.interfaces.items()},
        "zones": complete_options.zones,
    }


def test_draft_identity_is_stable_and_binds_options(policy_analysis, complete_options):
    first = build_review(policy_analysis, _options(complete_options), "source-digest")
    second = build_review(policy_analysis, _options(complete_options), "source-digest")
    changed = _options(complete_options)
    changed["zones"] = {"root": {"inside": "another-inside", "outside": "outside-zone"}}
    third = build_review(policy_analysis, changed, "source-digest")

    assert first["draft"]["digest"] == second["draft"]["digest"]
    assert first["draft"]["digest"] != third["draft"]["digest"]
    assert "artifact_id" not in first["draft"]
    assert "created_at" not in first["draft"]


def test_approval_expands_dependencies_and_artifact_binds_exact_output(policy_analysis, complete_options):
    options = _options(complete_options)
    review = build_review(policy_analysis, options, "source-digest")
    policy = next(item for item in review["report"]["items"] if item["family"] == "policy" and item["source_name"] == "allow-app")

    approval = approve_design(review, review["draft"], [policy["key"]])
    assert set(policy["dependencies"]).issubset(set(approval["selected_items"]))
    artifact = build_artifact(policy_analysis, options, "source-digest", approval)
    verified = verify_export_artifact(artifact)
    assert verified["command_sha256"] == approval["command_sha256"]
    assert verified["command_count"] == approval["command_count"]
    assert verified["report"]["selected_items"] == approval["selected_items"]

    changed = dict(artifact)
    changed["command_text"] += "set system host-name unreviewed\n"
    with pytest.raises(ValueError, match="integrity"):
        verify_export_artifact(changed)


def test_stale_options_and_expired_approval_are_rejected(policy_analysis, complete_options):
    options = _options(complete_options)
    review = build_review(policy_analysis, options, "source-digest")
    selectable = [item["key"] for item in review["report"]["items"] if item["render_disposition"] == "CREATE"]
    approval = approve_design(review, review["draft"], selectable)

    changed = _options(complete_options)
    changed["timezone"] = "UTC"
    changed_review = build_review(policy_analysis, changed, "source-digest")
    with pytest.raises(ValueError, match="Draft changed"):
        approve_design(changed_review, review["draft"], selectable)

    expired = {**approval, "expires_at": time.time() - 1}
    with pytest.raises(ValueError, match="expired"):
        validate_approval(review["plan"], review["draft"], expired)


def test_blocked_nat_group_cannot_be_approved(complete_options):
    source = FIXTURE.read_text(encoding="utf-8").replace("set nat disable", "set nat enable", 1)
    analysis = _analysis(source)
    review = build_review(analysis, _options(complete_options), "source-digest")
    policy = next(item for item in review["report"]["items"] if item["family"] == "policy" and item["source_name"] == "allow-app")

    assert policy["approval_group"]
    with pytest.raises(ValueError, match="blocked"):
        approve_design(review, review["draft"], [policy["key"]])


def test_mapping_import_is_source_and_pair_bound_and_restores_proposals_only(policy_analysis, complete_options):
    options = _options(complete_options)
    document = export_decisions("source-digest", options)
    document["design_approval"] = {"signature": "ignored and never restored"}
    imported = import_decisions(document, "source-digest")
    assert imported["source_vdom"] == "root"
    assert "design_approval" not in imported

    with pytest.raises(ValueError, match="different pair, source or schema"):
        import_decisions({**document, "source_vendor": "palo_alto"}, "source-digest")


def test_expired_artifact_is_rejected(policy_analysis, complete_options):
    options = _options(complete_options)
    review = build_review(policy_analysis, options, "source-digest")
    selectable = [item["key"] for item in review["report"]["items"] if item["render_disposition"] == "CREATE"]
    approval = approve_design(review, review["draft"], selectable)
    artifact = build_artifact(policy_analysis, options, "source-digest", approval)
    with pytest.raises(ValueError, match="expired"):
        verify_export_artifact({**artifact, "expires_at": time.time() - 1})
