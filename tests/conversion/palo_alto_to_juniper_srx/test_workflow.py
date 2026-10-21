from pathlib import Path

import pytest

from fwmigrate.conversion.palo_alto_to_juniper_srx.application import (
    approve_design, build_artifact, build_review, verify_export_artifact,
)
from fwmigrate.conversion.palo_alto_to_juniper_srx.options import SRXInterfaceMapping, SRXMigrationOptions
from fwmigrate.vendors.palo_alto.source_model import pan_scope_identity
from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter
from fwmigrate.vendors.juniper_srx.source_report import JuniperSRXSourceReporter


FIXTURE = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "all_targets_explicit.xml"


def _review():
    analysis = PaloAltoSourceReporter().analyze_source(FIXTURE.read_text(encoding="utf-8"))
    scope = next(row for row in analysis.config.scopes if row.kind == "vsys")
    options = SRXMigrationOptions(
        source_scope=pan_scope_identity(scope),
        interfaces={"ethernet1/1": SRXInterfaceMapping("ge-0/0/0"),
                    "ethernet1/2": SRXInterfaceMapping("ge-0/0/1")},
        zones={"inside": "inside", "outside": "outside"},
    )
    return analysis, options, build_review(analysis, options, "a" * 64)


def test_review_approval_and_artifact_bind_exact_source_and_commands():
    analysis, options, review = _review()
    selectable = [row.key for row in review["plan"].items
                  if row.family == "address" and not row.blockers]
    approval = approve_design(review, review["draft"], selectable)
    artifact = build_artifact(analysis, options, "a" * 64, approval)
    assert verify_export_artifact(artifact) is artifact
    assert artifact["report"]["deployment_available"] is False
    assert artifact["command_sha256"] == approval["command_sha256"]
    assert artifact["command_count"] == approval["command_count"]

    modified = dict(artifact, command_text=artifact["command_text"] + "set system host-name changed\n")
    with pytest.raises(ValueError, match="digest"):
        verify_export_artifact(modified)


def test_exact_address_reuse_is_bound_to_snapshot_and_emits_no_creation_command():
    analysis, options, _ = _review()
    planned = next(row for row in build_review(analysis, options, "a" * 64)["plan"].items
                   if row.family == "address" and not row.blockers)
    command = f"set security address-book global address {planned.target_name} {dict(planned.settings)['value']}"
    target_text = command + "\n"
    target = JuniperSRXSourceReporter().analyze_source(target_text)
    metadata = {"context": "root", "version": "25.2R1", "mode": "standalone",
                "complete_families": ["addresses"]}
    review = build_review(analysis, options, "a" * 64, target=target,
                          target_source_text=target_text, target_metadata=metadata)
    reused = next(row for row in review["plan"].items if row.key == planned.key)
    assert reused.target_disposition == "REUSE"
    approval = approve_design(review, review["draft"], [reused.key])
    artifact = build_artifact(analysis, options, "a" * 64, approval, target=target,
                              target_source_text=target_text, target_metadata=metadata)
    assert artifact["command_text"] == ""
    assert artifact["target_digest"] == review["target_evidence"].digest
    assert verify_export_artifact(artifact) is artifact


def test_target_comparison_requires_complete_family_and_matching_context():
    analysis, options, _ = _review()
    target_text = "set security address-book global address safe 192.0.2.1/32\n"
    target = JuniperSRXSourceReporter().analyze_source(target_text)
    metadata = {"context": "root", "version": "25.2R1", "mode": "standalone", "complete_families": []}
    review = build_review(analysis, options, "a" * 64, target=target,
                          target_source_text=target_text, target_metadata=metadata)
    address = next(row for row in review["plan"].items if row.family == "address")
    assert "addresses" not in review["report"]["destination_comparison"]["complete_families"]
    assert "TARGET_FAMILY_COMPLETENESS_UNCONFIRMED" in address.blockers
    conflict_text = f"set security address-book global address {address.target_name} 198.51.100.1/32\n"
    conflict_target = JuniperSRXSourceReporter().analyze_source(conflict_text)
    conflict = build_review(analysis, options, "a" * 64, target=conflict_target,
                            target_source_text=conflict_text,
                            target_metadata={**metadata, "complete_families": ["addresses"]})
    conflict_address = next(row for row in conflict["plan"].items if row.key == address.key)
    assert "TARGET_OBJECT_CONFLICT" in conflict_address.blockers
    bad = {**metadata, "context": "system"}
    blocked = build_review(analysis, options, "a" * 64, target=target,
                           target_source_text=target_text, target_metadata=bad)
    assert any("TARGET_CONTEXT_MISMATCH_OR_UNSUPPORTED" in row.blockers for row in blocked["plan"].items)
