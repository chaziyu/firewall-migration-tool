from fwmigrate.conversion.fortigate_to_palo_alto.decisions import (
    PANDecisionReviewState,
    PANMigrationDecision,
    PANMigrationDecisionSet,
)
from fwmigrate.conversion.fortigate_to_palo_alto.target.target_evidence import (
    bind_legacy_target_evidence,
    reconcile_target_evidence,
    target_evidence_changed,
)


TARGET_A = {"vendor": "palo_alto", "config_digest": "digest-a", "device": "fw-a"}
TARGET_B = {"vendor": "palo_alto", "config_digest": "digest-b", "device": "fw-a"}
TARGET_OTHER_DEVICE = {"vendor": "palo_alto", "config_digest": "digest-a", "device": "fw-b"}


def _confirmed(*, evidence_type="AUTOMATION_VERIFIED", digest="digest-a", device="fw-a"):
    return PANMigrationDecision(
        "root", "interface", "wan", "target_interface",
        value="ethernet1/1",
        review_state=PANDecisionReviewState.CONFIRMED,
        evidence_source="DERIVED",
        evidence_type=evidence_type,
        target_object="ethernet1/1",
        evidence_target_digest=digest,
        evidence_target_device=device,
    )


def test_target_evidence_changed_compares_digest_device_and_removal():
    assert target_evidence_changed(TARGET_A, TARGET_A) is False
    assert target_evidence_changed(TARGET_A, TARGET_B) is True
    assert target_evidence_changed(TARGET_A, TARGET_OTHER_DEVICE) is True
    assert target_evidence_changed(TARGET_A, None) is True
    assert target_evidence_changed(None, TARGET_A) is False


def test_reconcile_preserves_matching_and_invalidates_changed_or_removed_target_evidence():
    decisions = PANMigrationDecisionSet((_confirmed(),))
    same, same_invalidated = reconcile_target_evidence(decisions, TARGET_A)
    assert same == decisions
    assert same_invalidated == ()

    for evidence in (TARGET_B, TARGET_OTHER_DEVICE, None):
        reconciled, invalidated = reconcile_target_evidence(decisions, evidence)
        decision = reconciled.decisions[0]
        assert decision.review_state is PANDecisionReviewState.PENDING
        assert decision.value is None
        assert decision.target_object is None
        assert decision.evidence_target_digest is None
        assert decision.evidence_target_device is None
        assert invalidated[0]["old_value"] == "ethernet1/1"
        assert invalidated[0]["previous_target_digest"] == "digest-a"


def test_reconcile_does_not_invalidate_engineer_or_source_only_confirmations():
    engineer = PANMigrationDecision(
        "root", "vdom", "root", "vsys",
        value="vsys1",
        review_state=PANDecisionReviewState.CONFIRMED,
        evidence_source="ENGINEER",
        evidence_type="TARGET_INTENT",
        target_object="vsys1",
    )
    source_only = PANMigrationDecision(
        "root", "interface", "lan", "target_zone",
        value="TRUST",
        review_state=PANDecisionReviewState.CONFIRMED,
        evidence_source="DERIVED",
        evidence_type="AUTOMATION_DERIVED",
        target_object="TRUST",
    )
    decisions = PANMigrationDecisionSet((engineer, source_only))
    reconciled, invalidated = reconcile_target_evidence(decisions, TARGET_B)
    assert reconciled == decisions
    assert invalidated == ()


def test_legacy_auto_confirmations_bind_to_document_target_but_engineer_intent_does_not():
    auto = PANMigrationDecision(
        "root", "interface", "wan", "target_interface",
        value="ethernet1/1",
        review_state=PANDecisionReviewState.CONFIRMED,
        evidence_source="DERIVED",
        evidence_type="AUTOMATION_VERIFIED",
    )
    intent = PANMigrationDecision(
        "root", "vdom", "root", "vsys",
        value="vsys1",
        review_state=PANDecisionReviewState.CONFIRMED,
        evidence_source="ENGINEER",
        evidence_type="TARGET_INTENT",
    )
    upgraded = bind_legacy_target_evidence(PANMigrationDecisionSet((auto, intent)), TARGET_A)
    by_type = {item.evidence_type: item for item in upgraded.decisions}
    assert by_type["AUTOMATION_VERIFIED"].evidence_target_digest == "digest-a"
    assert by_type["AUTOMATION_VERIFIED"].evidence_target_device == "fw-a"
    assert by_type["TARGET_INTENT"].evidence_target_digest is None
