"""Pair-specific PAN-OS target-evidence provenance for migration decisions."""

from dataclasses import replace

from fwmigrate.conversion.fortigate_to_palo_alto.decisions import PANDecisionReviewState, PANMigrationDecisionSet


_LEGACY_TARGET_BOUND_EVIDENCE_TYPES = frozenset({
    "AUTOMATION_VERIFIED",
    "AUTOMATION_DERIVED",
    "APPROVED_AUTO_REVIEW",
    "ENGINEER_TARGET_SUGGESTION",
})


def target_evidence_identity(evidence):
    """Return the durable PAN-OS target identity used by migration evidence."""
    if evidence is None:
        return None
    if not isinstance(evidence, dict):
        raise ValueError("target evidence must be an object or null")
    vendor = evidence.get("vendor")
    if vendor not in {None, "palo_alto"}:
        raise ValueError("target evidence must describe Palo Alto PAN-OS")
    digest = evidence.get("config_digest")
    device = evidence.get("device")
    if not isinstance(digest, str) or not digest:
        raise ValueError("target evidence requires a non-empty config_digest")
    if device is not None and (not isinstance(device, str) or not device):
        raise ValueError("target evidence device must be a non-empty string or null")
    return digest, device


def target_evidence_changed(previous, current):
    """Return whether previously selected PAN-OS evidence no longer matches."""
    previous_identity = target_evidence_identity(previous) if previous else None
    current_identity = target_evidence_identity(current) if current else None
    return previous_identity is not None and previous_identity != current_identity


def bind_legacy_target_evidence(decisions: PANMigrationDecisionSet, target_evidence=None):
    """Bind legacy auto confirmations to the document-level target identity.

    Formats prior to v3 had document-level target evidence but no per-decision
    binding. Only known auto/approved-auto evidence types are upgraded.
    """
    identity = target_evidence_identity(target_evidence) if target_evidence else None
    if identity is None or identity[1] is None:
        return decisions
    digest, device = identity
    updated = []
    changed = False
    for decision in decisions.decisions:
        if (
            decision.review_state is PANDecisionReviewState.CONFIRMED
            and decision.evidence_type in _LEGACY_TARGET_BOUND_EVIDENCE_TYPES
            and not decision.evidence_target_digest
            and not decision.evidence_target_device
        ):
            decision = replace(
                decision,
                evidence_target_digest=digest,
                evidence_target_device=device,
            )
            changed = True
        updated.append(decision)
    if not changed:
        return decisions
    return PANMigrationDecisionSet(tuple(updated))


def _invalidation_reason(previous_identity, current_identity):
    if current_identity is None:
        return "Target evidence used by this confirmation is no longer available."
    previous_digest, previous_device = previous_identity
    current_digest, current_device = current_identity
    if previous_digest != current_digest:
        return "PAN-OS target configuration evidence changed."
    if previous_device != current_device:
        return "Selected PAN-OS target device changed."
    return "PAN-OS target evidence changed."


def reconcile_target_evidence(decisions: PANMigrationDecisionSet, current_evidence=None):
    """Invalidate only confirmations explicitly bound to stale PAN-OS evidence."""
    current_identity = target_evidence_identity(current_evidence) if current_evidence else None
    updated = []
    invalidated = []
    for decision in decisions.decisions:
        if (
            decision.review_state is not PANDecisionReviewState.CONFIRMED
            or not decision.evidence_target_digest
            or not decision.evidence_target_device
        ):
            updated.append(decision)
            continue

        previous_identity = (
            decision.evidence_target_digest,
            decision.evidence_target_device,
        )
        if previous_identity == current_identity:
            updated.append(decision)
            continue

        reason = _invalidation_reason(previous_identity, current_identity)
        invalidated.append({
            "decision_key": decision.key,
            "source_vdom": decision.source_vdom,
            "source_kind": decision.source_kind,
            "source_name": decision.source_name,
            "target_field": decision.target_field,
            "old_value": decision.value,
            "reason": reason,
            "previous_target_digest": decision.evidence_target_digest,
            "previous_target_device": decision.evidence_target_device,
        })
        updated.append(replace(
            decision,
            value=None,
            review_state=PANDecisionReviewState.PENDING,
            evidence_source=None,
            evidence_type=None,
            evidence_value=None,
            target_object=None,
            evidence_target_digest=None,
            evidence_target_device=None,
        ))

    return (
        PANMigrationDecisionSet(tuple(updated)),
        tuple(invalidated),
    )


__all__ = [
    "bind_legacy_target_evidence",
    "reconcile_target_evidence",
    "target_evidence_changed",
    "target_evidence_identity",
]
