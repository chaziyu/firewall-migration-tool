"""Readiness classification for rendered FortiGate to PAN-OS artifacts."""

from enum import StrEnum


class PANArtifactStatus(StrEnum):
    READY = "READY"
    READY_NO_CHANGES = "READY_NO_CHANGES"
    PARTIAL = "PARTIAL"
    NEEDS_MAPPING = "NEEDS_MAPPING"


def classify_artifact_status(rendered, *, pending_mapping_issues=(), coverage=None):
    report = rendered.report
    dispositions = report.get("render_dispositions", {})
    counts = report.get("counts", {})
    if pending_mapping_issues:
        return PANArtifactStatus.NEEDS_MAPPING
    if coverage is not None and not coverage.get("complete", False):
        return PANArtifactStatus.PARTIAL
    if dispositions.get("BLOCK", 0):
        return PANArtifactStatus.PARTIAL
    if any(counts.get(key, 0) for key in ("PARTIAL", "MANUAL_REVIEW", "UNSUPPORTED")):
        return PANArtifactStatus.PARTIAL
    additions = dispositions.get("CREATE", 0) + dispositions.get("CONFIGURE", 0)
    if additions == 0 and dispositions.get("REUSE", 0) > 0 and not rendered.commands:
        return PANArtifactStatus.READY_NO_CHANGES
    if additions > 0 or rendered.commands:
        return PANArtifactStatus.READY
    return PANArtifactStatus.NEEDS_MAPPING
