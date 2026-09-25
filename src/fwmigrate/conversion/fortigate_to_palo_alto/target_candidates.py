"""Scope-aware target candidates for FortiGate to PAN-OS recommendations."""

from dataclasses import dataclass
from enum import StrEnum

from ...vendors.palo_alto.relationships.scopes import build_scope_hierarchy, visible_scopes
from ...vendors.palo_alto.source_model import PANScope, pan_scope_identity


class PANTargetCandidateMatchClass(StrEnum):
    EXACT_EQUIVALENT = "EXACT_EQUIVALENT"
    LIKELY_REUSE = "LIKELY_REUSE"
    POSSIBLE = "POSSIBLE"
    CONFLICT = "CONFLICT"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(frozen=True, slots=True)
class PANTargetCandidate:
    family: str
    name: str
    scope_identity: str
    source_path: str
    match_class: PANTargetCandidateMatchClass
    strong_evidence: tuple[str, ...] = ()
    supporting_evidence: tuple[str, ...] = ()
    contradictions: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "family": self.family,
            "name": self.name,
            "scope_identity": self.scope_identity,
            "source_path": self.source_path,
            "match_class": self.match_class.value,
            "strong_evidence": list(self.strong_evidence),
            "supporting_evidence": list(self.supporting_evidence),
            "contradictions": list(self.contradictions),
        }


def classify_candidate(strong_evidence=(), supporting_evidence=(), contradictions=(), *, exact_equivalent=False):
    """Classify deterministic comparator output without assigning a score."""
    if contradictions:
        return PANTargetCandidateMatchClass.CONFLICT
    if exact_equivalent:
        return PANTargetCandidateMatchClass.EXACT_EQUIVALENT
    if strong_evidence:
        return PANTargetCandidateMatchClass.LIKELY_REUSE
    if supporting_evidence:
        return PANTargetCandidateMatchClass.POSSIBLE
    return PANTargetCandidateMatchClass.AMBIGUOUS


def target_vsys_value(decisions, source_vdom: str) -> str | None:
    """Return a target VSYS only from a usable, explicit decision value."""
    from .recommendations import decision_value
    from .decisions import make_decision_key

    return decision_value(decisions, make_decision_key(source_vdom, "vdom", source_vdom, "vsys"))


def build_target_candidates(target, attribute: str, family: str, source_name: str,
                            target_device: str | None, target_vsys: str | None,
                            comparator=None, source_object=None) -> tuple[PANTargetCandidate, ...]:
    """Find same-name PAN objects that are visible in the selected target scope.

    A same-name object is only a possible candidate here. Family comparators can
    add stronger evidence after field-level semantics have been verified.
    """
    if target is None or not source_name:
        return ()
    config = target.config
    records = tuple(item for item in getattr(config, attribute, ()) if getattr(item, "name", None) == source_name)
    if not records:
        return ()

    scopes_by_identity = {}
    for scope in (*getattr(config, "scopes", ()), *(getattr(item, "scope", None) for item in records)):
        if scope is not None:
            scopes_by_identity.setdefault(pan_scope_identity(scope), scope)
    scopes = tuple(scopes_by_identity.values())
    anchors = _anchor_scopes(target_device, target_vsys, scopes)
    visible = set()
    if len(anchors) == 1:
        index = getattr(getattr(target, "derived", None), "reference_index", None)
        hierarchy = getattr(getattr(target, "derived", None), "scope_hierarchy", None)
        if hierarchy is None and index is not None:
            hierarchy = getattr(index, "hierarchy", None)
        hierarchy = hierarchy or build_scope_hierarchy(list(scopes))
        anchor = anchors[0]
        visible.update(visible_scopes(anchor, hierarchy))
        if index is not None and hasattr(index, "candidates"):
            # The native index confirms visibility for families it indexes.
            indexed = index.candidates(family, source_name, anchor)
            if indexed:
                visible.update(pan_scope_identity(item.scope) for item in indexed if item.scope)
    # With no unique owner context, only explicitly shared objects are safely
    # eligible. A same-name object in another VSYS is never surfaced as a match.
    eligible = []
    for item in records:
        scope = getattr(item, "scope", None)
        if scope is None:
            continue
        identity = pan_scope_identity(scope)
        if scope.kind == "shared":
            pass
        elif len(anchors) != 1 or identity not in visible:
            continue
        if target_vsys and scope.vsys and scope.vsys != target_vsys:
            continue
        if target_device and _scope_device(scope) and _scope_device(scope) != target_device:
            continue
        eligible.append(item)
    result = []
    for item in eligible:
        strong, supporting, contradictions = comparator(source_object, item) if comparator else ((), ("same name and PAN-OS object family",), ())
        match_class = classify_candidate(strong, supporting, contradictions)
        if len(eligible) > 1:
            match_class = PANTargetCandidateMatchClass.AMBIGUOUS
        scope = getattr(item, "scope", None)
        result.append(PANTargetCandidate(
            family=family,
            name=str(item.name),
            scope_identity=pan_scope_identity(scope),
            source_path=str(getattr(item, "source_path", "") or ""),
            match_class=match_class,
            strong_evidence=tuple(strong),
            supporting_evidence=tuple(supporting),
            contradictions=tuple(contradictions),
        ))
    return tuple(sorted(result, key=lambda candidate: (candidate.scope_identity, candidate.name, candidate.source_path)))


def _scope_device(scope: PANScope) -> str | None:
    provenance = scope.template_provenance or {}
    return (
        scope.device_serial or scope.device_name
        or provenance.get("managed_device_serial") or provenance.get("managed_device")
    )


def _anchor_scopes(target_device: str | None, target_vsys: str | None,
                   scopes: tuple[PANScope, ...]) -> list[PANScope]:
    if not target_device:
        return []
    anchors = []
    for scope in scopes:
        if _scope_device(scope) != target_device:
            continue
        if target_vsys:
            if scope.vsys != target_vsys or scope.kind not in {"vsys", "device-group", "template", "template-stack"}:
                continue
        elif scope.kind not in {"device", "device-group"}:
            continue
        anchors.append(scope)
    return list({pan_scope_identity(scope): scope for scope in anchors}.values())
