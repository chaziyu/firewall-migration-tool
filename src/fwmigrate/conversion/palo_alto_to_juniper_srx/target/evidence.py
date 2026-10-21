"""Completeness-bound evidence from native Junos set configuration."""

from dataclasses import dataclass
import hashlib
import json


_FAMILIES = {
    "addresses": ("security address-book",),
    "applications": ("applications",),
    "interfaces": ("interfaces",),
    "zones": ("security zones",),
    "static_routes": ("routing-options static",),
    "policies": ("security policies",),
    "nat": ("security nat",),
}
_ITEM_FAMILY = {"address": "addresses", "address_group": "addresses", "service": "applications",
                "service_group": "applications", "interface": "interfaces", "zone": "zones",
                "static_route": "static_routes", "policy": "policies"}


@dataclass(frozen=True, slots=True)
class SRXTargetEvidence:
    digest: str
    context: str
    version: str
    mode: str
    complete_families: frozenset[str]
    statements: tuple[dict, ...]
    inactive_hierarchies: tuple[dict, ...]
    global_blockers: tuple[str, ...]
    family_blockers: tuple[tuple[str, tuple[str, ...]], ...]

    def blockers_for(self, family):
        return dict(self.family_blockers).get(family, ())


def _family(path):
    text = " ".join(path.split()).casefold()
    return next((name for name, prefixes in _FAMILIES.items()
                 if any(text == prefix or text.startswith(prefix + " ") for prefix in prefixes)), None)


def build_target_evidence(analysis, source_text, metadata, options):
    if not isinstance(source_text, str) or not source_text.strip():
        raise ValueError("Junos target configuration text is required")
    metadata = metadata if isinstance(metadata, dict) else {}
    context, version, mode = (metadata.get(key) if isinstance(metadata.get(key), str) else ""
                              for key in ("context", "version", "mode"))
    declared = metadata.get("complete_families")
    complete = frozenset(row for row in declared if isinstance(row, str)) if isinstance(declared, list) else frozenset()
    global_blockers, family_blockers = [], {family: [] for family in _FAMILIES}
    if not context or not version or not mode or not isinstance(declared, list):
        global_blockers.append("TARGET_EVIDENCE_METADATA_REQUIRED")
    if context != "root" or context != options.target_context:
        global_blockers.append("TARGET_CONTEXT_MISMATCH_OR_UNSUPPORTED")
    if version != "25.2R1" or version != options.target_version:
        global_blockers.append("TARGET_VERSION_MISMATCH_OR_UNSUPPORTED")
    if mode != "standalone" or mode != options.target_mode:
        global_blockers.append("TARGET_MODE_MISMATCH_OR_UNSUPPORTED")
    if not complete <= set(_FAMILIES) or (isinstance(declared, list) and len(complete) != len(declared)):
        global_blockers.append("TARGET_COMPLETENESS_MANIFEST_INVALID")
    view = getattr(analysis.derived, "inheritance_view", {}) or {}
    if view.get("issues"):
        global_blockers.append("TARGET_GROUP_RESOLUTION_UNVERIFIED")
    statements = tuple(dict(row) for row in view.get("effective_statements", ()))
    inactive = tuple(dict(row) for row in view.get("inactive_hierarchies", ()))
    if any(row.get("target_path", ())[:2] == ("chassis", "cluster") and row.get("status") == "EFFECTIVE" for row in statements):
        global_blockers.append("TARGET_CLUSTER_CONFIGURATION_PRESENT")
    for section in getattr(analysis, "source_sections", ()):
        family = _family(getattr(section, "path", ""))
        if family and getattr(section.status, "value", section.status) in {"PARTIAL", "SOURCE_ONLY", "UNSUPPORTED", "UNKNOWN", "IGNORED", "PARSE_ERROR"}:
            family_blockers[family].append("TARGET_FAMILY_EXTRACTION_INCOMPLETE")
        if family and (getattr(section, "semantic_unknowns", ()) or getattr(section, "unresolved_dependencies", 0)):
            family_blockers[family].append("TARGET_FAMILY_SEMANTIC_EVIDENCE_INCOMPLETE")
    for family in _FAMILIES:
        if family not in complete:
            family_blockers[family].append("TARGET_FAMILY_COMPLETENESS_UNCONFIRMED")
    evidence_identity = json.dumps({"source_sha256": hashlib.sha256(source_text.encode()).hexdigest(),
                                    "metadata": {"context": context, "version": version, "mode": mode,
                                                 "complete_families": sorted(complete)}},
                                   sort_keys=True, separators=(",", ":")).encode()
    return SRXTargetEvidence(hashlib.sha256(evidence_identity).hexdigest(), context, version, mode, complete,
                             statements, inactive, tuple(dict.fromkeys(global_blockers)),
                             tuple((family, tuple(dict.fromkeys(rows))) for family, rows in family_blockers.items()))


__all__ = ["SRXTargetEvidence", "build_target_evidence"]
