"""Validated, pair-owned evidence from a Junos configuration snapshot."""

from dataclasses import dataclass
import hashlib
import json


_FAMILY_PATHS = {
    "addresses": ("security address-book",),
    "applications": ("applications",),
    "interfaces": ("interfaces",),
    "zones": ("security zones",),
    "static_routes": ("routing-options static",),
    "schedules": ("schedulers",),
    "policies": ("security policies",),
    "nat": ("security nat",),
}
_ITEM_FAMILY = {
    "address": "addresses", "address_group": "addresses",
    "service": "applications", "service_group": "applications",
    "interface": "interfaces", "zone": "zones", "static_route": "static_routes",
    "schedule": "schedules", "policy": "policies", "source_nat": "nat", "source_nat_pool": "nat",
}
_INCOMPLETE_STATUSES = {"PARTIAL", "SOURCE_ONLY", "UNSUPPORTED", "UNKNOWN", "IGNORED", "PARSE_ERROR"}


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

    def blockers_for(self, family: str) -> tuple[str, ...]:
        return dict(self.family_blockers).get(family, ())


def _context_matches(value, expected):
    return isinstance(value, str) and value.strip() == expected


def _section_family(path):
    normalized = " ".join(str(path or "").lower().split())
    return next((family for family, prefixes in _FAMILY_PATHS.items()
                 if any(normalized == prefix or normalized.startswith(prefix + " ") for prefix in prefixes)), None)


def build_target_evidence(analysis, source_text, metadata, options):
    """Bind the parsed target snapshot to explicit scope and completeness attestations."""
    from ..options import SRXMigrationOptions

    if not isinstance(source_text, str):
        raise ValueError("Junos target configuration text is required")
    options = options if isinstance(options, SRXMigrationOptions) else SRXMigrationOptions(**(options or {}))
    metadata = metadata if isinstance(metadata, dict) else {}
    context = metadata.get("context") if isinstance(metadata.get("context"), str) else ""
    version = metadata.get("version") if isinstance(metadata.get("version"), str) else ""
    mode = metadata.get("mode") if isinstance(metadata.get("mode"), str) else ""
    declared = metadata.get("complete_families")
    complete_families = frozenset(item for item in declared if isinstance(item, str)) if isinstance(declared, list) else frozenset()

    global_blockers = []
    family_blockers: dict[str, list[str]] = {family: [] for family in _FAMILY_PATHS}
    if not context or not version or not mode or not isinstance(declared, list):
        global_blockers.append("TARGET_EVIDENCE_METADATA_REQUIRED")
    if context != "root" or options.target_context != context:
        global_blockers.append("TARGET_CONTEXT_MISMATCH_OR_UNSUPPORTED")
    if version != options.target_version or version != "25.2R1":
        global_blockers.append("TARGET_VERSION_MISMATCH_OR_UNSUPPORTED")
    if mode != options.target_mode or mode != "standalone":
        global_blockers.append("TARGET_MODE_MISMATCH_OR_UNSUPPORTED")
    if not complete_families <= set(_FAMILY_PATHS):
        global_blockers.append("TARGET_COMPLETENESS_FAMILY_UNKNOWN")
    if isinstance(declared, list) and len(complete_families) != len(declared):
        global_blockers.append("TARGET_COMPLETENESS_MANIFEST_INVALID")

    configured_version = getattr(analysis.config, "version", None)
    if configured_version and configured_version != version:
        global_blockers.append("TARGET_PARSED_VERSION_MISMATCH")

    inheritance = getattr(analysis.derived, "inheritance_view", {}) or {}
    if inheritance.get("issues"):
        global_blockers.append("TARGET_GROUP_RESOLUTION_UNVERIFIED")

    statements = tuple(dict(item) for item in inheritance.get("effective_statements", ()))
    inactive = tuple(dict(item) for item in inheritance.get("inactive_hierarchies", ()))
    if mode == "standalone" and any(
        tuple(str(token).lower() for token in item.get("target_path", ()))[:2] == ("chassis", "cluster")
        and item.get("status") == "EFFECTIVE"
        for item in statements
    ):
        global_blockers.append("TARGET_CLUSTER_CONFIGURATION_PRESENT")

    for section in getattr(analysis, "source_sections", ()):
        if getattr(section, "source_context", None):
            continue
        family = _section_family(getattr(section, "path", ""))
        if family and getattr(section.status, "value", section.status) in _INCOMPLETE_STATUSES:
            family_blockers[family].append("TARGET_FAMILY_EXTRACTION_INCOMPLETE")
        if family and (getattr(section, "semantic_unknowns", ()) or getattr(section, "unresolved_dependencies", 0)):
            family_blockers[family].append("TARGET_FAMILY_SEMANTIC_EVIDENCE_INCOMPLETE")

    for dependency in getattr(analysis.derived, "dependencies", ()):
        if getattr(dependency, "result", None) != "UNRESOLVED":
            continue
        family = _section_family(getattr(dependency, "source_path", ""))
        if family:
            family_blockers[family].append("TARGET_FAMILY_DEPENDENCY_UNRESOLVED")

    for family in _FAMILY_PATHS:
        if family not in complete_families:
            family_blockers[family].append("TARGET_FAMILY_COMPLETENESS_UNCONFIRMED")

    normalized_metadata = {
        "context": context, "version": version, "mode": mode,
        "complete_families": sorted(complete_families),
    }
    identity = json.dumps({
        "target_sha256": hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
        "metadata": normalized_metadata,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(identity).hexdigest()
    return SRXTargetEvidence(
        digest=digest,
        context=context,
        version=version,
        mode=mode,
        complete_families=complete_families,
        statements=statements,
        inactive_hierarchies=inactive,
        global_blockers=tuple(dict.fromkeys(global_blockers)),
        family_blockers=tuple((family, tuple(dict.fromkeys(blockers)))
                              for family, blockers in family_blockers.items()),
    )


__all__ = ["SRXTargetEvidence", "build_target_evidence"]
