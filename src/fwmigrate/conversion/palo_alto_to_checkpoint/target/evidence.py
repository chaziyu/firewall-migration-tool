"""Validated native Management evidence; Gaia evidence remains separate."""

from collections import Counter

from ..design.deterministic import digest


FAMILIES = {"objects", "services", "packages", "layers", "gateways", "policies", "nat"}


def build_target_evidence(analysis, source_text, metadata, options):
    if not isinstance(source_text, str) or not isinstance(metadata, dict):
        raise ValueError(
            "Check Point comparison requires sanitized source and explicit metadata"
        )
    if (
        metadata.get("context") != options.management_domain
        or metadata.get("version") != options.management_api_version
        or metadata.get("mode") != "management"
    ):
        raise ValueError(
            "Check Point destination scope or version differs from the design"
        )
    families = metadata.get("complete_families")
    if (
        not isinstance(families, list)
        or any(not isinstance(value, str) for value in families)
        or len(families) != len(set(families))
        or not set(families) <= FAMILIES
    ):
        raise ValueError("Declare valid complete Check Point evidence families")
    native_metadata = analysis.source_metadata
    if (
        native_metadata.api_version != options.management_api_version
        or native_metadata.management_server != options.management_target
    ):
        raise ValueError(
            "Destination must identify the selected Management server and API version"
        )
    if analysis.scope.ambiguous or analysis.scope.reasons:
        raise ValueError("Check Point destination scope is unresolved")
    if any(
        str(issue.severity).casefold() == "error"
        for issue in analysis.validation.issues
    ):
        raise ValueError("Check Point destination contains validation errors")
    if any(
        not row.complete
        or str(getattr(row.status, "value", row.status))
        not in {"OK", "SUCCESS_WITH_DATA", "SUCCESS_EMPTY"}
        for row in analysis.collection
        if row.command != "collection-coverage"
    ):
        raise ValueError(
            "Incomplete Check Point collection cannot prove target absence"
        )
    config = analysis.config
    if any(row.source_plane != "gaia" for row in analysis.source_objects):
        raise ValueError(
            "Unmodeled Management evidence prevents destination comparison"
        )
    objects = [
        obj
        for field in type(config).model_fields
        for obj in getattr(config, field)
        if hasattr(obj, "uid") and getattr(obj, "source_plane", None) != "gaia"
    ]
    if any(obj.domain != options.management_domain for obj in objects):
        raise ValueError(
            "Every Management object must have the selected explicit Domain"
        )
    if len({obj.domain_uid for obj in objects if obj.domain_uid}) > 1:
        raise ValueError("Ambiguous destination Domain identities")
    uids = [obj.uid for obj in objects if obj.uid]
    if any(count > 1 for count in Counter(uids).values()):
        raise ValueError("Duplicate destination UIDs are ambiguous")
    return {
        "config": config,
        "objects": objects,
        "complete_families": set(families),
        "digest": digest({"source": source_text, "metadata": metadata}),
    }
