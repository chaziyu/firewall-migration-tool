"""Read sanitized native target records; absence is never completeness."""
from collections import Counter


def build_target_evidence(analysis, source_digest):
    records = analysis.extracted.source_objects
    keys = [(r.cli_scope, r.vdom, r.source_path, r.object_name) for r in records]
    duplicates = {key for key, count in Counter(keys).items() if count > 1}
    return {"digest": source_digest, "records": records, "duplicates": duplicates,
            "version": analysis.extracted.source_metadata.fortios_version,
            "validation_errors": any(i.severity == "error" for i in analysis.validation.issues)}
