from dataclasses import asdict

from .. import PANMigrationDecisionSet, apply_explicit_options
from ..target_evidence import bind_legacy_target_evidence

_DECISION_FORMAT_VERSION = 4


def build_decision_document(source_digest, decision_set, target_evidence=None):
    document = {
        "format_version": _DECISION_FORMAT_VERSION,
        "source_vendor": "fortigate",
        "target_vendor": "palo_alto",
        "source_digest": source_digest,
        "decisions": [item.to_dict() for item in decision_set.decisions],
    }
    if target_evidence:
        document["target_evidence"] = target_evidence
    return document


def load_decision_document(document, source_digest):
    if not isinstance(document, dict) or document.get("format_version") not in {1, 2, 3, _DECISION_FORMAT_VERSION}:
        raise ValueError("Unsupported migration decision document")
    if document.get("source_vendor") != "fortigate" or document.get("target_vendor") != "palo_alto":
        raise ValueError("Migration decision document must be fortigate -> palo_alto")
    if document.get("source_digest") != source_digest:
        raise ValueError("Migration decisions belong to a different source configuration")
    rows = document.get("decisions")
    if document.get("format_version") < 4 and isinstance(rows, list):
        rows = [{key: value for key, value in row.items()
                 if key not in {"approved_operation", "approval_context"}} if isinstance(row, dict) else row for row in rows]
    decisions = PANMigrationDecisionSet.from_dict({"decisions": rows})
    if document.get("format_version") in {1, 2}:
        decisions = bind_legacy_target_evidence(decisions, document.get("target_evidence"))
    return decisions


def options_mapping(options):
    mapping = {
        "vdoms": {name: {key: value for key, value in asdict(item).items() if value is not None}
                   for name, item in options.vdoms.items()},
        "interfaces": {vdom: {name: {key: value for key, value in asdict(item).items() if value is not None}
                              for name, item in mappings.items()}
                       for vdom, mappings in options.interfaces.items()},
    }
    if options.zones is not None:
        mapping["zones"] = {vdom: {name: {"target_zone": item.target_zone} for name, item in mappings.items()
                                    if item.target_zone is not None}
                            for vdom, mappings in options.zones.items()}
    return mapping


def confirm_mapping_decisions(decision_set, options, config):
    return apply_explicit_options(config, decision_set, options)
